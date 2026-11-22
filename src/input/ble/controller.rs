//! High-level mouse and keyboard actions built on the Windows BLE HID service.

use anyhow::{Result, bail};

use super::{
    reports::{KeyboardReport, MouseReport},
    service::BleHidService,
};
use crate::input::event::{KeyModifiers, MouseButtons};

/// Single-phone input controller. The BLE service remains responsible for GATT transport;
/// this type turns ordinary mouse and keyboard actions into correctly ordered HID reports.
pub struct BleInputController {
    service: BleHidService,
}

impl BleInputController {
    /// Starts advertising the HID service and returns a ready-to-use controller.
    pub async fn start() -> Result<Self> {
        Ok(Self {
            service: BleHidService::start().await?,
        })
    }

    /// Sends relative pointer movement. Large movements are split into signed 8-bit reports.
    pub async fn move_mouse(&self, dx: i32, dy: i32) -> Result<()> {
        let (mut remaining_x, mut remaining_y) = (dx, dy);
        while remaining_x != 0 || remaining_y != 0 {
            let step_x = remaining_x.clamp(-127, 127) as i16;
            let step_y = remaining_y.clamp(-127, 127) as i16;
            self.service
                .send_mouse_report(MouseReport::new(MouseButtons::NONE, step_x, step_y, 0))
                .await?;
            remaining_x -= step_x as i32;
            remaining_y -= step_y as i32;

            // Keep consecutive relative reports distinct on slower BLE hosts. Without a
            // short pacing interval, back-to-back notifications can be coalesced or dropped
            // by some host stacks even though the GATT notification call itself succeeds.
            if remaining_x != 0 || remaining_y != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        Ok(())
    }

    /// Clicks one mouse button and then sends a release report.
    pub async fn click(&self, button: MouseButtons) -> Result<()> {
        if button.bits().count_ones() != 1 {
            bail!("click requires a supported mouse button");
        }
        self.service
            .send_mouse_report(MouseReport::new(button, 0, 0, 0))
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.service.send_mouse_report(MouseReport::release()).await
    }

    /// Sends vertical wheel movement, splitting values larger than one HID report.
    pub async fn scroll(&self, amount: i32) -> Result<()> {
        let mut remaining = amount;
        while remaining != 0 {
            let step = remaining.clamp(-127, 127) as i16;
            self.service
                .send_mouse_report(MouseReport::new(MouseButtons::NONE, 0, 0, step))
                .await?;
            remaining -= step as i32;
        }
        Ok(())
    }

    /// Presses a USB HID keyboard usage with optional modifier bits, then releases it.
    pub async fn tap_key(&self, modifiers: KeyModifiers, usage: u8) -> Result<()> {
        if usage == 0 {
            bail!("keyboard usage 0 is reserved for no key");
        }
        self.service
            .send_keyboard_report(KeyboardReport::new(modifiers, [usage, 0, 0, 0, 0, 0]))
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.service
            .send_keyboard_report(KeyboardReport::release())
            .await
    }

    /// Types basic ASCII text. Unsupported non-ASCII characters return an error instead of
    /// silently producing incorrect input. Unicode text injection can be added separately.
    pub async fn type_text(&self, text: &str) -> Result<()> {
        for character in text.chars() {
            let (usage, shifted) = ascii_key(character).ok_or_else(|| {
                anyhow::anyhow!("unsupported character for BLE HID typing: {character:?}")
            })?;
            let modifiers = if shifted {
                KeyModifiers::LEFT_SHIFT
            } else {
                KeyModifiers::NONE
            };
            self.tap_key(modifiers, usage).await?;
            tokio::time::sleep(std::time::Duration::from_millis(8)).await;
        }
        Ok(())
    }

    /// Releases all mouse buttons and keyboard keys.
    pub async fn release_all(&self) -> Result<()> {
        self.service
            .send_mouse_report(MouseReport::release())
            .await?;
        self.service
            .send_keyboard_report(KeyboardReport::release())
            .await
    }

    /// Stops BLE advertising.
    pub fn stop(&self) -> Result<()> {
        self.service.stop()
    }

    /// Returns the current Windows GATT advertising status.
    pub fn advertising_status(&self) -> Result<String> {
        self.service.advertising_status()
    }
}

/// Maps a printable/basic control ASCII character to (USB HID usage, Shift required).
fn ascii_key(character: char) -> Option<(u8, bool)> {
    let key = match character {
        'a'..='z' => (0x04 + (character as u8 - b'a'), false),
        'A'..='Z' => (0x04 + (character as u8 - b'A'), true),
        '1'..='9' => (0x1e + (character as u8 - b'1'), false),
        '0' => (0x27, false),
        ' ' => (0x2c, false),
        '\n' | '\r' => (0x28, false),
        '\t' => (0x2b, false),
        '!' => (0x1e, true),
        '@' => (0x1f, true),
        '#' => (0x20, true),
        '$' => (0x21, true),
        '%' => (0x22, true),
        '^' => (0x23, true),
        '&' => (0x24, true),
        '*' => (0x25, true),
        '(' => (0x26, true),
        ')' => (0x27, true),
        '-' => (0x2d, false),
        '_' => (0x2d, true),
        '=' => (0x2e, false),
        '+' => (0x2e, true),
        '[' => (0x2f, false),
        '{' => (0x2f, true),
        ']' => (0x30, false),
        '}' => (0x30, true),
        '\\' => (0x31, false),
        '|' => (0x31, true),
        ';' => (0x33, false),
        ':' => (0x33, true),
        '\'' => (0x34, false),
        '"' => (0x34, true),
        '`' => (0x35, false),
        '~' => (0x35, true),
        ',' => (0x36, false),
        '<' => (0x36, true),
        '.' => (0x37, false),
        '>' => (0x37, true),
        '/' => (0x38, false),
        '?' => (0x38, true),
        _ => return None,
    };
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::ascii_key;

    #[test]
    fn maps_letters_and_uppercase_shift() {
        assert_eq!(ascii_key('a'), Some((0x04, false)));
        assert_eq!(ascii_key('Z'), Some((0x1d, true)));
    }

    #[test]
    fn maps_digits_and_common_punctuation() {
        assert_eq!(ascii_key('0'), Some((0x27, false)));
        assert_eq!(ascii_key('!'), Some((0x1e, true)));
        assert_eq!(ascii_key('?'), Some((0x38, true)));
    }

    #[test]
    fn rejects_non_ascii_text() {
        assert_eq!(ascii_key('中'), None);
    }
}
