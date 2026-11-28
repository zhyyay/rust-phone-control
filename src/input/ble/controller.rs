//! High-level mouse and keyboard actions built on the Windows BLE HID service.

use anyhow::{Result, bail};
use std::sync::Mutex;

use super::{
    reports::{KeyboardReport, MouseReport},
    service::BleHidService,
};
use crate::input::event::{InputEvent, KeyModifiers, MouseButtons};

/// Single-phone input controller. The BLE service remains responsible for GATT transport;
/// this type turns ordinary mouse and keyboard actions into correctly ordered HID reports.
pub struct BleInputController {
    service: BleHidService,
    input_state: Mutex<ControllerInputState>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ControllerInputState {
    buttons: MouseButtons,
    modifiers: KeyModifiers,
}

impl ControllerInputState {
    fn apply(&mut self, event: InputEvent) {
        match event {
            InputEvent::PointerButtons(buttons) => self.buttons = buttons,
            InputEvent::KeyModifiers(modifiers) => self.modifiers = modifiers,
            InputEvent::ReleaseAll => *self = Self::default(),
            InputEvent::PointerMove { .. }
            | InputEvent::Scroll { .. }
            | InputEvent::KeyUsage(_) => {}
        }
    }
}

impl BleInputController {
    /// Starts advertising the HID service and returns a ready-to-use controller.
    pub async fn start() -> Result<Self> {
        Ok(Self {
            service: BleHidService::start().await?,
            input_state: Mutex::new(ControllerInputState::default()),
        })
    }

    /// Dispatches one platform-independent input event to the BLE HID transport.
    ///
    /// Button and modifier events update persistent state; subsequent pointer reports retain
    /// held buttons, and key taps retain currently-held modifiers. ReleaseAll clears both.
    pub async fn dispatch(&self, event: InputEvent) -> Result<()> {
        let (buttons, modifiers) = {
            let mut state = self.input_state.lock().unwrap_or_else(|p| p.into_inner());
            state.apply(event);
            (state.buttons, state.modifiers)
        };

        match event {
            InputEvent::PointerMove { dx, dy } => {
                let (mut remaining_x, mut remaining_y) = (dx as i32, dy as i32);
                while remaining_x != 0 || remaining_y != 0 {
                    let step_x = remaining_x.clamp(-127, 127) as i16;
                    let step_y = remaining_y.clamp(-127, 127) as i16;
                    self.service
                        .send_mouse_report(MouseReport::new(buttons, step_x, step_y, 0))
                        .await?;
                    remaining_x -= step_x as i32;
                    remaining_y -= step_y as i32;
                    if remaining_x != 0 || remaining_y != 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
                Ok(())
            }
            InputEvent::PointerButtons(_) => {
                self.service
                    .send_mouse_report(MouseReport::new(buttons, 0, 0, 0))
                    .await
            }
            InputEvent::Scroll { vertical } => {
                self.service
                    .send_mouse_report(MouseReport::new(buttons, 0, 0, vertical))
                    .await
            }
            InputEvent::KeyModifiers(_) => {
                self.service
                    .send_keyboard_report(KeyboardReport::new(modifiers, [0; 6]))
                    .await
            }
            InputEvent::KeyUsage(usage) => {
                if usage == 0 {
                    bail!("keyboard usage 0 is reserved for no key");
                }
                self.service
                    .send_keyboard_report(KeyboardReport::new(modifiers, [usage, 0, 0, 0, 0, 0]))
                    .await?;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                self.service
                    .send_keyboard_report(KeyboardReport::new(modifiers, [0; 6]))
                    .await
            }
            InputEvent::ReleaseAll => {
                self.service
                    .send_mouse_report(MouseReport::release())
                    .await?;
                self.service
                    .send_keyboard_report(KeyboardReport::release())
                    .await
            }
        }
    }

    /// Sends relative pointer movement. Large movements are split into signed 8-bit reports.
    pub async fn move_mouse(&self, dx: i32, dy: i32) -> Result<()> {
        self.dispatch(InputEvent::PointerMove { dx, dy }).await
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
        self.dispatch(InputEvent::Scroll { vertical: amount }).await
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
        // Validate the complete payload before sending the first HID report. This avoids
        // partially typing a message when a later character (for example, CJK text) is
        // unsupported by the current keyboard layout mapper.
        let keys = validate_text(text)?;

        for (usage, shifted) in keys {
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
        // Keep the controller's persistent state in sync with the reports sent to the host.
        // Going through dispatch also clears held buttons and modifiers before the next event.
        self.dispatch(InputEvent::ReleaseAll).await
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

/// Validates and maps an entire message before any HID reports are sent.
fn validate_text(text: &str) -> Result<Vec<(u8, bool)>> {
    text.chars()
        .map(|character| {
            ascii_key(character).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported character for BLE HID typing: {character:?}; only basic ASCII is supported"
                )
            })
        })
        .collect()
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
    use super::{ControllerInputState, ascii_key, validate_text};
    use crate::input::event::{InputEvent, KeyModifiers, MouseButtons};

    #[test]
    fn dispatcher_state_preserves_held_buttons_and_modifiers_until_release_all() {
        let mut state = ControllerInputState::default();
        state.apply(InputEvent::PointerButtons(
            MouseButtons::LEFT | MouseButtons::RIGHT,
        ));
        state.apply(InputEvent::KeyModifiers(KeyModifiers::LEFT_SHIFT));
        state.apply(InputEvent::PointerMove { dx: 12, dy: -4 });
        assert_eq!(state.buttons, MouseButtons::LEFT | MouseButtons::RIGHT);
        assert_eq!(state.modifiers, KeyModifiers::LEFT_SHIFT);

        state.apply(InputEvent::ReleaseAll);
        assert_eq!(state, ControllerInputState::default());
    }

    #[test]
    fn pointer_and_key_events_do_not_clear_held_state() {
        let mut state = ControllerInputState {
            buttons: MouseButtons::MIDDLE,
            modifiers: KeyModifiers::LEFT_CTRL,
        };
        state.apply(InputEvent::Scroll { vertical: 1 });
        state.apply(InputEvent::KeyUsage(0x04));
        assert_eq!(state.buttons, MouseButtons::MIDDLE);
        assert_eq!(state.modifiers, KeyModifiers::LEFT_CTRL);
    }

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
    fn rejects_non_ascii_text_before_typing_anything() {
        assert_eq!(ascii_key('中'), None);
        assert!(validate_text("hello 中 world").is_err());
    }

    #[test]
    fn validates_complete_ascii_messages() {
        assert_eq!(validate_text("Hello, World! 123").unwrap().len(), 17);
        assert!(validate_text("").unwrap().is_empty());
        assert!(validate_text("line 1\\nline 2").is_ok());
    }
}
