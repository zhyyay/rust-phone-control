use super::descriptor::{HID_INFORMATION_VALUE, HID_REPORT_MAP};
use crate::input::event::{KeyModifiers, MouseButtons};

/// Five-byte mouse report payload; the Report Reference descriptor carries report ID 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseReport {
    pub buttons: MouseButtons,
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,
    pub pan: i8,
}

impl MouseReport {
    pub const fn new(buttons: MouseButtons, dx: i16, dy: i16, wheel: i16, pan: i16) -> Self {
        Self {
            buttons,
            dx: clamp_i16_to_i8(dx),
            dy: clamp_i16_to_i8(dy),
            wheel: clamp_i16_to_i8(wheel),
            pan: clamp_i16_to_i8(pan),
        }
    }

    pub const fn release() -> Self {
        Self::new(MouseButtons::NONE, 0, 0, 0, 0)
    }

    pub const fn as_bytes(self) -> [u8; 5] {
        [
            self.buttons.bits(),
            self.dx as u8,
            self.dy as u8,
            self.wheel as u8,
            self.pan as u8,
        ]
    }
}

/// Eight-byte keyboard report payload; the Report Reference descriptor carries report ID 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardReport {
    pub modifiers: KeyModifiers,
    pub keys: [u8; 6],
}

impl KeyboardReport {
    pub const fn new(modifiers: KeyModifiers, keys: [u8; 6]) -> Self {
        Self { modifiers, keys }
    }

    pub const fn release() -> Self {
        Self::new(KeyModifiers::NONE, [0; 6])
    }

    pub const fn as_bytes(self) -> [u8; 8] {
        [
            self.modifiers.bits(),
            0,
            self.keys[0],
            self.keys[1],
            self.keys[2],
            self.keys[3],
            self.keys[4],
            self.keys[5],
        ]
    }
}

/// Clamp a relative movement value to the signed 8-bit range advertised by the descriptor.
pub const fn clamp_i16_to_i8(value: i16) -> i8 {
    if value > i8::MAX as i16 {
        i8::MAX
    } else if value < -127 {
        -127
    } else {
        value as i8
    }
}

/// Values useful to the future Windows GATT service publisher.
pub const fn report_map() -> &'static [u8] {
    HID_REPORT_MAP
}

pub const fn hid_information() -> [u8; 4] {
    HID_INFORMATION_VALUE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::event::{KeyModifiers, MouseButtons};

    #[test]
    fn mouse_report_has_expected_layout_and_clamps_motion() {
        let report = MouseReport::new(MouseButtons::LEFT | MouseButtons::RIGHT, 300, -300, 1, -2);
        assert_eq!(report.as_bytes(), [0b0000_0011, 127, 129, 1, 254]);
    }

    #[test]
    fn mouse_report_serializes_horizontal_pan_independently() {
        let report = MouseReport::new(MouseButtons::NONE, 0, 0, 0, 7);
        assert_eq!(report.as_bytes(), [0, 0, 0, 0, 7]);

        let reverse = MouseReport::new(MouseButtons::NONE, 0, 0, 0, -7);
        assert_eq!(reverse.as_bytes(), [0, 0, 0, 0, 249]);
    }

    #[test]
    fn release_report_clears_every_mouse_button_and_axis() {
        assert_eq!(MouseReport::release().as_bytes(), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn keyboard_report_has_standard_eight_byte_layout() {
        let report = KeyboardReport::new(KeyModifiers::LEFT_SHIFT, [0x04, 0, 0, 0, 0, 0]);
        assert_eq!(report.as_bytes(), [0x02, 0, 0x04, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn release_report_clears_modifiers_and_pressed_keys() {
        assert_eq!(KeyboardReport::release().as_bytes(), [0; 8]);
    }

    #[test]
    fn signed_motion_clamping_matches_report_range() {
        assert_eq!(clamp_i16_to_i8(-500), -127);
        assert_eq!(clamp_i16_to_i8(500), 127);
        assert_eq!(clamp_i16_to_i8(12), 12);
    }
}
