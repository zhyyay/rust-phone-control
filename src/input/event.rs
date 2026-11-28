/// Mouse button state. The five low bits map to HID buttons 1 through 5.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseButtons(u8);

impl MouseButtons {
    pub const NONE: Self = Self(0);
    pub const LEFT: Self = Self(1 << 0);
    pub const RIGHT: Self = Self(1 << 1);
    pub const MIDDLE: Self = Self(1 << 2);
    pub const BACK: Self = Self(1 << 3);
    pub const FORWARD: Self = Self(1 << 4);

    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & 0b0001_1111)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for MouseButtons {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from_bits_truncate(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for MouseButtons {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

/// USB HID keyboard modifier bits (left Ctrl/Shift/Alt/GUI, then right variants).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyModifiers(u8);

impl KeyModifiers {
    pub const NONE: Self = Self(0);
    pub const LEFT_CTRL: Self = Self(1 << 0);
    pub const LEFT_SHIFT: Self = Self(1 << 1);
    pub const LEFT_ALT: Self = Self(1 << 2);
    pub const LEFT_GUI: Self = Self(1 << 3);
    pub const RIGHT_CTRL: Self = Self(1 << 4);
    pub const RIGHT_SHIFT: Self = Self(1 << 5);
    pub const RIGHT_ALT: Self = Self(1 << 6);
    pub const RIGHT_GUI: Self = Self(1 << 7);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl std::ops::BitOr for KeyModifiers {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Events emitted by the desktop UI and translated by a platform backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    PointerMove {
        dx: i16,
        dy: i16,
    },
    PointerButtons(MouseButtons),
    Scroll {
        horizontal: i16,
        vertical: i16,
    },
    KeyModifiers(KeyModifiers),
    /// USB HID keyboard usage ID, not a Unicode character.
    KeyUsage(u8),
    /// Press or release one USB HID keyboard usage while preserving other held keys.
    KeyState {
        usage: u8,
        pressed: bool,
    },
    ReleaseAll,
}
