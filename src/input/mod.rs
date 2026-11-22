//! Platform-independent input types shared by desktop capture and device backends.

pub mod ble;
pub mod event;

pub use event::{InputEvent, KeyModifiers, MouseButtons};
