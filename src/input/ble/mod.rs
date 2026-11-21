//! HID-over-GATT protocol definitions.
//!
//! This module deliberately contains no fake platform implementation. Publishing a GATT
//! service requires a Windows BLE peripheral-capable adapter and a WinRT GATT server.

pub mod capability;
pub mod descriptor;
pub mod reports;

pub use capability::{BleCapability, BleCapabilityStatus};
pub use descriptor::{HID_INFORMATION, HID_REPORT_MAP, HID_SERVICE};
pub use reports::{KeyboardReport, MouseReport};
