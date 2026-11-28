//! HID-over-GATT protocol definitions.
//!
//! This module deliberately contains no fake platform implementation. Publishing a GATT
//! service requires a Windows BLE peripheral-capable adapter and a WinRT GATT server.

pub mod capability;
#[cfg(windows)]
pub mod controller;
pub mod descriptor;
#[cfg(windows)]
pub mod desktop;
pub mod reports;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod windows;

pub use capability::{BleCapability, BleCapabilityStatus};
#[cfg(windows)]
pub use controller::BleInputController;
pub use descriptor::{
    HID_CONTROL_POINT, HID_INFORMATION, HID_INFORMATION_VALUE, HID_PROTOCOL_MODE, HID_REPORT,
    HID_REPORT_MAP, HID_REPORT_MAP_CHARACTERISTIC, HID_REPORT_REFERENCE, HID_SERVICE,
    REPORT_TYPE_INPUT,
};
pub use reports::{KeyboardReport, MouseReport};
#[cfg(windows)]
pub use service::BleConnectionState;
