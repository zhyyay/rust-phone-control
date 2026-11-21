//! Windows BLE HID host capability checks.
//!
//! This module intentionally does not advertise yet. The first milestone verifies that
//! the default adapter supports BLE Peripheral mode and that Windows can create the
//! standard HID-over-GATT service provider.

use anyhow::{Context, Result};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    BluetoothError, GattServiceProvider, GattServiceUuids,
};

use crate::input::ble::{BleCapability, BleCapabilityStatus};
use crate::platform::windows::bluetooth::default_adapter_info;

/// Probe adapter role support and Windows HID GATT service-provider creation.
///
/// A successful result means the OS accepted creation of the service provider. It does
/// not mean that the service is advertised, discoverable, paired, or validated by iOS.
pub async fn probe_hid_peripheral() -> Result<BleCapability> {
    let adapter = default_adapter_info().await?;
    let adapter_name = Some(adapter.device_id.clone());

    if !adapter.low_energy_supported {
        return Ok(BleCapability {
            adapter_name,
            status: BleCapabilityStatus::Unsupported {
                reason: "The default Bluetooth adapter does not report Bluetooth LE support.".into(),
            },
        });
    }

    if !adapter.peripheral_role_supported {
        return Ok(BleCapability {
            adapter_name,
            status: BleCapabilityStatus::Unsupported {
                reason: "The adapter supports BLE Central but not BLE Peripheral/GATT Server mode.".into(),
            },
        });
    }

    let hid_uuid = GattServiceUuids::HumanInterfaceDevice()?;
    let result = GattServiceProvider::CreateAsync(hid_uuid)?
        .await
        .context("Windows failed while creating the HID GATT service provider")?;
    let error = result.Error()?;

    if error != BluetoothError::Success {
        return Ok(BleCapability {
            adapter_name,
            status: BleCapabilityStatus::ProbeFailed {
                reason: format!("Windows rejected HID GATT service creation: {error:?}"),
            },
        });
    }

    Ok(BleCapability {
        adapter_name,
        status: BleCapabilityStatus::Supported,
    })
}
