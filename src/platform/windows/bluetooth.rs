//! Windows Bluetooth adapter capability probing via WinRT.

use anyhow::{Context, Result};
use windows_062::Devices::Bluetooth::BluetoothAdapter;

/// Describes the default Windows Bluetooth adapter capabilities needed by a GATT server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BluetoothAdapterInfo {
    pub device_id: String,
    pub bluetooth_address: u64,
    pub low_energy_supported: bool,
    pub central_role_supported: bool,
    pub peripheral_role_supported: bool,
}

/// Query the default adapter. This does not start advertising or pair with a device.
pub async fn default_adapter_info() -> Result<BluetoothAdapterInfo> {
    let adapter = BluetoothAdapter::GetDefaultAsync()?
        .await
        .context("failed to query the default Windows Bluetooth adapter")?;

    Ok(BluetoothAdapterInfo {
        device_id: format!("{:?}", adapter.DeviceId()?),
        bluetooth_address: adapter.BluetoothAddress()?,
        low_energy_supported: adapter.IsLowEnergySupported()?,
        central_role_supported: adapter.IsCentralRoleSupported()?,
        peripheral_role_supported: adapter.IsPeripheralRoleSupported()?,
    })
}
