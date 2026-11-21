/// Result of checking whether the local Bluetooth adapter can advertise a GATT service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleCapabilityStatus {
    /// No platform probe has been run yet.
    NotChecked,
    /// The adapter reports BLE peripheral/GATT-server support.
    Supported,
    /// The adapter is present but cannot act as a BLE peripheral.
    Unsupported { reason: String },
    /// The capability query failed; this is not equivalent to unsupported.
    ProbeFailed { reason: String },
}

/// Hardware capability information shown by the UI before attempting to pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleCapability {
    pub adapter_name: Option<String>,
    pub status: BleCapabilityStatus,
}

impl Default for BleCapability {
    fn default() -> Self {
        Self {
            adapter_name: None,
            status: BleCapabilityStatus::NotChecked,
        }
    }
}

impl BleCapability {
    pub fn is_supported(&self) -> bool {
        matches!(self.status, BleCapabilityStatus::Supported)
    }
}
