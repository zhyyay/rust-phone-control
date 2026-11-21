//! Shared configuration for the built-in AirPlay control endpoint.

pub const SERVICE_TYPE: &str = "_airplay._tcp.local.";
pub const SERVICE_NAME: &str = "Rust Phone Control";
pub const HOST_NAME: &str = "rust-phone-control.local.";
pub const TCP_PORT: u16 = 7000;
pub const MODEL: &str = "RustPhoneControl1,1";
pub const SOURCE_VERSION: &str = "1.0";
pub const FEATURES: &str = "0x0";

/// Returns a locally administered identifier for mDNS.
///
/// This is deliberately not presented as a hardware MAC address. AirPlay's
/// deviceid field is commonly a MAC address; this stable-per-process value is
/// only a discovery identity until the Windows adapter identity is wired in.
pub fn device_id() -> String {
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-host".to_owned());
    let hash = host.bytes().fold(0x811c9dc5u32, |state, byte| {
        (state ^ u32::from(byte)).wrapping_mul(0x01000193)
    });
    let pid = std::process::id();
    format!(
        "02:52:50:{:02X}:{:02X}:{:02X}",
        (hash >> 16) as u8,
        (hash >> 8) as u8 ^ (pid >> 8) as u8,
        hash as u8 ^ pid as u8
    )
}
