//! Shared configuration for the built-in AirPlay control endpoint.

pub const SERVICE_TYPE: &str = "_airplay._tcp.local.";
pub const RAOP_SERVICE_TYPE: &str = "_raop._tcp.local.";
pub const SERVICE_NAME: &str = "Rust Phone Control";
pub const TCP_PORT: u16 = 7000;
pub const MODEL: &str = "RustPhoneControl1,1";
pub const SOURCE_VERSION: &str = "1.0";
// Use the widely deployed AirPlay mirroring feature profile used by open
// receivers. The first word covers the legacy 32-bit capability mask and the
// second word carries the extended AirPlay capability bits.
pub const FEATURES: &str = "0x5A7FFFF7,0x1E";
pub const STATUS_FLAGS: &str = "0x4";

/// Returns the MAC address of the active Wi-Fi adapter for AirPlay's
/// `deviceid` TXT property. No machine-specific address is hard-coded.
pub fn device_id() -> String {
    #[cfg(windows)]
    if let Some((mac, _)) = windows_wifi_adapter() {
        return mac;
    }

    // Keep a deterministic locally administered fallback when no active
    // Wi-Fi adapter can be identified. Do not include the process ID: the
    // discovery identity must not change on every application launch.
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-host".to_owned());
    let hash = host.bytes().fold(0x811c9dc5u32, |state, byte| {
        (state ^ u32::from(byte)).wrapping_mul(0x01000193)
    });
    format!(
        "02:52:50:{:02X}:{:02X}:{:02X}",
        (hash >> 16) as u8,
        (hash >> 8) as u8,
        hash as u8
    )
}

#[cfg(windows)]
pub fn wifi_interface_index() -> Option<u32> {
    windows_wifi_adapter().map(|(_, interface_index)| interface_index)
}

#[cfg(windows)]
fn windows_wifi_adapter() -> Option<(String, u32)> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::null_mut;

    const AF_UNSPEC: u32 = 0;
    const GAA_FLAGS: u32 = 0x0000_0002 | 0x0000_0004 | 0x0000_0008;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_TYPE_IEEE80211: u32 = 71;
    const IF_OPER_STATUS_UP: u32 = 1;

    #[repr(C)]
    struct AdapterAddresses {
        length: u32,
        if_index: u32,
        next: *mut AdapterAddresses,
        adapter_name: *mut i8,
        first_unicast_address: *mut c_void,
        first_anycast_address: *mut c_void,
        first_multicast_address: *mut c_void,
        first_dns_server_address: *mut c_void,
        dns_suffix: *mut u16,
        description: *mut u16,
        friendly_name: *mut u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: u32,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut c_void,
            addresses: *mut AdapterAddresses,
            size: *mut u32,
        ) -> u32;
    }

    let mut required_size = 0u32;
    // SAFETY: The first call intentionally supplies a null output buffer to
    // obtain the required allocation size, as documented by GetAdaptersAddresses.
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAGS,
            null_mut(),
            null_mut(),
            &mut required_size,
        )
    };
    if status != ERROR_BUFFER_OVERFLOW || required_size == 0 {
        return None;
    }

    let word_count = (required_size as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; word_count];
    let head = storage.as_mut_ptr().cast::<AdapterAddresses>();
    // SAFETY: storage is suitably aligned and large enough for the size
    // returned by the first API call. Windows initializes the linked list.
    let status =
        unsafe { GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, null_mut(), head, &mut required_size) };
    if status != 0 {
        return None;
    }

    let mut adapter = head;
    while !adapter.is_null() {
        // SAFETY: Each node is part of the buffer populated by Windows and
        // remains valid until the storage vector is dropped.
        let current = unsafe { &*adapter };
        if current.if_type == IF_TYPE_IEEE80211
            && current.oper_status == IF_OPER_STATUS_UP
            && current.physical_address_length == 6
        {
            let mac = current.physical_address[..6]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            return Some((mac, current.if_index));
        }
        adapter = current.next;
    }

    None
}
