//! Windows Data Protection API (DPAPI) wrappers.
//!
//! Data is protected for the current Windows user. It can be decrypted after
//! application restarts by the same Windows account, without storing an
//! application-managed encryption key beside the protected data.

use std::io;
use std::ptr::{null, null_mut};

#[repr(C)]
struct DataBlob {
    size: u32,
    data: *mut u8,
}

#[link(name = "Crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        input: *const DataBlob,
        description: *const u16,
        optional_entropy: *const DataBlob,
        reserved: *const std::ffi::c_void,
        prompt: *const std::ffi::c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;

    fn CryptUnprotectData(
        input: *const DataBlob,
        description: *mut *mut u16,
        optional_entropy: *const DataBlob,
        reserved: *const std::ffi::c_void,
        prompt: *const std::ffi::c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

/// Protect bytes using the current Windows user's DPAPI master keys.
pub fn protect(plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let input = input_blob(plaintext)?;
    let mut output = DataBlob { size: 0, data: null_mut() };

    // SAFETY: input points to a valid buffer for the duration of the call;
    // DPAPI allocates output memory that is released with LocalFree below.
    let success = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    copy_and_free(output)
}

/// Decrypt bytes previously protected for the current Windows user.
pub fn unprotect(ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let input = input_blob(ciphertext)?;
    let mut output = DataBlob { size: 0, data: null_mut() };

    // SAFETY: input points to a valid buffer for the duration of the call;
    // DPAPI allocates output memory that is released with LocalFree below.
    let success = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    copy_and_free(output)
}

fn input_blob(bytes: &[u8]) -> io::Result<DataBlob> {
    let size = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DPAPI input is too large"))?;
    Ok(DataBlob {
        size,
        data: if bytes.is_empty() {
            null_mut()
        } else {
            bytes.as_ptr() as *mut u8
        },
    })
}

fn copy_and_free(blob: DataBlob) -> io::Result<Vec<u8>> {
    if blob.size > 0 && blob.data.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI returned an invalid output buffer",
        ));
    }

    // SAFETY: DPAPI returned this allocation and its declared size. We copy
    // the bytes before releasing the allocation with the matching LocalFree.
    let result = if blob.size == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize).to_vec() }
    };

    if !blob.data.is_null() {
        // SAFETY: DPAPI output buffers must be released with LocalFree.
        unsafe {
            LocalFree(blob.data.cast());
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{protect, unprotect};

    #[test]
    fn dpapi_round_trip_preserves_binary_data() {
        let input = b"RustPhoneControl\0pairing-data\xff";
        let encrypted = protect(input).expect("DPAPI protect");
        assert_ne!(encrypted, input);
        let decrypted = unprotect(&encrypted).expect("DPAPI unprotect");
        assert_eq!(decrypted, input);
    }

    #[test]
    fn dpapi_rejects_tampered_ciphertext() {
        let mut encrypted = protect(b"pairing-data").expect("DPAPI protect");
        encrypted[0] ^= 0x80;
        assert!(unprotect(&encrypted).is_err());
    }
}
