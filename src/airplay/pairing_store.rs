//! DPAPI-protected persistence for AirPlay accessory identity and pairings.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::os::windows::ffi::OsStrExt;

use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "airplay-pairing.bin";
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredController {
    pub identifier: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredPairingState {
    pub version: u32,
    pub accessory_identifier: Vec<u8>,
    pub accessory_secret_key: Vec<u8>,
    pub controllers: Vec<StoredController>,
}

impl StoredPairingState {
    pub fn validate(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(invalid_data("unsupported AirPlay pairing store version"));
        }
        if self.accessory_identifier.is_empty() || self.accessory_identifier.len() > 64 {
            return Err(invalid_data("invalid accessory identifier in pairing store"));
        }
        if self.accessory_secret_key.len() != 32 {
            return Err(invalid_data("invalid accessory secret key in pairing store"));
        }
        if self.controllers.len() > 1024 {
            return Err(invalid_data("too many paired controllers in pairing store"));
        }
        for (index, controller) in self.controllers.iter().enumerate() {
            if controller.identifier.is_empty()
                || controller.identifier.len() > 64
                || controller.public_key.len() != 32
            {
                return Err(invalid_data("invalid controller entry in pairing store"));
            }
            if self.controllers[..index]
                .iter()
                .any(|previous| previous.identifier == controller.identifier)
            {
                return Err(invalid_data("duplicate controller identifier in pairing store"));
            }
        }
        Ok(())
    }
}

/// Load and decrypt the store. None means that no store exists yet.
/// Existing but unreadable or invalid data is an error; it is never overwritten.
pub fn load() -> io::Result<Option<StoredPairingState>> {
    let path = store_path()?;
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };

    let length = file.metadata()?.len();
    if length == 0 || length > MAX_FILE_BYTES {
        return Err(invalid_data("AirPlay pairing store has an invalid file size"));
    }

    let mut encrypted = Vec::with_capacity(length as usize);
    file.read_to_end(&mut encrypted)?;
    let plaintext = super::dpapi::unprotect(&encrypted)?;
    let state: StoredPairingState = serde_json::from_slice(&plaintext)
        .map_err(|error| invalid_data(format!("cannot parse AirPlay pairing store: {error}")))?;
    state.validate()?;
    Ok(Some(state))
}

/// Encrypt and atomically replace the store for the current Windows user.
pub fn save(state: &StoredPairingState) -> io::Result<()> {
    state.validate()?;
    let path = store_path()?;
    let directory = path
        .parent()
        .ok_or_else(|| invalid_data("AirPlay pairing store has no parent directory"))?;
    fs::create_dir_all(directory)?;

    let plaintext = serde_json::to_vec(state)
        .map_err(|error| invalid_data(format!("cannot serialize AirPlay pairing store: {error}")))?;
    let encrypted = super::dpapi::protect(&plaintext)?;

    let temp_path = temporary_path(&path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    let write_result = (|| {
        file.write_all(&encrypted)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temp_path, &path)
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn store_path() -> io::Result<PathBuf> {
    let app_data = std::env::var_os("APPDATA")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "APPDATA is not available"))?;
    Ok(PathBuf::from(app_data)
        .join("RustPhoneControl")
        .join(FILE_NAME))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();

    // SAFETY: both paths are valid, NUL-terminated UTF-16 strings.
    let success = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing_file_name: *const u16, new_file_name: *const u16, flags: u32) -> i32;
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
