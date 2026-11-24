//! DPAPI-protected persistence for AirPlay accessory identity and pairings.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    #[serde(default)]
    pub denied_controllers: Vec<StoredController>,
}

impl StoredPairingState {
    /// Return whether this exact Ed25519 controller key has been approved.
    /// IP addresses and transient network details are deliberately not identities.
    pub fn is_controller_trusted(&self, public_key: &[u8; 32]) -> bool {
        self.controllers
            .iter()
            .any(|controller| controller.public_key.as_slice() == public_key)
    }

    /// Persist a controller after an explicit user approval.
    /// Returns false when the same public key is already trusted.
    pub fn trust_controller(&mut self, public_key: [u8; 32]) -> io::Result<bool> {
        if self.is_controller_trusted(&public_key) {
            return Ok(false);
        }
        if self.controllers.len() >= 1024 {
            return Err(invalid_data("too many paired controllers in pairing store"));
        }

        let fingerprint = controller_fingerprint(&public_key);
        self.controllers.push(StoredController {
            identifier: fingerprint.to_vec(),
            public_key: public_key.to_vec(),
        });
        Ok(true)
    }

    /// Revoke a trusted controller by its SHA-256 public-key fingerprint.
    pub fn revoke_controller(&mut self, fingerprint: &[u8; 32]) -> bool {
        let previous_len = self.controllers.len();
        self.controllers
            .retain(|controller| controller.identifier.as_slice() != fingerprint);
        self.controllers.len() != previous_len
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(invalid_data("unsupported AirPlay pairing store version"));
        }
        if self.accessory_identifier.is_empty() || self.accessory_identifier.len() > 64 {
            return Err(invalid_data(
                "invalid accessory identifier in pairing store",
            ));
        }
        if self.accessory_secret_key.len() != 32 {
            return Err(invalid_data(
                "invalid accessory secret key in pairing store",
            ));
        }
        if self.controllers.len() > 1024 || self.denied_controllers.len() > 1024 {
            return Err(invalid_data("too many controller entries in pairing store"));
        }
        for entries in [&self.controllers, &self.denied_controllers] {
            for (index, controller) in entries.iter().enumerate() {
                if controller.identifier.is_empty()
                    || controller.identifier.len() > 64
                    || controller.public_key.len() != 32
                {
                    return Err(invalid_data("invalid controller entry in pairing store"));
                }
                if entries[..index]
                    .iter()
                    .any(|previous| previous.identifier == controller.identifier)
                {
                    return Err(invalid_data(
                        "duplicate controller identifier in pairing store",
                    ));
                }
            }
        }
        if self.controllers.iter().any(|trusted| {
            self.denied_controllers
                .iter()
                .any(|denied| denied.public_key == trusted.public_key)
        }) {
            return Err(invalid_data("controller cannot be both trusted and denied"));
        }
        Ok(())
    }
}

/// Stable device identity derived from the controller's Ed25519 public key.
pub fn controller_fingerprint(public_key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(public_key).into()
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
        return Err(invalid_data(
            "AirPlay pairing store has an invalid file size",
        ));
    }

    let mut encrypted = Vec::with_capacity(length as usize);
    file.read_to_end(&mut encrypted)?;
    let plaintext = crate::platform::windows::dpapi::unprotect(&encrypted)?;
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

    let plaintext = serde_json::to_vec(state).map_err(|error| {
        invalid_data(format!("cannot serialize AirPlay pairing store: {error}"))
    })?;
    let encrypted = crate::platform::windows::dpapi::protect(&plaintext)?;

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
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

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

#[cfg(test)]
mod tests {
    use super::{StoredController, StoredPairingState, controller_fingerprint};

    fn state() -> StoredPairingState {
        StoredPairingState {
            version: 1,
            accessory_identifier: vec![1; 16],
            accessory_secret_key: vec![2; 32],
            controllers: Vec::new(),
            denied_controllers: Vec::new(),
        }
    }

    #[test]
    fn controller_trust_uses_public_key_not_network_address() {
        let mut store = state();
        let key = [0x42; 32];
        assert!(!store.is_controller_trusted(&key));
        assert!(store.trust_controller(key).unwrap());
        assert!(store.is_controller_trusted(&key));
        assert!(!store.trust_controller(key).unwrap());
        assert_eq!(
            store.controllers[0].identifier,
            controller_fingerprint(&key)
        );
        store.validate().unwrap();
    }

    #[test]
    fn controller_can_be_revoked_by_fingerprint() {
        let mut store = state();
        let key = [0x24; 32];
        store.trust_controller(key).unwrap();
        let fingerprint = controller_fingerprint(&key);
        assert!(store.revoke_controller(&fingerprint));
        assert!(!store.is_controller_trusted(&key));
        assert!(!store.revoke_controller(&fingerprint));
    }

    #[test]
    fn validation_rejects_duplicate_trusted_identifiers() {
        let mut store = state();
        let key = [0x31; 32];
        let identifier = controller_fingerprint(&key).to_vec();
        store.controllers = vec![
            StoredController {
                identifier: identifier.clone(),
                public_key: key.to_vec(),
            },
            StoredController {
                identifier,
                public_key: [0x32; 32].to_vec(),
            },
        ];

        assert!(store.validate().is_err());
    }

    #[test]
    fn validation_rejects_a_controller_that_is_both_trusted_and_denied() {
        let mut store = state();
        let key = [0x41; 32];
        let controller = StoredController {
            identifier: controller_fingerprint(&key).to_vec(),
            public_key: key.to_vec(),
        };
        store.controllers.push(controller.clone());
        store.denied_controllers.push(controller);

        assert!(store.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_controller_key_lengths() {
        let mut store = state();
        store.controllers.push(StoredController {
            identifier: b"invalid-key".to_vec(),
            public_key: vec![0x51; 31],
        });

        assert!(store.validate().is_err());
    }

    #[test]
    fn validation_rejects_unsupported_store_versions() {
        let mut store = state();
        store.version = 2;

        assert!(store.validate().is_err());
    }
}
