//! Pair-Setup M5/M6 cryptographic identity exchange.
//!
//! M5 authenticates the controller's Ed25519 long-term public key. M6 returns
//! the accessory identity, signed with its Ed25519 key and encrypted with the
//! SRP-derived Pair-Setup session key. Identity and controller keys are stored
//! in a DPAPI-protected file on Windows.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};

use super::tlv8::{self, Tlv};

const TLV_IDENTIFIER: u8 = 0x01;
const TLV_PUBLIC_KEY: u8 = 0x03;
const TLV_SIGNATURE: u8 = 0x0a;
const TLV_ENCRYPTED_DATA: u8 = 0x05;
const NONCE_M5: &[u8; 12] = b"PS-Msg05\0\0\0\0";
const NONCE_M6: &[u8; 12] = b"PS-Msg06\0\0\0\0";

pub struct AccessoryIdentity {
    identifier: Vec<u8>,
    signing_key: SigningKey,
}

impl AccessoryIdentity {
    fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut random_id = [0u8; 16];
        OsRng.fill_bytes(&mut random_id);
        let identifier = format!(
            "rpc-{}",
            random_id
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        )
        .into_bytes();
        Self {
            identifier,
            signing_key,
        }
    }

    fn from_parts(identifier: Vec<u8>, secret_key: &[u8]) -> Result<Self, String> {
        if identifier.is_empty() || identifier.len() > 64 || secret_key.len() != 32 {
            return Err("invalid persisted AirPlay accessory identity".into());
        }
        let secret: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| "invalid persisted accessory secret key")?;
        Ok(Self {
            identifier,
            signing_key: SigningKey::from_bytes(&secret),
        })
    }

    fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

struct PairingState {
    accessory: AccessoryIdentity,
    controllers: HashMap<Vec<u8>, [u8; 32]>,
    denied_controllers: HashMap<Vec<u8>, [u8; 32]>,
}

impl PairingState {
    fn load_or_create() -> Result<Self, String> {
        #[cfg(windows)]
        {
            use super::pairing_store;
            if let Some(stored) = pairing_store::load()
                .map_err(|error| format!("cannot load protected AirPlay pairing store: {error}"))?
            {
                let accessory = AccessoryIdentity::from_parts(
                    stored.accessory_identifier,
                    &stored.accessory_secret_key,
                )?;
                let controllers = stored
                    .controllers
                    .into_iter()
                    .map(|entry| {
                        let public_key: [u8; 32] = entry
                            .public_key
                            .try_into()
                            .map_err(|_| "invalid persisted controller public key")?;
                        Ok((entry.identifier, public_key))
                    })
                    .collect::<Result<HashMap<_, _>, String>>()?;
                let denied_controllers = stored
                    .denied_controllers
                    .into_iter()
                    .map(|entry| {
                        let public_key: [u8; 32] = entry
                            .public_key
                            .try_into()
                            .map_err(|_| "invalid persisted denied controller public key")?;
                        Ok((entry.identifier, public_key))
                    })
                    .collect::<Result<HashMap<_, _>, String>>()?;
                return Ok(Self {
                    accessory,
                    controllers,
                    denied_controllers,
                });
            }

            let state = Self {
                accessory: AccessoryIdentity::generate(),
                controllers: HashMap::new(),
                denied_controllers: HashMap::new(),
            };
            state.persist().map_err(|error| {
                format!("cannot create protected AirPlay pairing store: {error}")
            })?;
            return Ok(state);
        }

        #[cfg(not(windows))]
        {
            Ok(Self {
                accessory: AccessoryIdentity::generate(),
                controllers: HashMap::new(),
                denied_controllers: HashMap::new(),
            })
        }
    }

    fn persist(&self) -> Result<(), String> {
        #[cfg(windows)]
        {
            use super::pairing_store::{self, StoredController, StoredPairingState};
            let stored = StoredPairingState {
                version: 1,
                accessory_identifier: self.accessory.identifier.clone(),
                accessory_secret_key: self.accessory.signing_key.to_bytes().to_vec(),
                controllers: self
                    .controllers
                    .iter()
                    .map(|(identifier, public_key)| StoredController {
                        identifier: identifier.clone(),
                        public_key: public_key.to_vec(),
                    })
                    .collect(),
                denied_controllers: self
                    .denied_controllers
                    .iter()
                    .map(|(identifier, public_key)| StoredController {
                        identifier: identifier.clone(),
                        public_key: public_key.to_vec(),
                    })
                    .collect(),
            };
            pairing_store::save(&stored).map_err(|error| {
                format!("cannot persist protected AirPlay pairing store: {error}")
            })?;
        }
        Ok(())
    }
}

static PAIRING_STATE: OnceLock<Result<Mutex<PairingState>, String>> = OnceLock::new();

fn pairing_state() -> Result<&'static Mutex<PairingState>, String> {
    match PAIRING_STATE.get_or_init(|| PairingState::load_or_create().map(Mutex::new)) {
        Ok(state) => Ok(state),
        Err(error) => Err(error.clone()),
    }
}

/// Return the persisted accessory identifier used by Pair-Verify.
/// Return the persistent accessory Ed25519 public key used by transient Pair-Setup.
pub fn accessory_public_key() -> Result<[u8; 32], String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    Ok(state.accessory.public_key())
}

pub fn accessory_identifier() -> Result<Vec<u8>, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    Ok(state.accessory.identifier.clone())
}

/// Return the persistent accessory public key and UUID used by DNS-SD.
pub fn discovery_identity() -> Result<(String, String), String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    let public_key = state
        .accessory
        .public_key()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let raw = state
        .accessory
        .identifier
        .strip_prefix(b"rpc-")
        .ok_or("invalid persisted AirPlay accessory identifier prefix")?;
    if raw.len() != 32 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err("invalid persisted AirPlay accessory identifier format".into());
    }
    let raw = std::str::from_utf8(raw)
        .map_err(|_| "persisted AirPlay accessory identifier is not ASCII")?;
    let pairing_id = format!(
        "{}-{}-{}-{}-{}",
        &raw[0..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..32]
    );
    Ok((public_key, pairing_id))
}

/// Sign a Pair-Verify transcript with the persistent accessory identity key.
pub fn sign_accessory_identity_message(message: &[u8]) -> Result<Vec<u8>, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    Ok(state
        .accessory
        .signing_key
        .sign(message)
        .to_bytes()
        .to_vec())
}

#[cfg(test)]
pub fn test_register_controller(identifier: &[u8], public_key: [u8; 32]) {
    let lock = pairing_state().expect("pairing state");
    let mut state = lock.lock().expect("pairing state lock");
    state.controllers.insert(identifier.to_vec(), public_key);
}

#[cfg(test)]
pub fn test_accessory_public_key() -> [u8; 32] {
    let lock = pairing_state().expect("pairing state");
    let state = lock.lock().expect("pairing state lock");
    state.accessory.public_key()
}

/// Check whether a verified Ed25519 public key is present in the persistent registry.
pub fn is_controller_public_key_paired(public_key: &[u8; 32]) -> Result<bool, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    Ok(state
        .controllers
        .values()
        .any(|stored| stored == public_key))
}

/// Check whether a controller was explicitly denied by the local user.
pub fn is_controller_public_key_denied(public_key: &[u8; 32]) -> Result<bool, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    Ok(state
        .denied_controllers
        .values()
        .any(|stored| stored == public_key))
}

/// Persist an explicit denial for a Legacy Pair-Verify controller.
pub fn deny_legacy_controller(public_key: [u8; 32]) -> Result<(), String> {
    let fingerprint = Sha256::digest(public_key);
    let identifier = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
    let lock = pairing_state()?;
    let mut state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    if state
        .denied_controllers
        .values()
        .any(|stored| stored == &public_key)
    {
        return Ok(());
    }
    let previous_trusted = state.controllers.remove(&identifier);
    let previous_denied = state
        .denied_controllers
        .insert(identifier.clone(), public_key);
    if let Err(error) = state.persist() {
        match previous_trusted {
            Some(key) => {
                state.controllers.insert(identifier.clone(), key);
            }
            None => {
                state.controllers.remove(&identifier);
            }
        }
        match previous_denied {
            Some(key) => {
                state.denied_controllers.insert(identifier, key);
            }
            None => {
                state.denied_controllers.remove(&identifier);
            }
        }
        return Err(error);
    }
    Ok(())
}

/// Persist a Legacy Pair-Verify controller after explicit local approval.
/// Its identifier is a stable SHA-256 fingerprint, never a network address.
pub fn trust_legacy_controller(public_key: [u8; 32]) -> Result<(), String> {
    let fingerprint = Sha256::digest(public_key);
    let identifier = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
    let lock = pairing_state()?;
    let mut state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    if state
        .controllers
        .values()
        .any(|stored| stored == &public_key)
    {
        return Ok(());
    }
    let previous_denied = state.denied_controllers.remove(&identifier);
    let previous = state.controllers.insert(identifier.clone(), public_key);
    if let Err(error) = state.persist() {
        if let Some(key) = previous_denied {
            state.denied_controllers.insert(identifier.clone(), key);
        }
        match previous {
            Some(key) => {
                state.controllers.insert(identifier, key);
            }
            None => {
                state.controllers.remove(&identifier);
            }
        }
        return Err(error);
    }
    Ok(())
}

/// List approved Legacy controller fingerprints for the local device-management UI.
pub fn trusted_controller_fingerprints() -> Result<Vec<String>, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    let mut fingerprints = state
        .controllers
        .values()
        .map(|public_key| {
            Sha256::digest(public_key)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    Ok(fingerprints)
}

/// List denied Legacy controller fingerprints for the local device-management UI.
pub fn denied_controller_fingerprints() -> Result<Vec<String>, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    let mut fingerprints = state
        .denied_controllers
        .values()
        .map(|public_key| {
            Sha256::digest(public_key)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    Ok(fingerprints)
}

/// Remove a denial by fingerprint so the next connection can request approval again.
pub fn clear_legacy_denial(fingerprint: &str) -> Result<bool, String> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid AirPlay controller fingerprint".into());
    }
    let normalized = fingerprint.to_ascii_lowercase();
    let lock = pairing_state()?;
    let mut state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    let identifier = state
        .denied_controllers
        .iter()
        .find_map(|(identifier, public_key)| {
            let candidate = Sha256::digest(public_key)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            (candidate == normalized).then(|| identifier.clone())
        });
    let Some(identifier) = identifier else {
        return Ok(false);
    };
    let Some(public_key) = state.denied_controllers.remove(&identifier) else {
        return Ok(false);
    };
    if let Err(error) = state.persist() {
        state.denied_controllers.insert(identifier, public_key);
        return Err(error);
    }
    Ok(true)
}

/// Revoke an approved Legacy controller by its SHA-256 public-key fingerprint.
pub fn revoke_legacy_controller(fingerprint: &str) -> Result<bool, String> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid AirPlay controller fingerprint".into());
    }
    let normalized = fingerprint.to_ascii_lowercase();
    let lock = pairing_state()?;
    let mut state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    let identifier = state
        .controllers
        .iter()
        .find_map(|(identifier, public_key)| {
            let candidate = Sha256::digest(public_key)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            (candidate == normalized).then(|| identifier.clone())
        });
    let Some(identifier) = identifier else {
        return Ok(false);
    };
    let Some(public_key) = state.controllers.remove(&identifier) else {
        return Ok(false);
    };
    if let Err(error) = state.persist() {
        state.controllers.insert(identifier, public_key);
        return Err(error);
    }
    Ok(true)
}

/// Look up a paired controller's long-term Ed25519 public key.
pub fn paired_controller_public_key(identifier: &[u8]) -> Result<Option<[u8; 32]>, String> {
    let lock = pairing_state()?;
    let state = lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    Ok(state.controllers.get(identifier).copied())
}

/// Process and validate an M5 encrypted exchange, then return the M6 TLV body.
pub fn handle_m5(session_key: &[u8; 64], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 16 {
        return Err("Pair-Setup M5 encrypted data is shorter than its authentication tag".into());
    }

    let encryption_key = derive_key(
        session_key,
        b"Pair-Setup-Encrypt-Salt",
        b"Pair-Setup-Encrypt-Info",
    )?;
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|_| "invalid Pair-Setup encryption key")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(NONCE_M5), encrypted_data)
        .map_err(|_| "Pair-Setup M5 authentication tag verification failed")?;

    let fields = tlv8::decode(&plaintext).map_err(|error| error.to_string())?;
    let controller_id = unique_field(&fields, TLV_IDENTIFIER)?;
    let controller_public_key = unique_field(&fields, TLV_PUBLIC_KEY)?;
    let controller_signature = unique_field(&fields, TLV_SIGNATURE)?;

    if controller_id.is_empty() || controller_id.len() > 64 {
        return Err("invalid Pair-Setup controller identifier length".into());
    }
    let controller_public_key: [u8; 32] = controller_public_key
        .try_into()
        .map_err(|_| "invalid Pair-Setup controller Ed25519 public key length")?;
    let signature = Signature::from_slice(controller_signature)
        .map_err(|_| "invalid Pair-Setup controller signature length")?;

    let controller_x = derive_key(
        session_key,
        b"Pair-Setup-Controller-Sign-Salt",
        b"Pair-Setup-Controller-Sign-Info",
    )?;
    let mut controller_info =
        Vec::with_capacity(controller_x.len() + controller_id.len() + controller_public_key.len());
    controller_info.extend_from_slice(&controller_x);
    controller_info.extend_from_slice(controller_id);
    controller_info.extend_from_slice(&controller_public_key);

    let controller_verifying_key = VerifyingKey::from_bytes(&controller_public_key)
        .map_err(|_| "invalid Pair-Setup controller public key")?;
    controller_verifying_key
        .verify(&controller_info, &signature)
        .map_err(|_| "Pair-Setup controller signature verification failed")?;

    let state_lock = pairing_state()?;
    let mut state = state_lock
        .lock()
        .map_err(|_| "AirPlay pairing state lock poisoned")?;
    let accessory = &state.accessory;
    let accessory_public_key = accessory.public_key();
    let accessory_x = derive_key(
        session_key,
        b"Pair-Setup-Accessory-Sign-Salt",
        b"Pair-Setup-Accessory-Sign-Info",
    )?;
    let mut accessory_info = Vec::with_capacity(
        accessory_x.len() + accessory.identifier.len() + accessory_public_key.len(),
    );
    accessory_info.extend_from_slice(&accessory_x);
    accessory_info.extend_from_slice(&accessory.identifier);
    accessory_info.extend_from_slice(&accessory_public_key);
    let accessory_signature = accessory.signing_key.sign(&accessory_info);

    let inner = tlv8::encode(&[
        Tlv {
            kind: TLV_IDENTIFIER,
            value: accessory.identifier.clone(),
        },
        Tlv {
            kind: TLV_PUBLIC_KEY,
            value: accessory_public_key.to_vec(),
        },
        Tlv {
            kind: TLV_SIGNATURE,
            value: accessory_signature.to_bytes().to_vec(),
        },
    ]);
    let encrypted_response = cipher
        .encrypt(Nonce::from_slice(NONCE_M6), inner.as_ref())
        .map_err(|_| "Pair-Setup M6 encryption failed")?;

    // Explicit Pair-Setup with the setup code may re-authorize a previously
    // denied controller. Persist a candidate snapshot and roll back on failure.
    let previous_denied = state.denied_controllers.clone();
    state
        .denied_controllers
        .retain(|_, denied_key| denied_key != &controller_public_key);
    let previous = state
        .controllers
        .insert(controller_id.to_vec(), controller_public_key);
    if let Err(error) = state.persist() {
        state.denied_controllers = previous_denied;
        match previous {
            Some(public_key) => {
                state.controllers.insert(controller_id.to_vec(), public_key);
            }
            None => {
                state.controllers.remove(controller_id);
            }
        }
        return Err(error);
    }

    Ok(tlv8::encode(&[
        Tlv {
            kind: 0x06,
            value: vec![0x06],
        },
        Tlv {
            kind: TLV_ENCRYPTED_DATA,
            value: encrypted_response,
        },
    ]))
}

fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| "Pair-Setup HKDF expansion failed".to_owned())?;
    Ok(output)
}

fn unique_field(fields: &[Tlv], kind: u8) -> Result<&[u8], String> {
    let mut matching = fields.iter().filter(|field| field.kind == kind);
    let value = matching
        .next()
        .ok_or_else(|| format!("Pair-Setup M5 is missing TLV {kind}"))?;
    if matching.next().is_some() {
        return Err(format!("Pair-Setup M5 contains duplicate TLV {kind}"));
    }
    Ok(&value.value)
}

#[cfg(test)]
mod tests {
    use super::{NONCE_M5, NONCE_M6, derive_key, handle_m5};
    use crate::airplay::tlv8::{self, Tlv};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    #[test]
    fn m5_authenticates_controller_and_returns_decryptable_signed_m6() {
        let session_key = [0x5au8; 64];
        let controller = SigningKey::generate(&mut OsRng);
        let controller_id = b"test-controller";
        let controller_public_key = controller.verifying_key().to_bytes();
        let controller_x = derive_key(
            &session_key,
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        )
        .unwrap();
        let mut signed = controller_x.to_vec();
        signed.extend_from_slice(controller_id);
        signed.extend_from_slice(&controller_public_key);
        let signature = controller.sign(&signed);
        let inner = tlv8::encode(&[
            Tlv {
                kind: 0x01,
                value: controller_id.to_vec(),
            },
            Tlv {
                kind: 0x03,
                value: controller_public_key.to_vec(),
            },
            Tlv {
                kind: 0x0a,
                value: signature.to_bytes().to_vec(),
            },
        ]);
        let key = derive_key(
            &session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        )
        .unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let encrypted = cipher
            .encrypt(Nonce::from_slice(NONCE_M5), inner.as_ref())
            .unwrap();
        let response = handle_m5(&session_key, &encrypted).expect("valid M5");

        let fields = tlv8::decode(&response).unwrap();
        assert_eq!(
            fields
                .iter()
                .find(|field| field.kind == 0x06)
                .unwrap()
                .value,
            [0x06]
        );
        let encrypted_m6 = &fields
            .iter()
            .find(|field| field.kind == 0x05)
            .unwrap()
            .value;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(NONCE_M6), encrypted_m6.as_ref())
            .unwrap();
        let m6 = tlv8::decode(&plaintext).unwrap();
        let accessory_id = m6
            .iter()
            .find(|field| field.kind == 0x01)
            .unwrap()
            .value
            .clone();
        let accessory_key: [u8; 32] = m6
            .iter()
            .find(|field| field.kind == 0x03)
            .unwrap()
            .value
            .as_slice()
            .try_into()
            .unwrap();
        let accessory_signature = &m6.iter().find(|field| field.kind == 0x0a).unwrap().value;
        let accessory_x = derive_key(
            &session_key,
            b"Pair-Setup-Accessory-Sign-Salt",
            b"Pair-Setup-Accessory-Sign-Info",
        )
        .unwrap();
        let mut accessory_signed = accessory_x.to_vec();
        accessory_signed.extend_from_slice(&accessory_id);
        accessory_signed.extend_from_slice(&accessory_key);
        let verifying_key = VerifyingKey::from_bytes(&accessory_key).unwrap();
        verifying_key
            .verify(
                &accessory_signed,
                &ed25519_dalek::Signature::from_slice(accessory_signature).unwrap(),
            )
            .unwrap();
    }

    fn encrypted_m5(
        session_key: &[u8; 64],
        controller_id: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let inner = tlv8::encode(&[
            Tlv {
                kind: 0x01,
                value: controller_id.to_vec(),
            },
            Tlv {
                kind: 0x03,
                value: public_key.to_vec(),
            },
            Tlv {
                kind: 0x0a,
                value: signature.to_vec(),
            },
        ]);
        let key = derive_key(
            session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        )
        .unwrap();
        ChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(Nonce::from_slice(NONCE_M5), inner.as_ref())
            .unwrap()
    }

    #[test]
    fn m5_rejects_controller_public_key_with_invalid_length() {
        let session_key = [0x27u8; 64];
        let encrypted = encrypted_m5(&session_key, b"bad-key-length", &[0x42; 31], &[0; 64]);
        let error = handle_m5(&session_key, &encrypted).unwrap_err();
        assert!(error.contains("public key length"));
    }

    #[test]
    fn m5_rejects_invalid_controller_signature() {
        let session_key = [0x39u8; 64];
        let controller = SigningKey::generate(&mut OsRng);
        let encrypted = encrypted_m5(
            &session_key,
            b"bad-signature",
            &controller.verifying_key().to_bytes(),
            &[0; 64],
        );
        let error = handle_m5(&session_key, &encrypted).unwrap_err();
        assert!(error.contains("signature verification failed"));
    }

    #[test]
    fn m5_rejects_tampered_authentication_tag() {
        let session_key = [0x11u8; 64];
        assert!(handle_m5(&session_key, &[0u8; 16]).is_err());
    }
}
