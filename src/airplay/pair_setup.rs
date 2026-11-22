//! Pair-Setup M5/M6 cryptographic identity exchange.
//!
//! M5 authenticates the controller's Ed25519 long-term public key. M6 returns
//! the accessory identity, signed with its Ed25519 key and encrypted with the
//! SRP-derived Pair-Setup session key.
//!
//! The accessory identity is currently generated once per process. Durable,
//! OS-protected identity and pairing storage must be added before relying on
//! pairings across application restarts.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;

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
            random_id.iter().map(|byte| format!("{:02x}", byte)).collect::<String>()
        ).into_bytes();
        Self { identifier, signing_key }
    }

    fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

static ACCESSORY_IDENTITY: OnceLock<AccessoryIdentity> = OnceLock::new();
static PAIRED_CONTROLLERS: OnceLock<Mutex<HashMap<Vec<u8>, [u8; 32]>>> = OnceLock::new();

fn identity() -> &'static AccessoryIdentity {
    ACCESSORY_IDENTITY.get_or_init(AccessoryIdentity::generate)
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
    let mut controller_info = Vec::with_capacity(
        controller_x.len() + controller_id.len() + controller_public_key.len(),
    );
    controller_info.extend_from_slice(&controller_x);
    controller_info.extend_from_slice(controller_id);
    controller_info.extend_from_slice(&controller_public_key);

    let controller_verifying_key = VerifyingKey::from_bytes(&controller_public_key)
        .map_err(|_| "invalid Pair-Setup controller public key")?;
    controller_verifying_key
        .verify(&controller_info, &signature)
        .map_err(|_| "Pair-Setup controller signature verification failed")?;

    let accessory = identity();
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
        Tlv { kind: TLV_IDENTIFIER, value: accessory.identifier.clone() },
        Tlv { kind: TLV_PUBLIC_KEY, value: accessory_public_key.to_vec() },
        Tlv { kind: TLV_SIGNATURE, value: accessory_signature.to_bytes().to_vec() },
    ]);
    let encrypted_response = cipher
        .encrypt(Nonce::from_slice(NONCE_M6), inner.as_ref())
        .map_err(|_| "Pair-Setup M6 encryption failed")?;

    let pairings = PAIRED_CONTROLLERS.get_or_init(|| Mutex::new(HashMap::new()));
    pairings
        .lock()
        .map_err(|_| "Pair-Setup pairing registry lock poisoned")?
        .insert(controller_id.to_vec(), controller_public_key);

    Ok(tlv8::encode(&[
        Tlv { kind: 0x06, value: vec![0x06] },
        Tlv { kind: TLV_ENCRYPTED_DATA, value: encrypted_response },
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
    let value = matching.next().ok_or_else(|| format!("Pair-Setup M5 is missing TLV {kind}"))?;
    if matching.next().is_some() {
        return Err(format!("Pair-Setup M5 contains duplicate TLV {kind}"));
    }
    Ok(&value.value)
}

#[cfg(test)]
mod tests {
    use super::{derive_key, handle_m5, NONCE_M5, NONCE_M6};
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
        ).unwrap();
        let mut signed = controller_x.to_vec();
        signed.extend_from_slice(controller_id);
        signed.extend_from_slice(&controller_public_key);
        let signature = controller.sign(&signed);
        let inner = tlv8::encode(&[
            Tlv { kind: 0x01, value: controller_id.to_vec() },
            Tlv { kind: 0x03, value: controller_public_key.to_vec() },
            Tlv { kind: 0x0a, value: signature.to_bytes().to_vec() },
        ]);
        let key = derive_key(
            &session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        ).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let encrypted = cipher.encrypt(Nonce::from_slice(NONCE_M5), inner.as_ref()).unwrap();
        let response = handle_m5(&session_key, &encrypted).expect("valid M5");

        let fields = tlv8::decode(&response).unwrap();
        assert_eq!(fields.iter().find(|field| field.kind == 0x06).unwrap().value, [0x06]);
        let encrypted_m6 = &fields.iter().find(|field| field.kind == 0x05).unwrap().value;
        let plaintext = cipher.decrypt(Nonce::from_slice(NONCE_M6), encrypted_m6.as_ref()).unwrap();
        let m6 = tlv8::decode(&plaintext).unwrap();
        let accessory_id = m6.iter().find(|field| field.kind == 0x01).unwrap().value.clone();
        let accessory_key: [u8; 32] = m6.iter().find(|field| field.kind == 0x03).unwrap().value.as_slice().try_into().unwrap();
        let accessory_signature = &m6.iter().find(|field| field.kind == 0x0a).unwrap().value;
        let accessory_x = derive_key(
            &session_key,
            b"Pair-Setup-Accessory-Sign-Salt",
            b"Pair-Setup-Accessory-Sign-Info",
        ).unwrap();
        let mut accessory_signed = accessory_x.to_vec();
        accessory_signed.extend_from_slice(&accessory_id);
        accessory_signed.extend_from_slice(&accessory_key);
        let verifying_key = VerifyingKey::from_bytes(&accessory_key).unwrap();
        verifying_key.verify(
            &accessory_signed,
            &ed25519_dalek::Signature::from_slice(accessory_signature).unwrap(),
        ).unwrap();
    }

    #[test]
    fn m5_rejects_tampered_authentication_tag() {
        let session_key = [0x11u8; 64];
        assert!(handle_m5(&session_key, &[0u8; 16]).is_err());
    }
}
