//! HAP Pair-Verify M1-M4 authenticated ephemeral key exchange.
//!
//! This implements the cryptographic Pair-Verify exchange only. It does not
//! establish the encrypted AirPlay media transport.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{pair_setup, tlv8::{self, Tlv}};

const STATE: u8 = 0x06;
const PUBLIC_KEY: u8 = 0x03;
const ENCRYPTED_DATA: u8 = 0x05;
const IDENTIFIER: u8 = 0x01;
const SIGNATURE: u8 = 0x0a;
const ERROR: u8 = 0x07;
const NONCE_M2: &[u8; 12] = b"PV-Msg02\0\0\0\0";
const NONCE_M3: &[u8; 12] = b"PV-Msg03\0\0\0\0";

pub struct PairVerifySession {
    controller_ephemeral: [u8; 32],
    accessory_ephemeral: [u8; 32],
    shared_secret: [u8; 32],
    encryption_key: [u8; 32],
}

impl PairVerifySession {
    /// Validate Pair-Verify M1 and create the M2 response.
    pub fn start(body: &[u8]) -> Result<(Self, Vec<u8>), String> {
        let fields = tlv8::decode(body).map_err(|error| error.to_string())?;
        require_state(&fields, 1)?;
        let controller_ephemeral: [u8; 32] = unique_field(&fields, PUBLIC_KEY)?
            .try_into()
            .map_err(|_| "Pair-Verify M1 public key must be 32 bytes")?;

        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let accessory_secret = StaticSecret::from(secret_bytes);
        secret_bytes.fill(0);

        let accessory_public = PublicKey::from(&accessory_secret);
        let controller_public = PublicKey::from(controller_ephemeral);
        let shared = accessory_secret.diffie_hellman(&controller_public);
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err("Pair-Verify rejected an all-zero X25519 shared secret".into());
        }
        let shared_secret = *shared.as_bytes();

        let encryption_key = derive_key(
            &shared_secret,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )?;
        let accessory_x = derive_key(
            &shared_secret,
            b"Pair-Verify-Accessory-Sign-Salt",
            b"Pair-Verify-Accessory-Sign-Info",
        )?;

        let accessory_ephemeral = accessory_public.to_bytes();
        let accessory_identifier = pair_setup::accessory_identifier()?;
        let mut signed = Vec::with_capacity(
            accessory_x.len() + accessory_ephemeral.len()
                + accessory_identifier.len() + controller_ephemeral.len(),
        );
        signed.extend_from_slice(&accessory_x);
        signed.extend_from_slice(&accessory_ephemeral);
        signed.extend_from_slice(&accessory_identifier);
        signed.extend_from_slice(&controller_ephemeral);
        let signature = pair_setup::sign_accessory_identity_message(&signed)?;

        let encrypted_inner = tlv8::encode(&[
            Tlv { kind: IDENTIFIER, value: accessory_identifier },
            Tlv { kind: SIGNATURE, value: signature },
        ]);
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|_| "invalid Pair-Verify encryption key")?;
        let encrypted = cipher.encrypt(Nonce::from_slice(NONCE_M2), encrypted_inner.as_ref())
            .map_err(|_| "Pair-Verify M2 encryption failed")?;

        let response = tlv8::encode(&[
            Tlv { kind: STATE, value: vec![2] },
            Tlv { kind: PUBLIC_KEY, value: accessory_ephemeral.to_vec() },
            Tlv { kind: ENCRYPTED_DATA, value: encrypted },
        ]);

        Ok((Self {
            controller_ephemeral,
            accessory_ephemeral,
            shared_secret,
            encryption_key,
        }, response))
    }

    /// Validate Pair-Verify M3 and return the M4 response.
    pub fn finish(self, body: &[u8]) -> Result<Vec<u8>, String> {
        let fields = tlv8::decode(body).map_err(|error| error.to_string())?;
        require_state(&fields, 3)?;
        let encrypted = unique_field(&fields, ENCRYPTED_DATA)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|_| "invalid Pair-Verify encryption key")?;
        let plaintext = cipher.decrypt(Nonce::from_slice(NONCE_M3), encrypted)
            .map_err(|_| "Pair-Verify M3 authentication tag verification failed")?;
        let inner = tlv8::decode(&plaintext).map_err(|error| error.to_string())?;
        let controller_identifier = unique_field(&inner, IDENTIFIER)?;
        let controller_signature = unique_field(&inner, SIGNATURE)?;

        if controller_identifier.is_empty() || controller_identifier.len() > 64 {
            return Err("invalid Pair-Verify controller identifier length".into());
        }

        let controller_public_key = pair_setup::paired_controller_public_key(controller_identifier)?
            .ok_or_else(|| "Pair-Verify controller is not paired".to_owned())?;
        let controller_x = derive_key(
            &self.shared_secret,
            b"Pair-Verify-Controller-Sign-Salt",
            b"Pair-Verify-Controller-Sign-Info",
        )?;
        let mut signed = Vec::with_capacity(
            controller_x.len() + self.controller_ephemeral.len()
                + controller_identifier.len() + self.accessory_ephemeral.len(),
        );
        signed.extend_from_slice(&controller_x);
        signed.extend_from_slice(&self.controller_ephemeral);
        signed.extend_from_slice(controller_identifier);
        signed.extend_from_slice(&self.accessory_ephemeral);

        let verifying_key = VerifyingKey::from_bytes(&controller_public_key)
            .map_err(|_| "invalid stored Pair-Verify controller public key")?;
        let signature = Signature::from_slice(controller_signature)
            .map_err(|_| "invalid Pair-Verify controller signature length")?;
        verifying_key.verify(&signed, &signature)
            .map_err(|_| "Pair-Verify controller signature verification failed")?;

        Ok(tlv8::encode(&[Tlv { kind: STATE, value: vec![4] }]))
    }
}

fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| "Pair-Verify HKDF expansion failed".to_owned())?;
    Ok(output)
}

fn require_state(fields: &[Tlv], expected: u8) -> Result<(), String> {
    let state = unique_field(fields, STATE)?;
    if state != [expected] {
        return Err(format!("unexpected Pair-Verify state; expected {expected}"));
    }
    Ok(())
}

fn unique_field(fields: &[Tlv], kind: u8) -> Result<&[u8], String> {
    let mut matching = fields.iter().filter(|field| field.kind == kind);
    let value = matching.next().ok_or_else(|| format!("Pair-Verify is missing TLV {kind}"))?;
    if matching.next().is_some() {
        return Err(format!("Pair-Verify contains duplicate TLV {kind}"));
    }
    Ok(&value.value)
}

/// Encode a protocol-level Pair-Verify authentication failure.
pub fn error_response() -> Vec<u8> {
    tlv8::encode(&[
        Tlv { kind: STATE, value: vec![4] },
        Tlv { kind: ERROR, value: vec![2] },
    ])
}

#[cfg(test)]
mod tests {
    use super::{PairVerifySession, PUBLIC_KEY, STATE};
    use crate::airplay::tlv8::{self, Tlv};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn m1_creates_valid_m2_with_ephemeral_public_key_and_encrypted_data() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let controller_secret = StaticSecret::from(bytes);
        let controller_public = PublicKey::from(&controller_secret);
        let request = tlv8::encode(&[
            Tlv { kind: STATE, value: vec![1] },
            Tlv { kind: PUBLIC_KEY, value: controller_public.as_bytes().to_vec() },
        ]);
        let (_session, response) = PairVerifySession::start(&request).expect("valid M1");
        let fields = tlv8::decode(&response).expect("decode M2");
        assert!(fields.iter().any(|field| field.kind == STATE && field.value == [2]));
        assert_eq!(
            fields.iter().find(|field| field.kind == PUBLIC_KEY).unwrap().value.len(),
            32
        );
        assert!(fields.iter().any(|field| field.kind == 0x05));
    }

    #[test]
    fn m1_rejects_wrong_state_and_short_public_key() {
        let wrong_state = tlv8::encode(&[
            Tlv { kind: STATE, value: vec![3] },
            Tlv { kind: PUBLIC_KEY, value: vec![1; 32] },
        ]);
        assert!(PairVerifySession::start(&wrong_state).is_err());

        let short_key = tlv8::encode(&[
            Tlv { kind: STATE, value: vec![1] },
            Tlv { kind: PUBLIC_KEY, value: vec![1; 31] },
        ]);
        assert!(PairVerifySession::start(&short_key).is_err());
    }
}
