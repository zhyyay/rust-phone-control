//! AirPlay Legacy and HAP Pair-Verify exchanges.
//!
//! Legacy AirPlay uses a 68-byte binary ECDH/Ed25519 exchange with AES-CTR;
//! HAP Pair-Verify uses the TLV8/ChaCha20-Poly1305 exchange.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    pair_setup,
    tlv8::{self, Tlv},
};

const STATE: u8 = 0x06;
const PUBLIC_KEY: u8 = 0x03;
const ENCRYPTED_DATA: u8 = 0x05;
const IDENTIFIER: u8 = 0x01;
const SIGNATURE: u8 = 0x0a;
const ERROR: u8 = 0x07;
const NONCE_M2: &[u8; 12] = b"PV-Msg02\0\0\0\0";
const NONCE_M3: &[u8; 12] = b"PV-Msg03\0\0\0\0";

#[derive(Zeroize, ZeroizeOnDrop)]
struct HapPairVerifySession {
    controller_ephemeral: [u8; 32],
    accessory_ephemeral: [u8; 32],
    shared_secret: [u8; 32],
    encryption_key: [u8; 32],
}

enum PairVerifyMode {
    Hap(HapPairVerifySession),
    Legacy(LegacyPairVerifySession),
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct LegacyPairVerifySession {
    controller_ephemeral: [u8; 32],
    controller_public_key: [u8; 32],
    accessory_ephemeral: [u8; 32],
    shared_secret: [u8; 32],
    aes_key: [u8; 16],
    aes_iv: [u8; 16],
}

pub struct PairVerifySession {
    mode: PairVerifyMode,
}

/// Values made available only after the controller's signature is verified.
pub(super) struct PairVerifyCompletion {
    pub(super) response: Vec<u8>,
    pub(super) shared_secret: Zeroizing<[u8; 32]>,
    pub(super) controller_public_key: [u8; 32],
}

impl PairVerifySession {
    /// Select the wire protocol from the request envelope.
    pub fn start(body: &[u8]) -> Result<(Self, Vec<u8>), String> {
        if body.len() == 68 && body[..4] == [1, 0, 0, 0] {
            let (session, response) = LegacyPairVerifySession::start(body)?;
            return Ok((
                Self {
                    mode: PairVerifyMode::Legacy(session),
                },
                response,
            ));
        }

        let (session, response) = HapPairVerifySession::start(body)?;
        Ok((
            Self {
                mode: PairVerifyMode::Hap(session),
            },
            response,
        ))
    }

    /// Complete the matching wire protocol's second message.
    pub fn finish(self, body: &[u8]) -> Result<PairVerifyCompletion, String> {
        match self.mode {
            PairVerifyMode::Hap(session) => session.finish(body),
            PairVerifyMode::Legacy(session) => session.finish(body),
        }
    }
}

impl LegacyPairVerifySession {
    fn start(body: &[u8]) -> Result<(Self, Vec<u8>), String> {
        if body.len() != 68 || body[..4] != [1, 0, 0, 0] {
            return Err("invalid legacy Pair-Verify M1 envelope".into());
        }
        let controller_ephemeral: [u8; 32] = body[4..36]
            .try_into()
            .map_err(|_| "invalid legacy Pair-Verify ECDH public key")?;
        let controller_public_key: [u8; 32] = body[36..68]
            .try_into()
            .map_err(|_| "invalid legacy Pair-Verify Ed25519 public key")?;

        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let accessory_secret = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();

        let accessory_public = PublicKey::from(&accessory_secret);
        let shared = accessory_secret.diffie_hellman(&PublicKey::from(controller_ephemeral));
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err("legacy Pair-Verify rejected an all-zero ECDH shared secret".into());
        }
        let shared_secret = Zeroizing::new(*shared.as_bytes());
        let accessory_ephemeral = accessory_public.to_bytes();
        let aes_material = legacy_aes_material(&shared_secret);
        let aes_key = Zeroizing::new(aes_material.0);
        let aes_iv = Zeroizing::new(aes_material.1);

        let mut signed = Zeroizing::new(Vec::with_capacity(64));
        signed.extend_from_slice(&accessory_ephemeral);
        signed.extend_from_slice(&controller_ephemeral);
        let signature = pair_setup::sign_accessory_identity_message(signed.as_slice())?;
        if signature.len() != 64 {
            return Err("accessory Ed25519 signature must be 64 bytes".into());
        }
        let encrypted_signature = legacy_aes_ctr(&aes_key, &aes_iv, &signature)?;

        let mut response = Vec::with_capacity(96);
        response.extend_from_slice(&accessory_ephemeral);
        response.extend_from_slice(&encrypted_signature);

        Ok((
            Self {
                controller_ephemeral,
                controller_public_key,
                accessory_ephemeral,
                shared_secret: *shared_secret,
                aes_key: *aes_key,
                aes_iv: *aes_iv,
            },
            response,
        ))
    }

    fn finish(self, body: &[u8]) -> Result<PairVerifyCompletion, String> {
        if body.len() != 68 || body[..4] != [0, 0, 0, 0] {
            return Err("invalid legacy Pair-Verify M3 envelope".into());
        }
        // UxPlay's legacy implementation advances the AES-CTR stream by
        // one 64-byte signature block after M2 before processing M3.
        let signature = Zeroizing::new(legacy_aes_ctr_at_offset(
            &self.aes_key,
            &self.aes_iv,
            &body[4..],
            64,
        )?);
        let verifying_key = VerifyingKey::from_bytes(&self.controller_public_key)
            .map_err(|_| "invalid legacy Pair-Verify controller Ed25519 public key")?;
        let signature = Signature::from_slice(signature.as_slice())
            .map_err(|_| "invalid legacy Pair-Verify controller signature length")?;

        let mut signed = Zeroizing::new(Vec::with_capacity(64));
        signed.extend_from_slice(&self.controller_ephemeral);
        signed.extend_from_slice(&self.accessory_ephemeral);
        verifying_key
            .verify(signed.as_slice(), &signature)
            .map_err(|_| "legacy Pair-Verify controller signature verification failed")?;

        Ok(PairVerifyCompletion {
            response: Vec::new(),
            shared_secret: Zeroizing::new(self.shared_secret),
            controller_public_key: self.controller_public_key,
        })
    }
}

fn legacy_aes_material(shared_secret: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut key_hash = Sha512::new();
    key_hash.update(b"Pair-Verify-AES-Key");
    key_hash.update(shared_secret);
    let mut key_digest = key_hash.finalize();

    let mut iv_hash = Sha512::new();
    iv_hash.update(b"Pair-Verify-AES-IV");
    iv_hash.update(shared_secret);
    let mut iv_digest = iv_hash.finalize();

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&key_digest[..16]);
    iv.copy_from_slice(&iv_digest[..16]);
    key_digest.as_mut_slice().zeroize();
    iv_digest.as_mut_slice().zeroize();
    (key, iv)
}

/// Apply AES-128-CTR after skipping a number of bytes in the keystream.
fn legacy_aes_ctr_at_offset(
    key: &[u8; 16],
    iv: &[u8; 16],
    input: &[u8],
    offset: usize,
) -> Result<Vec<u8>, String> {
    if offset % 16 != 0 {
        return Err("legacy Pair-Verify AES-CTR offset must be block-aligned".into());
    }
    let cipher = Aes128::new_from_slice(key).map_err(|_| "invalid legacy Pair-Verify AES key")?;
    let mut counter = *iv;
    for _ in 0..(offset / 16) {
        increment_aes_ctr_counter(&mut counter);
    }

    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        output.extend(
            chunk
                .iter()
                .zip(block.iter())
                .map(|(byte, mask)| byte ^ mask),
        );
        increment_aes_ctr_counter(&mut counter);
    }
    Ok(output)
}

fn increment_aes_ctr_counter(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

/// Apply AES-128-CTR. CTR encryption and decryption are the same operation.
fn legacy_aes_ctr(key: &[u8; 16], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| "invalid legacy Pair-Verify AES key")?;
    let mut counter = *iv;
    let mut output = Vec::with_capacity(input.len());

    for chunk in input.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        output.extend(
            chunk
                .iter()
                .zip(block.iter())
                .map(|(byte, mask)| byte ^ mask),
        );

        increment_aes_ctr_counter(&mut counter);
    }

    Ok(output)
}

impl HapPairVerifySession {
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
        secret_bytes.zeroize();

        let accessory_public = PublicKey::from(&accessory_secret);
        let controller_public = PublicKey::from(controller_ephemeral);
        let shared = accessory_secret.diffie_hellman(&controller_public);
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err("Pair-Verify rejected an all-zero X25519 shared secret".into());
        }
        let shared_secret = Zeroizing::new(*shared.as_bytes());

        let encryption_key = Zeroizing::new(derive_key(
            shared_secret.as_slice(),
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )?);
        let accessory_x = Zeroizing::new(derive_key(
            shared_secret.as_slice(),
            b"Pair-Verify-Accessory-Sign-Salt",
            b"Pair-Verify-Accessory-Sign-Info",
        )?);

        let accessory_ephemeral = accessory_public.to_bytes();
        let accessory_identifier = pair_setup::accessory_identifier()?;
        let mut signed = Zeroizing::new(Vec::with_capacity(
            accessory_x.len()
                + accessory_ephemeral.len()
                + accessory_identifier.len()
                + controller_ephemeral.len(),
        ));
        signed.extend_from_slice(accessory_x.as_slice());
        signed.extend_from_slice(&accessory_ephemeral);
        signed.extend_from_slice(&accessory_identifier);
        signed.extend_from_slice(&controller_ephemeral);
        let signature = pair_setup::sign_accessory_identity_message(&signed)?;

        let encrypted_inner = Zeroizing::new(tlv8::encode(&[
            Tlv {
                kind: IDENTIFIER,
                value: accessory_identifier,
            },
            Tlv {
                kind: SIGNATURE,
                value: signature,
            },
        ]));
        let cipher = ChaCha20Poly1305::new_from_slice(encryption_key.as_slice())
            .map_err(|_| "invalid Pair-Verify encryption key")?;
        let encrypted = cipher
            .encrypt(Nonce::from_slice(NONCE_M2), encrypted_inner.as_slice())
            .map_err(|_| "Pair-Verify M2 encryption failed")?;

        let response = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![2],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: accessory_ephemeral.to_vec(),
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: encrypted,
            },
        ]);

        Ok((
            Self {
                controller_ephemeral,
                accessory_ephemeral,
                shared_secret: *shared_secret,
                encryption_key: *encryption_key,
            },
            response,
        ))
    }

    /// Validate Pair-Verify M3 and return the M4 response.
    pub fn finish(self, body: &[u8]) -> Result<PairVerifyCompletion, String> {
        let fields = tlv8::decode(body).map_err(|error| error.to_string())?;
        require_state(&fields, 3)?;
        let encrypted = unique_field(&fields, ENCRYPTED_DATA)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|_| "invalid Pair-Verify encryption key")?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(NONCE_M3), encrypted)
                .map_err(|_| "Pair-Verify M3 authentication tag verification failed")?,
        );
        let inner = tlv8::decode(&plaintext).map_err(|error| error.to_string())?;
        let controller_identifier = unique_field(&inner, IDENTIFIER)?;
        let controller_signature = unique_field(&inner, SIGNATURE)?;

        if controller_identifier.is_empty() || controller_identifier.len() > 64 {
            return Err("invalid Pair-Verify controller identifier length".into());
        }

        let controller_public_key =
            pair_setup::paired_controller_public_key(controller_identifier)?
                .ok_or_else(|| "Pair-Verify controller is not paired".to_owned())?;
        let controller_x = Zeroizing::new(derive_key(
            self.shared_secret.as_slice(),
            b"Pair-Verify-Controller-Sign-Salt",
            b"Pair-Verify-Controller-Sign-Info",
        )?);
        let mut signed = Zeroizing::new(Vec::with_capacity(
            controller_x.len()
                + self.controller_ephemeral.len()
                + controller_identifier.len()
                + self.accessory_ephemeral.len(),
        ));
        signed.extend_from_slice(controller_x.as_slice());
        signed.extend_from_slice(&self.controller_ephemeral);
        signed.extend_from_slice(controller_identifier);
        signed.extend_from_slice(&self.accessory_ephemeral);

        let verifying_key = VerifyingKey::from_bytes(&controller_public_key)
            .map_err(|_| "invalid stored Pair-Verify controller public key")?;
        let signature = Signature::from_slice(controller_signature)
            .map_err(|_| "invalid Pair-Verify controller signature length")?;
        verifying_key
            .verify(signed.as_slice(), &signature)
            .map_err(|_| "Pair-Verify controller signature verification failed")?;

        Ok(PairVerifyCompletion {
            response: tlv8::encode(&[Tlv {
                kind: STATE,
                value: vec![4],
            }]),
            shared_secret: Zeroizing::new(self.shared_secret),
            controller_public_key,
        })
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
    let value = matching
        .next()
        .ok_or_else(|| format!("Pair-Verify is missing TLV {kind}"))?;
    if matching.next().is_some() {
        return Err(format!("Pair-Verify contains duplicate TLV {kind}"));
    }
    Ok(&value.value)
}

/// Encode a protocol-level Pair-Verify authentication failure.
pub fn error_response() -> Vec<u8> {
    tlv8::encode(&[
        Tlv {
            kind: STATE,
            value: vec![4],
        },
        Tlv {
            kind: ERROR,
            value: vec![2],
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::{
        ENCRYPTED_DATA, IDENTIFIER, NONCE_M2, NONCE_M3, PUBLIC_KEY, PairVerifySession, SIGNATURE,
        STATE, derive_key,
    };
    use crate::airplay::{
        pair_setup,
        tlv8::{self, Tlv},
    };
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use rand::RngCore;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn hap_pair_verify_rejects_all_zero_x25519_shared_secret() {
        let m1 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: vec![0; 32],
            },
        ]);

        let error = PairVerifySession::start(&m1)
            .err()
            .expect("reject zero shared secret");
        assert!(error.contains("all-zero X25519 shared secret"));
    }

    #[test]
    fn legacy_pair_verify_rejects_all_zero_x25519_shared_secret() {
        use super::LegacyPairVerifySession;

        let mut m1 = vec![1, 0, 0, 0];
        m1.extend_from_slice(&[0; 32]);
        m1.extend_from_slice(&[7; 32]);

        let error = LegacyPairVerifySession::start(&m1)
            .err()
            .expect("reject zero shared secret");
        assert!(error.contains("all-zero ECDH shared secret"));
    }

    #[test]
    fn completes_authenticated_pair_verify_m1_to_m4() {
        let mut ephemeral_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_bytes);
        let controller_ephemeral_secret = StaticSecret::from(ephemeral_bytes);
        let controller_ephemeral_public = PublicKey::from(&controller_ephemeral_secret);

        let controller_identity = SigningKey::generate(&mut OsRng);
        let controller_identifier = b"pair-verify-test-controller";
        pair_setup::test_register_controller(
            controller_identifier,
            controller_identity.verifying_key().to_bytes(),
        );

        let m1 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_ephemeral_public.as_bytes().to_vec(),
            },
        ]);
        let (session, m2) = PairVerifySession::start(&m1).expect("Pair-Verify M2");
        let m2_fields = tlv8::decode(&m2).expect("decode M2");
        let accessory_ephemeral: [u8; 32] = m2_fields
            .iter()
            .find(|field| field.kind == PUBLIC_KEY)
            .unwrap()
            .value
            .as_slice()
            .try_into()
            .unwrap();
        let encrypted_m2 = &m2_fields
            .iter()
            .find(|field| field.kind == ENCRYPTED_DATA)
            .unwrap()
            .value;

        let shared =
            controller_ephemeral_secret.diffie_hellman(&PublicKey::from(accessory_ephemeral));
        let encryption_key = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )
        .unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).unwrap();
        let m2_plaintext = cipher
            .decrypt(Nonce::from_slice(NONCE_M2), encrypted_m2.as_ref())
            .expect("decrypt M2");
        let m2_inner = tlv8::decode(&m2_plaintext).expect("decode M2 inner TLV");
        let accessory_identifier = m2_inner
            .iter()
            .find(|field| field.kind == IDENTIFIER)
            .unwrap()
            .value
            .clone();
        let accessory_signature = m2_inner
            .iter()
            .find(|field| field.kind == SIGNATURE)
            .unwrap()
            .value
            .clone();

        let accessory_x = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Accessory-Sign-Salt",
            b"Pair-Verify-Accessory-Sign-Info",
        )
        .unwrap();
        let mut accessory_signed = accessory_x.to_vec();
        accessory_signed.extend_from_slice(&accessory_ephemeral);
        accessory_signed.extend_from_slice(&accessory_identifier);
        accessory_signed.extend_from_slice(controller_ephemeral_public.as_bytes());
        VerifyingKey::from_bytes(&pair_setup::test_accessory_public_key())
            .unwrap()
            .verify(
                &accessory_signed,
                &ed25519_dalek::Signature::from_slice(&accessory_signature).unwrap(),
            )
            .expect("verify accessory M2 signature");

        let controller_x = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Controller-Sign-Salt",
            b"Pair-Verify-Controller-Sign-Info",
        )
        .unwrap();
        let mut controller_signed = controller_x.to_vec();
        controller_signed.extend_from_slice(controller_ephemeral_public.as_bytes());
        controller_signed.extend_from_slice(controller_identifier);
        controller_signed.extend_from_slice(&accessory_ephemeral);
        let controller_signature = controller_identity.sign(&controller_signed);
        let m3_inner = tlv8::encode(&[
            Tlv {
                kind: IDENTIFIER,
                value: controller_identifier.to_vec(),
            },
            Tlv {
                kind: SIGNATURE,
                value: controller_signature.to_bytes().to_vec(),
            },
        ]);
        let encrypted_m3 = cipher
            .encrypt(Nonce::from_slice(NONCE_M3), m3_inner.as_ref())
            .expect("encrypt M3");
        let m3 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: encrypted_m3,
            },
        ]);

        let completion = session.finish(&m3).expect("verify M3");
        assert_ne!(*completion.shared_secret, [0u8; 32]);
        let m4_fields = tlv8::decode(&completion.response).expect("decode M4");
        assert!(
            m4_fields
                .iter()
                .any(|field| field.kind == STATE && field.value == [4])
        );
    }

    #[test]
    fn hap_pair_verify_rejects_invalid_paired_controller_signature() {
        let controller_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let controller_ephemeral_public = PublicKey::from(&controller_ephemeral_secret);
        let registered_identity = SigningKey::generate(&mut OsRng);
        let forged_identity = SigningKey::generate(&mut OsRng);
        let controller_identifier = b"paired-controller-invalid-signature";
        pair_setup::test_register_controller(
            controller_identifier,
            registered_identity.verifying_key().to_bytes(),
        );

        let m1 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_ephemeral_public.as_bytes().to_vec(),
            },
        ]);
        let (session, m2) = PairVerifySession::start(&m1).expect("Pair-Verify M2");
        let fields = tlv8::decode(&m2).expect("decode M2");
        let accessory_ephemeral: [u8; 32] = fields
            .iter()
            .find(|field| field.kind == PUBLIC_KEY)
            .unwrap()
            .value
            .as_slice()
            .try_into()
            .unwrap();
        let shared =
            controller_ephemeral_secret.diffie_hellman(&PublicKey::from(accessory_ephemeral));
        let encryption_key = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )
        .unwrap();
        let controller_x = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Controller-Sign-Salt",
            b"Pair-Verify-Controller-Sign-Info",
        )
        .unwrap();
        let mut signed = controller_x.to_vec();
        signed.extend_from_slice(controller_ephemeral_public.as_bytes());
        signed.extend_from_slice(controller_identifier);
        signed.extend_from_slice(&accessory_ephemeral);

        // The M3 is correctly encrypted and names a paired controller, but
        // its signature comes from a different identity key.
        let forged_signature = forged_identity.sign(&signed);
        let inner = tlv8::encode(&[
            Tlv {
                kind: IDENTIFIER,
                value: controller_identifier.to_vec(),
            },
            Tlv {
                kind: SIGNATURE,
                value: forged_signature.to_bytes().to_vec(),
            },
        ]);
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).unwrap();
        let encrypted = cipher
            .encrypt(Nonce::from_slice(NONCE_M3), inner.as_ref())
            .expect("encrypt forged M3");
        let m3 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: encrypted,
            },
        ]);

        let error = session
            .finish(&m3)
            .err()
            .expect("reject forged controller signature");
        assert!(error.contains("signature verification failed"));
    }

    #[test]
    fn hap_pair_verify_rejects_controller_revoked_during_exchange() {
        let mut ephemeral_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_bytes);
        let controller_ephemeral_secret = StaticSecret::from(ephemeral_bytes);
        let controller_ephemeral_public = PublicKey::from(&controller_ephemeral_secret);
        let controller_identity = SigningKey::generate(&mut OsRng);
        let controller_identifier = b"revoked-controller-during-exchange";
        pair_setup::test_register_controller(
            controller_identifier,
            controller_identity.verifying_key().to_bytes(),
        );

        let m1 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_ephemeral_public.as_bytes().to_vec(),
            },
        ]);
        let (session, m2) = PairVerifySession::start(&m1).expect("Pair-Verify M2");
        let fields = tlv8::decode(&m2).expect("decode M2");
        let accessory_ephemeral: [u8; 32] = fields
            .iter()
            .find(|field| field.kind == PUBLIC_KEY)
            .unwrap()
            .value
            .as_slice()
            .try_into()
            .unwrap();
        let shared =
            controller_ephemeral_secret.diffie_hellman(&PublicKey::from(accessory_ephemeral));
        let encryption_key = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )
        .unwrap();
        let controller_x = derive_key(
            shared.as_bytes(),
            b"Pair-Verify-Controller-Sign-Salt",
            b"Pair-Verify-Controller-Sign-Info",
        )
        .unwrap();
        let mut signed = controller_x.to_vec();
        signed.extend_from_slice(controller_ephemeral_public.as_bytes());
        signed.extend_from_slice(controller_identifier);
        signed.extend_from_slice(&accessory_ephemeral);
        let signature = controller_identity.sign(&signed);
        let inner = tlv8::encode(&[
            Tlv {
                kind: IDENTIFIER,
                value: controller_identifier.to_vec(),
            },
            Tlv {
                kind: SIGNATURE,
                value: signature.to_bytes().to_vec(),
            },
        ]);
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).unwrap();
        let encrypted = cipher
            .encrypt(Nonce::from_slice(NONCE_M3), inner.as_ref())
            .expect("encrypt M3");
        let m3 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: encrypted,
            },
        ]);

        // Revocation after M1 but before M3 must take effect immediately.
        pair_setup::test_unregister_controller(controller_identifier);
        let error = session
            .finish(&m3)
            .err()
            .expect("reject revoked controller");
        assert!(error.contains("controller is not paired"));
    }

    #[test]
    fn completes_legacy_binary_pair_verify_exchange() {
        use super::{
            LegacyPairVerifySession, legacy_aes_ctr, legacy_aes_ctr_at_offset, legacy_aes_material,
        };
        use ed25519_dalek::{Signature, Signer};

        let mut controller_secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut controller_secret_bytes);
        let controller_secret = StaticSecret::from(controller_secret_bytes);
        let controller_ephemeral = PublicKey::from(&controller_secret);
        let controller_identity = SigningKey::generate(&mut OsRng);
        let controller_public = controller_identity.verifying_key().to_bytes();

        let mut m1 = vec![1, 0, 0, 0];
        m1.extend_from_slice(controller_ephemeral.as_bytes());
        m1.extend_from_slice(&controller_public);
        let (session, response) = LegacyPairVerifySession::start(&m1).expect("legacy M2");
        assert_eq!(response.len(), 96);

        let accessory_ephemeral: [u8; 32] = response[..32].try_into().unwrap();
        let shared = controller_secret.diffie_hellman(&PublicKey::from(accessory_ephemeral));
        let (aes_key, aes_iv) = legacy_aes_material(shared.as_bytes());
        let accessory_signature =
            legacy_aes_ctr(&aes_key, &aes_iv, &response[32..]).expect("decrypt M2 signature");
        let mut accessory_message = Vec::new();
        accessory_message.extend_from_slice(&accessory_ephemeral);
        accessory_message.extend_from_slice(controller_ephemeral.as_bytes());
        VerifyingKey::from_bytes(&pair_setup::test_accessory_public_key())
            .unwrap()
            .verify(
                &accessory_message,
                &Signature::from_slice(&accessory_signature).unwrap(),
            )
            .expect("verify accessory signature");

        let mut controller_message = Vec::new();
        controller_message.extend_from_slice(controller_ephemeral.as_bytes());
        controller_message.extend_from_slice(&accessory_ephemeral);
        let signature = controller_identity.sign(&controller_message);
        let encrypted_signature =
            legacy_aes_ctr_at_offset(&aes_key, &aes_iv, &signature.to_bytes(), 64)
                .expect("encrypt controller signature after M2 keystream");
        let mut m3 = vec![0, 0, 0, 0];
        m3.extend_from_slice(&encrypted_signature);

        let completion = session.finish(&m3).expect("legacy M4");
        assert!(completion.response.is_empty());
        assert_eq!(*completion.shared_secret, *shared.as_bytes());
    }

    #[test]
    fn hap_pair_verify_rejects_tampered_m3_ciphertext() {
        let controller_secret = StaticSecret::random_from_rng(OsRng);
        let controller_public = PublicKey::from(&controller_secret);
        let m1 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_public.as_bytes().to_vec(),
            },
        ]);
        let (session, _) = PairVerifySession::start(&m1).expect("Pair-Verify M2");
        let m3 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: vec![0xA5; 32],
            },
        ]);

        let error = session.finish(&m3).err().expect("reject tampered M3");
        assert!(error.contains("authentication tag verification failed"));
    }

    #[test]
    fn legacy_pair_verify_rejects_invalid_controller_signature() {
        use super::{LegacyPairVerifySession, legacy_aes_ctr_at_offset, legacy_aes_material};

        let controller_secret = StaticSecret::random_from_rng(OsRng);
        let controller_ephemeral = PublicKey::from(&controller_secret);
        let controller_identity = SigningKey::generate(&mut OsRng);
        let mut m1 = vec![1, 0, 0, 0];
        m1.extend_from_slice(controller_ephemeral.as_bytes());
        m1.extend_from_slice(&controller_identity.verifying_key().to_bytes());

        let (session, _) = LegacyPairVerifySession::start(&m1).expect("legacy M2");
        // The M3 body is encrypted with the session's derived AES material;
        // encrypting an invalid Ed25519 signature must never complete verify.
        let shared =
            controller_secret.diffie_hellman(&PublicKey::from(session.accessory_ephemeral));
        let (aes_key, aes_iv) = legacy_aes_material(shared.as_bytes());
        let invalid_signature = [0u8; 64];
        let encrypted = legacy_aes_ctr_at_offset(&aes_key, &aes_iv, &invalid_signature, 64)
            .expect("encrypt invalid signature");
        let mut m3 = vec![0, 0, 0, 0];
        m3.extend_from_slice(&encrypted);

        let error = session.finish(&m3).err().expect("reject invalid signature");
        assert!(error.contains("signature verification failed"));
    }

    #[test]
    fn hap_pair_verify_sessions_reject_cross_session_m3_replay() {
        let controller_a_secret = StaticSecret::random_from_rng(OsRng);
        let controller_a_public = PublicKey::from(&controller_a_secret);
        let controller_b_secret = StaticSecret::random_from_rng(OsRng);
        let controller_b_public = PublicKey::from(&controller_b_secret);

        let m1_a = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_a_public.as_bytes().to_vec(),
            },
        ]);
        let m1_b = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_b_public.as_bytes().to_vec(),
            },
        ]);

        let (_session_a, m2_a) = PairVerifySession::start(&m1_a).expect("session A M2");
        let (session_b, _m2_b) = PairVerifySession::start(&m1_b).expect("session B M2");
        let m2_fields = tlv8::decode(&m2_a).expect("decode session A M2");
        let accessory_a: [u8; 32] = m2_fields
            .iter()
            .find(|field| field.kind == PUBLIC_KEY)
            .expect("session A accessory public key")
            .value
            .as_slice()
            .try_into()
            .expect("32-byte accessory public key");
        let shared_a = controller_a_secret.diffie_hellman(&PublicKey::from(accessory_a));
        let encryption_key_a = derive_key(
            shared_a.as_bytes(),
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )
        .expect("derive session A encryption key");
        let cipher_a =
            ChaCha20Poly1305::new_from_slice(&encryption_key_a).expect("session A cipher");
        let encrypted_a = cipher_a
            .encrypt(
                Nonce::from_slice(NONCE_M3),
                b"session A private payload".as_ref(),
            )
            .expect("encrypt session A payload");
        let replayed_m3 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: encrypted_a,
            },
        ]);

        let error = session_b
            .finish(&replayed_m3)
            .err()
            .expect("session B must reject session A ciphertext");
        assert!(error.contains("authentication tag verification failed"));
    }

    #[test]
    fn m1_rejects_wrong_state_and_short_public_key() {
        let wrong_state = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: vec![1; 32],
            },
        ]);
        assert!(PairVerifySession::start(&wrong_state).is_err());

        let short_key = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: vec![1; 31],
            },
        ]);
        assert!(PairVerifySession::start(&short_key).is_err());
    }

    #[test]
    fn m1_rejects_duplicate_state_and_public_key_fields() {
        let duplicate_state = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: vec![1; 32],
            },
        ]);
        let error = PairVerifySession::start(&duplicate_state)
            .err()
            .expect("reject duplicate M1 state");
        assert!(error.contains("duplicate TLV"));

        let duplicate_public_key = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: vec![1; 32],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: vec![2; 32],
            },
        ]);
        let error = PairVerifySession::start(&duplicate_public_key)
            .err()
            .expect("reject duplicate M1 public key");
        assert!(error.contains("duplicate TLV"));
    }

    #[test]
    fn m3_rejects_duplicate_encrypted_data_fields() {
        let controller_secret = StaticSecret::random_from_rng(OsRng);
        let controller_public = PublicKey::from(&controller_secret);
        let m1 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![1],
            },
            Tlv {
                kind: PUBLIC_KEY,
                value: controller_public.as_bytes().to_vec(),
            },
        ]);
        let (session, _) = PairVerifySession::start(&m1).expect("Pair-Verify M2");
        let m3 = tlv8::encode(&[
            Tlv {
                kind: STATE,
                value: vec![3],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: vec![0x11; 32],
            },
            Tlv {
                kind: ENCRYPTED_DATA,
                value: vec![0x22; 32],
            },
        ]);

        let error = session
            .finish(&m3)
            .err()
            .expect("reject duplicate encrypted data");
        assert!(error.contains("duplicate TLV"));
    }

}
