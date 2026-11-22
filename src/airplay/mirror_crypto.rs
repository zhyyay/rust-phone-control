//! Independent AirPlay mirror-stream cryptographic primitives.
//!
//! This module does not implement FairPlay key unwrapping. It accepts the
//! 16-byte video key produced by a legitimate FairPlay implementation and
//! derives the per-stream AES key/IV, then decrypts type-110 video payloads.
//! Each payload starts at a fresh AES block boundary while the counter remains
//! continuous across payloads.

use aes::{
    Aes128,
    cipher::{Block, BlockEncrypt, KeyInit},
};
use sha2::{Digest, Sha512};

const AES_BLOCK_BYTES: usize = 16;
const FAIRPLAY_KEY_BYTES: usize = 16;
const X25519_SHARED_SECRET_BYTES: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct MirrorStreamKeyMaterial {
    key: [u8; AES_BLOCK_BYTES],
    iv: [u8; AES_BLOCK_BYTES],
}

impl std::fmt::Debug for MirrorStreamKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MirrorStreamKeyMaterial")
            .field("key", &"[REDACTED]")
            .field("iv", &"[REDACTED]")
            .finish()
    }
}

impl MirrorStreamKeyMaterial {
    pub fn key(&self) -> &[u8; AES_BLOCK_BYTES] {
        &self.key
    }

    pub fn iv(&self) -> &[u8; AES_BLOCK_BYTES] {
        &self.iv
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorCryptoError {
    InvalidFairPlayKeyLength(usize),
    InvalidSharedSecretLength(usize),
    CounterExhausted,
}

impl std::fmt::Display for MirrorCryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFairPlayKeyLength(length) => {
                write!(
                    formatter,
                    "FairPlay video key must be 16 bytes, got {length}"
                )
            }
            Self::InvalidSharedSecretLength(length) => {
                write!(
                    formatter,
                    "X25519 shared secret must be 32 bytes, got {length}"
                )
            }
            Self::CounterExhausted => formatter.write_str("AES-CTR counter exhausted"),
        }
    }
}

impl std::error::Error for MirrorCryptoError {}

/// Derive the type-110 mirror stream key and IV.
///
/// When a Pair-Verify shared secret is supplied, it is combined with the
/// FairPlay video key using SHA-512 before the stream-specific key/IV hashes.
/// The stream ID is formatted as an unsigned decimal integer, as used by the
/// AirPlay stream key labels.
///
/// This function deliberately does not unwrap the sender's FairPlay ekey.
pub fn derive_mirror_stream_keys(
    fairplay_video_key: &[u8],
    pair_verify_shared_secret: Option<&[u8]>,
    stream_connection_id: u64,
) -> Result<MirrorStreamKeyMaterial, MirrorCryptoError> {
    if fairplay_video_key.len() != FAIRPLAY_KEY_BYTES {
        return Err(MirrorCryptoError::InvalidFairPlayKeyLength(
            fairplay_video_key.len(),
        ));
    }

    let seed = match pair_verify_shared_secret {
        Some(shared_secret) => {
            if shared_secret.len() != X25519_SHARED_SECRET_BYTES {
                return Err(MirrorCryptoError::InvalidSharedSecretLength(
                    shared_secret.len(),
                ));
            }
            let mut digest = Sha512::new();
            digest.update(fairplay_video_key);
            digest.update(shared_secret);
            digest.finalize().to_vec()
        }
        None => fairplay_video_key.to_vec(),
    };

    let stream_id = stream_connection_id.to_string();
    let key_label = format!("AirPlayStreamKey{stream_id}");
    let iv_label = format!("AirPlayStreamIV{stream_id}");

    let mut key_digest = Sha512::new();
    key_digest.update(key_label.as_bytes());
    key_digest.update(&seed);
    let key_hash = key_digest.finalize();

    let mut iv_digest = Sha512::new();
    iv_digest.update(iv_label.as_bytes());
    iv_digest.update(&seed);
    let iv_hash = iv_digest.finalize();

    let mut key = [0u8; AES_BLOCK_BYTES];
    let mut iv = [0u8; AES_BLOCK_BYTES];
    key.copy_from_slice(&key_hash[..AES_BLOCK_BYTES]);
    iv.copy_from_slice(&iv_hash[..AES_BLOCK_BYTES]);

    Ok(MirrorStreamKeyMaterial { key, iv })
}

/// Stateful AES-128-CTR decryptor for one AirPlay mirror TCP stream.
///
/// Counter bytes are incremented as a big-endian 128-bit integer. The
/// keystream is continuous across packets, but unused bytes at the end of a
/// payload are discarded so the next payload begins at the next block
/// boundary.
pub struct MirrorStreamCipher {
    cipher: Aes128,
    counter: [u8; AES_BLOCK_BYTES],
}

impl std::fmt::Debug for MirrorStreamCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MirrorStreamCipher")
            .field("counter", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl MirrorStreamCipher {
    pub fn new(material: &MirrorStreamKeyMaterial) -> Self {
        Self {
            cipher: Aes128::new_from_slice(&material.key)
                .expect("AES-128 key material always has 16 bytes"),
            counter: material.iv,
        }
    }

    /// Decrypt one complete mirror payload in place.
    ///
    /// The final partial block consumes a complete counter block. Calling
    /// this method for the next payload therefore starts at the next block.
    pub fn decrypt_packet(&mut self, payload: &mut [u8]) -> Result<(), MirrorCryptoError> {
        for chunk in payload.chunks_mut(AES_BLOCK_BYTES) {
            let mut counter_block = Block::<Aes128>::clone_from_slice(&self.counter);
            self.cipher.encrypt_block(&mut counter_block);

            for (byte, mask) in chunk.iter_mut().zip(counter_block.iter()) {
                *byte ^= *mask;
            }

            increment_counter(&mut self.counter)?;
        }
        Ok(())
    }
}

fn increment_counter(counter: &mut [u8; AES_BLOCK_BYTES]) -> Result<(), MirrorCryptoError> {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return Ok(());
        }
    }
    Err(MirrorCryptoError::CounterExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .expect("valid hexadecimal test vector");
        }
        output
    }

    #[test]
    fn matches_nist_aes_128_ctr_block_vector() {
        let material = MirrorStreamKeyMaterial {
            key: hex("2b7e151628aed2a6abf7158809cf4f3c"),
            iv: hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        };
        let mut cipher = MirrorStreamCipher::new(&material);
        let mut payload: [u8; AES_BLOCK_BYTES] =
            hex("6bc1bee22e409f96e93d7e117393172a");
        cipher.decrypt_packet(&mut payload).expect("decrypt block");
        assert_eq!(payload, hex("874d6191b620e3261bef6864990db6ce"));
    }

    #[test]
    fn partial_payload_consumes_the_rest_of_its_counter_block() {
        let material = MirrorStreamKeyMaterial {
            key: [0x11; AES_BLOCK_BYTES],
            iv: [0x22; AES_BLOCK_BYTES],
        };
        let mut whole = vec![0u8; 63];
        let mut reference = MirrorStreamCipher::new(&material);
        reference
            .decrypt_packet(&mut whole)
            .expect("reference stream");

        let mut split = MirrorStreamCipher::new(&material);
        let mut first = vec![0u8; 17];
        let mut second = vec![0u8; 31];
        split.decrypt_packet(&mut first).expect("first packet");
        split.decrypt_packet(&mut second).expect("second packet");

        assert_eq!(&whole[..17], first.as_slice());
        assert_eq!(&whole[32..63], second.as_slice());
    }

    #[test]
    fn derives_distinct_keys_for_stream_ids() {
        let fairplay_key = [0x5a; FAIRPLAY_KEY_BYTES];
        let first = derive_mirror_stream_keys(&fairplay_key, None, 7).unwrap();
        let second = derive_mirror_stream_keys(&fairplay_key, None, 8).unwrap();
        assert_ne!(first.key(), second.key());
        assert_ne!(first.iv(), second.iv());
    }

    #[test]
    fn derives_expected_legacy_stream_key_and_iv_vector() {
        let material = derive_mirror_stream_keys(&[0x5a; 16], None, 7).unwrap();
        assert_eq!(material.key(), &hex("fd5d96a562458132f0570f3e6767ec94"));
        assert_eq!(material.iv(), &hex("9aed3fdb8c1a350dd4c9196598126771"));
    }

    #[test]
    fn includes_pair_verify_secret_when_supplied() {
        let fairplay_key = [0x5a; FAIRPLAY_KEY_BYTES];
        let shared_secret = [0xa5; X25519_SHARED_SECRET_BYTES];
        let legacy = derive_mirror_stream_keys(&fairplay_key, None, 7).unwrap();
        let paired = derive_mirror_stream_keys(&fairplay_key, Some(&shared_secret), 7).unwrap();
        assert_ne!(legacy.key(), paired.key());
        assert_ne!(legacy.iv(), paired.iv());
    }

    #[test]
    fn derives_expected_pair_verify_stream_key_and_iv_vector() {
        let material = derive_mirror_stream_keys(&[0x5a; 16], Some(&[0xa5; 32]), 7).unwrap();
        assert_eq!(material.key(), &hex("71ca71a8222c472ba1215b941a11aedb"));
        assert_eq!(material.iv(), &hex("f427cf9796528a860b61f83a0105fcb2"));
    }

    #[test]
    fn rejects_invalid_secret_lengths() {
        assert_eq!(
            derive_mirror_stream_keys(&[0; 15], None, 1).unwrap_err(),
            MirrorCryptoError::InvalidFairPlayKeyLength(15)
        );
        assert_eq!(
            derive_mirror_stream_keys(&[0; 16], Some(&[0; 31]), 1).unwrap_err(),
            MirrorCryptoError::InvalidSharedSecretLength(31)
        );
    }

    #[test]
    fn fails_closed_when_counter_would_wrap() {
        let material = MirrorStreamKeyMaterial {
            key: [0; AES_BLOCK_BYTES],
            iv: [0xff; AES_BLOCK_BYTES],
        };
        let mut cipher = MirrorStreamCipher::new(&material);
        assert_eq!(
            cipher.decrypt_packet(&mut [0u8; 1]),
            Err(MirrorCryptoError::CounterExhausted)
        );
    }
}
