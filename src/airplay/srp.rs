//! HomeKit-compatible SRP-6a server primitives (3072-bit group, SHA-512).
//!
//! This module implements only the SRP M2/M4 cryptographic exchange. Pair-Setup
//! transport state, HKDF, AEAD, and identity exchange are separate layers.
//!
//! BigUint modular exponentiation is variable-time. Do not use this implementation
//! in production until the secret-exponent operation is replaced by a vetted,
//! constant-time big-integer backend and reviewed.

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MODULUS_BYTES: usize = 384;
const USERNAME: &[u8] = b"Pair-Setup";
pub(super) const MODULUS_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B",
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9",
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6",
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8",
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C",
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D",
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D",
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226",
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC",
    "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpError {
    InvalidSetupCode,
    InvalidPrivateKey,
    InvalidClientPublicKey,
    InvalidClientProof,
    EncodingOverflow,
}

impl std::fmt::Display for SrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSetupCode => "invalid SRP setup code",
            Self::InvalidPrivateKey => "SRP private ephemeral must be non-zero",
            Self::InvalidClientPublicKey => "invalid SRP client public key",
            Self::InvalidClientProof => "SRP client proof verification failed",
            Self::EncodingOverflow => "SRP integer exceeds the 3072-bit group width",
        })
    }
}

impl std::error::Error for SrpError {}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SrpServerProof {
    pub session_key: [u8; 64],
    pub proof: [u8; 64],
}

impl std::fmt::Debug for SrpServerProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SrpServerProof")
            .field("session_key", &"[REDACTED]")
            .field("proof", &"[REDACTED]")
            .finish()
    }
}

pub struct SrpServer {
    salt: [u8; 16],
    private_b: BigUint,
    public_b: BigUint,
    verifier: BigUint,
}

impl SrpServer {
    /// Create a server exchange using a fresh OS-generated salt and ephemeral.
    pub fn new(setup_code: &str) -> Result<Self, SrpError> {
        if setup_code.is_empty() {
            return Err(SrpError::InvalidSetupCode);
        }
        let mut salt = [0u8; 16];
        let mut private = [0u8; 64];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut private);
        let private_b = BigUint::from_bytes_be(&private);
        private.zeroize();
        Self::new_with_parameters(setup_code, salt, private_b)
    }

    /// Deterministic constructor for protocol test vectors only.
    pub fn new_with_parameters(
        setup_code: &str,
        salt: [u8; 16],
        private_b: BigUint,
    ) -> Result<Self, SrpError> {
        if setup_code.is_empty() {
            return Err(SrpError::InvalidSetupCode);
        }
        if private_b.is_zero() {
            return Err(SrpError::InvalidPrivateKey);
        }

        let n = modulus();
        let g = generator();
        let k = multiplier(&n, &g);
        let x = password_exponent(&salt, setup_code);
        let verifier = g.modpow(&x, &n);
        let public_b = ((&k * &verifier) + g.modpow(&private_b, &n)) % &n;

        Ok(Self {
            salt,
            private_b,
            public_b,
            verifier,
        })
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Return the 384-byte, left-padded SRP server public value B for Pair-Setup M2.
    pub fn public_key(&self) -> Result<Vec<u8>, SrpError> {
        pad(&self.public_b)
    }

    /// Verify the controller's M3 proof and return the M4 proof and session key.
    pub fn verify_client(
        &self,
        client_public_key: &[u8],
        client_proof: &[u8],
    ) -> Result<SrpServerProof, SrpError> {
        let n = modulus();
        let g = generator();
        let a = BigUint::from_bytes_be(client_public_key);
        if a.is_zero() || a >= n || client_public_key.is_empty() {
            return Err(SrpError::InvalidClientPublicKey);
        }
        if client_proof.len() != 64 {
            return Err(SrpError::InvalidClientProof);
        }

        let a_bytes = a.to_bytes_be();
        let b_bytes = self.public_b.to_bytes_be();
        let a_pad = pad(&a)?;
        let b_pad = pad(&self.public_b)?;
        let u = BigUint::from_bytes_be(&hash(&[&a_pad, &b_pad]));
        if u.is_zero() {
            return Err(SrpError::InvalidClientPublicKey);
        }

        let vu = self.verifier.modpow(&u, &n);
        let shared = (a * vu).modpow(&self.private_b, &n);
        let shared_bytes = shared.to_bytes_be();
        let session_key = hash(&[&shared_bytes]);

        // HAP's proof transcript hashes N, g, A, and B in minimal
        // big-endian form; PAD is used only for k and u calculations.
        let hn = hash(&[&n.to_bytes_be()]);
        let hg = hash(&[&g.to_bytes_be()]);
        let mut xor = [0u8; 64];
        for (out, (left, right)) in xor.iter_mut().zip(hn.iter().zip(hg.iter())) {
            *out = left ^ right;
        }
        let hi = hash(&[USERNAME]);
        let expected = hash(&[&xor, &hi, &self.salt, &a_bytes, &b_bytes, &session_key]);
        if !bool::from(expected.as_slice().ct_eq(client_proof)) {
            return Err(SrpError::InvalidClientProof);
        }

        let server_proof = hash(&[&a_bytes, &expected, &session_key]);
        Ok(SrpServerProof {
            session_key,
            proof: server_proof,
        })
    }
}

fn modulus() -> BigUint {
    BigUint::parse_bytes(MODULUS_HEX.as_bytes(), 16).expect("valid RFC 5054 3072-bit modulus")
}

fn generator() -> BigUint {
    BigUint::from(5u8)
}

fn multiplier(n: &BigUint, g: &BigUint) -> BigUint {
    let n_pad = pad(n).expect("3072-bit modulus fits its width");
    let g_pad = pad(g).expect("generator fits its width");
    BigUint::from_bytes_be(&hash(&[&n_pad, &g_pad]))
}

fn password_exponent(salt: &[u8; 16], setup_code: &str) -> BigUint {
    let identity = [USERNAME, b":", setup_code.as_bytes()].concat();
    let inner = hash(&[&identity]);
    BigUint::from_bytes_be(&hash(&[salt, &inner]))
}

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn pad(value: &BigUint) -> Result<Vec<u8>, SrpError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > MODULUS_BYTES {
        return Err(SrpError::EncodingOverflow);
    }
    let mut output = vec![0u8; MODULUS_BYTES - bytes.len()];
    output.extend_from_slice(&bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{SrpError, SrpServer, generator, hash, modulus, pad, password_exponent};
    use num_bigint::BigUint;
    use num_traits::Zero;

    fn client_proof(
        setup_code: &str,
        salt: &[u8; 16],
        a_private: &BigUint,
        b_public: &BigUint,
    ) -> ([u8; 64], [u8; 64], [u8; 384]) {
        let n = modulus();
        let g = generator();
        let a_public = g.modpow(a_private, &n);
        let a_pad: [u8; 384] = pad(&a_public).unwrap().try_into().unwrap();
        let b_pad: [u8; 384] = pad(b_public).unwrap().try_into().unwrap();
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n).unwrap(), &pad(&g).unwrap()]));
        let x = password_exponent(salt, setup_code);
        let gx = g.modpow(&x, &n);
        let kgx = (&k * gx) % &n;
        let base = (b_public + &n - kgx) % &n;
        let u = BigUint::from_bytes_be(&hash(&[&a_pad, &b_pad]));
        let exponent = a_private + u * x;
        let shared = base.modpow(&exponent, &n);
        let session_key = hash(&[&shared.to_bytes_be()]);

        let hn = hash(&[&n.to_bytes_be()]);
        let hg = hash(&[&g.to_bytes_be()]);
        let mut xor = [0u8; 64];
        for (out, (left, right)) in xor.iter_mut().zip(hn.iter().zip(hg.iter())) {
            *out = left ^ right;
        }
        let hi = hash(&[b"Pair-Setup"]);
        let proof = hash(&[
            &xor,
            &hi,
            salt,
            &a_public.to_bytes_be(),
            &b_public.to_bytes_be(),
            &session_key,
        ]);
        (session_key, proof, a_pad)
    }

    #[test]
    fn srp_proof_debug_output_redacts_session_material() {
        let proof = super::SrpServerProof {
            session_key: [0xA5; 64],
            proof: [0x5A; 64],
        };
        let debug = format!("{proof:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("A5"));
        assert!(!debug.contains("5A"));
    }

    #[test]
    fn configured_group_is_exactly_3072_bits() {
        assert_eq!(modulus().bits(), 3072);
    }

    #[test]
    fn server_and_client_derive_matching_hap_session_and_proofs() {
        let salt = [0x5au8; 16];
        let server =
            SrpServer::new_with_parameters("518-08-582", salt, BigUint::from(0x123456789abcdefu64))
                .unwrap();
        let (client_key, client_m1, client_a) = client_proof(
            "518-08-582",
            &salt,
            &BigUint::from(0xfedcba987654321u64),
            &server.public_b,
        );

        let result = server.verify_client(&client_a, &client_m1).unwrap();
        assert_eq!(result.session_key, client_key);
        let client_a_minimal = BigUint::from_bytes_be(&client_a).to_bytes_be();
        assert_eq!(
            result.proof,
            hash(&[&client_a_minimal, &client_m1, &client_key])
        );
    }

    #[test]
    fn rejects_a_tampered_client_proof() {
        let salt = [0x33u8; 16];
        let server =
            SrpServer::new_with_parameters("518-08-582", salt, BigUint::from(987654321u64))
                .unwrap();
        let (_, mut proof, client_a) = client_proof(
            "518-08-582",
            &salt,
            &BigUint::from(123456789u64),
            &server.public_b,
        );
        proof[0] ^= 0x80;
        assert_eq!(
            server.verify_client(&client_a, &proof),
            Err(SrpError::InvalidClientProof)
        );
    }

    #[test]
    fn rejects_zero_and_out_of_range_client_public_values() {
        let server =
            SrpServer::new_with_parameters("518-08-582", [0x11; 16], BigUint::from(123u8)).unwrap();
        assert_eq!(
            server.verify_client(&[0], &[0; 64]),
            Err(SrpError::InvalidClientPublicKey)
        );
        assert_eq!(
            server.verify_client(&modulus().to_bytes_be(), &[0; 64]),
            Err(SrpError::InvalidClientPublicKey)
        );
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let server =
            SrpServer::new_with_parameters("518-08-582", [0x22; 16], BigUint::from(123u8)).unwrap();
        assert_eq!(
            server.verify_client(&[1], &[0; 63]),
            Err(SrpError::InvalidClientProof)
        );
    }

    #[test]
    fn validates_salt_and_private_ephemeral() {
        assert_eq!(
            SrpServer::new_with_parameters("518-08-582", [0; 16], BigUint::zero()).err(),
            Some(SrpError::InvalidPrivateKey)
        );
    }
}
