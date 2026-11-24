//! HomeKit-compatible SRP-6a server primitives (3072-bit group, SHA-512).
//!
//! Secret-exponent operations use the fixed-width constant-time backend in
//! `srp_ct`. BigUint is retained only for validating public client input and
//! constructing the public HAP proof transcript.

use super::srp_ct;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    ArithmeticFailure,
}

impl std::fmt::Display for SrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSetupCode => "invalid SRP setup code",
            Self::InvalidPrivateKey => "SRP private ephemeral must be non-zero",
            Self::InvalidClientPublicKey => "invalid SRP client public key",
            Self::InvalidClientProof => "SRP client proof verification failed",
            Self::EncodingOverflow => "SRP integer exceeds the 3072-bit group width",
            Self::ArithmeticFailure => "SRP fixed-width arithmetic failed",
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
    private_b: Zeroizing<[u8; MODULUS_BYTES]>,
    public_b: [u8; MODULUS_BYTES],
    verifier: Zeroizing<[u8; MODULUS_BYTES]>,
}

impl SrpServer {
    /// Create a server exchange using a fresh OS-generated salt and ephemeral.
    pub fn new(setup_code: &str) -> Result<Self, SrpError> {
        if setup_code.is_empty() {
            return Err(SrpError::InvalidSetupCode);
        }

        let mut salt = [0u8; 16];
        let mut private = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut *private);
        Self::new_with_private_bytes(setup_code, salt, &private[..])
    }

    fn new_with_private_bytes(
        setup_code: &str,
        salt: [u8; 16],
        private_bytes: &[u8],
    ) -> Result<Self, SrpError> {
        if setup_code.is_empty() {
            return Err(SrpError::InvalidSetupCode);
        }
        if private_bytes.is_empty() || private_bytes.iter().all(|byte| *byte == 0) {
            return Err(SrpError::InvalidPrivateKey);
        }
        if private_bytes.len() > MODULUS_BYTES {
            return Err(SrpError::EncodingOverflow);
        }

        let private_b = fixed_width(private_bytes)?;
        let x = password_exponent(&salt, setup_code);
        let generator_bytes = [5u8];
        let verifier =
            srp_ct::modpow(&generator_bytes, &x[..]).map_err(|_| SrpError::ArithmeticFailure)?;
        let n = modulus();
        let g = generator();
        let k = multiplier(&n, &g);
        let g_b = srp_ct::modpow(&generator_bytes, &private_b[..])
            .map_err(|_| SrpError::ArithmeticFailure)?;
        let k_v = srp_ct::mul_mod(&k, &verifier[..]).map_err(|_| SrpError::ArithmeticFailure)?;
        let public_b =
            srp_ct::add_mod(&k_v[..], &g_b[..]).map_err(|_| SrpError::ArithmeticFailure)?;

        let mut verifier_storage = Zeroizing::new([0u8; MODULUS_BYTES]);
        verifier_storage.copy_from_slice(&verifier[..]);
        let mut public_storage = [0u8; MODULUS_BYTES];
        public_storage.copy_from_slice(&public_b[..]);

        Ok(Self {
            salt,
            private_b,
            public_b: public_storage,
            verifier: verifier_storage,
        })
    }

    /// Deterministic constructor for protocol test vectors only.
    #[cfg(test)]
    pub fn new_with_parameters(
        setup_code: &str,
        salt: [u8; 16],
        private_b: BigUint,
    ) -> Result<Self, SrpError> {
        if private_b.is_zero() {
            return Err(SrpError::InvalidPrivateKey);
        }
        let bytes = private_b.to_bytes_be();
        Self::new_with_private_bytes(setup_code, salt, &bytes)
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Return the 384-byte, left-padded SRP server public value B for Pair-Setup M2.
    pub fn public_key(&self) -> Result<Vec<u8>, SrpError> {
        Ok(self.public_b.to_vec())
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
        let b_bytes = minimal_bytes(&self.public_b);
        let a_pad = pad(&a)?;
        let b_pad = self.public_b;
        let u = hash(&[&a_pad, &b_pad]);
        let vu = srp_ct::modpow(&self.verifier[..], &u).map_err(|_| SrpError::ArithmeticFailure)?;
        let a_vu = srp_ct::mul_mod(&a_pad, &vu[..]).map_err(|_| SrpError::ArithmeticFailure)?;
        let shared = srp_ct::modpow(&a_vu[..], &self.private_b[..])
            .map_err(|_| SrpError::ArithmeticFailure)?;

        // Preserve the existing HAP implementation's minimal big-endian S
        // encoding in K and the minimal A/B encoding in the proof transcript.
        let shared_minimal = Zeroizing::new(minimal_bytes(&shared[..]));
        let session_key = Zeroizing::new(hash(&[&shared_minimal]));
        let hn = hash(&[&n.to_bytes_be()]);
        let hg = hash(&[&g.to_bytes_be()]);
        let mut xor = [0u8; 64];
        for (out, (left, right)) in xor.iter_mut().zip(hn.iter().zip(hg.iter())) {
            *out = left ^ right;
        }
        let hi = hash(&[USERNAME]);
        let expected = hash(&[&xor, &hi, &self.salt, &a_bytes, &b_bytes, &session_key[..]]);
        if !bool::from(expected.as_slice().ct_eq(client_proof)) {
            return Err(SrpError::InvalidClientProof);
        }

        let server_proof = hash(&[&a_bytes, &expected, &session_key[..]]);
        let mut output_key = [0u8; 64];
        output_key.copy_from_slice(&session_key[..]);
        Ok(SrpServerProof {
            session_key: output_key,
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

fn multiplier(n: &BigUint, g: &BigUint) -> [u8; 64] {
    let n_pad = pad(n).expect("3072-bit modulus fits its width");
    let g_pad = pad(g).expect("generator fits its width");
    hash(&[&n_pad, &g_pad])
}

fn password_exponent(salt: &[u8; 16], setup_code: &str) -> Zeroizing<[u8; 64]> {
    let identity = Zeroizing::new([USERNAME, b":", setup_code.as_bytes()].concat());
    let inner = Zeroizing::new(hash(&[&identity]));
    Zeroizing::new(hash(&[salt, &inner[..]]))
}

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn fixed_width(value: &[u8]) -> Result<Zeroizing<[u8; MODULUS_BYTES]>, SrpError> {
    if value.len() > MODULUS_BYTES {
        return Err(SrpError::EncodingOverflow);
    }
    let mut output = Zeroizing::new([0u8; MODULUS_BYTES]);
    output[MODULUS_BYTES - value.len()..].copy_from_slice(value);
    Ok(output)
}

fn minimal_bytes(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    Zeroizing::new(value[first..].to_vec())
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
    use super::{
        MODULUS_BYTES, SrpError, SrpServer, generator, hash, modulus, pad, password_exponent,
    };
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
        let x = BigUint::from_bytes_be(&password_exponent(salt, setup_code)[..]);
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
            &server.public_b.iter().fold(BigUint::zero(), |value, byte| {
                (value << 8usize) + BigUint::from(*byte)
            }),
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
        let b_public = BigUint::from_bytes_be(&server.public_b);
        let (_, mut proof, client_a) =
            client_proof("518-08-582", &salt, &BigUint::from(123456789u64), &b_public);
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

    #[test]
    fn rejects_empty_setup_code_and_invalid_private_ephemeral_encodings() {
        assert_eq!(
            SrpServer::new_with_private_bytes("", [0x44; 16], &[1]).err(),
            Some(SrpError::InvalidSetupCode)
        );
        assert_eq!(
            SrpServer::new_with_private_bytes("518-08-582", [0x44; 16], &[]).err(),
            Some(SrpError::InvalidPrivateKey)
        );
        assert_eq!(
            SrpServer::new_with_private_bytes("518-08-582", [0x44; 16], &[0; 32]).err(),
            Some(SrpError::InvalidPrivateKey)
        );
        let oversized = vec![1; MODULUS_BYTES + 1];
        assert_eq!(
            SrpServer::new_with_private_bytes("518-08-582", [0x44; 16], &oversized).err(),
            Some(SrpError::EncodingOverflow)
        );
    }

    #[test]
    fn deterministic_parameters_produce_stable_public_server_key() {
        let salt = [0x6bu8; 16];
        let private = BigUint::from(0x123456789abcdefu64);
        let first =
            SrpServer::new_with_parameters("518-08-582", salt, private.clone()).unwrap();
        let second = SrpServer::new_with_parameters("518-08-582", salt, private).unwrap();

        assert_eq!(first.salt(), second.salt());
        assert_eq!(first.public_key().unwrap(), second.public_key().unwrap());
        assert_eq!(first.public_key().unwrap().len(), MODULUS_BYTES);
    }

    #[test]
    fn production_server_does_not_retain_biguint_secret_fields() {
        let server = SrpServer::new("518-08-582").unwrap();
        assert_eq!(server.private_b.len(), MODULUS_BYTES);
        assert_eq!(server.verifier.len(), MODULUS_BYTES);
    }
}
