//! HomeKit-style Pair-Setup message validation.
//!
//! This module validates TLV8 envelopes for M1 and M3. SRP operations and the
//! per-connection protocol state are owned by the RTSP layer.

use super::tlv8::{self, Tlv};

const TLV_METHOD: u8 = 0x00;
const TLV_STATE: u8 = 0x06;
const TLV_PUBLIC_KEY: u8 = 0x03;
const TLV_PROOF: u8 = 0x04;

const METHOD_PAIR_SETUP: u8 = 0x00;
const STATE_M1: u8 = 0x01;
const STATE_M3: u8 = 0x03;
const SRP_PUBLIC_KEY_BYTES: usize = 384;
const SRP_PROOF_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSetupError {
    InvalidTlv,
    MissingState,
    DuplicateState,
    InvalidState,
    MissingMethod,
    DuplicateMethod,
    InvalidMethod,
    MissingPublicKey,
    DuplicatePublicKey,
    InvalidPublicKey,
    MissingProof,
    DuplicateProof,
    InvalidProof,
}

impl std::fmt::Display for PairSetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidTlv => "invalid Pair-Setup TLV8 payload",
            Self::MissingState => "Pair-Setup message is missing State",
            Self::DuplicateState => "Pair-Setup message contains duplicate State fields",
            Self::InvalidState => "unexpected Pair-Setup state",
            Self::MissingMethod => "Pair-Setup M1 is missing Method",
            Self::DuplicateMethod => "Pair-Setup M1 contains duplicate Method fields",
            Self::InvalidMethod => "unsupported Pair-Setup method",
            Self::MissingPublicKey => "Pair-Setup M3 is missing PublicKey",
            Self::DuplicatePublicKey => "Pair-Setup M3 contains duplicate PublicKey fields",
            Self::InvalidPublicKey => "invalid Pair-Setup SRP public key length",
            Self::MissingProof => "Pair-Setup M3 is missing Proof",
            Self::DuplicateProof => "Pair-Setup M3 contains duplicate Proof fields",
            Self::InvalidProof => "invalid Pair-Setup SRP proof length",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PairSetupError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairSetupM1 {
    pub method: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairSetupM3 {
    pub public_key: Vec<u8>,
    pub proof: Vec<u8>,
}

pub fn parse_m1(payload: &[u8]) -> Result<PairSetupM1, PairSetupError> {
    let fields = tlv8::decode(payload).map_err(|_| PairSetupError::InvalidTlv)?;
    let state = unique_field(&fields, TLV_STATE, PairSetupError::MissingState, PairSetupError::DuplicateState)?;
    let method = unique_field(&fields, TLV_METHOD, PairSetupError::MissingMethod, PairSetupError::DuplicateMethod)?;

    if state != [STATE_M1] {
        return Err(PairSetupError::InvalidState);
    }
    if method != [METHOD_PAIR_SETUP] {
        return Err(PairSetupError::InvalidMethod);
    }
    Ok(PairSetupM1 { method: METHOD_PAIR_SETUP })
}

pub fn parse_m3(payload: &[u8]) -> Result<PairSetupM3, PairSetupError> {
    let fields = tlv8::decode(payload).map_err(|_| PairSetupError::InvalidTlv)?;
    let state = unique_field(&fields, TLV_STATE, PairSetupError::MissingState, PairSetupError::DuplicateState)?;
    if state != [STATE_M3] {
        return Err(PairSetupError::InvalidState);
    }

    let public_key = unique_field(&fields, TLV_PUBLIC_KEY, PairSetupError::MissingPublicKey, PairSetupError::DuplicatePublicKey)?;
    if public_key.is_empty() || public_key.len() > SRP_PUBLIC_KEY_BYTES {
        return Err(PairSetupError::InvalidPublicKey);
    }

    let proof = unique_field(&fields, TLV_PROOF, PairSetupError::MissingProof, PairSetupError::DuplicateProof)?;
    if proof.len() != SRP_PROOF_BYTES {
        return Err(PairSetupError::InvalidProof);
    }

    Ok(PairSetupM3 { public_key: public_key.to_vec(), proof: proof.to_vec() })
}

/// Pairing setup codes use the standard XXX-XX-XXX display format.
pub fn is_valid_setup_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.len() != 10
        || bytes[3] != b'-'
        || bytes[6] != b'-'
        || !bytes.iter().enumerate().all(|(index, byte)| {
            index == 3 || index == 6 || byte.is_ascii_digit()
        })
    {
        return false;
    }

    let digits: Vec<u8> = bytes.iter().copied().filter(|byte| *byte != b'-').collect();
    let repeated = digits.iter().all(|digit| *digit == digits[0]);
    !repeated && digits.as_slice() != b"12345678" && digits.as_slice() != b"87654321"
}

fn unique_field<'a>(
    fields: &'a [Tlv],
    kind: u8,
    missing: PairSetupError,
    duplicate: PairSetupError,
) -> Result<&'a [u8], PairSetupError> {
    let mut matching = fields.iter().filter(|field| field.kind == kind);
    let value = matching.next().ok_or(missing)?;
    if matching.next().is_some() {
        return Err(duplicate);
    }
    Ok(&value.value)
}

#[cfg(test)]
mod tests {
    use super::{is_valid_setup_code, parse_m1, parse_m3, PairSetupError};
    use crate::airplay::tlv8::{encode, Tlv};

    fn m1() -> Vec<u8> {
        encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ])
    }

    #[test]
    fn accepts_valid_pair_setup_m1() {
        assert!(parse_m1(&m1()).is_ok());
    }

    #[test]
    fn rejects_missing_state() {
        let payload = encode(&[Tlv { kind: 0x00, value: vec![0x00] }]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::MissingState));
    }

    #[test]
    fn rejects_wrong_state() {
        let payload = encode(&[
            Tlv { kind: 0x06, value: vec![0x03] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::InvalidState));
    }

    #[test]
    fn rejects_wrong_method() {
        let payload = encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x02] },
        ]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::InvalidMethod));
    }

    #[test]
    fn rejects_duplicate_state() {
        let payload = encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::DuplicateState));
    }

    #[test]
    fn rejects_empty_or_malformed_payload() {
        assert_eq!(parse_m1(&[]), Err(PairSetupError::MissingState));
        assert_eq!(parse_m1(&[0x06]), Err(PairSetupError::InvalidTlv));
    }

    #[test]
    fn parses_pair_setup_m3() {
        let payload = encode(&[
            Tlv { kind: 0x06, value: vec![0x03] },
            Tlv { kind: 0x03, value: vec![0x11; 384] },
            Tlv { kind: 0x04, value: vec![0x22; 64] },
        ]);
        let parsed = parse_m3(&payload).unwrap();
        assert_eq!(parsed.public_key, vec![0x11; 384]);
        assert_eq!(parsed.proof, vec![0x22; 64]);
    }

    #[test]
    fn rejects_invalid_m3_lengths() {
        let short_proof = encode(&[
            Tlv { kind: 0x06, value: vec![0x03] },
            Tlv { kind: 0x03, value: vec![0x11; 384] },
            Tlv { kind: 0x04, value: vec![0x22; 63] },
        ]);
        assert_eq!(parse_m3(&short_proof), Err(PairSetupError::InvalidProof));
        let oversized_key = encode(&[
            Tlv { kind: 0x06, value: vec![0x03] },
            Tlv { kind: 0x03, value: vec![0x11; 385] },
            Tlv { kind: 0x04, value: vec![0x22; 64] },
        ]);
        assert_eq!(parse_m3(&oversized_key), Err(PairSetupError::InvalidPublicKey));
    }

    #[test]
    fn validates_setup_code_display_format() {
        assert!(is_valid_setup_code("518-08-582"));
        assert!(!is_valid_setup_code("123-45-678"));\n        assert!(!is_valid_setup_code("111-11-111"));
        assert!(!is_valid_setup_code("12345678"));
        assert!(!is_valid_setup_code("abc-de-fgh"));
    }
}
