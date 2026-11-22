//! HomeKit-style Pair-Setup protocol framing and validation.
//!
//! Cryptographic operations are intentionally kept out of this module. This
//! layer validates the TLV8 envelope before a future SRP state machine handles
//! M1-M6. It does not claim that pairing is currently supported.

use super::tlv8::{self, Tlv};

const TLV_METHOD: u8 = 0x00;
const TLV_STATE: u8 = 0x06;

const METHOD_PAIR_SETUP: u8 = 0x00;
const STATE_M1: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSetupError {
    InvalidTlv,
    MissingState,
    DuplicateState,
    InvalidState,
    MissingMethod,
    DuplicateMethod,
    InvalidMethod,
}

impl std::fmt::Display for PairSetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidTlv => "invalid Pair-Setup TLV8 payload",
            Self::MissingState => "Pair-Setup M1 is missing State",
            Self::DuplicateState => "Pair-Setup M1 contains duplicate State fields",
            Self::InvalidState => "Pair-Setup request is not in M1 state",
            Self::MissingMethod => "Pair-Setup M1 is missing Method",
            Self::DuplicateMethod => "Pair-Setup M1 contains duplicate Method fields",
            Self::InvalidMethod => "unsupported Pair-Setup method",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PairSetupError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairSetupM1 {
    pub method: u8,
}

/// Validate the initial Pair-Setup request (M1).
///
/// M1 must contain exactly one State=1 and exactly one Method=0 field.
/// Unknown TLV fields are retained by the generic decoder but ignored here;
/// later message handlers will validate the fields relevant to each state.
pub fn parse_m1(payload: &[u8]) -> Result<PairSetupM1, PairSetupError> {
    let fields = tlv8::decode(payload).map_err(|_| PairSetupError::InvalidTlv)?;
    let state = unique_field(&fields, TLV_STATE)?;
    let method = unique_field(&fields, TLV_METHOD)?;

    if state.len() != 1 || state[0] != STATE_M1 {
        return Err(PairSetupError::InvalidState);
    }
    if method.len() != 1 || method[0] != METHOD_PAIR_SETUP {
        return Err(PairSetupError::InvalidMethod);
    }

    Ok(PairSetupM1 {
        method: METHOD_PAIR_SETUP,
    })
}

fn unique_field(fields: &[Tlv], kind: u8) -> Result<&[u8], PairSetupError> {
    let mut matching = fields.iter().filter(|field| field.kind == kind);
    let value = matching.next().ok_or_else(|| {
        if kind == TLV_STATE {
            PairSetupError::MissingState
        } else {
            PairSetupError::MissingMethod
        }
    })?;
    if matching.next().is_some() {
        return Err(if kind == TLV_STATE {
            PairSetupError::DuplicateState
        } else {
            PairSetupError::DuplicateMethod
        });
    }
    Ok(&value.value)
}

#[cfg(test)]
mod tests {
    use super::{parse_m1, PairSetupError};
    use crate::airplay::tlv8::{encode, Tlv};

    fn m1() -> Vec<u8> {
        encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ])
    }

    #[test]
    fn accepts_valid_pair_setup_m1() {
        assert!(parse_m1(&m1()).is_ok());
    }

    #[test]
    fn rejects_missing_state() {
        let payload = encode(&[Tlv {
            kind: 0x00,
            value: vec![0x00],
        }]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::MissingState));
    }

    #[test]
    fn rejects_wrong_state() {
        let payload = encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x03],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::InvalidState));
    }

    #[test]
    fn rejects_wrong_method() {
        let payload = encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x02],
            },
        ]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::InvalidMethod));
    }

    #[test]
    fn rejects_duplicate_state() {
        let payload = encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        assert_eq!(parse_m1(&payload), Err(PairSetupError::DuplicateState));
    }

    #[test]
    fn rejects_empty_or_malformed_payload() {
        assert_eq!(parse_m1(&[]), Err(PairSetupError::MissingState));
        assert_eq!(parse_m1(&[0x06]), Err(PairSetupError::InvalidTlv));
    }
}
