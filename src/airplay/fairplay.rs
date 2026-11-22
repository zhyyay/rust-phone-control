//! FairPlay SETUP session framing.
//!
//! This module intentionally implements only the public wire framing/state
//! around POST /fp-setup. The cryptographic FairPlay response tables and
//! proprietary key material are not embedded here. This keeps the project
//! Apache-2.0 clean and prevents a fake response from being advertised as a
//! working FairPlay implementation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePhase {
    Initial = 1,
    KeyMessage = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairPlayMessage {
    pub phase: MessagePhase,
    pub mode: Option<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FairPlayParseError {
    TooShort,
    InvalidMagic,
    UnsupportedMajorVersion(u8),
    UnsupportedPhase(u8),
    InvalidPayloadLength { declared: usize, actual: usize },
    InvalidInitialLength(usize),
    InvalidKeyMessageLength(usize),
}

impl std::fmt::Display for FairPlayParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "FairPlay message is too short"),
            Self::InvalidMagic => write!(formatter, "FairPlay message does not start with FPLY"),
            Self::UnsupportedMajorVersion(version) => {
                write!(formatter, "unsupported FairPlay major version {version}")
            }
            Self::UnsupportedPhase(phase) => {
                write!(formatter, "unsupported FairPlay message phase {phase}")
            }
            Self::InvalidPayloadLength { declared, actual } => {
                write!(
                    formatter,
                    "FairPlay header declares {declared} payload bytes, got {actual}"
                )
            }
            Self::InvalidInitialLength(length) => {
                write!(
                    formatter,
                    "FairPlay initial message must be 16 bytes, got {length}"
                )
            }
            Self::InvalidKeyMessageLength(length) => {
                write!(
                    formatter,
                    "FairPlay key message must be 164 bytes, got {length}"
                )
            }
        }
    }
}

impl std::error::Error for FairPlayParseError {}

pub fn parse_message(body: &[u8]) -> Result<FairPlayMessage, FairPlayParseError> {
    if body.len() < 16 {
        return Err(FairPlayParseError::TooShort);
    }
    if &body[..4] != b"FPLY" {
        return Err(FairPlayParseError::InvalidMagic);
    }

    // Packed FPLY header: signature[0..4], major[4], minor[5], phase[6].
    if body[4] != 3 {
        return Err(FairPlayParseError::UnsupportedMajorVersion(body[4]));
    }

    let declared_payload_length =
        u32::from_be_bytes(body[8..12].try_into().expect("four-byte length field")) as usize;
    let actual_payload_length = body.len() - 12;
    if declared_payload_length != actual_payload_length {
        return Err(FairPlayParseError::InvalidPayloadLength {
            declared: declared_payload_length,
            actual: actual_payload_length,
        });
    }

    let phase = body[6];
    match phase {
        1 => {
            if body.len() != 16 {
                return Err(FairPlayParseError::InvalidInitialLength(body.len()));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::Initial,
                mode: Some(body[14]),
                body: body.to_vec(),
            })
        }
        3 => {
            if body.len() != 164 {
                return Err(FairPlayParseError::InvalidKeyMessageLength(body.len()));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::KeyMessage,
                mode: None,
                body: body.to_vec(),
            })
        }
        other => Err(FairPlayParseError::UnsupportedPhase(other)),
    }
}

#[derive(Debug, Default)]
pub struct FairPlaySession {
    initial_mode: Option<u8>,
    key_message: Option<Vec<u8>>,
}

impl FairPlaySession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, message: FairPlayMessage) -> Result<FairPlayState, String> {
        match message.phase {
            MessagePhase::Initial => {
                if self.initial_mode.is_some() {
                    return Err("FairPlay initial message was already received".to_owned());
                }
                self.initial_mode = message.mode;
                Ok(FairPlayState::AwaitingKeyMessage)
            }
            MessagePhase::KeyMessage => {
                if self.initial_mode.is_none() {
                    return Err("FairPlay key message received before initial message".to_owned());
                }
                self.key_message = Some(message.body);
                Ok(FairPlayState::KeyMessageReceived)
            }
        }
    }

    pub fn mode(&self) -> Option<u8> {
        self.initial_mode
    }

    pub fn has_key_message(&self) -> bool {
        self.key_message.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairPlayState {
    AwaitingKeyMessage,
    KeyMessageReceived,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial_message(mode: u8) -> Vec<u8> {
        let mut body = vec![0u8; 16];
        body[..4].copy_from_slice(b"FPLY");
        body[4] = 3;
        body[5] = 1;
        body[6] = 1;
        body[8..12].copy_from_slice(&4u32.to_be_bytes());
        body[14] = mode;
        body
    }

    fn key_message() -> Vec<u8> {
        let mut body = vec![0u8; 164];
        body[..4].copy_from_slice(b"FPLY");
        body[4] = 3;
        body[5] = 1;
        body[6] = 3;
        body[8..12].copy_from_slice(&152u32.to_be_bytes());
        body
    }

    #[test]
    fn parses_initial_message_and_mode() {
        let message = parse_message(&initial_message(3)).expect("initial FairPlay message");
        assert_eq!(message.phase, MessagePhase::Initial);
        assert_eq!(message.mode, Some(3));
        assert_eq!(message.body.len(), 16);
    }

    #[test]
    fn parses_key_message() {
        let message = parse_message(&key_message()).expect("key FairPlay message");
        assert_eq!(message.phase, MessagePhase::KeyMessage);
        assert_eq!(message.mode, None);
        assert_eq!(message.body.len(), 164);
    }

    #[test]
    fn rejects_invalid_fairplay_framing() {
        assert_eq!(
            parse_message(b"not-fairplay").unwrap_err(),
            FairPlayParseError::TooShort
        );

        let mut body = initial_message(3);
        body[..4].copy_from_slice(b"NOPE");
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::InvalidMagic
        );

        let mut body = initial_message(3);
        body[6] = 2;
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::UnsupportedPhase(2)
        );

        let mut body = initial_message(3);
        body[4] = 2;
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::UnsupportedMajorVersion(2)
        );

        let mut body = initial_message(3);
        body[8..12].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::InvalidPayloadLength {
                declared: 3,
                actual: 4,
            }
        );

        let mut body = key_message();
        body[8..12].copy_from_slice(&151u32.to_be_bytes());
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::InvalidPayloadLength {
                declared: 151,
                actual: 152,
            }
        );

        assert_eq!(
            parse_message(&[0u8; 17]).unwrap_err(),
            FairPlayParseError::InvalidMagic
        );
    }

    #[test]
    fn enforces_message_order() {
        let mut session = FairPlaySession::new();
        let key = parse_message(&key_message()).expect("key message");
        assert!(session.accept(key).is_err());

        let initial = parse_message(&initial_message(3)).expect("initial message");
        assert_eq!(
            session.accept(initial).expect("accept initial"),
            FairPlayState::AwaitingKeyMessage
        );
        assert_eq!(session.mode(), Some(3));

        let key = parse_message(&key_message()).expect("key message");
        assert_eq!(
            session.accept(key).expect("accept key"),
            FairPlayState::KeyMessageReceived
        );
        assert!(session.has_key_message());
    }
}
