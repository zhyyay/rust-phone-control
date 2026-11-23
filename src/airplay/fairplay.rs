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
    Challenge = 2,
    KeyMessage = 3,
    Acknowledgement = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairPlayMessage {
    pub phase: MessagePhase,
    /// Raw selector byte at offset 14 of phase 1. Its interpretation is deliberately
    /// kept neutral until the target-device negotiation is independently verified.
    pub initial_selector: Option<u8>,
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
    InvalidChallengeLength(usize),
    InvalidKeyMessageLength(usize),
    InvalidAcknowledgementLength(usize),
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
            Self::InvalidChallengeLength(length) => {
                write!(
                    formatter,
                    "FairPlay challenge message must be 142 bytes, got {length}"
                )
            }
            Self::InvalidKeyMessageLength(length) => {
                write!(
                    formatter,
                    "FairPlay key message must be 164 bytes, got {length}"
                )
            }
            Self::InvalidAcknowledgementLength(length) => {
                write!(
                    formatter,
                    "FairPlay acknowledgement must be 32 bytes, got {length}"
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
                initial_selector: Some(body[14]),
                body: body.to_vec(),
            })
        }
        2 => {
            if body.len() != 142 {
                return Err(FairPlayParseError::InvalidChallengeLength(body.len()));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::Challenge,
                initial_selector: None,
                body: body.to_vec(),
            })
        }
        3 => {
            if body.len() != 164 {
                return Err(FairPlayParseError::InvalidKeyMessageLength(body.len()));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::KeyMessage,
                initial_selector: None,
                body: body.to_vec(),
            })
        }
        4 => {
            if body.len() != 32 {
                return Err(FairPlayParseError::InvalidAcknowledgementLength(body.len()));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::Acknowledgement,
                initial_selector: None,
                body: body.to_vec(),
            })
        }
        other => Err(FairPlayParseError::UnsupportedPhase(other)),
    }
}

/// Build the receiver's 142-byte phase-2 challenge record.
///
/// This only frames caller-provided protocol material. It does not generate a
/// valid FairPlay challenge or perform the proprietary SAP authentication.
pub fn build_m2(mode: u8, challenge: &[u8; 128]) -> [u8; 142] {
    let mut record = [0u8; 142];
    record[..4].copy_from_slice(b"FPLY");
    record[4..8].copy_from_slice(&[3, 1, 2, 0]);
    record[8..12].copy_from_slice(&130u32.to_be_bytes());
    record[12] = 2;
    record[13] = mode;
    record[14..].copy_from_slice(challenge);
    record
}

/// Build the receiver's 32-byte phase-4 acknowledgement record.
///
/// The caller must only invoke this after independently validating phase 3.
/// Framing an acknowledgement is not proof that the sender was authenticated.
pub fn build_m4(acknowledgement: &[u8; 20]) -> [u8; 32] {
    let mut record = [0u8; 32];
    record[..4].copy_from_slice(b"FPLY");
    record[4..8].copy_from_slice(&[3, 1, 4, 0]);
    record[8..12].copy_from_slice(&20u32.to_be_bytes());
    record[12..].copy_from_slice(acknowledgement);
    record
}

/// Build the phase-4 acknowledgement from a structurally valid phase-3 record.
///
/// The observed wire format echoes the final 20-byte response field. This is
/// framing compatibility only; it does not cryptographically authenticate M3
/// or unwrap the sender's media key.
pub fn build_m4_from_m3(m3: &[u8]) -> Result<[u8; 32], String> {
    let message = parse_message(m3).map_err(|error| error.to_string())?;
    if message.phase != MessagePhase::KeyMessage {
        return Err("FairPlay M4 requires a phase-3 key message".to_owned());
    }
    let acknowledgement: [u8; 20] = m3[144..164]
        .try_into()
        .expect("validated 164-byte FairPlay M3");
    Ok(build_m4(&acknowledgement))
}

#[derive(Debug, Default)]
pub struct FairPlaySession {
    initial_selector: Option<u8>,
    challenge_sent: bool,
    key_message: Option<Vec<u8>>,
    challenge_mode: Option<u8>,
    challenge: Option<[u8; 128]>,
}

impl FairPlaySession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, message: FairPlayMessage) -> Result<FairPlayState, String> {
        match message.phase {
            MessagePhase::Initial => {
                if self.initial_selector.is_some() {
                    return Err("FairPlay initial message was already received".to_owned());
                }
                self.initial_selector = message.initial_selector;
                Ok(FairPlayState::AwaitingChallenge)
            }
            MessagePhase::Challenge | MessagePhase::Acknowledgement => {
                return Err(format!(
                    "FairPlay phase {} is receiver-originated",
                    message.phase as u8
                ));
            }
            MessagePhase::KeyMessage => {
                if self.initial_selector.is_none() {
                    return Err("FairPlay key message received before initial message".to_owned());
                }
                if !self.challenge_sent {
                    return Err(
                        "FairPlay key message received before receiver challenge".to_owned()
                    );
                }
                if self.key_message.is_some() {
                    return Err("FairPlay key message was already received".to_owned());
                }
                self.key_message = Some(message.body);
                Ok(FairPlayState::KeyMessageReceived)
            }
        }
    }

    /// Raw phase-1 selector byte. Its protocol meaning is not normalized here.
    pub fn initial_selector(&self) -> Option<u8> {
        self.initial_selector
    }

    /// Record that a real, negotiated phase-2 challenge has been sent.
    /// Callers must not use this for placeholder or replayed challenge bytes.
    pub fn mark_challenge_sent(&mut self, mode: u8, challenge: [u8; 128]) -> Result<(), String> {
        if self.initial_selector.is_none() {
            return Err("FairPlay challenge cannot be sent before initial message".to_owned());
        }
        if self.challenge_sent {
            return Err("FairPlay challenge was already sent".to_owned());
        }
        if mode != 3 {
            return Err(format!("unsupported FairPlay challenge mode {mode}"));
        }
        self.challenge_mode = Some(mode);
        self.challenge = Some(challenge);
        self.challenge_sent = true;
        Ok(())
    }

    pub fn has_key_message(&self) -> bool {
        self.key_message.is_some()
    }

    pub fn challenge_mode(&self) -> Option<u8> {
        self.challenge_mode
    }

    pub fn challenge(&self) -> Option<&[u8; 128]> {
        self.challenge.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairPlayState {
    AwaitingChallenge,
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
    fn builds_protocol_framing_for_m2_and_m4() {
        let challenge = [0x5au8; 128];
        let m2 = build_m2(3, &challenge);
        assert_eq!(&m2[..12], b"FPLY\x03\x01\x02\x00\x00\x00\x00\x82");
        assert_eq!(m2[12], 2);
        assert_eq!(m2[13], 3);
        assert_eq!(&m2[14..], &challenge);
        assert_eq!(parse_message(&m2).unwrap().phase, MessagePhase::Challenge);

        let acknowledgement = [0xa5u8; 20];
        let m4 = build_m4(&acknowledgement);
        assert_eq!(&m4[..12], b"FPLY\x03\x01\x04\x00\x00\x00\x00\x14");
        assert_eq!(&m4[12..], &acknowledgement);
        assert_eq!(
            parse_message(&m4).unwrap().phase,
            MessagePhase::Acknowledgement
        );
    }

    #[test]
    fn builds_m4_by_echoing_the_m3_response_field() {
        let mut m3 = key_message();
        for (index, byte) in m3[144..164].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let m4 = build_m4_from_m3(&m3).expect("build M4 acknowledgement");
        assert_eq!(&m4[..12], b"FPLY\x03\x01\x04\x00\x00\x00\x00\x14");
        assert_eq!(&m4[12..], &m3[144..164]);
    }

    #[test]
    fn rejects_receiver_originated_records_as_inbound_session_messages() {
        let mut session = FairPlaySession::new();
        let m2 = parse_message(&build_m2(3, &[0u8; 128])).unwrap();
        assert_eq!(
            session.accept(m2).unwrap_err(),
            "FairPlay phase 2 is receiver-originated"
        );
    }

    #[test]
    fn parses_initial_message_and_mode() {
        let message = parse_message(&initial_message(3)).expect("initial FairPlay message");
        assert_eq!(message.phase, MessagePhase::Initial);
        assert_eq!(message.initial_selector, Some(3));
        assert_eq!(message.body.len(), 16);
    }

    #[test]
    fn parses_key_message() {
        let message = parse_message(&key_message()).expect("key FairPlay message");
        assert_eq!(message.phase, MessagePhase::KeyMessage);
        assert_eq!(message.initial_selector, None);
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
            FairPlayParseError::InvalidChallengeLength(16)
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
            FairPlayState::AwaitingChallenge
        );
        assert_eq!(session.initial_selector(), Some(3));
        let key_before_challenge = parse_message(&key_message()).expect("key before challenge");
        assert_eq!(
            session.accept(key_before_challenge).unwrap_err(),
            "FairPlay key message received before receiver challenge"
        );
        let challenge = [0x5au8; 128];
        session
            .mark_challenge_sent(3, challenge)
            .expect("send M2 challenge");
        assert_eq!(session.challenge_mode(), Some(3));
        assert_eq!(session.challenge(), Some(&challenge));

        let duplicate_initial = parse_message(&initial_message(3)).expect("duplicate initial");
        assert_eq!(
            session.accept(duplicate_initial).unwrap_err(),
            "FairPlay initial message was already received"
        );

        let key = parse_message(&key_message()).expect("key message");
        assert_eq!(
            session.accept(key).expect("accept key"),
            FairPlayState::KeyMessageReceived
        );
        assert!(session.has_key_message());

        let duplicate_key = parse_message(&key_message()).expect("duplicate key message");
        assert_eq!(
            session.accept(duplicate_key).unwrap_err(),
            "FairPlay key message was already received"
        );
        assert!(session.has_key_message());
    }
}
