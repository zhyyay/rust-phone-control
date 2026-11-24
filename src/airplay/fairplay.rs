//! FairPlay SAP wire framing and session-state validation.
//!
//! This module does not implement the SAP cryptographic transform or ekey
//! unwrapping. Framing helpers are for protocol tests only; the RTSP server
//! must fail closed rather than send placeholder challenges or acknowledgements.
//! Keep this module Apache-2.0 clean: do not vendor LGPL implementations,
//! Apple-derived white-box tables, captured response blobs, or replay prefixes.

use zeroize::Zeroizing;

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
    /// Raw four-byte M1 payload. Byte 14 is the sender capability mask.
    pub initial_parameters: Option<[u8; 4]>,
    pub initial_capabilities: Option<u8>,
    pub challenge_mode: Option<u8>,
    pub challenge: Option<Zeroizing<[u8; 128]>>,
    pub key_mode: Option<u8>,
    pub key_label: Option<[u8; 3]>,
    pub local_sap: Option<Zeroizing<[u8; 128]>>,
    pub key_response: Option<Zeroizing<[u8; 20]>>,
    pub acknowledgement: Option<Zeroizing<[u8; 20]>>,
    pub body: Zeroizing<Vec<u8>>,
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
    InvalidInitialPayload,
    InvalidChallengePayload,
    UnsupportedChallengeMode(u8),
    UnsupportedKeyMessageMode(u8),
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
            Self::InvalidInitialPayload => {
                write!(formatter, "invalid FairPlay M1 capability payload")
            }
            Self::InvalidChallengePayload => {
                write!(formatter, "invalid FairPlay M2 challenge payload")
            }
            Self::UnsupportedChallengeMode(mode) => {
                write!(formatter, "unsupported FairPlay M2 mode {mode}")
            }
            Self::UnsupportedKeyMessageMode(mode) => {
                write!(formatter, "unsupported FairPlay M3 mode {mode}")
            }
        }
    }
}

impl std::error::Error for FairPlayParseError {}

/// Output from an authenticated SAP provider after processing an M1 record.
///
/// The provider must generate this challenge from the negotiated SAP exchange;
/// callers must never fill it with random bytes, captured responses, or a
/// placeholder value.
#[derive(Debug)]
pub struct FairPlayChallenge {
    pub mode: u8,
    pub challenge: Zeroizing<[u8; 128]>,
}

/// Session media keys returned only after the provider authenticates M3.
///
/// These values are deliberately zeroized on drop and must remain scoped to
/// the RTSP connection that completed the exchange.
#[derive(Debug)]
pub struct FairPlayKeys {
    /// The 16-byte video key produced by the authorized SAP implementation.
    pub video_key: Zeroizing<[u8; 16]>,
    pub acknowledgement: Zeroizing<[u8; 20]>,
}

/// Integration boundary for a legitimately licensed/authorized FairPlay SAP
/// implementation. This crate intentionally does not implement Apple's
/// proprietary SAP transform or derive media keys from unauthenticated input.
pub trait FairPlaySapProvider: Send + Sync {
    /// Process the sender's initial FPLY record and return an authenticated
    /// receiver challenge. Implementations must reject unsupported modes.
    fn begin(&self, initial: &FairPlayMessage) -> Result<FairPlayChallenge, FairPlayProviderError>;

    /// Authenticate the sender's key message against the exact M1/M2 exchange.
    /// Returning keys is an authorization boundary: implementations must not
    /// return media keys unless SAP authentication succeeded.
    fn finish(
        &self,
        initial: &FairPlayMessage,
        challenge: &FairPlayChallenge,
        key_message: &FairPlayMessage,
    ) -> Result<FairPlayKeys, FairPlayProviderError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FairPlayProviderError {
    Unavailable,
    UnsupportedMode(u8),
    InvalidMessage,
    AuthenticationFailed,
    Internal(String),
}

impl std::fmt::Display for FairPlayProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(
                formatter,
                "no authorized FairPlay SAP provider is configured"
            ),
            Self::UnsupportedMode(mode) => {
                write!(formatter, "FairPlay SAP mode {mode} is unsupported")
            }
            Self::InvalidMessage => write!(formatter, "FairPlay SAP message is invalid"),
            Self::AuthenticationFailed => write!(formatter, "FairPlay SAP authentication failed"),
            Self::Internal(reason) => write!(formatter, "FairPlay SAP provider error: {reason}"),
        }
    }
}

impl std::error::Error for FairPlayProviderError {}

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
            if body[12] != 0x02 || body[13] != 0x00 || body[15] != 0xbb {
                return Err(FairPlayParseError::InvalidInitialPayload);
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::Initial,
                initial_parameters: Some(
                    body[12..16].try_into().expect("four-byte initial payload"),
                ),
                initial_capabilities: Some(body[14]),
                challenge_mode: None,
                challenge: None,
                key_mode: None,
                key_label: None,
                local_sap: None,
                key_response: None,
                acknowledgement: None,
                body: Zeroizing::new(body.to_vec()),
            })
        }
        2 => {
            if body.len() != 142 {
                return Err(FairPlayParseError::InvalidChallengeLength(body.len()));
            }
            if body[12] != 0x02 {
                return Err(FairPlayParseError::InvalidChallengePayload);
            }
            let mode = body[13];
            if mode > 3 {
                return Err(FairPlayParseError::UnsupportedChallengeMode(mode));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::Challenge,
                initial_parameters: None,
                initial_capabilities: None,
                challenge_mode: Some(mode),
                challenge: Some(Zeroizing::new(
                    body[14..142]
                        .try_into()
                        .expect("128-byte FairPlay challenge"),
                )),
                key_mode: None,
                key_label: None,
                local_sap: None,
                key_response: None,
                acknowledgement: None,
                body: Zeroizing::new(body.to_vec()),
            })
        }
        3 => {
            if body.len() != 164 {
                return Err(FairPlayParseError::InvalidKeyMessageLength(body.len()));
            }
            let mode = body[12];
            if mode > 3 {
                return Err(FairPlayParseError::UnsupportedKeyMessageMode(mode));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::KeyMessage,
                initial_parameters: None,
                initial_capabilities: None,
                challenge_mode: None,
                challenge: None,
                key_mode: Some(mode),
                key_label: Some(
                    body[13..16]
                        .try_into()
                        .expect("three-byte FairPlay M3 label"),
                ),
                local_sap: Some(Zeroizing::new(
                    body[16..144]
                        .try_into()
                        .expect("128-byte FairPlay local SAP"),
                )),
                key_response: Some(Zeroizing::new(
                    body[144..164]
                        .try_into()
                        .expect("20-byte FairPlay key response"),
                )),
                acknowledgement: None,
                body: Zeroizing::new(body.to_vec()),
            })
        }
        4 => {
            if body.len() != 32 {
                return Err(FairPlayParseError::InvalidAcknowledgementLength(body.len()));
            }
            Ok(FairPlayMessage {
                phase: MessagePhase::Acknowledgement,
                initial_parameters: None,
                initial_capabilities: None,
                challenge_mode: None,
                challenge: None,
                key_mode: None,
                key_label: None,
                local_sap: None,
                key_response: None,
                acknowledgement: Some(Zeroizing::new(
                    body[12..32]
                        .try_into()
                        .expect("20-byte FairPlay acknowledgement"),
                )),
                body: Zeroizing::new(body.to_vec()),
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

#[derive(Debug, Default)]
pub struct FairPlaySession {
    initial_parameters: Option<[u8; 4]>,
    challenge_sent: bool,
    key_message: Option<Zeroizing<Vec<u8>>>,
    challenge_mode: Option<u8>,
    challenge: Option<Zeroizing<[u8; 128]>>,
}

impl FairPlaySession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, message: FairPlayMessage) -> Result<FairPlayState, String> {
        match message.phase {
            MessagePhase::Initial => {
                if self.initial_parameters.is_some() {
                    return Err("FairPlay initial message was already received".to_owned());
                }
                self.initial_parameters = message.initial_parameters;
                Ok(FairPlayState::AwaitingChallenge)
            }
            MessagePhase::Challenge | MessagePhase::Acknowledgement => {
                return Err(format!(
                    "FairPlay phase {} is receiver-originated",
                    message.phase as u8
                ));
            }
            MessagePhase::KeyMessage => {
                if self.initial_parameters.is_none() {
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
                let received_mode = message
                    .key_mode
                    .ok_or_else(|| "FairPlay M3 did not contain a parsed mode".to_owned())?;
                if Some(received_mode) != self.challenge_mode {
                    return Err(format!(
                        "FairPlay M3 mode {received_mode} does not match negotiated mode {:?}",
                        self.challenge_mode
                    ));
                }
                self.key_message = Some(message.body);
                Ok(FairPlayState::KeyMessageReceivedUnverified)
            }
        }
    }

    /// Raw four-byte M1 payload.
    pub fn initial_parameters(&self) -> Option<[u8; 4]> {
        self.initial_parameters
    }

    /// Sender capability mask advertised in byte 14 of the M1 payload.
    pub fn initial_capabilities(&self) -> Option<u8> {
        self.initial_parameters.map(|parameters| parameters[2])
    }

    /// Record that a real, negotiated phase-2 challenge has been sent.
    /// Callers must not use this for placeholder or replayed challenge bytes.
    pub fn mark_challenge_sent(&mut self, mode: u8, challenge: [u8; 128]) -> Result<(), String> {
        if self.initial_parameters.is_none() {
            return Err("FairPlay challenge cannot be sent before initial message".to_owned());
        }
        if self.challenge_sent {
            return Err("FairPlay challenge was already sent".to_owned());
        }
        if mode != 3 {
            return Err(format!("unsupported FairPlay challenge mode {mode}"));
        }
        self.challenge_mode = Some(mode);
        self.challenge = Some(Zeroizing::new(challenge));
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
        self.challenge.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairPlayState {
    AwaitingChallenge,
    /// M3 passed structural and mode checks, but SAP authentication is pending.
    KeyMessageReceivedUnverified,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial_message(capabilities: u8) -> Vec<u8> {
        let mut body = vec![0u8; 16];
        body[..4].copy_from_slice(b"FPLY");
        body[4] = 3;
        body[5] = 1;
        body[6] = 1;
        body[8..12].copy_from_slice(&4u32.to_be_bytes());
        body[12..16].copy_from_slice(&[0x02, 0x00, capabilities, 0xbb]);
        body
    }

    fn key_message() -> Vec<u8> {
        let mut body = vec![0u8; 164];
        body[..4].copy_from_slice(b"FPLY");
        body[4] = 3;
        body[5] = 1;
        body[6] = 3;
        body[8..12].copy_from_slice(&152u32.to_be_bytes());
        body[12] = 3;
        body[13..16].copy_from_slice(&[0x8f, 0x1a, 0x9c]);
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
        let parsed_m2 = parse_message(&m2).unwrap();
        assert_eq!(parsed_m2.phase, MessagePhase::Challenge);
        assert_eq!(parsed_m2.challenge_mode, Some(3));
        assert_eq!(parsed_m2.challenge.as_deref(), Some(&challenge));

        let acknowledgement = [0xa5u8; 20];
        let m4 = build_m4(&acknowledgement);
        assert_eq!(&m4[..12], b"FPLY\x03\x01\x04\x00\x00\x00\x00\x14");
        assert_eq!(&m4[12..], &acknowledgement);
        let parsed_m4 = parse_message(&m4).unwrap();
        assert_eq!(parsed_m4.phase, MessagePhase::Acknowledgement);
        assert_eq!(parsed_m4.acknowledgement.as_deref(), Some(&acknowledgement));
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
    fn parses_initial_message_and_preserves_all_parameters() {
        let message = parse_message(&initial_message(3)).expect("initial FairPlay message");
        assert_eq!(message.phase, MessagePhase::Initial);
        assert_eq!(message.initial_parameters, Some([0x02, 0x00, 3, 0xbb]));
        assert_eq!(message.initial_capabilities, Some(3));
        assert_eq!(message.body.len(), 16);
    }

    #[test]
    fn parses_observed_iphone_phase1_capability_payload() {
        let mut body = initial_message(2);
        body[12..16].copy_from_slice(&[0x02, 0x00, 0x02, 0xbb]);
        let message = parse_message(&body).expect("observed iPhone phase-1 message");
        assert_eq!(message.initial_parameters, Some([0x02, 0x00, 0x02, 0xbb]));
        assert_eq!(message.initial_capabilities, Some(2));
    }

    #[test]
    fn rejects_duplicate_m1_and_challenge_transitions() {
        let mut session = FairPlaySession::new();
        session
            .accept(parse_message(&initial_message(3)).unwrap())
            .unwrap();
        assert!(
            session
                .accept(parse_message(&initial_message(3)).unwrap())
                .unwrap_err()
                .contains("already received")
        );

        let mut empty = FairPlaySession::new();
        assert!(
            empty
                .mark_challenge_sent(3, [0x11; 128])
                .unwrap_err()
                .contains("before initial")
        );
        empty
            .accept(parse_message(&initial_message(3)).unwrap())
            .unwrap();
        empty.mark_challenge_sent(3, [0x11; 128]).unwrap();
        assert!(
            empty
                .mark_challenge_sent(3, [0x22; 128])
                .unwrap_err()
                .contains("already sent")
        );
    }

    #[test]
    fn rejects_m2_with_unsupported_mode() {
        let mut body = build_m2(3, &[0x5a; 128]);
        body[13] = 4;
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::UnsupportedChallengeMode(4)
        );
    }

    #[test]
    fn accepts_structural_m3_without_claiming_sap_authentication() {
        let mut session = FairPlaySession::new();
        session
            .accept(parse_message(&initial_message(3)).unwrap())
            .unwrap();
        session.mark_challenge_sent(3, [0x5a; 128]).unwrap();

        let state = session
            .accept(parse_message(&key_message()).unwrap())
            .unwrap();
        assert_eq!(state, FairPlayState::KeyMessageReceivedUnverified);
        assert!(session.has_key_message());
    }

    #[test]
    fn rejects_m3_when_mode_does_not_match_the_negotiated_m2_mode() {
        let mut session = FairPlaySession::new();
        let initial = parse_message(&initial_message(3)).unwrap();
        session.accept(initial).unwrap();
        session.mark_challenge_sent(3, [0x5a; 128]).unwrap();

        let mut mismatched = key_message();
        mismatched[12] = 2;
        let parsed = parse_message(&mismatched).unwrap();
        assert!(
            session
                .accept(parsed)
                .unwrap_err()
                .contains("does not match")
        );
        assert!(!session.has_key_message());
    }

    #[test]
    fn fairplay_negotiation_state_is_isolated_between_sessions() {
        let mut first = FairPlaySession::new();
        let mut second = FairPlaySession::new();

        first
            .accept(parse_message(&initial_message(3)).unwrap())
            .expect("first session accepts M1");
        first
            .mark_challenge_sent(3, [0x5a; 128])
            .expect("first session records its challenge");

        // A valid-looking M3 must not inherit another RTSP connection's M1
        // or challenge state.
        let second_session_m3 = parse_message(&key_message()).unwrap();
        assert!(
            second.accept(second_session_m3).is_err(),
            "a fresh RTSP session must reject M3 without its own M1 and M2"
        );
        assert!(!second.has_key_message());

        let first_m3 = parse_message(&key_message()).unwrap();
        assert_eq!(
            first.accept(first_m3).unwrap(),
            FairPlayState::KeyMessageReceivedUnverified
        );
        assert!(first.has_key_message());
        assert!(!second.has_key_message());
    }

    #[test]
    fn fairplay_sessions_keep_distinct_challenges_and_m3_state() {
        let mut first = FairPlaySession::new();
        let mut second = FairPlaySession::new();

        first
            .accept(parse_message(&initial_message(3)).unwrap())
            .expect("first session accepts M1");
        second
            .accept(parse_message(&initial_message(3)).unwrap())
            .expect("second session accepts its own M1");

        let first_challenge = [0x11; 128];
        let second_challenge = [0x22; 128];
        first
            .mark_challenge_sent(3, first_challenge)
            .expect("first session sends its challenge");
        second
            .mark_challenge_sent(3, second_challenge)
            .expect("second session sends its challenge");

        assert_eq!(first.challenge(), Some(&first_challenge));
        assert_eq!(second.challenge(), Some(&second_challenge));

        first
            .accept(parse_message(&key_message()).unwrap())
            .expect("first session accepts its M3");
        assert!(first.has_key_message());
        assert!(!second.has_key_message());
        assert_eq!(second.challenge(), Some(&second_challenge));

        second
            .accept(parse_message(&key_message()).unwrap())
            .expect("second session accepts its own M3");
        assert!(second.has_key_message());
        assert_eq!(first.challenge(), Some(&first_challenge));
        assert_eq!(second.challenge(), Some(&second_challenge));
    }

    #[test]
    fn rejects_invalid_m1_payload_marker_and_trailer() {
        let mut body = initial_message(3);
        body[12] = 0;
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::InvalidInitialPayload
        );

        let mut body = initial_message(3);
        body[15] = 0;
        assert_eq!(
            parse_message(&body).unwrap_err(),
            FairPlayParseError::InvalidInitialPayload
        );
    }

    #[test]
    fn parses_key_message() {
        let message = parse_message(&key_message()).expect("key FairPlay message");
        assert_eq!(message.phase, MessagePhase::KeyMessage);
        assert_eq!(message.initial_parameters, None);
        assert_eq!(message.key_mode, Some(3));
        assert_eq!(message.key_label, Some([0x8f, 0x1a, 0x9c]));
        assert_eq!(message.local_sap.as_deref(), Some(&[0u8; 128]));
        assert_eq!(message.key_response.as_deref(), Some(&[0u8; 20]));
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
        assert_eq!(session.initial_parameters(), Some([0x02, 0x00, 3, 0xbb]));
        assert_eq!(session.initial_capabilities(), Some(3));
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
            FairPlayState::KeyMessageReceivedUnverified
        );
        assert!(session.has_key_message());

        let duplicate_key = parse_message(&key_message()).expect("duplicate key message");
        assert_eq!(
            session.accept(duplicate_key).unwrap_err(),
            "FairPlay key message was already received"
        );
        assert!(session.has_key_message());
    }

    #[test]
    fn rejects_truncated_and_malformed_fply_headers() {
        assert_eq!(parse_message(&[0u8; 15]).unwrap_err(), FairPlayParseError::TooShort);

        let mut wrong_magic = initial_message(3);
        wrong_magic[..4].copy_from_slice(b"NOPE");
        assert_eq!(parse_message(&wrong_magic).unwrap_err(), FairPlayParseError::InvalidMagic);

        let mut wrong_version = initial_message(3);
        wrong_version[4] = 2;
        assert_eq!(
            parse_message(&wrong_version).unwrap_err(),
            FairPlayParseError::UnsupportedMajorVersion(2)
        );

        let mut wrong_length = initial_message(3);
        wrong_length[8..12].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            parse_message(&wrong_length).unwrap_err(),
            FairPlayParseError::InvalidPayloadLength { declared: 5, actual: 4 }
        );
    }

    #[test]
    fn rejects_unknown_phase_and_invalid_m1_payload() {
        let mut unknown_phase = initial_message(3);
        unknown_phase[6] = 9;
        assert_eq!(
            parse_message(&unknown_phase).unwrap_err(),
            FairPlayParseError::UnsupportedPhase(9)
        );

        let mut invalid_m1 = initial_message(3);
        invalid_m1[12] = 0xff;
        assert_eq!(
            parse_message(&invalid_m1).unwrap_err(),
            FairPlayParseError::InvalidInitialPayload
        );
    }

    #[test]
    fn rejects_duplicate_m3_and_never_marks_structural_m3_as_authenticated() {
        let mut session = FairPlaySession::new();
        session.accept(parse_message(&initial_message(3)).unwrap()).unwrap();
        session.mark_challenge_sent(3, [0x33; 128]).unwrap();

        let first = parse_message(&key_message()).unwrap();
        assert_eq!(
            session.accept(first).unwrap(),
            FairPlayState::KeyMessageReceivedUnverified
        );
        assert!(session.has_key_message());

        let duplicate = parse_message(&key_message()).unwrap();
        assert!(
            session.accept(duplicate).unwrap_err().contains("already received"),
            "a second M3 must not replace the first message"
        );
        // The state type intentionally has no authenticated/ready variant:
        // only an authorized SAP provider may produce media keys.
        assert_eq!(
            session.accept(parse_message(&build_m4(&[0x44; 20])).unwrap()).unwrap_err(),
            "FairPlay phase 4 is receiver-originated"
        );
    }

    #[test]
    fn rejects_truncated_m2_m3_and_m4_records() {
        let m2 = build_m2(3, &[0x55; 128]);
        assert!(matches!(
            parse_message(&m2[..m2.len() - 1]),
            Err(FairPlayParseError::InvalidPayloadLength { .. })
                | Err(FairPlayParseError::InvalidChallengeLength(_))
        ));

        let m3 = key_message();
        assert!(matches!(
            parse_message(&m3[..m3.len() - 1]),
            Err(FairPlayParseError::InvalidPayloadLength { .. })
                | Err(FairPlayParseError::InvalidKeyMessageLength(_))
        ));

        let m4 = build_m4(&[0x66; 20]);
        assert!(matches!(
            parse_message(&m4[..m4.len() - 1]),
            Err(FairPlayParseError::InvalidPayloadLength { .. })
                | Err(FairPlayParseError::InvalidAcknowledgementLength(_))
        ));
    }

}
