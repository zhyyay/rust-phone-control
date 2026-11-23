//! Typed parsing for the two AirPlay 2 RTSP SETUP plist messages.
//!
//! The first SETUP describes the mirroring session and timing endpoint. A
//! subsequent SETUP carries one or more stream descriptors. This module only
//! validates and extracts metadata; socket allocation and response generation
//! are handled by the RTSP session layer.

use ::plist::Value;

/// A validated AirPlay 2 SETUP request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SetupRequest {
    Session(SessionSetup),
    Streams(Vec<StreamSetup>),
}

/// Session-level metadata from the first SETUP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionSetup {
    pub timing_port: Option<u16>,
    pub session_uuid: Option<String>,
    pub screen_mirroring: bool,
    pub timing_protocol: Option<String>,
    /// FairPlay-wrapped 16-byte video key supplied by the sender.
    pub fairplay_ekey: Option<[u8; 72]>,
    /// Optional stream IV supplied alongside the wrapped key.
    pub fairplay_eiv: Option<[u8; 16]>,
}

/// One stream descriptor from a subsequent SETUP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StreamSetup {
    pub stream_type: u64,
    pub connection_id: Option<u64>,
}

/// Decode and validate an AirPlay 2 SETUP property list.
pub(super) fn parse_setup_request(bytes: &[u8]) -> Result<SetupRequest, String> {
    let value =
        super::plist::decode(bytes).map_err(|error| format!("invalid SETUP plist: {error}"))?;
    let dictionary = value
        .as_dictionary()
        .ok_or_else(|| "SETUP plist root must be a dictionary".to_owned())?;

    // Log only plist field names and value kinds. SETUP contains wrapped
    // FairPlay key material, so never log field values or raw plist bytes.
    let top_level_fields = dictionary
        .iter()
        .map(|(key, value)| {
            let kind = match value {
                Value::Array(_) => "array",
                Value::Data(_) => "data",
                Value::Dictionary(_) => "dictionary",
                Value::Boolean(_) => "boolean",
                Value::Integer(_) => "integer",
                Value::Real(_) => "real",
                Value::String(_) => "string",
                Value::Date(_) => "date",
                Value::Uid(_) => "uid",
            };
            format!("{key}:{kind}")
        })
        .collect::<Vec<_>>();
    tracing::info!(
        fields = ?top_level_fields,
        "AirPlay SETUP plist fields inspected"
    );

    if let Some(streams_value) = dictionary.get("streams") {
        let streams = streams_value
            .as_array()
            .ok_or_else(|| "SETUP streams field must be an array".to_owned())?;
        if streams.is_empty() || streams.len() > 16 {
            return Err("SETUP streams array must contain between 1 and 16 entries".to_owned());
        }

        let mut parsed = Vec::with_capacity(streams.len());
        for (index, value) in streams.iter().enumerate() {
            let stream = value
                .as_dictionary()
                .ok_or_else(|| format!("SETUP streams[{index}] must be a dictionary"))?;
            let stream_type = unsigned_integer(stream.get("type")).ok_or_else(|| {
                format!("SETUP streams[{index}].type must be an unsigned integer")
            })?;
            let connection_id = match stream.get("streamConnectionID") {
                Some(value) => Some(unsigned_integer(Some(value)).ok_or_else(|| {
                    format!("SETUP streams[{index}].streamConnectionID must be an unsigned integer")
                })?),
                None => None,
            };
            parsed.push(StreamSetup {
                stream_type,
                connection_id,
            });
        }
        return Ok(SetupRequest::Streams(parsed));
    }

    let timing_port = match dictionary.get("timingPort") {
        Some(value) => {
            let port = unsigned_integer(Some(value))
                .ok_or_else(|| "SETUP timingPort must be an unsigned integer".to_owned())?;
            if port == 0 || port > u64::from(u16::MAX) {
                return Err("SETUP timingPort is outside the valid UDP port range".to_owned());
            }
            Some(port as u16)
        }
        None => None,
    };

    let session_uuid = match dictionary.get("sessionUUID") {
        Some(value) => {
            let uuid = value
                .as_string()
                .ok_or_else(|| "SETUP sessionUUID must be a string".to_owned())?;
            if uuid.is_empty() || uuid.len() > 128 {
                return Err("SETUP sessionUUID length is invalid".to_owned());
            }
            Some(uuid.to_owned())
        }
        None => None,
    };

    let screen_mirroring = match dictionary.get("isScreenMirroringSession") {
        Some(value) => value
            .as_boolean()
            .ok_or_else(|| "SETUP isScreenMirroringSession must be a boolean".to_owned())?,
        None => false,
    };

    let fairplay_ekey = fixed_data::<72>(dictionary.get("ekey"), "ekey")?;
    let fairplay_eiv = fixed_data::<16>(dictionary.get("eiv"), "eiv")?;

    let timing_protocol = match dictionary.get("timingProtocol") {
        Some(value) => {
            let protocol = value
                .as_string()
                .ok_or_else(|| "SETUP timingProtocol must be a string".to_owned())?;
            if protocol != "NTP" && protocol != "PTP" {
                return Err("SETUP timingProtocol must be NTP or PTP".to_owned());
            }
            Some(protocol.to_owned())
        }
        None => None,
    };

    if timing_port.is_none()
        && session_uuid.is_none()
        && !screen_mirroring
        && timing_protocol.is_none()
    {
        return Err(
            "SETUP plist contains neither session metadata nor stream descriptors".to_owned(),
        );
    }

    Ok(SetupRequest::Session(SessionSetup {
        timing_port,
        session_uuid,
        screen_mirroring,
        timing_protocol,
        fairplay_ekey,
        fairplay_eiv,
    }))
}

fn fixed_data<const N: usize>(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<[u8; N]>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = match value {
        Value::Data(bytes) => bytes,
        _ => return Err(format!("SETUP {field} must be a data value")),
    };
    let data: [u8; N] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("SETUP {field} must be exactly {N} bytes"))?;
    Ok(Some(data))
}

fn unsigned_integer(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Integer(integer) => integer.as_unsigned(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{SetupRequest, parse_setup_request};
    use crate::airplay::plist;
    use ::plist::{Dictionary, Value};

    #[test]
    fn parses_session_level_setup_metadata() {
        let mut dictionary = Dictionary::new();
        dictionary.insert("timingPort".into(), Value::Integer(7010.into()));
        dictionary.insert("ekey".into(), Value::Data(vec![0x11; 72]));
        dictionary.insert("eiv".into(), Value::Data(vec![0x22; 16]));
        dictionary.insert(
            "sessionUUID".into(),
            Value::String("48FE92D4-3786-4D24-8270-752ACCCF8A47".into()),
        );
        dictionary.insert("isScreenMirroringSession".into(), Value::Boolean(true));
        dictionary.insert("timingProtocol".into(), Value::String("PTP".into()));
        let bytes = plist::encode_binary(&Value::Dictionary(dictionary)).expect("encode plist");

        let parsed = parse_setup_request(&bytes).expect("parse session SETUP");
        match parsed {
            SetupRequest::Session(session) => {
                assert_eq!(session.timing_port, Some(7010));
                assert_eq!(
                    session.session_uuid.as_deref(),
                    Some("48FE92D4-3786-4D24-8270-752ACCCF8A47")
                );
                assert!(session.screen_mirroring);
                assert_eq!(session.timing_protocol.as_deref(), Some("PTP"));
                assert_eq!(session.fairplay_ekey, Some([0x11; 72]));
                assert_eq!(session.fairplay_eiv, Some([0x22; 16]));
            }
            SetupRequest::Streams(_) => panic!("expected session SETUP"),
        }
    }

    #[test]
    fn parses_stream_setup_descriptors() {
        let mut stream = Dictionary::new();
        stream.insert("type".into(), Value::Integer(110.into()));
        stream.insert(
            "streamConnectionID".into(),
            Value::Integer(3_873_339_193_950_757_022u64.into()),
        );
        let mut root = Dictionary::new();
        root.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(stream)]),
        );
        let bytes = plist::encode_binary(&Value::Dictionary(root)).expect("encode plist");

        let parsed = parse_setup_request(&bytes).expect("parse stream SETUP");
        assert_eq!(
            parsed,
            SetupRequest::Streams(vec![super::StreamSetup {
                stream_type: 110,
                connection_id: Some(3_873_339_193_950_757_022),
            }])
        );
    }

    #[test]
    fn rejects_invalid_fairplay_key_material_lengths_and_types() {
        let mut root = Dictionary::new();
        root.insert("isScreenMirroringSession".into(), Value::Boolean(true));
        root.insert("ekey".into(), Value::Data(vec![0; 71]));
        let bytes = plist::encode_binary(&Value::Dictionary(root)).expect("encode plist");
        assert!(parse_setup_request(&bytes).is_err());

        let mut root = Dictionary::new();
        root.insert("isScreenMirroringSession".into(), Value::Boolean(true));
        root.insert("eiv".into(), Value::String("not binary data".into()));
        let bytes = plist::encode_binary(&Value::Dictionary(root)).expect("encode plist");
        assert!(parse_setup_request(&bytes).is_err());
    }

    #[test]
    fn rejects_malformed_setup_metadata() {
        let mut root = Dictionary::new();
        root.insert("timingPort".into(), Value::Integer(70_000.into()));
        let bytes = plist::encode_binary(&Value::Dictionary(root)).expect("encode plist");
        assert!(parse_setup_request(&bytes).is_err());

        let mut root = Dictionary::new();
        root.insert("streams".into(), Value::String("not-an-array".into()));
        let bytes = plist::encode_binary(&Value::Dictionary(root)).expect("encode plist");
        assert!(parse_setup_request(&bytes).is_err());

        assert!(parse_setup_request(b"not a plist").is_err());
    }
}
