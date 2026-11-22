//! Bounded RTSP/HTTP control parser for the AirPlay endpoint.
//!
//! The handler supports persistent RTSP connections, bounded request bodies,
//! OPTIONS, GET /server-info, and binary-plist /info responses.
//! Pair-Setup M1/M3 SRP and encrypted M5/M6 identity exchange are implemented; media transport is not implemented.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::{config, pair_setup, pair_verify::PairVerifySession, pairing, plist, srp::SrpServer, tlv8::{self, Tlv}};
use ::plist::{Dictionary, Value};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 2048;

struct Request {
    method: String,
    path: String,
    protocol: String,
    cseq: String,
    connection_close: bool,
    body: Vec<u8>,
}

pub fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut pending = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut pair_setup_srp: Option<SrpServer> = None;
    let mut pair_setup_session_key: Option<[u8; 64]> = None;
    let mut pair_verify_session: Option<PairVerifySession> = None;
    tracing::info!("AirPlay RTSP session started");

    loop {
        let Some(request) = read_request(&mut stream, &mut pending)? else {
            tracing::info!("AirPlay RTSP peer closed the session");
            return Ok(());
        };

        tracing::info!(
            method = %request.method,
            path = %request.path,
            protocol = %request.protocol,
            cseq = %request.cseq,
            body_bytes = request.body.len(),
            "AirPlay RTSP request parsed"
        );

        let close_after_response = request.connection_close
            || request.protocol == "HTTP/1.1"
            || request.protocol == "HTTP/1.0";

        match (
            request.method.as_str(),
            request.path.as_str(),
            request.protocol.as_str(),
        ) {
            ("OPTIONS", _, "RTSP/1.0") => {
                let response = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nPublic: OPTIONS, GET, POST\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                write_response(&mut stream, &response, 200)?;
            }
            ("GET", "/server-info", "HTTP/1.1")
            | ("GET", "/server-info", "RTSP/1.0") => {
                let body = server_info_plist();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                write_response(&mut stream, &response, 200)?;
                return Ok(());
            }
            ("POST", "/pair-setup", "RTSP/1.0") => {
                let setup_code = super::setup_code();
                match handle_pair_setup(
                    &request.body,
                    &mut pair_setup_srp,
                    &mut pair_setup_session_key,
                    Some(&setup_code),
                ) {
                    Ok(body) => {
                        let header = format!(
                            "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                            request.cseq,
                            body.len()
                        );
                        stream.write_all(header.as_bytes())?;
                        stream.write_all(&body)?;
                        stream.flush()?;
                    }
                    Err(error) => {
                        tracing::warn!(status = error.status, reason = %error.reason, "Pair-Setup request rejected");
                        let reason = if error.status == 503 { "Service Unavailable" } else { "Bad Request" };
                        let response = format!(
                            "RTSP/1.0 {} {}\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                            error.status,
                            reason,
                            request.cseq
                        );
                        write_response(&mut stream, &response, error.status)?;
                    }
                }
            }
            ("POST", "/pair-verify", "RTSP/1.0") => {
                let response_body = match handle_pair_verify(
                    &request.body,
                    &mut pair_verify_session,
                ) {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!(%error, "Pair-Verify exchange rejected");
                        pair_verify_session = None;
                        pair_verify_error_response()
                    }
                };
                let header = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                    request.cseq,
                    response_body.len()
                );
                stream.write_all(header.as_bytes())?;
                stream.write_all(&response_body)?;
                stream.flush()?;
            }
            ("GET", "/info", "RTSP/1.0") | ("POST", "/info", "RTSP/1.0") => {
                match build_info_response(&request.body) {
                    Ok(body) => {
                        let header = format!(
                            "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
                            request.cseq,
                            body.len()
                        );
                        stream.write_all(header.as_bytes())?;
                        stream.write_all(&body)?;
                        stream.flush()?;
                    }
                    Err(reason) => {
                        tracing::warn!(%reason, "Rejected invalid AirPlay /info plist request");
                        let response = format!(
                            "RTSP/1.0 400 Bad Request\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                            request.cseq
                        );
                        write_response(&mut stream, &response, 400)?;
                    }
                }
            }
            _ => {
                tracing::warn!(
                    method = %request.method,
                    path = %request.path,
                    protocol = %request.protocol,
                    "AirPlay control method is not implemented"
                );
                let protocol = if request.protocol == "RTSP/1.0" {
                    "RTSP/1.0"
                } else {
                    "HTTP/1.1"
                };
                let response = format!(
                    "{protocol} 501 Not Implemented\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                write_response(&mut stream, &response, 501)?;
            }
        }

        if close_after_response {
            return Ok(());
        }
    }
}

/// Read one complete request and retain bytes belonging to a subsequent request.
fn read_request(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
) -> std::io::Result<Option<Request>> {
    let mut chunk = [0u8; READ_CHUNK_BYTES];

    let header_end = loop {
        if let Some(index) = find_header_end(pending) {
            break index + 4;
        }
        if pending.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AirPlay request headers exceeded size limit",
            ));
        }

        let count = stream.read(&mut chunk)?;
        if count == 0 {
            if pending.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before completing AirPlay request headers",
            ));
        }
        pending.extend_from_slice(&chunk[..count]);
    };

    if header_end > MAX_HEADER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AirPlay request headers exceeded size limit",
        ));
    }

    let header_text = String::from_utf8_lossy(&pending[..header_end - 4]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let protocol = parts.next().unwrap_or_default().to_owned();

    if method.is_empty() || path.is_empty() || protocol.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid AirPlay request line",
        ));
    }

    let mut content_length = 0usize;
    let mut cseq = "0".to_owned();
    let mut connection_close = false;

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid AirPlay Content-Length",
                    )
                })?;
            } else if name.eq_ignore_ascii_case("CSeq") {
                cseq = value.to_owned();
            } else if name.eq_ignore_ascii_case("Connection") {
                connection_close = value.eq_ignore_ascii_case("close");
            }
        }
    }

    if content_length > MAX_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AirPlay request body exceeded size limit",
        ));
    }

    let request_end = header_end.checked_add(content_length).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "AirPlay request size overflow")
    })?;

    while pending.len() < request_end {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before completing AirPlay request body",
            ));
        }
        pending.extend_from_slice(&chunk[..count]);
    }

    let body = pending[header_end..request_end].to_vec();
    pending.drain(..request_end);

    Ok(Some(Request {
        method,
        path,
        protocol,
        cseq,
        connection_close,
        body,
    }))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_response(
    stream: &mut TcpStream,
    response: &str,
    status: u16,
) -> std::io::Result<()> {
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    tracing::info!(
        status,
        response_bytes = response.len(),
        "AirPlay RTSP response sent"
    );
    Ok(())
}

#[derive(Debug)]
struct PairSetupFailure {
    status: u16,
    reason: String,
}

impl PairSetupFailure {
    fn bad_request(reason: impl Into<String>) -> Self {
        Self { status: 400, reason: reason.into() }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self { status: 503, reason: reason.into() }
    }
}

/// Handle Pair-Setup M1/M3/M5 on one persistent RTSP connection.
/// The setup code is supplied by the application and is never logged.
fn handle_pair_setup(
    body: &[u8],
    srp_state: &mut Option<SrpServer>,
    session_key: &mut Option<[u8; 64]>,
    setup_code: Option<&str>,
) -> Result<Vec<u8>, PairSetupFailure> {
    let fields = tlv8::decode(body)
        .map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;
    let mut states = fields.iter().filter(|field| field.kind == 0x06);
    let state = states.next().ok_or_else(|| PairSetupFailure::bad_request("missing Pair-Setup State"))?;
    if states.next().is_some() || state.value.len() != 1 {
        return Err(PairSetupFailure::bad_request("invalid Pair-Setup State field"));
    }

    match state.value[0] {
        1 => {
            pairing::parse_m1(body)
                .map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;
            let code = setup_code.ok_or_else(|| {
                PairSetupFailure::unavailable(
                    "the receiver has no generated pairing code",
                )
            })?;
            if !pairing::is_valid_setup_code(code) {
                return Err(PairSetupFailure::unavailable(
                    "the generated pairing code has an invalid format",
                ));
            }

            let server = SrpServer::new(code)
                .map_err(|error| PairSetupFailure::unavailable(error.to_string()))?;
            let response = tlv8::encode(&[
                Tlv { kind: 0x06, value: vec![0x02] },
                Tlv {
                    kind: 0x03,
                    value: server.public_key()
                        .map_err(|error| PairSetupFailure::unavailable(error.to_string()))?,
                },
                Tlv { kind: 0x02, value: server.salt().to_vec() },
            ]);
            *srp_state = Some(server);
            *session_key = None;
            Ok(response)
        }
        5 => {
            let encrypted_data = fields
                .iter()
                .filter(|field| field.kind == 0x05)
                .collect::<Vec<_>>();
            if encrypted_data.len() != 1 {
                *session_key = None;
                return Ok(tlv8::encode(&[
                    Tlv { kind: 0x06, value: vec![0x06] },
                    Tlv { kind: 0x07, value: vec![0x02] },
                ]));
            }
            let key = session_key.take().ok_or_else(|| {
                PairSetupFailure::bad_request("Pair-Setup M5 received without a verified M3 exchange")
            })?;
            match pair_setup::handle_m5(&key, &encrypted_data[0].value) {
                Ok(response) => Ok(response),
                Err(error) => {
                    tracing::warn!(%error, "Pair-Setup M5 identity exchange rejected");
                    Ok(tlv8::encode(&[
                        Tlv { kind: 0x06, value: vec![0x06] },
                        Tlv { kind: 0x07, value: vec![0x02] },
                    ]))
                }
            }
        }
        3 => {
            let message = pairing::parse_m3(body)
                .map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;
            let server = srp_state.take().ok_or_else(|| {
                PairSetupFailure::bad_request("Pair-Setup M3 received without an M1 exchange")
            })?;

            match server.verify_client(&message.public_key, &message.proof) {
                Ok(result) => {
                    let response = tlv8::encode(&[
                        Tlv { kind: 0x06, value: vec![0x04] },
                        Tlv { kind: 0x04, value: result.proof.to_vec() },
                    ]);
                    *session_key = Some(result.session_key);
                    Ok(response)
                }
                Err(error) => {
                    tracing::warn!(%error, "Pair-Setup SRP proof rejected");
                    *session_key = None;
                    Ok(tlv8::encode(&[
                        Tlv { kind: 0x06, value: vec![0x04] },
                        Tlv { kind: 0x07, value: vec![0x02] },
                    ]))
                }
            }
        }
        other => Err(PairSetupFailure::bad_request(format!(
            "unsupported Pair-Setup state {other}"
        ))),
    }
}

/// Handle one Pair-Verify state transition on the current RTSP connection.
fn handle_pair_verify(
    body: &[u8],
    session: &mut Option<PairVerifySession>,
) -> Result<Vec<u8>, String> {
    let fields = tlv8::decode(body).map_err(|error| error.to_string())?;
    let mut states = fields.iter().filter(|field| field.kind == 0x06);
    let state = states.next().ok_or_else(|| "Pair-Verify request is missing State".to_owned())?;
    if states.next().is_some() || state.value.len() != 1 {
        return Err("Pair-Verify request has an invalid State field".into());
    }

    match state.value[0] {
        1 => {
            if session.is_some() {
                return Err("Pair-Verify M1 received while another exchange is active".into());
            }
            let (new_session, response) = PairVerifySession::start(body)?;
            *session = Some(new_session);
            Ok(response)
        }
        3 => {
            let current = session.take()
                .ok_or_else(|| "Pair-Verify M3 received without M1".to_owned())?;
            current.finish(body)
        }
        other => Err(format!("unsupported Pair-Verify state {other}")),
    }
}

fn pair_verify_error_response() -> Vec<u8> {
    tlv8::encode(&[
        Tlv { kind: 0x06, value: vec![4] },
        Tlv { kind: 0x07, value: vec![2] },
    ])
}

fn server_info_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>deviceid</key><string>{}</string><key>features</key><integer>0</integer><key>model</key><string>{}</string><key>protovers</key><string>1.0</string><key>srcvers</key><string>{}</string></dict></plist>",
        config::device_id(),
        config::MODEL,
        config::SOURCE_VERSION
    )
}

fn build_info_response(request_body: &[u8]) -> Result<Vec<u8>, String> {
    let response = if request_body.is_empty() {
        // Unqualified /info asks for baseline playback information.
        let mut dictionary = Dictionary::new();
        dictionary.insert("initialVolume".into(), Value::Integer((-120).into()));
        dictionary
    } else {
        let request = plist::decode(request_body).map_err(|error| error.to_string())?;
        let dictionary = request
            .as_dictionary()
            .ok_or_else(|| "AirPlay /info request root must be a dictionary".to_owned())?;

        let qualifier = dictionary
            .get("qualifier")
            .ok_or_else(|| "AirPlay /info request is missing qualifier".to_owned())?
            .as_array()
            .ok_or_else(|| "AirPlay /info qualifier must be an array".to_owned())?;

        if qualifier.iter().any(|value| value.as_string().is_none()) {
            return Err("AirPlay /info qualifier entries must be strings".to_owned());
        }

        let asks_for_txt = qualifier
            .iter()
            .filter_map(Value::as_string)
            .any(|value| value == "txtAirPlay");

        if asks_for_txt {
            txt_airplay_dictionary()
        } else {
            return Err("unsupported AirPlay /info qualifier".to_owned());
        }
    };

    plist::encode_binary(&Value::Dictionary(response)).map_err(|error| error.to_string())
}

/// Return the conservative properties also published in the mDNS TXT record.
fn txt_airplay_dictionary() -> Dictionary {
    let mut dictionary = Dictionary::new();
    dictionary.insert("deviceid".into(), Value::String(config::device_id()));
    dictionary.insert("features".into(), Value::String(config::FEATURES.into()));
    dictionary.insert("model".into(), Value::String(config::MODEL.into()));
    dictionary.insert("srcvers".into(), Value::String(config::SOURCE_VERSION.into()));
    dictionary.insert("flags".into(), Value::String("0x0".into()));
    dictionary
}

#[cfg(test)]
mod tests {
    use super::{build_info_response, find_header_end, handle_pair_setup, server_info_plist};
    use crate::airplay::tlv8::{self, Tlv};
    use super::plist;
    use ::plist::{Dictionary, Value};

    #[test]
    fn finds_header_terminator() {
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        assert_eq!(
            find_header_end(request),
            Some(b"OPTIONS * RTSP/1.0\r\nCSeq: 1".len())
        );
        assert_eq!(find_header_end(b"OPTIONS * RTSP/1.0\r\n"), None);
    }
    #[test]
    fn server_info_contains_declared_model_and_zero_features() {
        let body = server_info_plist();
        assert!(body.contains("<key>features</key><integer>0</integer>"));
        assert!(body.contains("<key>model</key><string>RustPhoneControl1,1</string>"));
    }

    #[test]
    fn unqualified_info_returns_initial_volume() {
        let bytes = build_info_response(&[]).expect("build /info response");
        assert!(bytes.starts_with(b"bplist00"));
        let value = plist::decode(&bytes).expect("decode response");
        let dict = value.as_dictionary().expect("response dictionary");
        assert!(matches!(dict.get("initialVolume"), Some(Value::Integer(_))));
    }

    #[test]
    fn txt_airplay_qualifier_returns_mdns_properties_as_strings() {
        let mut request = Dictionary::new();
        request.insert(
            "qualifier".into(),
            Value::Array(vec![Value::String("txtAirPlay".into())]),
        );
        let bytes = plist::encode_binary(&Value::Dictionary(request)).expect("encode request");
        let response = build_info_response(&bytes).expect("build TXT response");
        let value = plist::decode(&response).expect("decode response");
        let dict = value.as_dictionary().expect("response dictionary");

        for key in ["deviceid", "features", "model", "srcvers", "flags"] {
            assert!(matches!(dict.get(key), Some(Value::String(_))), "missing string key {key}");
        }
        assert_eq!(dict.get("features").and_then(Value::as_string), Some("0x0"));
    }


    #[test]
    fn pair_setup_m1_returns_srp_challenge() {
        let request = tlv8::encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let response = handle_pair_setup(
            &request,
            &mut srp,
            &mut session_key,
            Some("518-08-582"),
        ).expect("M1 response");
        let fields = tlv8::decode(&response).expect("decode M2");
        assert_eq!(fields.iter().find(|field| field.kind == 0x06).unwrap().value, [0x02]);
        assert_eq!(fields.iter().find(|field| field.kind == 0x02).unwrap().value.len(), 16);
        assert_eq!(fields.iter().find(|field| field.kind == 0x03).unwrap().value.len(), 384);
        assert!(srp.is_some());
    }

    #[test]
    fn pair_setup_requires_explicit_setup_code() {
        let request = tlv8::encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let error = handle_pair_setup(&request, &mut srp, &mut session_key, None)
            .expect_err("missing code must not start pairing");
        assert_eq!(error.status, 503);
        assert!(srp.is_none());
    }

    #[test]
    fn pair_setup_rejects_m3_without_m1() {
        let request = tlv8::encode(&[
            Tlv { kind: 0x06, value: vec![0x03] },
            Tlv { kind: 0x03, value: vec![0x01] },
            Tlv { kind: 0x04, value: vec![0x00; 64] },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let error = handle_pair_setup(&request, &mut srp, &mut session_key, None)
            .expect_err("M3 without M1 must fail");
        assert_eq!(error.status, 400);
    }


    #[test]
    fn pair_setup_rejects_invalid_setup_code_format() {
        let request = tlv8::encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let error = handle_pair_setup(&request, &mut srp, &mut session_key, Some("12345678"))
            .expect_err("invalid code format must fail");
        assert_eq!(error.status, 503);
        assert!(srp.is_none());
    }

    #[test]
    fn pair_setup_returns_authentication_error_for_bad_m3_proof() {
        let m1 = tlv8::encode(&[
            Tlv { kind: 0x06, value: vec![0x01] },
            Tlv { kind: 0x00, value: vec![0x00] },
        ]);
        let m3 = tlv8::encode(&[
            Tlv { kind: 0x06, value: vec![0x03] },
            Tlv { kind: 0x03, value: vec![0x01] },
            Tlv { kind: 0x04, value: vec![0x00; 64] },
        ]);
        let mut srp = None;
        let mut session_key = None;
        handle_pair_setup(&m1, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("M1 should create SRP challenge");
        let response = handle_pair_setup(&m3, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("bad proof is represented as an M4 TLV error");
        let fields = tlv8::decode(&response).expect("decode M4 error");
        assert!(fields.iter().any(|field| field.kind == 0x06 && field.value == [0x04]));
        assert!(fields.iter().any(|field| field.kind == 0x07 && field.value == [0x02]));
        assert!(session_key.is_none());
    }

    #[test]
    fn unsupported_info_qualifier_is_rejected() {
        let mut request = Dictionary::new();
        request.insert(
            "qualifier".into(),
            Value::Array(vec![Value::String("unknownCapability".into())]),
        );
        let bytes = plist::encode_binary(&Value::Dictionary(request)).expect("encode request");
        assert!(build_info_response(&bytes).is_err());
    }
}
