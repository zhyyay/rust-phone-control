//! Bounded RTSP/HTTP control parser for the AirPlay endpoint.
//!
//! The handler supports persistent RTSP connections, bounded request bodies,
//! OPTIONS, GET /server-info, and a conservative XML-plist GET /info response.
//! Pairing and media transport are intentionally not advertised or implemented.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::{config, plist};
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
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nPublic: OPTIONS, GET\r\nContent-Length: 0\r\n\r\n",
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

fn server_info_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>deviceid</key><string>{}</string><key>features</key><integer>0</integer><key>model</key><string>{}</string><key>protovers</key><string>1.0</string><key>srcvers</key><string>{}</string></dict></plist>",
        config::device_id(),
        config::MODEL,
        config::SOURCE_VERSION
    )
}

fn build_info_response(request_body: &[u8]) -> Result<Vec<u8>, String> {
    if !request_body.is_empty() {
        let request = plist::decode(request_body).map_err(|error| error.to_string())?;
        let dictionary = request
            .as_dictionary()
            .ok_or_else(|| "AirPlay /info request root must be a dictionary".to_owned())?;

        if let Some(qualifier) = dictionary.get("qualifier") {
            let values = qualifier
                .as_array()
                .ok_or_else(|| "AirPlay /info qualifier must be an array".to_owned())?;
            if values.iter().any(|value| value.as_string().is_none()) {
                return Err("AirPlay /info qualifier entries must be strings".to_owned());
            }
        }
    }

    let mut response = Dictionary::new();
    response.insert("deviceID".into(), Value::String(config::device_id()));
    response.insert("features".into(), Value::Integer(0.into()));
    response.insert("model".into(), Value::String(config::MODEL.into()));
    response.insert("protocolVersion".into(), Value::String("1.0".into()));
    response.insert("sourceVersion".into(), Value::String(config::SOURCE_VERSION.into()));
    response.insert("statusFlags".into(), Value::Integer(0.into()));

    plist::encode_binary(&Value::Dictionary(response)).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{build_info_response, find_header_end, server_info_plist};
    use super::plist;
    use ::plist::{Dictionary, Value};

    #[test]
    fn finds_header_terminator() {
        assert_eq!(find_header_end(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"), Some(27));
        assert_eq!(find_header_end(b"OPTIONS * RTSP/1.0\r\n"), None);
    }

    #[test]
    fn server_info_contains_declared_model_and_zero_features() {
        let body = server_info_plist();
        assert!(body.contains("<key>features</key><integer>0</integer>"));
        assert!(body.contains("<key>model</key><string>RustPhoneControl1,1</string>"));
    }

    #[test]
    fn info_response_is_binary_plist_with_conservative_capabilities() {
        let bytes = build_info_response(&[]).expect("build /info response");
        assert!(bytes.starts_with(b"bplist00"));
        let value = plist::decode(&bytes).expect("decode response");
        let dict = value.as_dictionary().expect("response dictionary");
        assert!(matches!(dict.get("features"), Some(Value::Integer(_))));
        assert!(matches!(dict.get("statusFlags"), Some(Value::Integer(_))));
    }

    #[test]
    fn info_request_parses_binary_qualifier_array() {
        let mut request = Dictionary::new();
        request.insert(
            "qualifier".into(),
            Value::Array(vec![Value::String("deviceID".into()), Value::String("features".into())]),
        );
        let bytes = plist::encode_binary(&Value::Dictionary(request)).expect("encode request");
        assert!(build_info_response(&bytes).is_ok());
    }

    #[test]
    fn info_request_rejects_invalid_qualifier() {
        let mut request = Dictionary::new();
        request.insert("qualifier".into(), Value::String("deviceID".into()));
        let bytes = plist::encode_binary(&Value::Dictionary(request)).expect("encode request");
        assert!(build_info_response(&bytes).is_err());
    }
}
