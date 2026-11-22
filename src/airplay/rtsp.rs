//! Bounded RTSP/HTTP control parser for the AirPlay endpoint.
//!
//! The handler supports persistent RTSP connections, request bodies, OPTIONS,
//! GET /server-info, and a conservative XML-plist GET /info response.
//! Pairing and media transport are intentionally not advertised or implemented.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::config;

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

        match (request.method.as_str(), request.path.as_str(), request.protocol.as_str()) {
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
            ("GET", "/info", "RTSP/1.0") => {
                // This is a deliberately minimal discovery response. AirPlay
                // senders commonly expect a binary plist and richer capability
                // data here; no unsupported video/pairing features are claimed.
                let body = info_plist();
                let response = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: {}\r\n\r\n{}",
                    request.cseq,
                    body.len(),
                    body
                );
                write_response(&mut stream, &response, 200)?;
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

/// Reads one complete request while retaining any bytes belonging to the next
/// request. Both headers and bodies are bounded to avoid unbounded allocation.
fn read_request(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
) -> std::io::Result<Option<Request>> {
    let mut chunk = [0u8; READ_CHUNK_BYTES];

    let header_end = loop {
        if let Some(index) = find_header_end(pending) {
            break index + 4;
        }
        if pending.len() > MAX_HEADER_BYTES {
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

<<<<<<< HEAD
    match (method, path, protocol) {
        ("OPTIONS", _, "RTSP/1.0") => {
            let response = format!(
                "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: RustPhoneControl/0.1\r\nPublic: OPTIONS\r\nContent-Length: 0\r\n\r\n"
            );
            stream.write_all(response.as_bytes())
        }
        ("GET", "/server-info", "HTTP/1.1") | ("GET", "/server-info", "RTSP/1.0") => {
            let body = server_info_plist();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes())
        }
        _ => {
            tracing::debug!(
                method,
                path,
                protocol,
                "AirPlay control method is not implemented"
            );
            let response = format!(
                "{protocol} 501 Not Implemented\r\nCSeq: {cseq}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes())
=======
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
>>>>>>> f6d0ee1911c8cc6b6e8b5f22739e4e5ac144ccdb
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

<<<<<<< HEAD
fn write_http_error(stream: &mut TcpStream, status: u16, reason: &str) -> std::io::Result<()> {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes())
=======
fn info_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>deviceID</key><string>{}</string><key>features</key><integer>0</integer><key>model</key><string>{}</string><key>protocolVersion</key><string>1.0</string><key>sourceVersion</key><string>{}</string><key>statusFlags</key><integer>0</integer></dict></plist>",
        config::device_id(),
        config::MODEL,
        config::SOURCE_VERSION
    )
>>>>>>> f6d0ee1911c8cc6b6e8b5f22739e4e5ac144ccdb
}

#[cfg(test)]
mod tests {
    use super::{find_header_end, info_plist, server_info_plist};

    #[test]
    fn finds_header_terminator() {
        assert_eq!(find_header_end(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"), Some(27));
        assert_eq!(find_header_end(b"OPTIONS * RTSP/1.0\r\n"), None);
    }

    #[test]
    fn server_info_contains_declared_model_and_zero_features() {
        let plist = server_info_plist();
        assert!(plist.contains("<key>features</key><integer>0</integer>"));
        assert!(plist.contains("<key>model</key><string>RustPhoneControl1,1</string>"));
    }

    #[test]
    fn info_contains_conservative_capabilities() {
        let plist = info_plist();
        assert!(plist.contains("<key>features</key><integer>0</integer>"));
        assert!(plist.contains("<key>statusFlags</key><integer>0</integer>"));
    }
}
