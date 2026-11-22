//! Small, bounded RTSP/HTTP control parser.
//!
//! This module only implements capability discovery and /server-info. Secure
//! pairing and media methods deliberately return 501 until their protocol
//! implementations are present.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::config;

const MAX_HEADER_BYTES: usize = 16 * 1024;

pub fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut request = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > MAX_HEADER_BYTES {
            write_http_error(&mut stream, 431, "Request Header Fields Too Large")?;
            return Ok(());
        }
    }

    let text = String::from_utf8_lossy(&request);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let protocol = parts.next().unwrap_or_default();
    let cseq = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("CSeq"))
        .map(|(_, value)| value.trim())
        .unwrap_or("0");

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
        }
    }
}

fn server_info_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>deviceid</key><string>{}</string><key>features</key><integer>0</integer><key>model</key><string>{}</string><key>protovers</key><string>1.0</string><key>srcvers</key><string>{}</string></dict></plist>",
        config::device_id(),
        config::MODEL,
        config::SOURCE_VERSION
    )
}

fn write_http_error(stream: &mut TcpStream, status: u16, reason: &str) -> std::io::Result<()> {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::server_info_plist;

    #[test]
    fn server_info_contains_declared_model_and_zero_features() {
        let plist = server_info_plist();
        assert!(plist.contains("<key>features</key><integer>0</integer>"));
        assert!(plist.contains("<key>model</key><string>RustPhoneControl1,1</string>"));
    }
}
