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
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut request = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];

    tracing::info!("AirPlay RTSP handler started; waiting for request headers");

    loop {
        let count = match stream.read(&mut chunk) {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(
                    error_kind = ?error.kind(),
                    error = %error,
                    received_bytes = request.len(),
                    "AirPlay RTSP request read failed"
                );
                return Err(error);
            }
        };

        if count == 0 {
            tracing::warn!(
                received_bytes = request.len(),
                "AirPlay client closed connection before completing request headers"
            );
            return Ok(());
        }

        request.extend_from_slice(&chunk[..count]);
        tracing::debug!(
            chunk_bytes = count,
            total_bytes = request.len(),
            "AirPlay RTSP request data received"
        );

        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }

        if request.len() > MAX_HEADER_BYTES {
            tracing::warn!(
                received_bytes = request.len(),
                "AirPlay RTSP request headers exceeded size limit"
            );
            return write_response(
                &mut stream,
                "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                431,
            );
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

    tracing::info!(
        method,
        path,
        protocol,
        cseq,
        request_bytes = request.len(),
        "AirPlay RTSP request parsed"
    );

    match (method, path, protocol) {
        ("OPTIONS", _, "RTSP/1.0") => {
            let response = format!(
                "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: RustPhoneControl/0.1\r\nPublic: OPTIONS\r\nContent-Length: 0\r\n\r\n"
            );
            write_response(&mut stream, &response, 200)
        }
        ("GET", "/server-info", "HTTP/1.1") | ("GET", "/server-info", "RTSP/1.0") => {
            let body = server_info_plist();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            write_response(&mut stream, &response, 200)
        }
        _ => {
            tracing::warn!(
                method,
                path,
                protocol,
                "AirPlay control method is not implemented; returning 501"
            );
            let response = format!(
                "{protocol} 501 Not Implemented\r\nCSeq: {cseq}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            write_response(&mut stream, &response, 501)
        }
    }
}

fn write_response(
    stream: &mut TcpStream,
    response: &str,
    status: u16,
) -> std::io::Result<()> {
    match stream.write_all(response.as_bytes()) {
        Ok(()) => {
            tracing::info!(
                status,
                response_bytes = response.len(),
                "AirPlay RTSP response sent"
            );
            if let Err(error) = stream.flush() {
                tracing::error!(
                    error_kind = ?error.kind(),
                    error = %error,
                    "AirPlay RTSP response flush failed"
                );
                return Err(error);
            }
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                status,
                error_kind = ?error.kind(),
                error = %error,
                response_bytes = response.len(),
                "AirPlay RTSP response write failed"
            );
            Err(error)
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
