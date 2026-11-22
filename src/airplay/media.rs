//! Bounded RTP v2 packet parsing for the AirPlay media pipeline.
//!
//! This module only parses the standard RTP envelope. It does not decrypt,
//! authenticate, reassemble, or decode AirPlay media payloads.

use std::fmt;

/// A parsed RTP version 2 packet. All byte slices borrow from the input packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extension: Option<RtpExtension<'a>>,
    pub payload: &'a [u8],
    pub padding_len: usize,
}

/// The optional RTP header extension, excluding its four-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpExtension<'a> {
    pub profile: u16,
    pub data: &'a [u8],
}

/// Why an RTP packet could not be parsed safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpParseError {
    TruncatedHeader,
    UnsupportedVersion(u8),
    TruncatedCsrcList,
    TruncatedExtensionHeader,
    TruncatedExtensionData,
    InvalidPadding,
}

impl fmt::Display for RtpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("RTP fixed header is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported RTP version {version}")
            }
            Self::TruncatedCsrcList => f.write_str("RTP CSRC list is truncated"),
            Self::TruncatedExtensionHeader => {
                f.write_str("RTP extension header is truncated")
            }
            Self::TruncatedExtensionData => {
                f.write_str("RTP extension data is truncated")
            }
            Self::InvalidPadding => f.write_str("RTP padding length is invalid"),
        }
    }
}

impl std::error::Error for RtpParseError {}

/// Parse one complete RTP v2 packet without reading beyond the supplied slice.
///
/// The parser validates the fixed header, CSRC list, optional extension and
/// padding. Payload interpretation and AirPlay-specific decryption happen in
/// later pipeline stages.
pub fn parse_rtp_packet(packet: &[u8]) -> Result<RtpPacket<'_>, RtpParseError> {
    if packet.len() < 12 {
        return Err(RtpParseError::TruncatedHeader);
    }

    let version = packet[0] >> 6;
    if version != 2 {
        return Err(RtpParseError::UnsupportedVersion(version));
    }

    let has_padding = packet[0] & 0x20 != 0;
    let has_extension = packet[0] & 0x10 != 0;
    let csrc_count = usize::from(packet[0] & 0x0f);
    let payload_type = packet[1] & 0x7f;
    let marker = packet[1] & 0x80 != 0;

    let csrc_bytes = csrc_count * 4;
    let mut offset = 12usize;
    let csrc_end = offset + csrc_bytes;
    if csrc_end > packet.len() {
        return Err(RtpParseError::TruncatedCsrcList);
    }

    let mut csrcs = Vec::with_capacity(csrc_count);
    for chunk in packet[offset..csrc_end].chunks_exact(4) {
        csrcs.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    offset = csrc_end;

    let extension = if has_extension {
        if packet.len().saturating_sub(offset) < 4 {
            return Err(RtpParseError::TruncatedExtensionHeader);
        }
        let profile = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let words = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        let extension_bytes = words * 4;
        let data_start = offset + 4;
        let data_end = data_start
            .checked_add(extension_bytes)
            .ok_or(RtpParseError::TruncatedExtensionData)?;
        if data_end > packet.len() {
            return Err(RtpParseError::TruncatedExtensionData);
        }
        offset = data_end;
        Some(RtpExtension {
            profile,
            data: &packet[data_start..data_end],
        })
    } else {
        None
    };

    let padding_len = if has_padding {
        let padding = usize::from(*packet.last().ok_or(RtpParseError::InvalidPadding)?);
        if padding == 0 || padding > packet.len().saturating_sub(offset) {
            return Err(RtpParseError::InvalidPadding);
        }
        padding
    } else {
        0
    };

    let payload_end = packet.len() - padding_len;
    if payload_end < offset {
        return Err(RtpParseError::InvalidPadding);
    }

    Ok(RtpPacket {
        marker,
        payload_type,
        sequence_number: u16::from_be_bytes([packet[2], packet[3]]),
        timestamp: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        ssrc: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        csrcs,
        extension,
        payload: &packet[offset..payload_end],
        padding_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_rtp_packet() {
        let bytes = [
            0x80, 0xE0, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0xA0, 0xB0, 0xC0, 0xD0,
            0xDE, 0xAD,
        ];
        let parsed = parse_rtp_packet(&bytes).expect("valid RTP packet");
        assert!(parsed.marker);
        assert_eq!(parsed.payload_type, 96);
        assert_eq!(parsed.sequence_number, 0x1234);
        assert_eq!(parsed.timestamp, 0x0102_0304);
        assert_eq!(parsed.ssrc, 0xA0B0_C0D0);
        assert_eq!(parsed.payload, &[0xDE, 0xAD]);
        assert!(parsed.csrcs.is_empty());
        assert!(parsed.extension.is_none());
    }

    #[test]
    fn parses_csrc_and_header_extension() {
        let bytes = [
            0x91, 0x60, 0, 7, 0, 0, 0, 9, 0, 0, 0, 11,
            0x11, 0x11, 0x22, 0x22,
            0xBE, 0xDE, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD,
            0xFE,
        ];
        let parsed = parse_rtp_packet(&bytes).expect("valid extended RTP packet");
        assert_eq!(parsed.csrcs, vec![0x1111_2222]);
        let extension = parsed.extension.expect("extension present");
        assert_eq!(extension.profile, 0xBEDE);
        assert_eq!(extension.data, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(parsed.payload, &[0xFE]);
    }

    #[test]
    fn excludes_valid_padding_from_payload() {
        let bytes = [
            0xA0, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0x10, 0x20, 0, 2,
        ];
        let parsed = parse_rtp_packet(&bytes).expect("valid padded RTP packet");
        assert_eq!(parsed.payload, &[0x10, 0x20]);
        assert_eq!(parsed.padding_len, 2);
    }

    #[test]
    fn rejects_truncated_and_invalid_packets() {
        assert_eq!(parse_rtp_packet(&[0; 11]), Err(RtpParseError::TruncatedHeader));

        let mut wrong_version = [0u8; 12];
        wrong_version[0] = 0x40;
        assert_eq!(
            parse_rtp_packet(&wrong_version),
            Err(RtpParseError::UnsupportedVersion(1))
        );

        let mut truncated_csrc = [0u8; 12];
        truncated_csrc[0] = 0x81;
        assert_eq!(
            parse_rtp_packet(&truncated_csrc),
            Err(RtpParseError::TruncatedCsrcList)
        );

        let mut zero_padding = [0u8; 13];
        zero_padding[0] = 0xA0;
        assert_eq!(
            parse_rtp_packet(&zero_padding),
            Err(RtpParseError::InvalidPadding)
        );
    }
}
