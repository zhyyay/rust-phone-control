//! Codec payload assembly for AirPlay screen mirroring.
//!
//! This module deliberately stays codec-agnostic at the transport boundary:
//! decrypted payload fragments are accumulated into access units, while H.264
//! and HEVC Annex-B NAL units are recognized without decoding them. The actual
//! video decoder is a later platform layer.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    pub timestamp: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoAssemblyError {
    EmptyPayload,
    InvalidFragment,
}

impl fmt::Display for VideoAssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => f.write_str("video fragment is empty"),
            Self::InvalidFragment => f.write_str("video fragment is invalid"),
        }
    }
}

impl std::error::Error for VideoAssemblyError {}

pub fn detect_annex_b_codec(data: &[u8]) -> VideoCodec {
    let Some(offset) = start_code_offset(data) else {
        return VideoCodec::Unknown;
    };
    if offset >= data.len() {
        return VideoCodec::Unknown;
    }

    let header = data[offset];
    let h264_type = header & 0x1f;
    if h264_type != 0 && (header & 0x80) == 0 {
        return VideoCodec::H264;
    }

    if offset + 1 < data.len() {
        let hevc_type = (data[offset] >> 1) & 0x3f;
        let temporal_id_plus1 = data[offset + 1] & 0x07;
        if temporal_id_plus1 != 0 && hevc_type <= 63 {
            return VideoCodec::Hevc;
        }
    }

    VideoCodec::Unknown
}

fn start_code_offset(data: &[u8]) -> Option<usize> {
    if data.len() >= 4 && data[..4] == [0, 0, 0, 1] {
        return Some(4);
    }
    if data.len() >= 3 && data[..3] == [0, 0, 1] {
        return Some(3);
    }
    None
}

pub struct AccessUnitAssembler {
    max_bytes: usize,
    timestamp: Option<u64>,
    data: Vec<u8>,
}

impl AccessUnitAssembler {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes: max_bytes.max(1),
            timestamp: None,
            data: Vec::new(),
        }
    }

    pub fn push_fragment(
        &mut self,
        timestamp: u64,
        fragment: &[u8],
    ) -> Result<(), VideoAssemblyError> {
        if fragment.is_empty() {
            return Err(VideoAssemblyError::EmptyPayload);
        }

        if let Some(existing) = self.timestamp {
            if existing != timestamp {
                return Err(VideoAssemblyError::InvalidFragment);
            }
        } else {
            self.timestamp = Some(timestamp);
        }

        let new_len = self
            .data
            .len()
            .checked_add(fragment.len())
            .ok_or(VideoAssemblyError::InvalidFragment)?;
        if new_len > self.max_bytes {
            return Err(VideoAssemblyError::InvalidFragment);
        }

        self.data.extend_from_slice(fragment);
        Ok(())
    }

    pub fn finish(&mut self) -> Option<AccessUnit> {
        let timestamp = self.timestamp.take()?;
        if self.data.is_empty() {
            return None;
        }

        let data = std::mem::take(&mut self.data);
        Some(AccessUnit { timestamp, data })
    }

    pub fn clear(&mut self) {
        self.timestamp = None;
        self.data.clear();
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Default for AccessUnitAssembler {
    fn default() -> Self {
        Self::new(16 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_h264_annex_b() {
        assert_eq!(
            detect_annex_b_codec(&[0, 0, 0, 1, 0x67, 0x64, 0, 0]),
            VideoCodec::H264
        );
        assert_eq!(
            detect_annex_b_codec(&[0, 0, 1, 0x65, 0x88]),
            VideoCodec::H264
        );
    }

    #[test]
    fn detects_hevc_annex_b() {
        assert_eq!(
            detect_annex_b_codec(&[0, 0, 0, 1, 0x40, 0x01, 0x0c]),
            VideoCodec::Hevc
        );
    }

    #[test]
    fn rejects_unknown_payload() {
        assert_eq!(detect_annex_b_codec(b"encrypted"), VideoCodec::Unknown);
        assert_eq!(detect_annex_b_codec(&[]), VideoCodec::Unknown);
    }

    #[test]
    fn assembles_fragments_with_one_timestamp() {
        let mut assembler = AccessUnitAssembler::new(32);
        assembler.push_fragment(7, &[1, 2]).expect("first fragment");
        assembler.push_fragment(7, &[3, 4]).expect("second fragment");

        let unit = assembler.finish().expect("completed access unit");
        assert_eq!(unit.timestamp, 7);
        assert_eq!(unit.data, vec![1, 2, 3, 4]);
        assert_eq!(assembler.len(), 0);
    }

    #[test]
    fn rejects_timestamp_switch_and_size_overflow() {
        let mut assembler = AccessUnitAssembler::new(3);
        assembler.push_fragment(1, &[1, 2]).expect("first fragment");
        assert_eq!(
            assembler.push_fragment(2, &[3]),
            Err(VideoAssemblyError::InvalidFragment)
        );
        assert_eq!(
            assembler.push_fragment(1, &[3, 4]),
            Err(VideoAssemblyError::InvalidFragment)
        );
    }

    #[test]
    fn empty_fragment_does_not_change_state() {
        let mut assembler = AccessUnitAssembler::default();
        assert_eq!(
            assembler.push_fragment(1, &[]),
            Err(VideoAssemblyError::EmptyPayload)
        );
        assert_eq!(assembler.len(), 0);
        assert!(assembler.finish().is_none());
    }
}
