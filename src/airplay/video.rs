//! AirPlay screen-mirroring video transport helpers.
//!
//! This module only handles codec detection and bounded access-unit assembly.
//! It intentionally does not implement FairPlay decryption or video decoding.

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct AccessUnitAssembler {
    queue: VecDeque<AccessUnit>,
    max_bytes: usize,
    buffered_bytes: usize,
}

impl AccessUnitAssembler {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_bytes: max_bytes.max(1),
            buffered_bytes: 0,
        }
    }

    pub fn push(&mut self, unit: AccessUnit) -> bool {
        if unit.payload.len() > self.max_bytes {
            return false;
        }

        while self.buffered_bytes + unit.payload.len() > self.max_bytes {
            let Some(old) = self.queue.pop_front() else {
                break;
            };
            self.buffered_bytes = self.buffered_bytes.saturating_sub(old.payload.len());
        }

        self.buffered_bytes += unit.payload.len();
        self.queue.push_back(unit);
        true
    }

    pub fn pop(&mut self) -> Option<AccessUnit> {
        let unit = self.queue.pop_front()?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(unit.payload.len());
        Some(unit)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }
}

pub fn detect_annex_b_codec(data: &[u8]) -> VideoCodec {
    let mut i = 0;
    while i + 4 <= data.len() {
        let start_len = if data[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if i + 3 <= data.len() && data[i..].starts_with(&[0, 0, 1]) {
            3
        } else {
            i += 1;
            continue;
        };

        let nal = i + start_len;
        if nal >= data.len() {
            break;
        }

        let h264_type = data[nal] & 0x1f;
        let hevc_type = (data[nal] >> 1) & 0x3f;

        if matches!(h264_type, 5 | 7 | 8 | 9 | 1) {
            return VideoCodec::H264;
        }

        if matches!(hevc_type, 19 | 20 | 21 | 32 | 33 | 34) {
            return VideoCodec::Hevc;
        }

        i = nal + 1;
    }

    VideoCodec::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_h264_annex_b() {
        assert_eq!(
            detect_annex_b_codec(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e]),
            VideoCodec::H264
        );
    }

    #[test]
    fn detects_hevc_annex_b() {
        assert_eq!(
            detect_annex_b_codec(&[0, 0, 0, 1, 0x42, 0x01, 0x01]),
            VideoCodec::Hevc
        );
    }

    #[test]
    fn rejects_unknown_payload() {
        assert_eq!(detect_annex_b_codec(&[1, 2, 3, 4]), VideoCodec::Unknown);
    }

    #[test]
    fn assembler_is_bounded() {
        let mut assembler = AccessUnitAssembler::new(5);
        assert!(assembler.push(AccessUnit {
            timestamp: 1,
            payload: vec![1, 2, 3],
        }));
        assert!(assembler.push(AccessUnit {
            timestamp: 2,
            payload: vec![4, 5, 6],
        }));

        assert_eq!(assembler.len(), 1);
        assert_eq!(assembler.buffered_bytes(), 3);
        assert_eq!(assembler.pop().unwrap().timestamp, 2);
        assert!(assembler.is_empty());
    }

    #[test]
    fn oversized_unit_is_rejected() {
        let mut assembler = AccessUnitAssembler::new(4);
        assert!(!assembler.push(AccessUnit {
            timestamp: 1,
            payload: vec![1, 2, 3, 4, 5],
        }));
        assert!(assembler.is_empty());
    }
}
