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


/// A NAL unit found in an Annex-B byte stream. The slice excludes its start code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NalUnit<'a> {
    pub bytes: &'a [u8],
    pub start_offset: usize,
    pub start_code_len: usize,
}

/// Find the next Annex-B start code (three or four bytes).
fn find_start_code(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut index = from;
    while index + 3 <= data.len() {
        if data[index..].starts_with(&[0, 0, 1]) {
            return Some((index, 3));
        }
        if index + 4 <= data.len() && data[index..].starts_with(&[0, 0, 0, 1]) {
            return Some((index, 4));
        }
        index += 1;
    }
    None
}

/// Split an Annex-B stream into NAL units without copying the payload.
pub fn split_annex_b(data: &[u8]) -> Vec<NalUnit<'_>> {
    let mut units = Vec::new();
    let Some((mut start, mut code_len)) = find_start_code(data, 0) else {
        return units;
    };

    loop {
        let payload_start = start + code_len;
        let next = find_start_code(data, payload_start);
        let payload_end = next.map_or(data.len(), |(offset, _)| offset);

        if payload_start < payload_end {
            units.push(NalUnit {
                bytes: &data[payload_start..payload_end],
                start_offset: start,
                start_code_len: code_len,
            });
        }

        match next {
            Some((next_start, next_code_len)) => {
                start = next_start;
                code_len = next_code_len;
            }
            None => break,
        }
    }

    units
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalUnitKind {
    H264Slice,
    H264Idr,
    H264Sps,
    H264Pps,
    H264Aud,
    HevcSlice,
    HevcIdr,
    HevcVps,
    HevcSps,
    HevcPps,
    HevcAud,
    Other,
    Invalid,
}

/// Classify a NAL unit after the codec has been negotiated or identified.
pub fn classify_nal(codec: VideoCodec, nal: &[u8]) -> NalUnitKind {
    if nal.is_empty() {
        return NalUnitKind::Invalid;
    }

    match codec {
        VideoCodec::H264 => match nal[0] & 0x1f {
            1..=4 => NalUnitKind::H264Slice,
            5 => NalUnitKind::H264Idr,
            7 => NalUnitKind::H264Sps,
            8 => NalUnitKind::H264Pps,
            9 => NalUnitKind::H264Aud,
            _ => NalUnitKind::Other,
        },
        VideoCodec::Hevc => {
            if nal.len() < 2 || nal[1] & 0x07 == 0 {
                return NalUnitKind::Invalid;
            }
            match (nal[0] >> 1) & 0x3f {
                0..=31 => {
                    if matches!((nal[0] >> 1) & 0x3f, 19 | 20) {
                        NalUnitKind::HevcIdr
                    } else {
                        NalUnitKind::HevcSlice
                    }
                }
                32 => NalUnitKind::HevcVps,
                33 => NalUnitKind::HevcSps,
                34 => NalUnitKind::HevcPps,
                35 => NalUnitKind::HevcAud,
                _ => NalUnitKind::Other,
            }
        }
        VideoCodec::Unknown => NalUnitKind::Invalid,
    }
}

/// Collect codec parameter sets from one Annex-B configuration buffer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CodecParameterSets {
    pub vps: Option<Vec<u8>>,
    pub sps: Option<Vec<u8>>,
    pub pps: Option<Vec<u8>>,
}

impl CodecParameterSets {
    pub fn update_from_annex_b(&mut self, codec: VideoCodec, data: &[u8]) -> usize {
        let mut updated = 0;
        for unit in split_annex_b(data) {
            let slot = match classify_nal(codec, unit.bytes) {
                NalUnitKind::H264Sps | NalUnitKind::HevcSps => &mut self.sps,
                NalUnitKind::H264Pps | NalUnitKind::HevcPps => &mut self.pps,
                NalUnitKind::HevcVps => &mut self.vps,
                _ => continue,
            };
            *slot = Some(unit.bytes.to_vec());
            updated += 1;
        }
        updated
    }

    pub fn is_ready(&self, codec: VideoCodec) -> bool {
        self.sps.is_some()
            && self.pps.is_some()
            && (codec != VideoCodec::Hevc || self.vps.is_some())
    }
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

    #[test]
    fn splits_annex_b_with_three_and_four_byte_start_codes() {
        let data = [0, 0, 0, 1, 0x67, 0x11, 0, 0, 1, 0x68, 0x22];
        let units = split_annex_b(&data);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].bytes, &[0x67, 0x11]);
        assert_eq!(units[0].start_code_len, 4);
        assert_eq!(units[1].bytes, &[0x68, 0x22]);
        assert_eq!(units[1].start_code_len, 3);
    }

    #[test]
    fn ignores_data_without_annex_b_start_code() {
        assert!(split_annex_b(&[0x67, 0x11, 0x68]).is_empty());
    }

    #[test]
    fn classifies_h264_parameter_sets_and_idr() {
        assert_eq!(classify_nal(VideoCodec::H264, &[0x67]), NalUnitKind::H264Sps);
        assert_eq!(classify_nal(VideoCodec::H264, &[0x68]), NalUnitKind::H264Pps);
        assert_eq!(classify_nal(VideoCodec::H264, &[0x65]), NalUnitKind::H264Idr);
    }

    #[test]
    fn collects_h264_parameter_sets() {
        let data = [
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e,
            0, 0, 1, 0x68, 0xce, 0x06,
        ];
        let mut sets = CodecParameterSets::default();
        assert_eq!(sets.update_from_annex_b(VideoCodec::H264, &data), 2);
        assert!(sets.is_ready(VideoCodec::H264));
    }

    #[test]
    fn hevc_requires_vps_sps_and_pps() {
        let data = [
            0, 0, 1, 0x40, 0x01, 0xaa,
            0, 0, 1, 0x42, 0x01, 0xbb,
            0, 0, 1, 0x44, 0x01, 0xcc,
        ];
        let mut sets = CodecParameterSets::default();
        assert_eq!(sets.update_from_annex_b(VideoCodec::Hevc, &data), 3);
        assert!(sets.is_ready(VideoCodec::Hevc));
    }

}
