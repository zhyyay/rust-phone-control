//! AirPlay screen-mirroring video transport helpers.
//!
//! This module only handles codec detection and bounded access-unit assembly.
//! It intentionally does not implement FairPlay decryption or video decoding.

use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Unknown,
}

/// Parsed H.264 AVCDecoderConfigurationRecord (avcC) from AirPlay codec packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvcConfiguration {
    pub profile: u8,
    pub compatibility: u8,
    pub level: u8,
    /// Number of bytes used for each NAL length in AVCC samples (1, 2, or 4).
    pub nal_length_size: usize,
    pub sequence_parameter_sets: Vec<Vec<u8>>,
    pub picture_parameter_sets: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvcConfigError {
    TooShort,
    UnsupportedVersion(u8),
    InvalidReservedBits,
    UnsupportedNalLengthSize,
    TruncatedSpsCount,
    TruncatedSpsLength,
    EmptySps,
    TruncatedSps,
    TruncatedPpsCount,
    TruncatedPpsLength,
    EmptyPps,
    TruncatedPps,
    TooManyParameterSets,
    TrailingData,
    InvalidNalLength,
    TruncatedNal,
    SizeOverflow,
}

impl std::fmt::Display for AvcConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid AVC configuration: {self:?}")
    }
}

impl std::error::Error for AvcConfigError {}

impl AvcConfiguration {
    /// Parse an ISO/IEC 14496-15 AVCDecoderConfigurationRecord.
    /// Parsing is bounded by the supplied slice and rejects malformed lengths.
    pub fn parse(data: &[u8]) -> Result<Self, AvcConfigError> {
        if data.len() < 7 {
            return Err(AvcConfigError::TooShort);
        }
        if data[0] != 1 {
            return Err(AvcConfigError::UnsupportedVersion(data[0]));
        }
        if data[4] & 0xfc != 0xfc || data[5] & 0xe0 != 0xe0 {
            return Err(AvcConfigError::InvalidReservedBits);
        }
        let nal_length_size = usize::from((data[4] & 0x03) + 1);
        if nal_length_size == 3 {
            return Err(AvcConfigError::UnsupportedNalLengthSize);
        }

        let mut offset = 6usize;
        let sps_count = usize::from(data[5] & 0x1f);
        if sps_count > 31 {
            return Err(AvcConfigError::TooManyParameterSets);
        }
        let mut sequence_parameter_sets = Vec::with_capacity(sps_count);
        for _ in 0..sps_count {
            if data.len().saturating_sub(offset) < 2 {
                return Err(AvcConfigError::TruncatedSpsLength);
            }
            let length = usize::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
            offset += 2;
            if length == 0 {
                return Err(AvcConfigError::EmptySps);
            }
            let end = offset.checked_add(length).ok_or(AvcConfigError::SizeOverflow)?;
            if end > data.len() {
                return Err(AvcConfigError::TruncatedSps);
            }
            sequence_parameter_sets.push(data[offset..end].to_vec());
            offset = end;
        }

        if offset >= data.len() {
            return Err(AvcConfigError::TruncatedPpsCount);
        }
        let pps_count = usize::from(data[offset]);
        offset += 1;
        if pps_count > 255 {
            return Err(AvcConfigError::TooManyParameterSets);
        }
        let mut picture_parameter_sets = Vec::with_capacity(pps_count);
        for _ in 0..pps_count {
            if data.len().saturating_sub(offset) < 2 {
                return Err(AvcConfigError::TruncatedPpsLength);
            }
            let length = usize::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
            offset += 2;
            if length == 0 {
                return Err(AvcConfigError::EmptyPps);
            }
            let end = offset.checked_add(length).ok_or(AvcConfigError::SizeOverflow)?;
            if end > data.len() {
                return Err(AvcConfigError::TruncatedPps);
            }
            picture_parameter_sets.push(data[offset..end].to_vec());
            offset = end;
        }

        // High-profile avcC records may append chroma/bit-depth and SPS-extension
        // fields. They are not needed for the H.264 decoder input path; retain
        // strict framing by accepting only the standard optional extension shape.
        if offset < data.len() {
            let profile_has_extension = matches!(
                data[1],
                100 | 110 | 122 | 144 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
            );
            if !profile_has_extension || data.len() - offset < 4 {
                return Err(AvcConfigError::TrailingData);
            }
            if data[offset] & 0xfc != 0xfc
                || data[offset + 1] & 0xf8 != 0xf8
                || data[offset + 2] & 0xf8 != 0xf8
            {
                return Err(AvcConfigError::InvalidReservedBits);
            }
            offset += 3;
            let extension_count = usize::from(data[offset]);
            offset += 1;
            for _ in 0..extension_count {
                if data.len().saturating_sub(offset) < 2 {
                    return Err(AvcConfigError::TruncatedSpsLength);
                }
                let length = usize::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
                offset += 2;
                if length == 0 {
                    return Err(AvcConfigError::EmptySps);
                }
                let end = offset.checked_add(length).ok_or(AvcConfigError::SizeOverflow)?;
                if end > data.len() {
                    return Err(AvcConfigError::TruncatedSps);
                }
                offset = end;
            }
        }
        if offset != data.len() {
            return Err(AvcConfigError::TrailingData);
        }

        Ok(Self {
            profile: data[1],
            compatibility: data[2],
            level: data[3],
            nal_length_size,
            sequence_parameter_sets,
            picture_parameter_sets,
        })
    }

    /// Return SPS/PPS with Annex-B start codes for decoder initialization.
    pub fn parameter_sets_annex_b(&self) -> Vec<u8> {
        let mut output = Vec::new();
        for nal in self
            .sequence_parameter_sets
            .iter()
            .chain(self.picture_parameter_sets.iter())
        {
            output.extend_from_slice(&[0, 0, 0, 1]);
            output.extend_from_slice(nal);
        }
        output
    }

    /// Convert one AVCC length-prefixed access unit to Annex-B.
    pub fn access_unit_to_annex_b(&self, data: &[u8]) -> Result<Vec<u8>, AvcConfigError> {
        let mut offset = 0usize;
        let mut output = Vec::with_capacity(data.len().saturating_add(16));
        while offset < data.len() {
            if data.len().saturating_sub(offset) < self.nal_length_size {
                return Err(AvcConfigError::InvalidNalLength);
            }
            let mut length = 0usize;
            for byte in &data[offset..offset + self.nal_length_size] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or(AvcConfigError::SizeOverflow)?;
            }
            offset += self.nal_length_size;
            if length == 0 {
                return Err(AvcConfigError::InvalidNalLength);
            }
            let end = offset.checked_add(length).ok_or(AvcConfigError::SizeOverflow)?;
            if end > data.len() {
                return Err(AvcConfigError::TruncatedNal);
            }
            output.extend_from_slice(&[0, 0, 0, 1]);
            output.extend_from_slice(&data[offset..end]);
            offset = end;
        }
        Ok(output)
    }
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

/// Maximum accepted decoded-frame dimension. Prevents hostile media metadata
/// from causing unbounded allocations in the presentation pipeline.
pub const MAX_FRAME_DIMENSION: u32 = 8192;

/// A decoded NV12 frame borrowed from a decoder output buffer.
#[derive(Debug, Clone, Copy)]
pub struct Nv12Frame<'a> {
    pub width: u32,
    pub height: u32,
    pub y_stride: usize,
    pub uv_stride: usize,
    pub data: &'a [u8],
}

/// Packed 32-bit BGRA frame suitable for upload to a desktop graphics surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgraFrame {
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub data: Vec<u8>,
}

/// A single-slot, latest-frame mailbox shared by the decoder worker and UI.
///
/// Publishing replaces any stale frame instead of building an unbounded
/// queue. The UI can therefore always consume the newest available image
/// without allowing rendering lag to grow over time.
#[derive(Debug, Default)]
pub struct LatestFrameMailbox {
    sequence: AtomicU64,
    frame: Mutex<Option<(u64, Arc<BgraFrame>)>>,
}

#[derive(Debug, Clone)]
pub struct FrameSnapshot {
    pub sequence: u64,
    pub frame: Arc<BgraFrame>,
}

impl LatestFrameMailbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a decoded frame, replacing the previous unconsumed frame.
    pub fn publish(&self, frame: BgraFrame) -> Result<u64, FrameMailboxError> {
        let mut slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        *slot = Some((sequence, Arc::new(frame)));
        Ok(sequence)
    }

    /// Take the newest frame. A frame is returned to at most one consumer.
    pub fn take_latest(&self) -> Result<Option<FrameSnapshot>, FrameMailboxError> {
        let mut slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        Ok(slot
            .take()
            .map(|(sequence, frame)| FrameSnapshot { sequence, frame }))
    }

    /// Discard any pending frame, for example when a mirror session stops.
    pub fn clear(&self) -> Result<(), FrameMailboxError> {
        let mut slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        *slot = None;
        Ok(())
    }

    pub fn has_pending_frame(&self) -> Result<bool, FrameMailboxError> {
        let slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        Ok(slot.is_some())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameMailboxError {
    Poisoned,
}

impl std::fmt::Display for FrameMailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => f.write_str("decoded-frame mailbox lock is poisoned"),
        }
    }
}

impl std::error::Error for FrameMailboxError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameConversionError {
    ZeroDimension,
    OddNv12Dimension,
    DimensionTooLarge,
    InvalidStride,
    BufferTooSmall,
    SizeOverflow,
}

impl std::fmt::Display for FrameConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroDimension => "frame dimensions must be non-zero",
            Self::OddNv12Dimension => "NV12 frame dimensions must be even",
            Self::DimensionTooLarge => "frame dimensions exceed the configured limit",
            Self::InvalidStride => "NV12 plane stride is smaller than its row width",
            Self::BufferTooSmall => "NV12 buffer does not contain all declared rows",
            Self::SizeOverflow => "frame allocation size overflowed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FrameConversionError {}

impl<'a> Nv12Frame<'a> {
    /// Convert limited-range BT.601 NV12 into an owned BGRA frame.
    ///
    /// The input layout is Y plane followed by interleaved UV plane. Strides
    /// may include row padding; the output is tightly packed BGRA.
    pub fn to_bgra(self) -> Result<BgraFrame, FrameConversionError> {
        let width = usize::try_from(self.width).map_err(|_| FrameConversionError::SizeOverflow)?;
        let height =
            usize::try_from(self.height).map_err(|_| FrameConversionError::SizeOverflow)?;

        if width == 0 || height == 0 {
            return Err(FrameConversionError::ZeroDimension);
        }
        if self.width > MAX_FRAME_DIMENSION || self.height > MAX_FRAME_DIMENSION {
            return Err(FrameConversionError::DimensionTooLarge);
        }
        if width % 2 != 0 || height % 2 != 0 {
            return Err(FrameConversionError::OddNv12Dimension);
        }
        if self.y_stride < width || self.uv_stride < width {
            return Err(FrameConversionError::InvalidStride);
        }

        let y_bytes = self
            .y_stride
            .checked_mul(height)
            .ok_or(FrameConversionError::SizeOverflow)?;
        let uv_bytes = self
            .uv_stride
            .checked_mul(height / 2)
            .ok_or(FrameConversionError::SizeOverflow)?;
        let required = y_bytes
            .checked_add(uv_bytes)
            .ok_or(FrameConversionError::SizeOverflow)?;
        if self.data.len() < required {
            return Err(FrameConversionError::BufferTooSmall);
        }

        let output_stride = width
            .checked_mul(4)
            .ok_or(FrameConversionError::SizeOverflow)?;
        let output_len = output_stride
            .checked_mul(height)
            .ok_or(FrameConversionError::SizeOverflow)?;
        let mut output = vec![0u8; output_len];
        let uv_base = y_bytes;

        for row in 0..height {
            let y_row = row * self.y_stride;
            let uv_row = uv_base + (row / 2) * self.uv_stride;
            for col in 0..width {
                let y = i32::from(self.data[y_row + col]);
                let uv_index = uv_row + (col / 2) * 2;
                let u = i32::from(self.data[uv_index]) - 128;
                let v = i32::from(self.data[uv_index + 1]) - 128;

                // Integer BT.601 limited-range conversion.
                let c = (y - 16).max(0);
                let r = ((298 * c + 409 * v + 128) >> 8).clamp(0, 255) as u8;
                let g = ((298 * c - 100 * u - 208 * v + 128) >> 8).clamp(0, 255) as u8;
                let b = ((298 * c + 516 * u + 128) >> 8).clamp(0, 255) as u8;

                let out = row * output_stride + col * 4;
                output[out] = b;
                output[out + 1] = g;
                output[out + 2] = r;
                output[out + 3] = 255;
            }
        }

        Ok(BgraFrame {
            width: self.width,
            height: self.height,
            stride: output_stride,
            data: output,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_airplay_avcc_configuration_and_converts_access_unit() {
        // Captured-format avcC example: one SPS and one PPS.
        let config = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01,
            0x00, 0x02, 0x68, 0xee,
        ];
        let parsed = AvcConfiguration::parse(&config).expect("valid avcC record");
        assert_eq!(parsed.profile, 0x64);
        assert_eq!(parsed.compatibility, 0xc0);
        assert_eq!(parsed.level, 0x28);
        assert_eq!(parsed.nal_length_size, 4);
        assert_eq!(parsed.sequence_parameter_sets, vec![vec![0x67, 0x64, 0xc0, 0x28]]);
        assert_eq!(parsed.picture_parameter_sets, vec![vec![0x68, 0xee]]);
        assert_eq!(
            parsed.parameter_sets_annex_b(),
            vec![0, 0, 0, 1, 0x67, 0x64, 0xc0, 0x28, 0, 0, 0, 1, 0x68, 0xee]
        );

        let avcc = [0x00, 0x00, 0x00, 0x02, 0x65, 0xaa, 0x00, 0x00, 0x00, 0x01, 0x41];
        assert_eq!(
            parsed.access_unit_to_annex_b(&avcc).expect("valid AVCC unit"),
            vec![0, 0, 0, 1, 0x65, 0xaa, 0, 0, 0, 1, 0x41]
        );
    }

    #[test]
    fn rejects_malformed_avcc_configuration_and_access_units() {
        assert_eq!(AvcConfiguration::parse(&[1, 2, 3]), Err(AvcConfigError::TooShort));
        assert_eq!(
            AvcConfiguration::parse(&[2, 0, 0, 0, 0xff, 0xe1, 0, 0]),
            Err(AvcConfigError::UnsupportedVersion(2))
        );

        let invalid_reserved = [1, 0x64, 0, 0x1f, 0, 0xe1, 0, 0];
        assert_eq!(
            AvcConfiguration::parse(&invalid_reserved),
            Err(AvcConfigError::InvalidReservedBits)
        );

        let config = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x01, 0x67, 0x01, 0x00, 0x01, 0x68,
        ];
        let parsed = AvcConfiguration::parse(&config).expect("valid compact avcC");
        assert_eq!(
            parsed.access_unit_to_annex_b(&[0, 0, 0, 3, 0x65]),
            Err(AvcConfigError::TruncatedNal)
        );
        assert_eq!(
            parsed.access_unit_to_annex_b(&[0, 0]),
            Err(AvcConfigError::InvalidNalLength)
        );
        assert_eq!(
            parsed.access_unit_to_annex_b(&[0, 0, 0, 0]),
            Err(AvcConfigError::InvalidNalLength)
        );
    }

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
        assert_eq!(
            classify_nal(VideoCodec::H264, &[0x67]),
            NalUnitKind::H264Sps
        );
        assert_eq!(
            classify_nal(VideoCodec::H264, &[0x68]),
            NalUnitKind::H264Pps
        );
        assert_eq!(
            classify_nal(VideoCodec::H264, &[0x65]),
            NalUnitKind::H264Idr
        );
    }

    #[test]
    fn collects_h264_parameter_sets() {
        let data = [
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1e, 0, 0, 1, 0x68, 0xce, 0x06,
        ];
        let mut sets = CodecParameterSets::default();
        assert_eq!(sets.update_from_annex_b(VideoCodec::H264, &data), 2);
        assert!(sets.is_ready(VideoCodec::H264));
    }

    #[test]
    fn hevc_requires_vps_sps_and_pps() {
        let data = [
            0, 0, 1, 0x40, 0x01, 0xaa, 0, 0, 1, 0x42, 0x01, 0xbb, 0, 0, 1, 0x44, 0x01, 0xcc,
        ];
        let mut sets = CodecParameterSets::default();
        assert_eq!(sets.update_from_annex_b(VideoCodec::Hevc, &data), 3);
        assert!(sets.is_ready(VideoCodec::Hevc));
    }

    #[test]
    fn latest_frame_mailbox_replaces_stale_frames() {
        let mailbox = LatestFrameMailbox::new();
        let first = BgraFrame {
            width: 1,
            height: 1,
            stride: 4,
            data: vec![1, 2, 3, 4],
        };
        let second = BgraFrame {
            width: 1,
            height: 1,
            stride: 4,
            data: vec![5, 6, 7, 8],
        };

        assert_eq!(mailbox.publish(first).unwrap(), 1);
        assert_eq!(mailbox.publish(second).unwrap(), 2);
        let snapshot = mailbox.take_latest().unwrap().unwrap();
        assert_eq!(snapshot.sequence, 2);
        assert_eq!(snapshot.frame.data, vec![5, 6, 7, 8]);
        assert!(!mailbox.has_pending_frame().unwrap());
        assert!(mailbox.take_latest().unwrap().is_none());
    }

    #[test]
    fn latest_frame_mailbox_clear_discards_pending_frame() {
        let mailbox = LatestFrameMailbox::new();
        mailbox
            .publish(BgraFrame {
                width: 1,
                height: 1,
                stride: 4,
                data: vec![0; 4],
            })
            .unwrap();
        assert!(mailbox.has_pending_frame().unwrap());
        mailbox.clear().unwrap();
        assert!(!mailbox.has_pending_frame().unwrap());
    }

    #[test]
    fn converts_neutral_nv12_black_and_white_to_bgra() {
        let data = [
            16, 16, 16, 16, // Y plane
            128, 128, // UV plane
        ];
        let frame = Nv12Frame {
            width: 2,
            height: 2,
            y_stride: 2,
            uv_stride: 2,
            data: &data,
        }
        .to_bgra()
        .unwrap();

        assert_eq!(frame.stride, 8);
        assert_eq!(frame.data.len(), 16);
        assert_eq!(&frame.data[0..4], &[0, 0, 0, 255]);
        assert_eq!(&frame.data[4..8], &[0, 0, 0, 255]);
    }

    #[test]
    fn handles_padded_nv12_strides() {
        let data = [16, 16, 99, 99, 16, 16, 99, 99, 128, 128, 99, 99];
        let frame = Nv12Frame {
            width: 2,
            height: 2,
            y_stride: 4,
            uv_stride: 4,
            data: &data,
        }
        .to_bgra()
        .unwrap();
        assert_eq!(frame.data.len(), 16);
        assert_eq!(&frame.data[0..4], &[0, 0, 0, 255]);
    }

    #[test]
    fn rejects_invalid_nv12_layouts() {
        let data = [0u8; 16];
        let odd = Nv12Frame {
            width: 3,
            height: 2,
            y_stride: 3,
            uv_stride: 4,
            data: &data,
        };
        assert_eq!(
            odd.to_bgra().unwrap_err(),
            FrameConversionError::OddNv12Dimension
        );

        let short = Nv12Frame {
            width: 2,
            height: 2,
            y_stride: 2,
            uv_stride: 2,
            data: &[0; 5],
        };
        assert_eq!(
            short.to_bgra().unwrap_err(),
            FrameConversionError::BufferTooSmall
        );
    }

    #[test]
    fn rejects_excessive_frame_dimensions() {
        let data = [0u8; 16];
        let frame = Nv12Frame {
            width: MAX_FRAME_DIMENSION + 2,
            height: 2,
            y_stride: (MAX_FRAME_DIMENSION + 2) as usize,
            uv_stride: (MAX_FRAME_DIMENSION + 2) as usize,
            data: &data,
        };
        assert_eq!(
            frame.to_bgra().unwrap_err(),
            FrameConversionError::DimensionTooLarge
        );
    }
}
