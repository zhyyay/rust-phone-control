//! AirPlay screen-mirroring video transport helpers.
//!
//! This module handles codec configuration, encrypted access-unit conversion,
//! bounded assembly, frame conversion, and the decoded-frame mailbox. FairPlay
//! key recovery is deliberately delegated to the authorized SAP provider boundary.

use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

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
    MissingSps,
    MissingPps,
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
    InvalidNalHeader,
    TruncatedNal,
    OutputTooLarge,
    InvalidSps,
    InvalidPps,
    InvalidSpsNalType(u8),
    InvalidPpsNalType(u8),
    ForbiddenSpsNalHeader,
    ForbiddenPpsNalHeader,
    InvalidSpsExtensionNalType(u8),
    SizeOverflow,
}

impl std::fmt::Display for AvcConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid AVC configuration: {self:?}")
    }
}

impl std::error::Error for AvcConfigError {}

const MAX_ANNEX_B_ACCESS_UNIT_BYTES: usize = 64 * 1024 * 1024;
const MAX_AVC_PARAMETER_SETS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedAccessUnitError {
    MissingConfiguration,
    Crypto(super::mirror_crypto::MirrorCryptoError),
    Avc(AvcConfigError),
}

impl std::fmt::Display for EncryptedAccessUnitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingConfiguration => {
                formatter.write_str("cannot decrypt video before receiving AVC configuration")
            }
            Self::Crypto(error) => write!(formatter, "mirror payload decryption failed: {error}"),
            Self::Avc(error) => write!(formatter, "decrypted AVCC access unit is invalid: {error}"),
        }
    }
}

impl std::error::Error for EncryptedAccessUnitError {}

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
        if sps_count == 0 {
            return Err(AvcConfigError::MissingSps);
        }
        if sps_count > MAX_AVC_PARAMETER_SETS {
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
            let end = offset
                .checked_add(length)
                .ok_or(AvcConfigError::SizeOverflow)?;
            if end > data.len() {
                return Err(AvcConfigError::TruncatedSps);
            }
            let nal = &data[offset..end];
            if nal[0] & 0x80 != 0 {
                return Err(AvcConfigError::ForbiddenSpsNalHeader);
            }
            let nal_type = nal[0] & 0x1f;
            if nal_type != 7 {
                return Err(AvcConfigError::InvalidSpsNalType(nal_type));
            }
            sequence_parameter_sets.push(nal.to_vec());
            offset = end;
        }

        if offset >= data.len() {
            return Err(AvcConfigError::TruncatedPpsCount);
        }
        let pps_count = usize::from(data[offset]);
        offset += 1;
        if pps_count == 0 {
            return Err(AvcConfigError::MissingPps);
        }
        if pps_count > MAX_AVC_PARAMETER_SETS {
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
            let end = offset
                .checked_add(length)
                .ok_or(AvcConfigError::SizeOverflow)?;
            if end > data.len() {
                return Err(AvcConfigError::TruncatedPps);
            }
            let nal = &data[offset..end];
            if nal[0] & 0x80 != 0 {
                return Err(AvcConfigError::ForbiddenPpsNalHeader);
            }
            let nal_type = nal[0] & 0x1f;
            if nal_type != 8 {
                return Err(AvcConfigError::InvalidPpsNalType(nal_type));
            }
            picture_parameter_sets.push(nal.to_vec());
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
            if extension_count > MAX_AVC_PARAMETER_SETS {
                return Err(AvcConfigError::TooManyParameterSets);
            }
            for _ in 0..extension_count {
                if data.len().saturating_sub(offset) < 2 {
                    return Err(AvcConfigError::TruncatedSpsLength);
                }
                let length = usize::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
                offset += 2;
                if length == 0 {
                    return Err(AvcConfigError::EmptySps);
                }
                let end = offset
                    .checked_add(length)
                    .ok_or(AvcConfigError::SizeOverflow)?;
                if end > data.len() {
                    return Err(AvcConfigError::TruncatedSps);
                }
                let nal_type = data[offset] & 0x1f;
                if data[offset] & 0x80 != 0 || nal_type != 13 {
                    return Err(AvcConfigError::InvalidSpsExtensionNalType(nal_type));
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
        // AvcConfiguration is public and may be constructed without parse(),
        // so validate the prefix width again at this API boundary.
        if !matches!(self.nal_length_size, 1 | 2 | 4) {
            return Err(AvcConfigError::UnsupportedNalLengthSize);
        }
        if data.is_empty() {
            return Err(AvcConfigError::InvalidNalLength);
        }
        if data.len() > MAX_ANNEX_B_ACCESS_UNIT_BYTES {
            return Err(AvcConfigError::OutputTooLarge);
        }

        let mut offset = 0usize;
        // The four-byte start codes are accounted for incrementally below;
        // don't reserve an unchecked input-size-plus-overhead allocation.
        let mut output = Vec::with_capacity(data.len());
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
            let end = offset
                .checked_add(length)
                .ok_or(AvcConfigError::SizeOverflow)?;
            if end > data.len() {
                return Err(AvcConfigError::TruncatedNal);
            }
            // AVCC carries complete H.264 NAL units, not RTP packetization
            // units. Reject forbidden_zero_bit and the unspecified type 0
            // before forwarding bytes to the decoder.
            let nal_header = data[offset];
            let nal_type = nal_header & 0x1f;
            if nal_header & 0x80 != 0 || nal_type == 0 {
                return Err(AvcConfigError::InvalidNalHeader);
            }
            let next_length = output
                .len()
                .checked_add(4)
                .and_then(|value| value.checked_add(length))
                .ok_or(AvcConfigError::SizeOverflow)?;
            if next_length > MAX_ANNEX_B_ACCESS_UNIT_BYTES {
                return Err(AvcConfigError::OutputTooLarge);
            }
            output.extend_from_slice(&[0, 0, 0, 1]);
            output.extend_from_slice(&data[offset..end]);
            offset = end;
        }
        Ok(output)
    }
}

/// Coded picture dimensions parsed from an H.264 sequence parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvcVideoDimensions {
    pub width: u32,
    pub height: u32,
}

impl AvcConfiguration {
    /// Read the dimensions from the first SPS in this configuration.
    ///
    /// Returns None when the avcC record did not contain an SPS. Malformed or
    /// unsupported SPS syntax is rejected instead of guessing a frame size.
    pub fn video_dimensions(&self) -> Result<Option<AvcVideoDimensions>, AvcConfigError> {
        self.sequence_parameter_sets
            .first()
            .map(|sps| parse_h264_sps_dimensions(sps))
            .transpose()
    }
}

fn parse_h264_sps_dimensions(sps: &[u8]) -> Result<AvcVideoDimensions, AvcConfigError> {
    if sps.len() < 4 || sps[0] & 0x80 != 0 || sps[0] & 0x1f != 7 {
        return Err(AvcConfigError::InvalidSps);
    }

    let mut rbsp = Vec::with_capacity(sps.len().saturating_sub(1));
    let mut zero_count = 0usize;
    let mut index = 1usize;
    while index < sps.len() {
        let byte = sps[index];
        if zero_count >= 2 && byte == 3 {
            if index + 1 >= sps.len() || sps[index + 1] > 3 {
                return Err(AvcConfigError::InvalidSps);
            }
            zero_count = 2;
            index += 1;
            continue;
        }
        rbsp.push(byte);
        zero_count = if byte == 0 {
            zero_count.saturating_add(1)
        } else {
            0
        };
        index += 1;
    }

    let mut bits = H264BitReader::new(&rbsp);
    let profile_idc = bits.read_bits(8)?;
    let constraint_flags = bits.read_bits(8)?;
    if constraint_flags & 0x03 != 0 {
        return Err(AvcConfigError::InvalidSps);
    }
    let _level_idc = bits.read_bits(8)?;
    let _seq_parameter_set_id = bits.read_ue()?;

    let mut chroma_format_idc = 1u32;
    let mut separate_colour_plane = false;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135 | 144
    ) {
        chroma_format_idc = bits.read_ue()?;
        if chroma_format_idc > 3 {
            return Err(AvcConfigError::InvalidSps);
        }
        if chroma_format_idc == 3 {
            separate_colour_plane = bits.read_bit()?;
        }
        let bit_depth_luma_minus8 = bits.read_ue()?;
        let bit_depth_chroma_minus8 = bits.read_ue()?;
        if bit_depth_luma_minus8 > 6 || bit_depth_chroma_minus8 > 6 {
            return Err(AvcConfigError::InvalidSps);
        }
        let _qpprime_y_zero_transform_bypass_flag = bits.read_bit()?;
        if bits.read_bit()? {
            let list_count = if chroma_format_idc == 3 { 12 } else { 8 };
            for list_index in 0..list_count {
                if bits.read_bit()? {
                    skip_scaling_list(&mut bits, if list_index < 6 { 16 } else { 64 })?;
                }
            }
        }
    }

    let log2_max_frame_num_minus4 = bits.read_ue()?;
    if log2_max_frame_num_minus4 > 12 {
        return Err(AvcConfigError::InvalidSps);
    }
    let pic_order_cnt_type = bits.read_ue()?;
    match pic_order_cnt_type {
        0 => {
            if bits.read_ue()? > 12 {
                return Err(AvcConfigError::InvalidSps);
            }
        }
        1 => {
            let _delta_pic_order_always_zero_flag = bits.read_bit()?;
            let _offset_for_non_ref_pic = bits.read_se()?;
            let _offset_for_top_to_bottom_field = bits.read_se()?;
            let cycle_count = bits.read_ue()?;
            if cycle_count > 255 {
                return Err(AvcConfigError::InvalidSps);
            }
            for _ in 0..cycle_count {
                let _offset_for_ref_frame = bits.read_se()?;
            }
        }
        2 => {}
        _ => return Err(AvcConfigError::InvalidSps),
    }

    let _max_num_ref_frames = bits.read_ue()?;
    let _gaps_in_frame_num_value_allowed_flag = bits.read_bit()?;
    let pic_width_in_mbs_minus1 = bits.read_ue()?;
    let pic_height_in_map_units_minus1 = bits.read_ue()?;
    let frame_mbs_only_flag = bits.read_bit()?;
    if !frame_mbs_only_flag {
        let _mb_adaptive_frame_field_flag = bits.read_bit()?;
    }
    let _direct_8x8_inference_flag = bits.read_bit()?;

    let (crop_left, crop_right, crop_top, crop_bottom) = if bits.read_bit()? {
        (
            bits.read_ue()?,
            bits.read_ue()?,
            bits.read_ue()?,
            bits.read_ue()?,
        )
    } else {
        (0, 0, 0, 0)
    };

    let frame_factor = if frame_mbs_only_flag { 1u64 } else { 2u64 };
    let coded_width = u64::from(pic_width_in_mbs_minus1)
        .checked_add(1)
        .and_then(|value| value.checked_mul(16))
        .ok_or(AvcConfigError::InvalidSps)?;
    let coded_height = u64::from(pic_height_in_map_units_minus1)
        .checked_add(1)
        .and_then(|value| value.checked_mul(16))
        .and_then(|value| value.checked_mul(frame_factor))
        .ok_or(AvcConfigError::InvalidSps)?;

    let chroma_array_type = if separate_colour_plane {
        0
    } else {
        chroma_format_idc
    };
    let (sub_width_c, sub_height_c) = match chroma_array_type {
        0 => (1u64, 1u64),
        1 => (2, 2),
        2 => (2, 1),
        3 => (1, 1),
        _ => return Err(AvcConfigError::InvalidSps),
    };
    let crop_unit_x = if chroma_array_type == 0 {
        1
    } else {
        sub_width_c
    };
    let crop_unit_y = if chroma_array_type == 0 {
        frame_factor
    } else {
        sub_height_c * frame_factor
    };
    let crop_x = u64::from(crop_left)
        .checked_add(u64::from(crop_right))
        .and_then(|value| value.checked_mul(crop_unit_x))
        .ok_or(AvcConfigError::InvalidSps)?;
    let crop_y = u64::from(crop_top)
        .checked_add(u64::from(crop_bottom))
        .and_then(|value| value.checked_mul(crop_unit_y))
        .ok_or(AvcConfigError::InvalidSps)?;
    let width = coded_width
        .checked_sub(crop_x)
        .ok_or(AvcConfigError::InvalidSps)?;
    let height = coded_height
        .checked_sub(crop_y)
        .ok_or(AvcConfigError::InvalidSps)?;
    if width == 0
        || height == 0
        || width > u64::from(MAX_FRAME_DIMENSION)
        || height > u64::from(MAX_FRAME_DIMENSION)
    {
        return Err(AvcConfigError::InvalidSps);
    }

    Ok(AvcVideoDimensions {
        width: u32::try_from(width).map_err(|_| AvcConfigError::InvalidSps)?,
        height: u32::try_from(height).map_err(|_| AvcConfigError::InvalidSps)?,
    })
}

fn skip_scaling_list(bits: &mut H264BitReader<'_>, size: usize) -> Result<(), AvcConfigError> {
    let mut last_scale = 8i32;
    let mut next_scale = 8i32;
    for _ in 0..size {
        if next_scale != 0 {
            let delta_scale = bits.read_se()?;
            next_scale =
                (i64::from(last_scale) + i64::from(delta_scale) + 256).rem_euclid(256) as i32;
        }
        if next_scale != 0 {
            last_scale = next_scale;
        }
    }
    Ok(())
}

struct H264BitReader<'a> {
    bytes: &'a [u8],
    bit_offset: usize,
}

impl<'a> H264BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bit_offset: 0,
        }
    }

    fn read_bit(&mut self) -> Result<bool, AvcConfigError> {
        let byte_index = self.bit_offset / 8;
        let bit_index = 7 - (self.bit_offset % 8);
        let byte = *self
            .bytes
            .get(byte_index)
            .ok_or(AvcConfigError::InvalidSps)?;
        self.bit_offset = self
            .bit_offset
            .checked_add(1)
            .ok_or(AvcConfigError::InvalidSps)?;
        Ok((byte >> bit_index) & 1 != 0)
    }

    fn read_bits(&mut self, count: usize) -> Result<u32, AvcConfigError> {
        if count > 32 {
            return Err(AvcConfigError::InvalidSps);
        }
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit()?);
        }
        Ok(value)
    }

    fn read_ue(&mut self) -> Result<u32, AvcConfigError> {
        let mut leading_zero_bits = 0usize;
        while !self.read_bit()? {
            leading_zero_bits += 1;
            if leading_zero_bits > 31 {
                return Err(AvcConfigError::InvalidSps);
            }
        }
        let suffix = self.read_bits(leading_zero_bits)?;
        ((1u64 << leading_zero_bits) - 1)
            .checked_add(u64::from(suffix))
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AvcConfigError::InvalidSps)
    }

    fn read_se(&mut self) -> Result<i32, AvcConfigError> {
        let code_num = self.read_ue()?;
        let magnitude =
            i32::try_from(code_num.div_ceil(2)).map_err(|_| AvcConfigError::InvalidSps)?;
        Ok(if code_num & 1 == 0 {
            -magnitude
        } else {
            magnitude
        })
    }
}

/// Decrypt one encrypted type-110 video payload and convert its AVCC NAL
/// units to Annex-B for the H.264 decoder. The cipher must belong to this
/// stream and must be called exactly once for every video payload in order.
pub fn decrypt_access_unit_to_annex_b(
    configuration: &AvcConfiguration,
    cipher: &mut super::mirror_crypto::MirrorStreamCipher,
    encrypted_payload: &[u8],
) -> Result<Vec<u8>, EncryptedAccessUnitError> {
    let mut plaintext = encrypted_payload.to_vec();
    cipher
        .decrypt_packet(&mut plaintext)
        .map_err(EncryptedAccessUnitError::Crypto)?;
    configuration
        .access_unit_to_annex_b(&plaintext)
        .map_err(EncryptedAccessUnitError::Avc)
}

/// Result of processing one packet from the TCP mirror stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorPacketOutcome {
    CodecConfigurationUpdated {
        profile: u8,
        level: u8,
        nal_length_size: usize,
        sps_count: usize,
        pps_count: usize,
    },
    InvalidCodecConfiguration(AvcConfigError),
    /// Video bytes are deliberately held back until the negotiated encryption
    /// mode and FairPlay-derived AES key are available.
    VideoWaitingForDecryption {
        payload_bytes: usize,
        has_configuration: bool,
    },
    Heartbeat,
}

/// Bounds decoder construction attempts for one accepted AVC configuration.
///
/// The initial attempt and one retry are allowed. Repeated identical avcC
/// packets cannot trigger unbounded Media Foundation activation attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderInitializationPolicy {
    attempts: u8,
    max_attempts: u8,
}

impl Default for DecoderInitializationPolicy {
    fn default() -> Self {
        Self {
            attempts: 0,
            max_attempts: 2,
        }
    }
}

impl DecoderInitializationPolicy {
    /// Reserve an initialization attempt, returning false when the budget is spent.
    pub fn begin_attempt(&mut self) -> bool {
        if self.attempts >= self.max_attempts {
            return false;
        }
        self.attempts += 1;
        true
    }

    /// Reset the budget when a different codec configuration is accepted.
    pub fn reset(&mut self) {
        self.attempts = 0;
    }

    /// Number of attempts made for the current codec configuration.
    pub fn attempts(&self) -> u8 {
        self.attempts
    }
}

/// Tracks codec configuration for one AirPlay mirror TCP session.
///
/// This stage validates and remembers avcC packets, but never assumes video
/// payloads are plaintext. The stream can optionally encrypt video packets.
#[derive(Debug, Default)]
pub struct MirrorStreamProcessor {
    configuration: Option<AvcConfiguration>,
}

impl MirrorStreamProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configuration(&self) -> Option<&AvcConfiguration> {
        self.configuration.as_ref()
    }

    /// Decrypt one video payload using this stream's accepted AVC
    /// configuration. The cipher is advanced only after configuration exists.
    /// Call once per video packet, in receive order, with the stream's cipher.
    pub fn decrypt_video_packet(
        &self,
        cipher: &mut super::mirror_crypto::MirrorStreamCipher,
        encrypted_payload: &[u8],
    ) -> Result<Vec<u8>, EncryptedAccessUnitError> {
        let configuration = self
            .configuration
            .as_ref()
            .ok_or(EncryptedAccessUnitError::MissingConfiguration)?;
        decrypt_access_unit_to_annex_b(configuration, cipher, encrypted_payload)
    }

    pub fn process_packet(
        &mut self,
        packet_type: super::media::ScreenMirrorPacketType,
        payload: &[u8],
    ) -> MirrorPacketOutcome {
        match packet_type {
            super::media::ScreenMirrorPacketType::CodecConfiguration => {
                match AvcConfiguration::parse(payload) {
                    Ok(configuration) => {
                        let outcome = MirrorPacketOutcome::CodecConfigurationUpdated {
                            profile: configuration.profile,
                            level: configuration.level,
                            nal_length_size: configuration.nal_length_size,
                            sps_count: configuration.sequence_parameter_sets.len(),
                            pps_count: configuration.picture_parameter_sets.len(),
                        };
                        self.configuration = Some(configuration);
                        outcome
                    }
                    Err(error) => {
                        // A malformed replacement invalidates the previous
                        // configuration too: continuing with stale SPS/PPS
                        // could decode packets using the wrong stream geometry.
                        self.configuration = None;
                        MirrorPacketOutcome::InvalidCodecConfiguration(error)
                    }
                }
            }
            super::media::ScreenMirrorPacketType::Video => {
                MirrorPacketOutcome::VideoWaitingForDecryption {
                    payload_bytes: payload.len(),
                    has_configuration: self.configuration.is_some(),
                }
            }
            super::media::ScreenMirrorPacketType::Heartbeat => MirrorPacketOutcome::Heartbeat,
        }
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
        // Empty access units consume queue metadata but no byte budget. Reject
        // them so repeated empty pushes cannot grow this supposedly bounded
        // queue without limit.
        if unit.payload.is_empty() || unit.payload.len() > self.max_bytes {
            return false;
        }

        while self.buffered_bytes > self.max_bytes.saturating_sub(unit.payload.len()) {
            let Some(old) = self.queue.pop_front() else {
                break;
            };
            self.buffered_bytes = self.buffered_bytes.saturating_sub(old.payload.len());
        }

        // The subtraction-based capacity check above guarantees this addition
        // cannot overflow and never exceeds max_bytes.
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
        let raw_payload_end = next.map_or(data.len(), |(offset, _)| offset);
        // Annex-B permits trailing_zero_8bits between NAL units and at the
        // end of the byte stream. They are framing bytes, not part of the NAL.
        let mut payload_end = raw_payload_end;
        while payload_end > payload_start && data[payload_end - 1] == 0 {
            payload_end -= 1;
        }

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
        VideoCodec::H264 => {
            // forbidden_zero_bit is required to be zero by the H.264 spec.
            if nal[0] & 0x80 != 0 {
                return NalUnitKind::Invalid;
            }
            match nal[0] & 0x1f {
                1..=4 => NalUnitKind::H264Slice,
                5 => NalUnitKind::H264Idr,
                7 => NalUnitKind::H264Sps,
                8 => NalUnitKind::H264Pps,
                9 => NalUnitKind::H264Aud,
                _ => NalUnitKind::Other,
            }
        }
        VideoCodec::Hevc => {
            // HEVC has a two-byte NAL header: forbidden_zero_bit must be
            // clear and temporal_id_plus1 (the low three bits) cannot be zero.
            if nal.len() < 2 || nal[0] & 0x80 != 0 || nal[1] & 0x07 == 0 {
                return NalUnitKind::Invalid;
            }
            // This receiver currently supports only single-layer HEVC streams.
            // Reject non-zero nuh_layer_id rather than passing an unsupported
            // multilayer NAL to a decoder configured for the base layer.
            let layer_id = ((nal[0] & 0x01) << 5) | (nal[1] >> 3);
            if layer_id != 0 {
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

/// Maximum decoded frame retained by the preview mailbox (128 MiB).
/// This caps retained memory independently of the dimension limit.
pub const MAX_BGRA_FRAME_BYTES: usize = 128 * 1024 * 1024;

/// A decoded NV12 frame borrowed from a decoder output buffer.
#[derive(Debug, Clone, Copy)]
pub struct Nv12Frame<'a> {
    pub width: u32,
    pub height: u32,
    pub y_stride: usize,
    pub uv_stride: usize,
    pub data: &'a [u8],
}

/// Owned NV12 frame copied from the decoder and retained until the UI uploads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedNv12Frame {
    pub width: u32,
    pub height: u32,
    /// Byte distance between consecutive luma rows.
    pub y_stride: usize,
    /// Byte distance between consecutive interleaved chroma rows.
    pub uv_stride: usize,
    pub data: Vec<u8>,
}

/// A decoded frame retained in its native pixel format until presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedVideoFrame {
    Bgra(BgraFrame),
    Nv12(OwnedNv12Frame),
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
/// Pixel formats accepted by the native presentation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoPixelFormat {
    Bgra8,
    Nv12,
}

/// Metadata passed to a renderer independently of the backing GPU resource.
/// Timestamps use a monotonic nanosecond clock domain supplied by the producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoFrameMetadata {
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub format: VideoPixelFormat,
    pub timestamp_ns: u64,
}

/// Snapshot of bounded latest-frame handoff activity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LatestFrameMailboxStats {
    pub published: u64,
    pub replaced_before_consumption: u64,
    pub consumed: u64,
    pub cleared: u64,
    /// Number of explicit mailbox clear operations, including empty mailboxes.
    pub clear_events: u64,
    pub pending: bool,
}

#[derive(Debug, Default)]
pub struct LatestFrameMailbox {
    sequence: AtomicU64,
    published: AtomicU64,
    replaced_before_consumption: AtomicU64,
    consumed: AtomicU64,
    cleared: AtomicU64,
    clear_events: AtomicU64,
    frame: Mutex<Option<(u64, Arc<DecodedVideoFrame>, Instant)>>,
}

#[derive(Debug, Clone)]
pub struct FrameSnapshot {
    pub sequence: u64,
    pub frame: Arc<DecodedVideoFrame>,
    /// Monotonic instant at which this frame entered the latest-frame mailbox.
    pub enqueued_at: Instant,
}

impl LatestFrameMailbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a decoded frame, replacing the previous unconsumed frame.
    ///
    /// Validate dimensions, stride and backing storage before retaining bytes
    /// from a decoder or other untrusted media source.
    pub fn publish(&self, frame: BgraFrame) -> Result<u64, FrameMailboxError> {
        if frame.width == 0 || frame.height == 0 {
            return Err(FrameMailboxError::ZeroDimension);
        }
        if frame.width > MAX_FRAME_DIMENSION || frame.height > MAX_FRAME_DIMENSION {
            return Err(FrameMailboxError::DimensionTooLarge);
        }
        let row_bytes = usize::try_from(frame.width)
            .ok()
            .and_then(|width| width.checked_mul(4))
            .ok_or(FrameMailboxError::InvalidStride)?;
        if frame.stride < row_bytes {
            return Err(FrameMailboxError::InvalidStride);
        }
        // The final row only needs its visible pixel bytes; decoder buffers
        // are not required to include padding after the last row.
        let rows_before_last =
            usize::try_from(frame.height - 1).map_err(|_| FrameMailboxError::InvalidStride)?;
        let required_bytes = frame
            .stride
            .checked_mul(rows_before_last)
            .and_then(|bytes| bytes.checked_add(row_bytes))
            .ok_or(FrameMailboxError::InvalidStride)?;
        if required_bytes > MAX_BGRA_FRAME_BYTES {
            return Err(FrameMailboxError::FrameTooLarge);
        }
        if frame.data.len() < required_bytes {
            return Err(FrameMailboxError::BufferTooSmall);
        }
        self.publish_frame(DecodedVideoFrame::Bgra(frame))
    }

    /// Publish an owned NV12 frame without converting it to BGRA on the decoder worker.
    pub fn publish_nv12(&self, frame: OwnedNv12Frame) -> Result<u64, FrameMailboxError> {
        if frame.width == 0 || frame.height == 0 {
            return Err(FrameMailboxError::ZeroDimension);
        }
        if frame.width > MAX_FRAME_DIMENSION || frame.height > MAX_FRAME_DIMENSION {
            return Err(FrameMailboxError::DimensionTooLarge);
        }
        if frame.width % 2 != 0 || frame.height % 2 != 0 {
            return Err(FrameMailboxError::InvalidDimensions);
        }
        let width = usize::try_from(frame.width).map_err(|_| FrameMailboxError::InvalidStride)?;
        let height = usize::try_from(frame.height).map_err(|_| FrameMailboxError::InvalidStride)?;
        if frame.y_stride < width || frame.uv_stride < width {
            return Err(FrameMailboxError::InvalidStride);
        }
        let y_bytes = frame
            .y_stride
            .checked_mul(height)
            .ok_or(FrameMailboxError::InvalidStride)?;
        let uv_required = frame
            .uv_stride
            .checked_mul(height / 2 - 1)
            .and_then(|bytes| bytes.checked_add(width))
            .ok_or(FrameMailboxError::InvalidStride)?;
        let required = y_bytes
            .checked_add(uv_required)
            .ok_or(FrameMailboxError::InvalidStride)?;
        if required > MAX_BGRA_FRAME_BYTES {
            return Err(FrameMailboxError::FrameTooLarge);
        }
        if frame.data.len() < required {
            return Err(FrameMailboxError::BufferTooSmall);
        }
        self.publish_frame(DecodedVideoFrame::Nv12(frame))
    }

    fn publish_frame(&self, frame: DecodedVideoFrame) -> Result<u64, FrameMailboxError> {
        let mut slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        if slot.is_some() {
            self.replaced_before_consumption
                .fetch_add(1, Ordering::Relaxed);
        }
        *slot = Some((sequence, Arc::new(frame), Instant::now()));
        self.published.fetch_add(1, Ordering::Relaxed);
        Ok(sequence)
    }

    /// Take the newest frame. A frame is returned to at most one consumer.
    pub fn take_latest(&self) -> Result<Option<FrameSnapshot>, FrameMailboxError> {
        let mut slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        let snapshot = slot
            .take()
            .map(|(sequence, frame, enqueued_at)| FrameSnapshot {
                sequence,
                frame,
                enqueued_at,
            });
        if snapshot.is_some() {
            self.consumed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(snapshot)
    }

    /// Discard any pending frame, for example when a mirror session stops.
    pub fn clear(&self) -> Result<(), FrameMailboxError> {
        let mut slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        if slot.take().is_some() {
            self.cleared.fetch_add(1, Ordering::Relaxed);
        }
        self.clear_events.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Read counters without consuming the pending frame.
    pub fn stats(&self) -> Result<LatestFrameMailboxStats, FrameMailboxError> {
        let pending = self
            .frame
            .lock()
            .map_err(|_| FrameMailboxError::Poisoned)?
            .is_some();
        Ok(LatestFrameMailboxStats {
            published: self.published.load(Ordering::Relaxed),
            replaced_before_consumption: self.replaced_before_consumption.load(Ordering::Relaxed),
            consumed: self.consumed.load(Ordering::Relaxed),
            cleared: self.cleared.load(Ordering::Relaxed),
            clear_events: self.clear_events.load(Ordering::Acquire),
            pending,
        })
    }

    pub fn has_pending_frame(&self) -> Result<bool, FrameMailboxError> {
        let slot = self.frame.lock().map_err(|_| FrameMailboxError::Poisoned)?;
        Ok(slot.is_some())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameMailboxError {
    Poisoned,
    ZeroDimension,
    DimensionTooLarge,
    InvalidStride,
    InvalidDimensions,
    BufferTooSmall,
    FrameTooLarge,
}

impl std::fmt::Display for FrameMailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Poisoned => f.write_str("decoded-frame mailbox lock is poisoned"),
            Self::ZeroDimension => f.write_str("decoded frame has a zero dimension"),
            Self::DimensionTooLarge => f.write_str("decoded frame exceeds the maximum dimension"),
            Self::InvalidStride => f.write_str("decoded frame has an invalid row stride"),
            Self::InvalidDimensions => f.write_str("NV12 frame dimensions must be even"),
            Self::BufferTooSmall => {
                f.write_str("decoded frame buffer is smaller than its dimensions")
            }
            Self::FrameTooLarge => {
                f.write_str("decoded frame exceeds the maximum retained frame size")
            }
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
    FrameTooLarge,
    SizeOverflow,
    Cancelled,
}

impl std::fmt::Display for FrameConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroDimension => "frame dimensions must be non-zero",
            Self::OddNv12Dimension => "NV12 frame dimensions must be even",
            Self::DimensionTooLarge => "frame dimensions exceed the configured limit",
            Self::InvalidStride => "NV12 plane stride is smaller than its row width",
            Self::BufferTooSmall => "NV12 buffer does not contain all declared rows",
            Self::FrameTooLarge => "converted BGRA frame exceeds the 128 MiB limit",
            Self::SizeOverflow => "frame allocation size overflowed",
            Self::Cancelled => "frame conversion was cancelled",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FrameConversionError {}

/// Normalize a bottom-up contiguous NV12 buffer into top-down row order.
///
/// Media Foundation represents a negative default stride as a bottom-up
/// image. The Y plane and interleaved UV plane must each have their own row
/// order reversed before the normal NV12 converter can consume the buffer.
pub(super) fn normalize_nv12_bottom_up(
    data: &mut [u8],
    width: u32,
    height: u32,
    stride: usize,
) -> Result<(), FrameConversionError> {
    if width == 0 || height == 0 {
        return Err(FrameConversionError::ZeroDimension);
    }
    if width > MAX_FRAME_DIMENSION || height > MAX_FRAME_DIMENSION {
        return Err(FrameConversionError::DimensionTooLarge);
    }
    if width % 2 != 0 || height % 2 != 0 {
        return Err(FrameConversionError::OddNv12Dimension);
    }
    let width = usize::try_from(width).map_err(|_| FrameConversionError::SizeOverflow)?;
    let height = usize::try_from(height).map_err(|_| FrameConversionError::SizeOverflow)?;
    if stride < width {
        return Err(FrameConversionError::InvalidStride);
    }

    let y_bytes = stride
        .checked_mul(height)
        .ok_or(FrameConversionError::SizeOverflow)?;
    let uv_rows = height / 2;
    let uv_bytes = stride
        .checked_mul(uv_rows)
        .ok_or(FrameConversionError::SizeOverflow)?;
    let required = y_bytes
        .checked_add(uv_bytes)
        .ok_or(FrameConversionError::SizeOverflow)?;
    if data.len() < required {
        return Err(FrameConversionError::BufferTooSmall);
    }

    fn reverse_plane_rows(data: &mut [u8], offset: usize, rows: usize, stride: usize) {
        for row in 0..rows / 2 {
            let top_start = offset + row * stride;
            let bottom_start = offset + (rows - 1 - row) * stride;
            let (before_bottom, bottom_and_after) = data.split_at_mut(bottom_start);
            before_bottom[top_start..top_start + stride]
                .swap_with_slice(&mut bottom_and_after[..stride]);
        }
    }

    reverse_plane_rows(data, 0, height, stride);
    reverse_plane_rows(data, y_bytes, uv_rows, stride);
    Ok(())
}

impl<'a> Nv12Frame<'a> {
    /// Convert limited-range BT.601 NV12 into an owned BGRA frame.
    ///
    /// The input layout is Y plane followed by interleaved UV plane. Strides
    /// may include row padding; the output is tightly packed BGRA.
    pub fn to_bgra(self) -> Result<BgraFrame, FrameConversionError> {
        self.to_bgra_cancellable(|| false)
    }

    /// Convert NV12 while checking a caller-provided cancellation condition
    /// once per output row. This bounds shutdown latency without coupling the
    /// video module to a particular synchronization primitive.
    pub fn to_bgra_cancellable(
        self,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<BgraFrame, FrameConversionError> {
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

        // The UV plane begins after the full pitched Y plane, but the
        // final UV row only needs its visible interleaved samples. Media
        // Foundation buffers may omit padding after that final row.
        let y_bytes = self
            .y_stride
            .checked_mul(height)
            .ok_or(FrameConversionError::SizeOverflow)?;
        let uv_rows_before_last = height / 2 - 1;
        let uv_required = self
            .uv_stride
            .checked_mul(uv_rows_before_last)
            .and_then(|bytes| bytes.checked_add(width))
            .ok_or(FrameConversionError::SizeOverflow)?;
        let required = y_bytes
            .checked_add(uv_required)
            .ok_or(FrameConversionError::SizeOverflow)?;

        let output_stride = width
            .checked_mul(4)
            .ok_or(FrameConversionError::SizeOverflow)?;
        let output_len = output_stride
            .checked_mul(height)
            .ok_or(FrameConversionError::SizeOverflow)?;
        if output_len > MAX_BGRA_FRAME_BYTES {
            return Err(FrameConversionError::FrameTooLarge);
        }
        if self.data.len() < required {
            return Err(FrameConversionError::BufferTooSmall);
        }
        let mut output = vec![0u8; output_len];
        let uv_base = y_bytes;

        for row in 0..height {
            if is_cancelled() {
                return Err(FrameConversionError::Cancelled);
            }
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
    fn nal_classifier_rejects_forbidden_header_bits_and_invalid_hevc_temporal_id() {
        assert_eq!(
            classify_nal(VideoCodec::H264, &[0xe5]),
            NalUnitKind::Invalid
        );
        assert_eq!(
            classify_nal(VideoCodec::H264, &[0x65]),
            NalUnitKind::H264Idr
        );

        assert_eq!(
            classify_nal(VideoCodec::Hevc, &[0x80, 0x01]),
            NalUnitKind::Invalid
        );
        assert_eq!(
            classify_nal(VideoCodec::Hevc, &[0x26, 0x00]),
            NalUnitKind::Invalid
        );
        assert_eq!(
            classify_nal(VideoCodec::Hevc, &[0x26, 0x01]),
            NalUnitKind::HevcIdr
        );
        // nuh_layer_id is split across bit 0 of byte 0 and bits 3..7 of byte 1.
        assert_eq!(
            classify_nal(VideoCodec::Hevc, &[0x27, 0x01]),
            NalUnitKind::Invalid
        );
        assert_eq!(
            classify_nal(VideoCodec::Hevc, &[0x26, 0x09]),
            NalUnitKind::Invalid
        );
        assert_eq!(
            classify_nal(VideoCodec::Hevc, &[0x42]),
            NalUnitKind::Invalid
        );
    }

    #[test]
    fn annex_b_split_excludes_trailing_zero_bytes_from_each_nal() {
        let data = [0, 0, 0, 1, 0x67, 0x64, 0, 0, 0, 1, 0x68, 0xee, 0, 0];
        let units = split_annex_b(&data);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].bytes, &[0x67, 0x64]);
        assert_eq!(units[1].bytes, &[0x68, 0xee]);
    }

    #[test]
    fn decoder_initialization_policy_allows_only_two_attempts_per_configuration() {
        let mut policy = DecoderInitializationPolicy::default();
        assert!(policy.begin_attempt());
        assert_eq!(policy.attempts(), 1);
        assert!(policy.begin_attempt());
        assert_eq!(policy.attempts(), 2);
        assert!(!policy.begin_attempt());
        assert_eq!(policy.attempts(), 2);

        policy.reset();
        assert_eq!(policy.attempts(), 0);
        assert!(policy.begin_attempt());
    }

    #[test]
    fn nv12_conversion_accepts_uv_plane_without_padding_after_last_row() {
        // 4x4 image with a six-byte row pitch. The UV plane starts after
        // all four pitched Y rows, but its final row has only four valid bytes.
        let mut data = vec![128u8; 6 * 4 + 6 + 4];
        data[..24].fill(100);
        data[24..].fill(128);
        let frame = Nv12Frame {
            width: 4,
            height: 4,
            y_stride: 6,
            uv_stride: 6,
            data: &data,
        };
        let converted = frame.to_bgra().expect("compact final UV row is valid");
        assert_eq!(converted.data.len(), 4 * 4 * 4);
    }

    #[test]
    fn nv12_conversion_rejects_oversized_bgra_before_allocating() {
        let frame = Nv12Frame {
            width: MAX_FRAME_DIMENSION,
            height: MAX_FRAME_DIMENSION,
            y_stride: MAX_FRAME_DIMENSION as usize,
            uv_stride: MAX_FRAME_DIMENSION as usize,
            data: &[],
        };
        assert_eq!(frame.to_bgra(), Err(FrameConversionError::FrameTooLarge));
    }

    #[test]
    fn parses_baseline_sps_dimensions() {
        fn push_bits(bits: &mut Vec<bool>, value: u32, count: usize) {
            for shift in (0..count).rev() {
                bits.push((value >> shift) & 1 != 0);
            }
        }
        fn push_ue(bits: &mut Vec<bool>, value: u32) {
            let code = value + 1;
            let width = (u32::BITS - code.leading_zeros()) as usize;
            for _ in 0..width - 1 {
                bits.push(false);
            }
            push_bits(bits, code, width);
        }

        // Baseline profile, 40x30 macroblocks, progressive and uncropped.
        let mut bits = Vec::new();
        push_bits(&mut bits, 66, 8); // profile_idc
        push_bits(&mut bits, 0, 8); // constraint flags
        push_bits(&mut bits, 30, 8); // level_idc
        push_ue(&mut bits, 0); // seq_parameter_set_id
        push_ue(&mut bits, 0); // log2_max_frame_num_minus4
        push_ue(&mut bits, 0); // pic_order_cnt_type
        push_ue(&mut bits, 0); // log2_max_pic_order_cnt_lsb_minus4
        push_ue(&mut bits, 1); // max_num_ref_frames
        bits.push(false); // gaps_in_frame_num_value_allowed_flag
        push_ue(&mut bits, 39); // pic_width_in_mbs_minus1
        push_ue(&mut bits, 29); // pic_height_in_map_units_minus1
        bits.push(true); // frame_mbs_only_flag
        bits.push(true); // direct_8x8_inference_flag
        bits.push(false); // frame_cropping_flag
        bits.push(false); // vui_parameters_present_flag
        bits.push(true); // rbsp_stop_one_bit
        while bits.len() % 8 != 0 {
            bits.push(false);
        }

        let mut sps = vec![0x67];
        for chunk in bits.chunks_exact(8) {
            let byte = chunk
                .iter()
                .fold(0u8, |value, bit| (value << 1) | u8::from(*bit));
            sps.push(byte);
        }

        let dimensions = parse_h264_sps_dimensions(&sps).expect("valid baseline SPS");
        assert_eq!(dimensions.width, 640);
        assert_eq!(dimensions.height, 480);
    }

    #[test]
    fn rejects_invalid_sps_dimensions() {
        assert_eq!(
            parse_h264_sps_dimensions(&[0x68, 0, 0, 0]),
            Err(AvcConfigError::InvalidSps)
        );
        assert_eq!(
            parse_h264_sps_dimensions(&[0x67, 0, 0, 0]),
            Err(AvcConfigError::InvalidSps)
        );
    }

    #[test]
    fn parses_airplay_avcc_configuration_and_converts_access_unit() {
        // Captured-format avcC example: one SPS and one PPS.
        let config = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        let parsed = AvcConfiguration::parse(&config).expect("valid avcC record");
        assert_eq!(parsed.profile, 0x64);
        assert_eq!(parsed.compatibility, 0xc0);
        assert_eq!(parsed.level, 0x28);
        assert_eq!(parsed.nal_length_size, 4);
        assert_eq!(
            parsed.sequence_parameter_sets,
            vec![vec![0x67, 0x64, 0xc0, 0x28]]
        );
        assert_eq!(parsed.picture_parameter_sets, vec![vec![0x68, 0xee]]);
        assert_eq!(
            parsed.parameter_sets_annex_b(),
            vec![0, 0, 0, 1, 0x67, 0x64, 0xc0, 0x28, 0, 0, 0, 1, 0x68, 0xee]
        );

        let avcc = [
            0x00, 0x00, 0x00, 0x02, 0x65, 0xaa, 0x00, 0x00, 0x00, 0x01, 0x41,
        ];
        assert_eq!(
            parsed
                .access_unit_to_annex_b(&avcc)
                .expect("valid AVCC unit"),
            vec![0, 0, 0, 1, 0x65, 0xaa, 0, 0, 0, 1, 0x41]
        );
    }

    #[test]
    fn rejects_malformed_avcc_configuration_and_access_units() {
        assert_eq!(
            AvcConfiguration::parse(&[1, 2, 3]),
            Err(AvcConfigError::TooShort)
        );
        assert_eq!(
            AvcConfiguration::parse(&[2, 0, 0, 0, 0xff, 0xe1, 0, 0]),
            Err(AvcConfigError::UnsupportedVersion(2))
        );

        let invalid_reserved = [1, 0x64, 0, 0x1f, 0, 0xe1, 0, 0];
        assert_eq!(
            AvcConfiguration::parse(&invalid_reserved),
            Err(AvcConfigError::InvalidReservedBits)
        );

        let missing_sps = [1, 0x64, 0, 0x1f, 0xff, 0xe0, 0];
        assert_eq!(
            AvcConfiguration::parse(&missing_sps),
            Err(AvcConfigError::MissingSps)
        );

        let missing_pps = [1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 1, 0x67, 0];
        assert_eq!(
            AvcConfiguration::parse(&missing_pps),
            Err(AvcConfigError::MissingPps)
        );

        let wrong_sps_type = [1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 1, 0x68, 1, 0, 1, 0x68];
        assert_eq!(
            AvcConfiguration::parse(&wrong_sps_type),
            Err(AvcConfigError::InvalidSpsNalType(8))
        );

        let wrong_pps_type = [1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 1, 0x67, 1, 0, 1, 0x67];
        assert_eq!(
            AvcConfiguration::parse(&wrong_pps_type),
            Err(AvcConfigError::InvalidPpsNalType(7))
        );

        let forbidden_sps_header = [1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 1, 0xe7, 1, 0, 1, 0x68];
        assert_eq!(
            AvcConfiguration::parse(&forbidden_sps_header),
            Err(AvcConfigError::ForbiddenSpsNalHeader)
        );

        let forbidden_pps_header = [1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 1, 0x67, 1, 0, 1, 0xe8];
        assert_eq!(
            AvcConfiguration::parse(&forbidden_pps_header),
            Err(AvcConfigError::ForbiddenPpsNalHeader)
        );

        let too_many_pps = {
            let mut bytes = vec![1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 1, 0x67, 33];
            for _ in 0..33 {
                bytes.extend_from_slice(&[0, 1, 0x68]);
            }
            bytes
        };
        assert_eq!(
            AvcConfiguration::parse(&too_many_pps),
            Err(AvcConfigError::TooManyParameterSets)
        );

        let too_many_sps_extensions = [
            1, 100, 0, 0x1f, 0xff, 0xe1, 0, 1, 0x67, 1, 0, 1, 0x68, 0xfc, 0xf8, 0xf8, 33,
        ];
        assert_eq!(
            AvcConfiguration::parse(&too_many_sps_extensions),
            Err(AvcConfigError::TooManyParameterSets)
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
    fn avcc_access_unit_parser_supports_one_two_and_four_byte_lengths() {
        let mut configuration = AvcConfiguration {
            profile: 0x64,
            compatibility: 0,
            level: 0x1f,
            nal_length_size: 1,
            sequence_parameter_sets: vec![vec![0x67]],
            picture_parameter_sets: vec![vec![0x68]],
        };

        for (length_size, packet) in [
            (1, vec![2, 0x65, 0xaa]),
            (2, vec![0, 2, 0x65, 0xaa]),
            (4, vec![0, 0, 0, 2, 0x65, 0xaa]),
        ] {
            configuration.nal_length_size = length_size;
            assert_eq!(
                configuration.access_unit_to_annex_b(&packet),
                Ok(vec![0, 0, 0, 1, 0x65, 0xaa]),
                "length prefix width {length_size}"
            );
        }
    }

    #[test]
    fn avcc_access_unit_parser_rejects_invalid_public_prefix_width_and_empty_input() {
        let mut configuration = AvcConfiguration {
            profile: 0x64,
            compatibility: 0,
            level: 0x1f,
            nal_length_size: 3,
            sequence_parameter_sets: vec![vec![0x67]],
            picture_parameter_sets: vec![vec![0x68]],
        };
        assert_eq!(
            configuration.access_unit_to_annex_b(&[0, 0, 2, 0x65, 0xaa]),
            Err(AvcConfigError::UnsupportedNalLengthSize)
        );
        configuration.nal_length_size = 0;
        assert_eq!(
            configuration.access_unit_to_annex_b(&[]),
            Err(AvcConfigError::UnsupportedNalLengthSize)
        );
        configuration.nal_length_size = 4;
        assert_eq!(
            configuration.access_unit_to_annex_b(&[]),
            Err(AvcConfigError::InvalidNalLength)
        );
    }

    #[test]
    fn avcc_access_unit_parser_rejects_forbidden_and_zero_nal_headers() {
        let configuration = AvcConfiguration {
            profile: 0x64,
            compatibility: 0,
            level: 0x1f,
            nal_length_size: 4,
            sequence_parameter_sets: vec![vec![0x67]],
            picture_parameter_sets: vec![vec![0x68]],
        };

        assert_eq!(
            configuration.access_unit_to_annex_b(&[0, 0, 0, 1, 0xe5]),
            Err(AvcConfigError::InvalidNalHeader)
        );
        assert_eq!(
            configuration.access_unit_to_annex_b(&[0, 0, 0, 1, 0x00]),
            Err(AvcConfigError::InvalidNalHeader)
        );
        assert_eq!(
            configuration.access_unit_to_annex_b(&[0, 0, 0, 1, 0x65]),
            Ok(vec![0, 0, 0, 1, 0x65])
        );
    }

    #[test]
    fn decrypts_encrypted_avcc_payload_and_converts_to_annex_b() {
        use super::super::mirror_crypto::{MirrorStreamCipher, derive_mirror_stream_keys};
        use super::{AvcConfiguration, decrypt_access_unit_to_annex_b};

        let avcc = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        let configuration = AvcConfiguration::parse(&avcc).unwrap();
        let keys = derive_mirror_stream_keys(&[0x31; 16], None, 42).unwrap();

        let mut encrypted = vec![0x00, 0x00, 0x00, 0x02, 0x65, 0x88];
        MirrorStreamCipher::new(&keys)
            .decrypt_packet(&mut encrypted)
            .expect("test payload encryption uses the symmetric CTR operation");

        let mut decryptor = MirrorStreamCipher::new(&keys);
        let annex_b = decrypt_access_unit_to_annex_b(&configuration, &mut decryptor, &encrypted)
            .expect("decrypt and convert access unit");
        assert_eq!(annex_b, [0, 0, 0, 1, 0x65, 0x88]);
    }

    #[test]
    fn mirror_stream_processors_keep_codec_state_isolated_between_sessions() {
        use super::super::media::ScreenMirrorPacketType;

        let valid_avcc = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        let mut first_session = MirrorStreamProcessor::new();
        let mut second_session = MirrorStreamProcessor::new();

        assert!(matches!(
            first_session.process_packet(ScreenMirrorPacketType::CodecConfiguration, &valid_avcc),
            MirrorPacketOutcome::CodecConfigurationUpdated { .. }
        ));
        assert!(first_session.configuration().is_some());
        assert!(second_session.configuration().is_none());

        assert!(matches!(
            second_session.process_packet(ScreenMirrorPacketType::CodecConfiguration, &[1, 2, 3]),
            MirrorPacketOutcome::InvalidCodecConfiguration(_)
        ));

        // A malformed reconfiguration in one RTSP media session must not
        // erase the active codec configuration owned by another session.
        assert!(first_session.configuration().is_some());
        assert!(second_session.configuration().is_none());
    }

    #[test]
    fn stream_processor_decrypts_video_only_after_codec_configuration() {
        use super::super::media::ScreenMirrorPacketType;
        use super::super::mirror_crypto::{MirrorStreamCipher, derive_mirror_stream_keys};

        let keys = derive_mirror_stream_keys(&[0x31; 16], None, 42).unwrap();
        let mut decryptor = MirrorStreamCipher::new(&keys);
        let mut processor = MirrorStreamProcessor::new();

        assert_eq!(
            processor.decrypt_video_packet(&mut decryptor, &[0, 0, 0, 2, 0x65, 0x88]),
            Err(EncryptedAccessUnitError::MissingConfiguration)
        );

        let avcc = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        assert!(matches!(
            processor.process_packet(ScreenMirrorPacketType::CodecConfiguration, &avcc),
            MirrorPacketOutcome::CodecConfigurationUpdated { .. }
        ));

        let plaintext = [0, 0, 0, 2, 0x65, 0x88];
        let mut encrypted = plaintext;
        MirrorStreamCipher::new(&keys)
            .decrypt_packet(&mut encrypted)
            .expect("test encryption");
        let annex_b = processor
            .decrypt_video_packet(&mut decryptor, &encrypted)
            .expect("configured stream decrypts");
        assert_eq!(annex_b, [0, 0, 0, 1, 0x65, 0x88]);
    }

    #[test]
    fn invalid_replacement_configuration_discards_previous_configuration() {
        use super::super::media::ScreenMirrorPacketType;

        let mut processor = MirrorStreamProcessor::new();
        let valid_avcc = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        assert!(matches!(
            processor.process_packet(ScreenMirrorPacketType::CodecConfiguration, &valid_avcc),
            MirrorPacketOutcome::CodecConfigurationUpdated { .. }
        ));
        assert!(processor.configuration().is_some());

        assert!(matches!(
            processor.process_packet(ScreenMirrorPacketType::CodecConfiguration, &[1, 2, 3]),
            MirrorPacketOutcome::InvalidCodecConfiguration(_)
        ));
        assert!(processor.configuration().is_none());
        assert!(matches!(
            processor.process_packet(ScreenMirrorPacketType::Video, &[0, 0, 0, 2, 0x65, 0x88]),
            MirrorPacketOutcome::VideoWaitingForDecryption {
                has_configuration: false,
                ..
            }
        ));
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
    fn empty_units_are_rejected_without_consuming_queue_capacity() {
        let mut assembler = AccessUnitAssembler::new(4);
        for timestamp in 0..128 {
            assert!(!assembler.push(AccessUnit {
                timestamp,
                payload: Vec::new(),
            }));
        }
        assert!(assembler.is_empty());
        assert_eq!(assembler.len(), 0);
        assert_eq!(assembler.buffered_bytes(), 0);
    }

    #[test]
    fn assembler_accounts_bytes_when_popping_and_preserves_order() {
        let mut assembler = AccessUnitAssembler::new(8);
        for (timestamp, payload) in [(1, vec![1, 2]), (2, vec![3, 4, 5])] {
            assert!(assembler.push(AccessUnit { timestamp, payload }));
        }

        assert_eq!(assembler.buffered_bytes(), 5);
        assert_eq!(assembler.pop().unwrap().timestamp, 1);
        assert_eq!(assembler.buffered_bytes(), 3);
        assert_eq!(assembler.pop().unwrap().timestamp, 2);
        assert_eq!(assembler.buffered_bytes(), 0);
        assert!(assembler.pop().is_none());
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
        match snapshot.frame.as_ref() {
            DecodedVideoFrame::Bgra(frame) => assert_eq!(frame.data, vec![5, 6, 7, 8]),
            DecodedVideoFrame::Nv12(_) => panic!("expected BGRA frame"),
        }
        assert!(!mailbox.has_pending_frame().unwrap());
        assert!(mailbox.take_latest().unwrap().is_none());
    }

    #[test]
    fn latest_frame_mailbox_retains_nv12_without_bgra_conversion() {
        let mailbox = LatestFrameMailbox::new();
        let mut data = vec![128u8; 6 * 4 + 6 + 4];
        data[..24].fill(100);
        assert_eq!(
            mailbox.publish_nv12(OwnedNv12Frame {
                width: 4,
                height: 4,
                y_stride: 6,
                uv_stride: 6,
                data,
            }),
            Ok(1)
        );
        let snapshot = mailbox.take_latest().unwrap().unwrap();
        match snapshot.frame.as_ref() {
            DecodedVideoFrame::Nv12(frame) => {
                assert_eq!(
                    (frame.width, frame.height, frame.y_stride, frame.uv_stride),
                    (4, 4, 6, 6)
                );
                assert_eq!(frame.data.len(), 34);
            }
            DecodedVideoFrame::Bgra(_) => panic!("expected native NV12 frame"),
        }
    }

    #[test]
    fn latest_frame_mailbox_accepts_distinct_nv12_plane_strides() {
        let mailbox = LatestFrameMailbox::new();
        // 4x4 Y plane: 6-byte pitch (24 bytes). UV plane: 8-byte
        // pitch with only the visible final row required (8 + 4 bytes).
        let frame = OwnedNv12Frame {
            width: 4,
            height: 4,
            y_stride: 6,
            uv_stride: 8,
            data: vec![0; 36],
        };
        assert_eq!(mailbox.publish_nv12(frame), Ok(1));
        let snapshot = mailbox.take_latest().unwrap().unwrap();
        match snapshot.frame.as_ref() {
            DecodedVideoFrame::Nv12(frame) => {
                assert_eq!((frame.y_stride, frame.uv_stride), (6, 8));
            }
            DecodedVideoFrame::Bgra(_) => panic!("expected native NV12 frame"),
        }
    }

    #[test]
    fn latest_frame_mailbox_rejects_truncated_nv12_buffer() {
        let mailbox = LatestFrameMailbox::new();
        assert_eq!(
            mailbox.publish_nv12(OwnedNv12Frame {
                width: 4,
                height: 4,
                y_stride: 6,
                uv_stride: 6,
                data: vec![0; 33],
            }),
            Err(FrameMailboxError::BufferTooSmall)
        );
        assert!(!mailbox.has_pending_frame().unwrap());
    }

    #[test]
    fn latest_frame_mailbox_accepts_bgra_without_trailing_last_row_padding() {
        let mailbox = LatestFrameMailbox::new();
        let frame = BgraFrame {
            width: 2,
            height: 2,
            stride: 12,
            // First row occupies 12 bytes; the last row needs only 8.
            data: vec![0; 20],
        };
        assert_eq!(mailbox.publish(frame), Ok(1));
        assert!(mailbox.has_pending_frame().unwrap());
    }

    #[test]
    fn latest_frame_mailbox_rejects_frames_over_retained_byte_limit() {
        let mailbox = LatestFrameMailbox::new();
        let frame = BgraFrame {
            width: MAX_FRAME_DIMENSION,
            height: MAX_FRAME_DIMENSION,
            stride: MAX_FRAME_DIMENSION as usize * 4,
            data: Vec::new(),
        };
        assert_eq!(
            mailbox.publish(frame),
            Err(FrameMailboxError::FrameTooLarge)
        );
        assert!(!mailbox.has_pending_frame().unwrap());
    }

    #[test]
    fn latest_frame_mailbox_rejects_invalid_frames() {
        let mailbox = LatestFrameMailbox::new();
        let frame = |width, height, stride, data: Vec<u8>| BgraFrame {
            width,
            height,
            stride,
            data,
        };

        assert_eq!(
            mailbox.publish(frame(0, 1, 4, vec![0; 4])),
            Err(FrameMailboxError::ZeroDimension)
        );
        assert_eq!(
            mailbox.publish(frame(MAX_FRAME_DIMENSION + 1, 1, 4, vec![0; 4])),
            Err(FrameMailboxError::DimensionTooLarge)
        );
        assert_eq!(
            mailbox.publish(frame(2, 1, 4, vec![0; 8])),
            Err(FrameMailboxError::InvalidStride)
        );
        assert_eq!(
            mailbox.publish(frame(2, 2, 8, vec![0; 8])),
            Err(FrameMailboxError::BufferTooSmall)
        );
        assert!(!mailbox.has_pending_frame().unwrap());
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
    fn normalizes_bottom_up_nv12_y_and_uv_planes_independently() {
        let mut data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, // Four Y rows.
            10, 11, 12, 13, // Two interleaved UV rows.
        ];
        normalize_nv12_bottom_up(&mut data, 2, 4, 2).expect("valid bottom-up NV12");
        assert_eq!(data, vec![7, 8, 5, 6, 3, 4, 1, 2, 12, 13, 10, 11]);
    }

    #[test]
    fn rejects_truncated_bottom_up_nv12_buffer() {
        assert_eq!(
            normalize_nv12_bottom_up(&mut [0; 5], 2, 2, 2),
            Err(FrameConversionError::BufferTooSmall)
        );
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
    fn nv12_conversion_stops_when_cancelled_between_rows() {
        let data = [16u8, 16, 16, 16, 128, 128];
        let mut checks = 0usize;
        let result = Nv12Frame {
            width: 2,
            height: 2,
            y_stride: 2,
            uv_stride: 2,
            data: &data,
        }
        .to_bgra_cancellable(|| {
            checks += 1;
            checks > 1
        });
        assert_eq!(result.unwrap_err(), FrameConversionError::Cancelled);
        assert_eq!(checks, 2);
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
    fn mirror_stream_processor_tracks_avc_configuration_and_waits_for_decryption() {
        use super::super::media::ScreenMirrorPacketType;
        use super::{MirrorPacketOutcome, MirrorStreamProcessor};

        let avcc = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        let mut processor = MirrorStreamProcessor::new();
        assert!(processor.configuration().is_none());

        assert_eq!(
            processor.process_packet(ScreenMirrorPacketType::CodecConfiguration, &avcc),
            MirrorPacketOutcome::CodecConfigurationUpdated {
                profile: 0x64,
                level: 0x28,
                nal_length_size: 4,
                sps_count: 1,
                pps_count: 1,
            }
        );
        assert!(processor.configuration().is_some());

        assert_eq!(
            processor.process_packet(
                ScreenMirrorPacketType::Video,
                &[0x00, 0x00, 0x00, 0x02, 0x65, 0x88]
            ),
            MirrorPacketOutcome::VideoWaitingForDecryption {
                payload_bytes: 6,
                has_configuration: true,
            }
        );
        assert_eq!(
            processor.process_packet(ScreenMirrorPacketType::Heartbeat, &[]),
            MirrorPacketOutcome::Heartbeat
        );
    }

    #[test]
    fn invalid_avc_configuration_discards_previous_configuration() {
        use super::super::media::ScreenMirrorPacketType;
        use super::{MirrorPacketOutcome, MirrorStreamProcessor};

        let valid = [
            0x01, 0x64, 0xc0, 0x28, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x64, 0xc0, 0x28, 0x01, 0x00,
            0x02, 0x68, 0xee,
        ];
        let mut processor = MirrorStreamProcessor::new();
        processor.process_packet(ScreenMirrorPacketType::CodecConfiguration, &valid);
        assert_eq!(
            processor.process_packet(ScreenMirrorPacketType::CodecConfiguration, &[0x01]),
            MirrorPacketOutcome::InvalidCodecConfiguration(super::AvcConfigError::TooShort)
        );
        assert!(processor.configuration().is_none());
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

#[cfg(test)]
mod latest_frame_diagnostics_tests {
    use super::*;

    fn frame(value: u8) -> BgraFrame {
        BgraFrame {
            width: 1,
            height: 1,
            stride: 4,
            data: vec![value, value, value, 255],
        }
    }

    #[test]
    fn latest_frame_mailbox_reports_replacements_and_consumption() {
        let mailbox = LatestFrameMailbox::new();
        assert_eq!(mailbox.publish(frame(1)).unwrap(), 1);
        assert_eq!(mailbox.publish(frame(2)).unwrap(), 2);

        let stats = mailbox.stats().unwrap();
        assert_eq!(stats.published, 2);
        assert_eq!(stats.replaced_before_consumption, 1);
        assert_eq!(stats.consumed, 0);
        assert!(stats.pending);

        let snapshot = mailbox.take_latest().unwrap().unwrap();
        assert_eq!(snapshot.sequence, 2);
        match snapshot.frame.as_ref() {
            DecodedVideoFrame::Bgra(frame) => assert_eq!(frame.data[0], 2),
            DecodedVideoFrame::Nv12(_) => panic!("expected BGRA frame"),
        }

        let stats = mailbox.stats().unwrap();
        assert_eq!(stats.consumed, 1);
        assert!(!stats.pending);
    }

    #[test]
    fn latest_frame_mailbox_counts_explicit_clear() {
        let mailbox = LatestFrameMailbox::new();
        mailbox.publish(frame(7)).unwrap();
        mailbox.clear().unwrap();

        let stats = mailbox.stats().unwrap();
        assert_eq!(stats.published, 1);
        assert_eq!(stats.cleared, 1);
        assert_eq!(stats.clear_events, 1);
        assert!(!stats.pending);

        // A teardown must still be observable when the last frame was already
        // consumed and the mailbox is empty.
        mailbox.clear().unwrap();
        let stats = mailbox.stats().unwrap();
        assert_eq!(stats.cleared, 1);
        assert_eq!(stats.clear_events, 2);
        assert!(!stats.pending);
    }
}
