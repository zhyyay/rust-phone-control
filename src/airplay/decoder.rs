//! Windows Media Foundation runtime lifecycle for the AirPlay decoder.
//!
//! This module owns the Media Foundation runtime and a synchronous H.264 MFT
//! input/output adapter. AirPlay packet decryption, depacketization, access-unit
//! reconstruction, and delivery to the GPUI renderer remain separate stages.

use std::fmt;

#[cfg(windows)]
use std::mem::ManuallyDrop;

#[cfg(windows)]
use windows_062::Win32::{
    Media::MediaFoundation::{
        IMFMediaBuffer, MF_MT_DEFAULT_STRIDE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE,
        MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE,
        MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video,
        MFT_CATEGORY_VIDEO_DECODER, MFT_ENUM_FLAG_LOCALMFT, MFT_ENUM_FLAG_SORTANDFILTER,
        MFT_ENUM_FLAG_SYNCMFT, MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
        MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264, MFVideoFormat_HEVC,
        MFVideoFormat_NV12, MFVideoInterlace_Progressive,
    },
    System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize},
};

#[cfg(windows)]
const MF_VERSION: u32 = 0x0002_0070;
#[cfg(windows)]
const MFSTARTUP_FULL: u32 = 0;
#[cfg(windows)]
const MF_E_NOTACCEPTING_HR: i32 = 0xC00D_36B0u32 as i32;
#[cfg(windows)]
const MF_E_TRANSFORM_STREAM_CHANGE_HR: i32 = 0xC00D_6D61u32 as i32;
#[cfg(windows)]
const MF_E_TRANSFORM_NEED_MORE_INPUT_HR: i32 = 0xC00D_6D72u32 as i32;

#[cfg(windows)]
#[link(name = "mfplat")]
unsafe extern "system" {
    fn MFStartup(version: u32, flags: u32) -> i32;
    fn MFShutdown() -> i32;
}

/// COM apartment initialized on the same thread that owns the MFT interfaces.
#[cfg(windows)]
struct ComApartment {
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(windows)]
impl ComApartment {
    fn initialize() -> Result<Self, MediaFoundationError> {
        // SAFETY: this initializes COM for the current worker thread. The
        // matching CoUninitialize is called by Drop on this same thread.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(|error| MediaFoundationError::ComInitializationFailed(error.code().0))?;
        Ok(Self {
            _thread_bound: std::marker::PhantomData,
        })
    }
}

#[cfg(windows)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: this guard is only constructed after a successful
        // CoInitializeEx call and is not Send, so it drops on its owner thread.
        unsafe { CoUninitialize() };
    }
}

/// A successfully initialized Media Foundation runtime.
///
/// The runtime is shut down when the value is dropped. Keep one instance alive
/// for the complete lifetime of Media Foundation decoder transforms.
#[cfg(windows)]
pub struct MediaFoundationRuntime {
    _private: (),
}

#[cfg(windows)]
impl MediaFoundationRuntime {
    /// Initialize Media Foundation for this process.
    pub fn startup() -> Result<Self, MediaFoundationError> {
        // SAFETY: MFStartup is a process-wide OS API with scalar arguments.
        // Its matching MFShutdown call is made by Drop.
        let result = unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL) };
        if result < 0 {
            return Err(MediaFoundationError::StartupFailed(result));
        }

        tracing::info!("Windows Media Foundation runtime initialized");
        Ok(Self { _private: () })
    }
}

#[cfg(windows)]
impl Drop for MediaFoundationRuntime {
    fn drop(&mut self) {
        // SAFETY: this instance represents one successful MFStartup call.
        let result = unsafe { MFShutdown() };
        if result < 0 {
            tracing::warn!(
                hresult = format_args!("0x{:08X}", result as u32),
                "Media Foundation shutdown failed"
            );
        } else {
            tracing::debug!("Windows Media Foundation runtime shut down");
        }
    }
}

/// Number of registered synchronous/local decoder transforms for each codec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecoderInventory {
    pub h264: u32,
    pub hevc: u32,
}

#[cfg(windows)]
struct ActivationArray {
    ptr: *mut Option<windows_062::Win32::Media::MediaFoundation::IMFActivate>,
    count: u32,
}

#[cfg(windows)]
impl Drop for ActivationArray {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // Release each COM activation interface before freeing the
            // task-allocated pointer array returned by MFTEnumEx.
            unsafe {
                for activation in std::slice::from_raw_parts_mut(self.ptr, self.count as usize) {
                    let _ = activation.take();
                }
                CoTaskMemFree(Some(self.ptr.cast()));
            }
        }
    }
}

#[cfg(windows)]
fn count_video_decoders(subtype: windows_062::core::GUID) -> Result<u32, MediaFoundationError> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: subtype,
    };
    let mut raw: *mut Option<windows_062::Win32::Media::MediaFoundation::IMFActivate> =
        std::ptr::null_mut();
    let mut count = 0u32;
    let flags = MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_LOCALMFT | MFT_ENUM_FLAG_SORTANDFILTER;

    // SAFETY: input is a valid registration descriptor; raw/count are
    // writable output locations. The returned activation array is released
    // by ActivationArray, including each COM interface and its task memory.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_DECODER,
            flags,
            Some(&input),
            None,
            &mut raw,
            &mut count,
        )
    }
    .map_err(|error| MediaFoundationError::EnumerationFailed(error.code().0))?;

    let activations = ActivationArray { ptr: raw, count };
    drop(activations);
    Ok(count)
}

#[cfg(windows)]
impl MediaFoundationRuntime {
    /// Inspect the system's registered synchronous/local H.264 and HEVC
    /// decoder transforms. This does not activate or configure a decoder.
    pub fn decoder_inventory(&self) -> Result<DecoderInventory, MediaFoundationError> {
        let _com_apartment = ComApartment::initialize()?;
        Ok(DecoderInventory {
            h264: count_video_decoders(MFVideoFormat_H264)?,
            hevc: count_video_decoders(MFVideoFormat_HEVC)?,
        })
    }
}

/// A decoded NV12 frame copied out of a Media Foundation output sample.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedNv12Frame {
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub data: Vec<u8>,
}

#[cfg(windows)]
impl DecodedNv12Frame {
    /// Convert the decoder's NV12 output into BGRA for the GPUI fallback path.
    ///
    /// Media Foundation exposes one default stride for the NV12 surface;
    /// the Y and interleaved UV planes use that same row pitch.
    pub fn to_bgra(
        &self,
    ) -> Result<crate::airplay::video::BgraFrame, crate::airplay::video::FrameConversionError> {
        crate::airplay::video::Nv12Frame {
            width: self.width,
            height: self.height,
            y_stride: self.stride,
            uv_stride: self.stride,
            data: &self.data,
        }
        .to_bgra()
    }
}

/// A synchronous Windows H.264 decoder MFT.
///
/// This object is thread-local because Windows COM interfaces are not Send/Sync.
/// Create and use it on the dedicated media worker thread.
/// Guarantees that a successful IMFMediaBuffer::Lock is paired with Unlock,
/// including early-return paths while validating or copying the buffer.
#[cfg(windows)]
struct MediaBufferLock<'a> {
    buffer: &'a IMFMediaBuffer,
    locked: bool,
}

#[cfg(windows)]
impl<'a> MediaBufferLock<'a> {
    fn new(buffer: &'a IMFMediaBuffer) -> Self {
        Self {
            buffer,
            locked: true,
        }
    }

    fn unlock(mut self) -> Result<(), MediaFoundationError> {
        let result = unsafe { self.buffer.Unlock() };
        if result.is_ok() {
            self.locked = false;
        }
        result.map_err(|error| MediaFoundationError::BufferFailed(error.code().0))
    }
}

#[cfg(windows)]
impl Drop for MediaBufferLock<'_> {
    fn drop(&mut self) {
        if self.locked {
            if let Err(error) = unsafe { self.buffer.Unlock() } {
                tracing::warn!(
                    hresult = format_args!("0x{:08X}", error.code().0 as u32),
                    "Media Foundation buffer unlock failed during cleanup"
                );
            }
        }
    }
}

#[cfg(windows)]
/// Owns the COM fields of an MFT_OUTPUT_DATA_BUFFER while ProcessOutput is
/// executing. The generated bindings use ManuallyDrop for these fields because
/// Media Foundation may write COM references into them. Keeping this guard
/// alive across the FFI call also makes panic/unwind cleanup explicit.
struct ProcessOutputBufferGuard {
    output: *mut MFT_OUTPUT_DATA_BUFFER,
    active: bool,
}

#[cfg(windows)]
impl ProcessOutputBufferGuard {
    fn new(output: &mut MFT_OUTPUT_DATA_BUFFER) -> Self {
        Self {
            output,
            active: true,
        }
    }

    fn take(
        mut self,
    ) -> (
        Option<windows_062::Win32::Media::MediaFoundation::IMFSample>,
        Option<windows_062::Win32::Media::MediaFoundation::IMFCollection>,
    ) {
        self.active = false;
        // SAFETY: the guard exclusively owns cleanup of these ManuallyDrop
        // fields until they are taken exactly once.
        unsafe {
            (
                ManuallyDrop::take(&mut (*self.output).pSample),
                ManuallyDrop::take(&mut (*self.output).pEvents),
            )
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessOutputBufferGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: the guard was created from a live output buffer and is
            // the sole owner of these ManuallyDrop COM fields.
            unsafe {
                drop(ManuallyDrop::take(&mut (*self.output).pSample));
                drop(ManuallyDrop::take(&mut (*self.output).pEvents));
            }
        }
    }
}

#[cfg(windows)]
pub struct H264Decoder<'runtime> {
    _runtime: &'runtime MediaFoundationRuntime,
    transform: windows_062::Win32::Media::MediaFoundation::IMFTransform,
    input_stream: u32,
    output_stream: u32,
    width: u32,
    height: u32,
    _com_apartment: ComApartment,
}

#[cfg(windows)]
impl<'runtime> H264Decoder<'runtime> {
    /// Activate a local synchronous H.264 decoder and negotiate NV12 output.
    pub fn new(
        runtime: &'runtime MediaFoundationRuntime,
        width: u32,
        height: u32,
    ) -> Result<Self, MediaFoundationError> {
        let com_apartment = ComApartment::initialize()?;
        if width == 0
            || height == 0
            || width % 2 != 0
            || height % 2 != 0
            || width > crate::airplay::video::MAX_FRAME_DIMENSION
            || height > crate::airplay::video::MAX_FRAME_DIMENSION
        {
            return Err(MediaFoundationError::InvalidDimensions);
        }

        let input = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_H264,
        };
        let mut raw: *mut Option<windows_062::Win32::Media::MediaFoundation::IMFActivate> =
            std::ptr::null_mut();
        let mut count = 0u32;
        let flags = MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_LOCALMFT | MFT_ENUM_FLAG_SORTANDFILTER;

        // SAFETY: input is a valid registration descriptor; raw/count are
        // writable outputs. ActivationArray owns the returned references.
        unsafe {
            MFTEnumEx(
                MFT_CATEGORY_VIDEO_DECODER,
                flags,
                Some(&input),
                None,
                &mut raw,
                &mut count,
            )
        }
        .map_err(|error| MediaFoundationError::EnumerationFailed(error.code().0))?;

        let activations = ActivationArray { ptr: raw, count };
        let activation = unsafe { activations.ptr.as_ref().and_then(Option::as_ref) }
            .ok_or(MediaFoundationError::NoH264Decoder)?
            .clone();

        // SAFETY: activation is a live IMFActivate returned by MFTEnumEx.
        let transform = unsafe {
            activation.ActivateObject::<windows_062::Win32::Media::MediaFoundation::IMFTransform>()
        }
        .map_err(|error| MediaFoundationError::ActivationFailed(error.code().0))?;
        drop(activations);

        let input_type = unsafe { MFCreateMediaType() }
            .map_err(|error| MediaFoundationError::MediaTypeFailed(error.code().0))?;
        let frame_size = (u64::from(width) << 32) | u64::from(height);
        let frame_rate = (30u64 << 32) | 1;
        // SAFETY: all keys are standard Media Foundation media-type attributes.
        unsafe {
            input_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .and_then(|_| input_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264))
                .and_then(|_| input_type.SetUINT64(&MF_MT_FRAME_SIZE, frame_size))
                .and_then(|_| input_type.SetUINT64(&MF_MT_FRAME_RATE, frame_rate))
                .and_then(|_| input_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, (1u64 << 32) | 1))
                .and_then(|_| {
                    input_type
                        .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                })
        }
        .map_err(|error| MediaFoundationError::MediaTypeFailed(error.code().0))?;

        let mut input_stream = 0u32;
        let mut output_stream = 0u32;
        let mut input_ids = [0u32; 1];
        let mut output_ids = [0u32; 1];
        // GetStreamIDs may return E_NOTIMPL; stream zero is the documented fallback.
        if unsafe { transform.GetStreamIDs(&mut input_ids, &mut output_ids) }.is_ok() {
            input_stream = input_ids[0];
            output_stream = output_ids[0];
        }

        // SAFETY: stream ID and media type belong to this transform.
        unsafe { transform.SetInputType(input_stream, &input_type, 0) }
            .map_err(|error| MediaFoundationError::InputTypeFailed(error.code().0))?;

        let mut selected_output = None;
        for index in 0..64u32 {
            let candidate = match unsafe { transform.GetOutputAvailableType(output_stream, index) }
            {
                Ok(media_type) => media_type,
                Err(_) => break,
            };
            if unsafe { candidate.GetGUID(&MF_MT_SUBTYPE) }
                .is_ok_and(|subtype| subtype == MFVideoFormat_NV12)
            {
                selected_output = Some(candidate);
                break;
            }
        }
        let output_type = selected_output.ok_or(MediaFoundationError::Nv12OutputUnavailable)?;
        // SAFETY: this is one of the output types advertised by the transform.
        unsafe { transform.SetOutputType(output_stream, &output_type, 0) }
            .map_err(|error| MediaFoundationError::OutputTypeFailed(error.code().0))?;

        tracing::info!(
            width,
            height,
            input_stream,
            output_stream,
            "Windows H.264 decoder MFT activated with NV12 output"
        );

        Ok(Self {
            _runtime: runtime,
            transform,
            input_stream,
            output_stream,
            width,
            height,
            _com_apartment: com_apartment,
        })
    }

    /// Re-negotiate the decoder output after MFT_E_TRANSFORM_STREAM_CHANGE.
    ///
    /// The H.264 decoder can expose a new output type when the bitstream's
    /// sequence parameters change. Keep NV12 as the presentation format and
    /// refresh dimensions from the newly selected media type when available.
    fn refresh_output_type(&mut self) -> Result<(), MediaFoundationError> {
        let mut selected_output = None;
        for index in 0..64u32 {
            let candidate = match unsafe {
                self.transform
                    .GetOutputAvailableType(self.output_stream, index)
            } {
                Ok(media_type) => media_type,
                Err(_) => break,
            };
            if unsafe { candidate.GetGUID(&MF_MT_SUBTYPE) }
                .is_ok_and(|subtype| subtype == MFVideoFormat_NV12)
            {
                selected_output = Some(candidate);
                break;
            }
        }

        let output_type = selected_output.ok_or(MediaFoundationError::Nv12OutputUnavailable)?;
        unsafe {
            self.transform
                .SetOutputType(self.output_stream, &output_type, 0)
        }
        .map_err(|error| MediaFoundationError::OutputTypeFailed(error.code().0))?;

        // Read the committed type rather than trusting the enumerated
        // candidate: transforms may adjust attributes while accepting it.
        let current_type = unsafe { self.transform.GetOutputCurrentType(self.output_stream) }
            .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
        let major_type = unsafe { current_type.GetGUID(&MF_MT_MAJOR_TYPE) }
            .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
        let subtype = unsafe { current_type.GetGUID(&MF_MT_SUBTYPE) }
            .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
        if major_type != MFMediaType_Video || subtype != MFVideoFormat_NV12 {
            return Err(MediaFoundationError::Nv12OutputUnavailable);
        }
        let frame_size = unsafe { current_type.GetUINT64(&MF_MT_FRAME_SIZE) }
            .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
        let width = (frame_size >> 32) as u32;
        let height = frame_size as u32;
        if width == 0
            || height == 0
            || width % 2 != 0
            || height % 2 != 0
            || width > crate::airplay::video::MAX_FRAME_DIMENSION
            || height > crate::airplay::video::MAX_FRAME_DIMENSION
        {
            return Err(MediaFoundationError::InvalidDimensions);
        }
        self.width = width;
        self.height = height;

        tracing::info!(
            width = self.width,
            height = self.height,
            "H.264 decoder output type refreshed after stream change"
        );
        Ok(())
    }

    /// Submit one complete Annex-B H.264 access unit.
    pub fn submit_access_unit(&mut self, access_unit: &[u8]) -> Result<(), MediaFoundationError> {
        if access_unit.is_empty() {
            return Err(MediaFoundationError::EmptyInput);
        }
        let length =
            u32::try_from(access_unit.len()).map_err(|_| MediaFoundationError::InputTooLarge)?;
        let buffer = unsafe { MFCreateMemoryBuffer(length) }
            .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?;
        let mut destination = std::ptr::null_mut();
        // SAFETY: Lock exposes writable storage until the matching Unlock.
        unsafe { buffer.Lock(&mut destination, None, None) }
            .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?;
        let buffer_lock = MediaBufferLock::new(&buffer);
        if destination.is_null() {
            return Err(MediaFoundationError::NullBuffer);
        }
        // SAFETY: the allocated buffer has at least length bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(access_unit.as_ptr(), destination, access_unit.len());
        }
        buffer_lock.unlock()?;
        unsafe { buffer.SetCurrentLength(length) }
            .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?;

        let sample = unsafe { MFCreateSample() }
            .map_err(|error| MediaFoundationError::SampleFailed(error.code().0))?;
        unsafe { sample.AddBuffer(&buffer) }
            .map_err(|error| MediaFoundationError::SampleFailed(error.code().0))?;
        unsafe { self.transform.ProcessInput(self.input_stream, &sample, 0) }
            .map_err(|error| MediaFoundationError::ProcessInputFailed(error.code().0))?;
        Ok(())
    }

    /// Submit one access unit and collect all immediately available output.
    ///
    /// Existing output is drained before accepting new input, which helps
    /// synchronous MFTs that refuse input while decoded samples are pending.
    /// Each drain is bounded so a malformed or unusual transform cannot keep
    /// this call busy indefinitely.
    pub fn submit_access_unit_and_drain(
        &mut self,
        access_unit: &[u8],
    ) -> Result<Vec<DecodedNv12Frame>, MediaFoundationError> {
        const MAX_INPUT_RETRIES: usize = 4;

        let mut frames = Vec::with_capacity(MAX_FRAMES_PER_DRAIN);
        let mut decoded_bytes = 0usize;
        for attempt in 0..MAX_INPUT_RETRIES {
            let remaining = MAX_FRAMES_PER_DRAIN.saturating_sub(frames.len());
            let drained = self.drain_available_frames_with_budget(
                remaining,
                MAX_DECODED_BYTES_PER_ACCESS_UNIT.saturating_sub(decoded_bytes),
            )?;
            decoded_bytes = decoded_bytes.saturating_add(frame_bytes_total(&drained)?);
            frames.extend(drained);
            match self.submit_access_unit(access_unit) {
                Ok(()) => {
                    let remaining = MAX_FRAMES_PER_DRAIN.saturating_sub(frames.len());
                    let drained = self.drain_available_frames_with_budget(
                        remaining,
                        MAX_DECODED_BYTES_PER_ACCESS_UNIT.saturating_sub(decoded_bytes),
                    )?;
                    decoded_bytes = decoded_bytes.saturating_add(frame_bytes_total(&drained)?);
                    frames.extend(drained);
                    return Ok(frames);
                }
                Err(MediaFoundationError::ProcessInputFailed(hr)) if hr == MF_E_NOTACCEPTING_HR => {
                    if frames.len() == MAX_FRAMES_PER_DRAIN {
                        return Err(MediaFoundationError::OutputBacklog);
                    }
                    if attempt + 1 == MAX_INPUT_RETRIES {
                        return Err(MediaFoundationError::ProcessInputFailed(hr));
                    }
                    // The transform still has output queued. Drain another
                    // bounded batch before retrying the same not-yet-accepted
                    // access unit.
                }
                Err(error) => return Err(error),
            }
        }

        Err(MediaFoundationError::ProcessInputFailed(
            MF_E_NOTACCEPTING_HR,
        ))
    }

    /// Submit one Annex-B access unit, drain decoded frames, and convert
    /// each NV12 output into tightly packed BGRA for the desktop mailbox.
    pub fn submit_access_unit_and_drain_bgra(
        &mut self,
        access_unit: &[u8],
    ) -> Result<Vec<crate::airplay::video::BgraFrame>, MediaFoundationError> {
        self.submit_access_unit_and_drain(access_unit)?
            .into_iter()
            .map(|frame| {
                frame
                    .to_bgra()
                    .map_err(MediaFoundationError::FrameConversion)
            })
            .collect()
    }

    /// Retrieve up to the requested number of immediately available frames.
    ///
    /// The effective limit is capped to keep a single media-worker turn bounded,
    /// even when callers pass an unexpectedly large value.
    pub fn drain_available_frames(
        &mut self,
        limit: usize,
    ) -> Result<Vec<DecodedNv12Frame>, MediaFoundationError> {
        self.drain_available_frames_with_budget(limit, MAX_DECODED_BYTES_PER_ACCESS_UNIT)
    }

    fn drain_available_frames_with_budget(
        &mut self,
        limit: usize,
        byte_budget: usize,
    ) -> Result<Vec<DecodedNv12Frame>, MediaFoundationError> {
        let limit = bounded_drain_limit(limit);
        let mut frames = Vec::with_capacity(limit);
        let mut decoded_bytes = 0usize;
        for _ in 0..limit {
            match self.try_get_frame_with_budget(byte_budget.saturating_sub(decoded_bytes))? {
                Some(frame) => {
                    let next_bytes = decoded_bytes
                        .checked_add(frame.data.len())
                        .ok_or(MediaFoundationError::FrameSizeOverflow)?;
                    if next_bytes > byte_budget {
                        return Err(MediaFoundationError::OutputMemoryBudgetExceeded);
                    }
                    decoded_bytes = next_bytes;
                    frames.push(frame);
                }
                None => break,
            }
        }
        Ok(frames)
    }

    /// Retrieve one decoded NV12 frame, or None when more input is required.
    pub fn try_get_frame(&mut self) -> Result<Option<DecodedNv12Frame>, MediaFoundationError> {
        self.try_get_frame_with_budget(MAX_DECODED_NV12_BYTES)
    }

    fn try_get_frame_with_budget(
        &mut self,
        max_frame_bytes: usize,
    ) -> Result<Option<DecodedNv12Frame>, MediaFoundationError> {
        const MAX_STREAM_CHANGE_RETRIES: usize = 4;
        let mut stream_change_retries = 0;

        loop {
            let stream_info = unsafe { self.transform.GetOutputStreamInfo(self.output_stream) }
                .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
            let caller_allocates =
                stream_info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) == 0;

            let supplied_sample = if caller_allocates {
                let frame_bytes = self
                    .width
                    .checked_mul(self.height)
                    .and_then(|pixels| pixels.checked_mul(3))
                    .map(|bytes| bytes / 2)
                    .ok_or(MediaFoundationError::FrameSizeOverflow)?;
                let buffer_size = stream_info.cbSize.max(frame_bytes);
                if buffer_size as usize > MAX_DECODED_NV12_BYTES {
                    return Err(MediaFoundationError::OutputBufferTooLarge);
                }
                let buffer = unsafe { MFCreateMemoryBuffer(buffer_size) }
                    .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?;
                let sample = unsafe { MFCreateSample() }
                    .map_err(|error| MediaFoundationError::SampleFailed(error.code().0))?;
                unsafe { sample.AddBuffer(&buffer) }
                    .map_err(|error| MediaFoundationError::SampleFailed(error.code().0))?;
                Some(sample)
            } else {
                None
            };

            let mut output = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: self.output_stream,
                pSample: ManuallyDrop::new(supplied_sample),
                dwStatus: 0,
                pEvents: ManuallyDrop::new(None),
            };
            // Keep ownership of both generated COM fields across the FFI call.
            // If an unwind occurs while ProcessOutput is executing, the guard
            // releases any sample/event references that were left in the buffer.
            let output_guard = ProcessOutputBufferGuard::new(&mut output);
            let mut status = 0u32;
            let result = unsafe {
                self.transform
                    .ProcessOutput(0, std::slice::from_mut(&mut output), &mut status)
            };
            let (sample, events) = output_guard.take();
            drop(events);

            if let Err(error) = result {
                if error.code().0 == MF_E_TRANSFORM_NEED_MORE_INPUT_HR {
                    return Ok(None);
                }
                if error.code().0 == MF_E_TRANSFORM_STREAM_CHANGE_HR {
                    drop(sample);
                    stream_change_retries += 1;
                    if stream_change_retries > MAX_STREAM_CHANGE_RETRIES {
                        return Err(MediaFoundationError::RepeatedOutputStreamChange);
                    }
                    self.refresh_output_type()?;
                    continue;
                }
                return Err(MediaFoundationError::ProcessOutputFailed(error.code().0));
            }
            let Some(sample) = sample else {
                return Ok(None);
            };

            // Query the negotiated output layout before copying the sample. The
            // current length must cover every pitched row in both NV12 planes.
            let output_type = unsafe { self.transform.GetOutputCurrentType(self.output_stream) }
                .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
            // The current sample's negotiated media type is authoritative.
            // Reject unexpected formats instead of interpreting their memory
            // layout as NV12 planes.
            let major_type = unsafe { output_type.GetGUID(&MF_MT_MAJOR_TYPE) }
                .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
            let subtype = unsafe { output_type.GetGUID(&MF_MT_SUBTYPE) }
                .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
            if major_type != MFMediaType_Video || subtype != MFVideoFormat_NV12 {
                return Err(MediaFoundationError::Nv12OutputUnavailable);
            }
            let frame_size = unsafe { output_type.GetUINT64(&MF_MT_FRAME_SIZE) }
                .map_err(|error| MediaFoundationError::OutputInfoFailed(error.code().0))?;
            let width = (frame_size >> 32) as u32;
            let height = frame_size as u32;
            if width == 0
                || height == 0
                || width % 2 != 0
                || height % 2 != 0
                || width > crate::airplay::video::MAX_FRAME_DIMENSION
                || height > crate::airplay::video::MAX_FRAME_DIMENSION
            {
                return Err(MediaFoundationError::InvalidDimensions);
            }
            let signed_stride = unsafe { output_type.GetUINT32(&MF_MT_DEFAULT_STRIDE) }
                .map(|value| value as i32)
                .unwrap_or(width as i32);
            let stride = signed_stride.unsigned_abs() as usize;
            if stride < width as usize {
                return Err(MediaFoundationError::FrameConversion(
                    crate::airplay::video::FrameConversionError::InvalidStride,
                ));
            }
            let y_bytes = stride
                .checked_mul(height as usize)
                .ok_or(MediaFoundationError::FrameSizeOverflow)?;
            let uv_bytes = stride
                .checked_mul(height as usize / 2)
                .ok_or(MediaFoundationError::FrameSizeOverflow)?;
            let required_length = y_bytes
                .checked_add(uv_bytes)
                .ok_or(MediaFoundationError::FrameSizeOverflow)?;
            if required_length > MAX_DECODED_NV12_BYTES {
                return Err(MediaFoundationError::OutputBufferTooLarge);
            }

            let buffer = unsafe { sample.ConvertToContiguousBuffer() }
                .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?;
            let current_length = unsafe { buffer.GetCurrentLength() }
                .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?
                as usize;
            if current_length > MAX_DECODED_NV12_BYTES {
                return Err(MediaFoundationError::OutputBufferTooLarge);
            }
            if current_length > max_frame_bytes {
                return Err(MediaFoundationError::OutputMemoryBudgetExceeded);
            }
            if current_length < required_length {
                return Err(MediaFoundationError::OutputBufferTooSmall {
                    actual: current_length,
                    required: required_length,
                });
            }
            let mut source = std::ptr::null_mut();
            unsafe { buffer.Lock(&mut source, None, None) }
                .map_err(|error| MediaFoundationError::BufferFailed(error.code().0))?;
            let buffer_lock = MediaBufferLock::new(&buffer);
            if source.is_null() {
                return Err(MediaFoundationError::NullBuffer);
            }
            // SAFETY: current_length is the valid data length reported by MF.
            let mut data = unsafe { std::slice::from_raw_parts(source, current_length) }.to_vec();
            buffer_lock.unlock()?;
            if signed_stride < 0 {
                crate::airplay::video::normalize_nv12_bottom_up(&mut data, width, height, stride)
                    .map_err(MediaFoundationError::FrameConversion)?;
            }

            if (width, height) != (self.width, self.height) {
                tracing::info!(
                    old_width = self.width,
                    old_height = self.height,
                    width,
                    height,
                    "Media Foundation decoder output resolution changed"
                );
                self.width = width;
                self.height = height;
            }

            return Ok(Some(DecodedNv12Frame {
                width,
                height,
                stride,
                data,
            }));
        }
    }
}

/// Maximum number of decoded frames collected during one drain operation.
const MAX_FRAMES_PER_DRAIN: usize = 16;

/// Return the bounded frame count used by one decoder drain operation.
fn bounded_drain_limit(requested: usize) -> usize {
    requested.min(MAX_FRAMES_PER_DRAIN)
}

/// Maximum Annex-B access-unit size accepted by the decode pipeline.
#[cfg(windows)]
const MAX_DECODE_ACCESS_UNIT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum NV12 output buffer accepted from a Media Foundation transform.
#[cfg(windows)]
const MAX_DECODED_NV12_BYTES: usize = 128 * 1024 * 1024;

/// Maximum decoded NV12 memory retained for one submitted access unit.
const MAX_DECODED_BYTES_PER_ACCESS_UNIT: usize = 256 * 1024 * 1024;

/// Sum frame payload sizes with overflow checking.
fn frame_bytes_total(frames: &[DecodedNv12Frame]) -> Result<usize, MediaFoundationError> {
    frames.iter().try_fold(0usize, |total, frame| {
        total
            .checked_add(frame.data.len())
            .ok_or(MediaFoundationError::FrameSizeOverflow)
    })
}

/// Limits consecutive decoder rebuilds until a real frame is decoded.
///
/// A successful rebuild alone does not prove the decoder recovered. The
/// budget is reset only after at least one frame has been decoded and
/// published, preventing repeated rebuild loops on a broken stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderRecoveryPolicy {
    attempts_without_frame: u8,
    max_attempts: u8,
}

impl Default for DecoderRecoveryPolicy {
    fn default() -> Self {
        Self {
            attempts_without_frame: 0,
            max_attempts: 2,
        }
    }
}

impl DecoderRecoveryPolicy {
    /// Reserve one rebuild attempt, returning false after the retry budget is exhausted.
    pub fn begin_rebuild(&mut self) -> bool {
        if self.attempts_without_frame >= self.max_attempts {
            return false;
        }
        self.attempts_without_frame += 1;
        true
    }

    /// Reset the retry budget only after decoded output proves recovery.
    pub fn record_decoded_frame(&mut self) {
        self.attempts_without_frame = 0;
    }

    /// Number of rebuild attempts since the last decoded frame.
    pub fn attempts_without_frame(&self) -> u8 {
        self.attempts_without_frame
    }
}

/// H.264 decode-to-frame pipeline for one mirror session.
///
/// Construct and use this value on the dedicated media worker thread. It
/// accepts complete Annex-B access units or encrypted AVCC access units when
/// supplied with a valid per-stream cipher, decodes them via Media Foundation,
/// publishes native NV12 output into the bounded latest-frame mailbox. It
/// deliberately does not unwrap FairPlay keys or reconstruct transport fragments.
#[cfg(windows)]
pub struct H264FramePipeline<'runtime> {
    decoder: H264Decoder<'runtime>,
    parameter_sets: Vec<u8>,
    recovery: DecoderRecoveryPolicy,
    frames: std::sync::Arc<crate::airplay::video::LatestFrameMailbox>,
}

#[cfg(windows)]
impl<'runtime> H264FramePipeline<'runtime> {
    /// Create the decoder pipeline for a negotiated H.264 stream.
    pub fn new(
        runtime: &'runtime MediaFoundationRuntime,
        width: u32,
        height: u32,
        frames: std::sync::Arc<crate::airplay::video::LatestFrameMailbox>,
    ) -> Result<Self, MediaFoundationError> {
        let decoder = H264Decoder::new(runtime, width, height)?;
        Ok(Self {
            decoder,
            parameter_sets: Vec::new(),
            recovery: DecoderRecoveryPolicy::default(),
            frames,
        })
    }

    /// Build a decoder directly from the dimensions carried by the stream avcC SPS.
    pub fn from_avc_configuration(
        runtime: &'runtime MediaFoundationRuntime,
        configuration: &crate::airplay::video::AvcConfiguration,
        frames: std::sync::Arc<crate::airplay::video::LatestFrameMailbox>,
    ) -> Result<Self, MediaFoundationError> {
        let dimensions = configuration
            .video_dimensions()
            .map_err(MediaFoundationError::InvalidAvcConfiguration)?
            .ok_or(MediaFoundationError::MissingSps)?;
        let mut pipeline = Self::new(runtime, dimensions.width, dimensions.height, frames)?;

        // avcC carries the stream's SPS/PPS. Submit them before the first
        // picture so Media Foundation has the codec state needed to decode
        // the first IDR access unit once encrypted video becomes available.
        pipeline.parameter_sets = configuration.parameter_sets_annex_b();
        if !pipeline.parameter_sets.is_empty() {
            let _ = pipeline
                .decoder
                .submit_access_unit_and_drain(&pipeline.parameter_sets)?;
        }

        Ok(pipeline)
    }

    /// Decode one complete, already-decrypted Annex-B access unit.
    ///
    /// Returns the number of output frames published. The mailbox retains
    /// only the newest frame, so slow UI rendering cannot grow memory usage.
    pub fn submit_access_unit(
        &mut self,
        access_unit: &[u8],
    ) -> Result<usize, MediaFoundationError> {
        if access_unit.len() > MAX_DECODE_ACCESS_UNIT_BYTES {
            return Err(MediaFoundationError::InputTooLarge);
        }

        let decoded = self.decoder.submit_access_unit_and_drain(access_unit)?;
        let mut published = 0usize;
        for frame in decoded {
            self.frames
                .publish_nv12(crate::airplay::video::OwnedNv12Frame {
                    width: frame.width,
                    height: frame.height,
                    // Media Foundation exposes one default stride for both NV12
                    // planes; keep the mailbox representation plane-specific
                    // for decoder backends that can provide distinct pitches.
                    y_stride: frame.stride,
                    uv_stride: frame.stride,
                    data: frame.data,
                })
                .map_err(MediaFoundationError::FrameMailbox)?;
            published = published.saturating_add(1);
        }
        if published > 0 {
            self.recovery.record_decoded_frame();
        }
        Ok(published)
    }

    /// Decrypt and decode one complete encrypted AVCC access unit.
    ///
    /// The caller must supply the cipher for this exact stream and invoke
    /// this method once per access unit in sender order. FairPlay key unwrap
    /// and transport-fragment reconstruction remain outside this method.
    pub fn submit_encrypted_access_unit(
        &mut self,
        processor: &crate::airplay::video::MirrorStreamProcessor,
        cipher: &mut crate::airplay::mirror_crypto::MirrorStreamCipher,
        encrypted_payload: &[u8],
    ) -> Result<usize, MediaFoundationError> {
        let annex_b = processor
            .decrypt_video_packet(cipher, encrypted_payload)
            .map_err(MediaFoundationError::VideoDecryption)?;
        self.submit_access_unit(&annex_b)
    }

    /// Recreate the Media Foundation transform after a fatal decoder-state error.
    ///
    /// The replacement is fully initialized and receives the cached SPS/PPS
    /// before it replaces the active transform. If initialization fails, the
    /// current decoder remains available to the caller for diagnostics.
    pub fn rebuild_decoder(&mut self, width: u32, height: u32) -> Result<(), MediaFoundationError> {
        if !self.recovery.begin_rebuild() {
            return Err(MediaFoundationError::DecoderRecoveryLimitReached);
        }
        let mut replacement = H264Decoder::new(self.decoder._runtime, width, height)?;
        if !self.parameter_sets.is_empty() {
            let _ = replacement.submit_access_unit_and_drain(&self.parameter_sets)?;
        }
        self.frames
            .clear()
            .map_err(MediaFoundationError::FrameMailbox)?;
        self.decoder = replacement;
        tracing::info!(width, height, "H.264 decoder transform rebuilt");
        Ok(())
    }

    /// Discard any pending frame when this mirror session is ending.
    pub fn clear_pending_frame(&self) -> Result<(), MediaFoundationError> {
        self.frames
            .clear()
            .map_err(MediaFoundationError::FrameMailbox)
    }
}

/// Errors from initializing the Windows media runtime and inspecting decoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFoundationError {
    StartupFailed(i32),
    ComInitializationFailed(i32),
    EnumerationFailed(i32),
    InvalidDimensions,
    MissingSps,
    InvalidAvcConfiguration(crate::airplay::video::AvcConfigError),
    NoH264Decoder,
    ActivationFailed(i32),
    MediaTypeFailed(i32),
    InputTypeFailed(i32),
    OutputTypeFailed(i32),
    Nv12OutputUnavailable,
    EmptyInput,
    InputTooLarge,
    BufferFailed(i32),
    SampleFailed(i32),
    NullBuffer,
    ProcessInputFailed(i32),
    OutputInfoFailed(i32),
    FrameSizeOverflow,
    OutputBufferTooLarge,
    OutputBufferTooSmall { actual: usize, required: usize },
    VideoDecryption(crate::airplay::video::EncryptedAccessUnitError),
    FrameConversion(crate::airplay::video::FrameConversionError),
    FrameMailbox(crate::airplay::video::FrameMailboxError),
    ProcessOutputFailed(i32),
    RepeatedOutputStreamChange,
    OutputBacklog,
    OutputMemoryBudgetExceeded,
    DecoderRecoveryLimitReached,
}

impl fmt::Display for MediaFoundationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupFailed(hr) => {
                write!(
                    f,
                    "Media Foundation startup failed (HRESULT 0x{:08X})",
                    *hr as u32
                )
            }
            Self::ComInitializationFailed(hr) => write!(
                f,
                "COM MTA initialization failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::EnumerationFailed(hr) => {
                write!(
                    f,
                    "Media Foundation decoder enumeration failed (HRESULT 0x{:08X})",
                    *hr as u32
                )
            }
            Self::InvalidDimensions => f.write_str("invalid H.264 frame dimensions"),
            Self::MissingSps => f.write_str("AVC configuration does not contain an SPS"),
            Self::InvalidAvcConfiguration(error) => {
                write!(f, "AVC configuration SPS is invalid: {error}")
            }
            Self::NoH264Decoder => {
                f.write_str("no synchronous/local H.264 decoder MFT is registered")
            }
            Self::ActivationFailed(hr) => write!(
                f,
                "H.264 decoder activation failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::MediaTypeFailed(hr) => write!(
                f,
                "Media Foundation media type operation failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::InputTypeFailed(hr) => write!(
                f,
                "H.264 decoder rejected input type (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::OutputTypeFailed(hr) => write!(
                f,
                "H.264 decoder rejected NV12 output type (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::Nv12OutputUnavailable => {
                f.write_str("H.264 decoder does not advertise NV12 output")
            }
            Self::EmptyInput => f.write_str("H.264 access unit is empty"),
            Self::InputTooLarge => {
                f.write_str("H.264 access unit exceeds Media Foundation buffer limits")
            }
            Self::BufferFailed(hr) => write!(
                f,
                "Media Foundation buffer operation failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::SampleFailed(hr) => write!(
                f,
                "Media Foundation sample operation failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::NullBuffer => f.write_str("Media Foundation returned a null buffer pointer"),
            Self::ProcessInputFailed(hr) => write!(
                f,
                "H.264 decoder input failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::OutputInfoFailed(hr) => write!(
                f,
                "H.264 decoder output query failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::FrameSizeOverflow => f.write_str("decoded frame allocation size overflowed"),
            Self::OutputBufferTooLarge => {
                f.write_str("Media Foundation output buffer exceeds the 128 MiB limit")
            }
            Self::OutputBufferTooSmall { actual, required } => write!(
                f,
                "Media Foundation NV12 output buffer is truncated: {actual} bytes available, {required} required"
            ),
            Self::VideoDecryption(error) => {
                write!(f, "encrypted H.264 access unit decryption failed: {error}")
            }
            Self::FrameConversion(error) => {
                write!(f, "decoded NV12 frame conversion failed: {error}")
            }
            Self::FrameMailbox(error) => {
                write!(f, "decoded-frame mailbox publish failed: {error}")
            }
            Self::ProcessOutputFailed(hr) => write!(
                f,
                "H.264 decoder output failed (HRESULT 0x{:08X})",
                *hr as u32
            ),
            Self::RepeatedOutputStreamChange => {
                f.write_str("H.264 decoder repeatedly changed its output type")
            }
            Self::OutputBacklog => {
                f.write_str("H.264 decoder output backlog exceeded the per-access-unit frame limit")
            }
            Self::OutputMemoryBudgetExceeded => f.write_str(
                "H.264 decoded output exceeded the 256 MiB per-access-unit memory budget",
            ),
            Self::DecoderRecoveryLimitReached => {
                f.write_str("H.264 decoder rebuild retry limit reached before a frame was decoded")
            }
        }
    }
}

impl std::error::Error for MediaFoundationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_drain_limit_is_bounded() {
        assert_eq!(bounded_drain_limit(0), 0);
        assert_eq!(bounded_drain_limit(1), 1);
        assert_eq!(
            bounded_drain_limit(MAX_FRAMES_PER_DRAIN),
            MAX_FRAMES_PER_DRAIN
        );
        assert_eq!(bounded_drain_limit(usize::MAX), MAX_FRAMES_PER_DRAIN);
    }

    #[test]
    fn repeated_output_stream_change_has_a_clear_error_message() {
        assert_eq!(
            MediaFoundationError::RepeatedOutputStreamChange.to_string(),
            "H.264 decoder repeatedly changed its output type"
        );
    }

    #[test]
    fn decoder_recovery_policy_limits_rebuilds_until_output_recovers() {
        let mut policy = DecoderRecoveryPolicy::default();
        assert!(policy.begin_rebuild());
        assert!(policy.begin_rebuild());
        assert!(!policy.begin_rebuild());
        assert_eq!(policy.attempts_without_frame(), 2);

        policy.record_decoded_frame();
        assert_eq!(policy.attempts_without_frame(), 0);
        assert!(policy.begin_rebuild());
    }

    #[test]
    fn decoded_frame_payload_total_sums_frame_sizes() {
        let frames = vec![
            DecodedNv12Frame {
                width: 2,
                height: 2,
                stride: 2,
                data: vec![0; 6],
            },
            DecodedNv12Frame {
                width: 2,
                height: 2,
                stride: 2,
                data: vec![0; 10],
            },
        ];
        assert_eq!(frame_bytes_total(&frames).unwrap(), 16);
    }

    #[test]
    fn decoder_output_memory_budget_error_is_actionable() {
        assert_eq!(
            MediaFoundationError::OutputMemoryBudgetExceeded.to_string(),
            "H.264 decoded output exceeded the 256 MiB per-access-unit memory budget"
        );
    }

    #[test]
    fn decoder_output_backlog_error_is_actionable() {
        assert_eq!(
            MediaFoundationError::OutputBacklog.to_string(),
            "H.264 decoder output backlog exceeded the per-access-unit frame limit"
        );
    }

    #[test]
    fn decoder_recovery_limit_error_is_actionable() {
        assert_eq!(
            MediaFoundationError::DecoderRecoveryLimitReached.to_string(),
            "H.264 decoder rebuild retry limit reached before a frame was decoded"
        );
    }

    #[test]
    fn startup_error_contains_hresult() {
        let error = MediaFoundationError::StartupFailed(0x8000_4005u32 as i32);
        assert_eq!(
            error.to_string(),
            "Media Foundation startup failed (HRESULT 0x80004005)"
        );
    }
}
