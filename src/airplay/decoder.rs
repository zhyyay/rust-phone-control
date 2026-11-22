//! Windows Media Foundation runtime lifecycle for the AirPlay decoder.
//!
//! This is deliberately only the platform-runtime layer. It does not claim to
//! decode encrypted AirPlay packets: FairPlay decryption, access-unit parsing,
//! decoder MFT negotiation, and frame delivery are separate pipeline stages.

use std::fmt;

#[cfg(windows)]
use windows_062::Win32::{
    Media::MediaFoundation::{
        MFTEnumEx, MFT_REGISTER_TYPE_INFO, MFT_CATEGORY_VIDEO_DECODER,
        MFT_ENUM_FLAG_LOCALMFT, MFT_ENUM_FLAG_SORTANDFILTER, MFT_ENUM_FLAG_SYNCMFT,
        MFMediaType_Video, MFVideoFormat_H264, MFVideoFormat_HEVC,
    },
    System::Com::CoTaskMemFree,
};

#[cfg(windows)]
const MF_VERSION: u32 = 0x0002_0070;
#[cfg(windows)]
const MFSTARTUP_FULL: u32 = 0;

#[cfg(windows)]
#[link(name = "mfplat")]
unsafe extern "system" {
    fn MFStartup(version: u32, flags: u32) -> i32;
    fn MFShutdown() -> i32;
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
                for activation in std::slice::from_raw_parts_mut(
                    self.ptr,
                    self.count as usize,
                ) {
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
    let mut raw: *mut Option<
        windows_062::Win32::Media::MediaFoundation::IMFActivate,
    > = std::ptr::null_mut();
    let mut count = 0u32;
    let flags = MFT_ENUM_FLAG_SYNCMFT
        | MFT_ENUM_FLAG_LOCALMFT
        | MFT_ENUM_FLAG_SORTANDFILTER;

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
        Ok(DecoderInventory {
            h264: count_video_decoders(MFVideoFormat_H264)?,
            hevc: count_video_decoders(MFVideoFormat_HEVC)?,
        })
    }
}

/// Errors from initializing the Windows media runtime and inspecting decoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFoundationError {
    StartupFailed(i32),
    EnumerationFailed(i32),
}

impl fmt::Display for MediaFoundationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupFailed(hr) => {
                write!(f, "Media Foundation startup failed (HRESULT 0x{:08X})", *hr as u32)
            }
            Self::EnumerationFailed(hr) => {
                write!(f, "Media Foundation decoder enumeration failed (HRESULT 0x{:08X})", *hr as u32)
            }
        }
    }
}

impl std::error::Error for MediaFoundationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_error_contains_hresult() {
        let error = MediaFoundationError::StartupFailed(0x8000_4005u32 as i32);
        assert_eq!(
            error.to_string(),
            "Media Foundation startup failed (HRESULT 0x80004005)"
        );
    }
}
