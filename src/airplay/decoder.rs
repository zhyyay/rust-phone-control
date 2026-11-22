//! Windows Media Foundation runtime lifecycle for the AirPlay decoder.
//!
//! This is deliberately only the platform-runtime layer. It does not claim to
//! decode encrypted AirPlay packets: FairPlay decryption, access-unit parsing,
//! decoder MFT negotiation, and frame delivery are separate pipeline stages.

use std::fmt;

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

/// Errors from initializing the Windows media runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFoundationError {
    StartupFailed(i32),
}

impl fmt::Display for MediaFoundationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupFailed(hr) => {
                write!(f, "Media Foundation startup failed (HRESULT 0x{:08X})", *hr as u32)
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
