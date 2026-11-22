//! Built-in AirPlay receiver protocol implementation (in progress).
//!
//! The endpoint publishes mDNS, handles RTSP control and pairing exchanges,
//! negotiates session/event/timing channels, and accepts the screen-mirroring
//! TCP data stream. The RTSP media worker still cannot decrypt sender video
//! until FairPlay key recovery is implemented; the GPUI preview consumes the
//! latest-frame mailbox once a decoded frame is published.
//! PTP synchronization and unsupported AirPlay feature bits remain disabled.

mod config;
#[cfg(windows)]
#[allow(dead_code)]
mod decoder;
mod discovery;
#[allow(dead_code)]
mod event;
#[allow(dead_code)]
mod fairplay;
#[allow(dead_code)]
mod media;
#[allow(dead_code)]
mod mirror_crypto;
mod pair_setup;
mod pair_verify;
mod pairing;
#[cfg(windows)]
mod pairing_store;
mod plist;
mod rtsp;
mod server;
#[allow(dead_code)]
mod setup;
mod srp;
#[allow(dead_code)]
mod timing;
mod tlv8;
#[allow(dead_code)]
mod video;

#[cfg(windows)]
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(windows)]
pub use video::{BgraFrame, FrameSnapshot};

#[cfg(windows)]
struct ReceiverRuntime {
    server: server::ControlServer,
    advertisement: discovery::Advertisement,
    _media_foundation: Option<Arc<decoder::MediaFoundationRuntime>>,
    video_frames: Arc<video::LatestFrameMailbox>,
}

#[cfg(windows)]
static RECEIVER: OnceLock<Mutex<Option<ReceiverRuntime>>> = OnceLock::new();

#[cfg(windows)]
static PAIRING_CODE: OnceLock<String> = OnceLock::new();

#[cfg(windows)]
fn receiver_slot() -> &'static Mutex<Option<ReceiverRuntime>> {
    RECEIVER.get_or_init(|| Mutex::new(None))
}

#[cfg(windows)]
pub fn setup_code() -> String {
    PAIRING_CODE
        .get_or_init(pairing::generate_setup_code)
        .clone()
}

#[cfg(windows)]
pub fn start() -> anyhow::Result<()> {
    let mut runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;

    if runtime.is_some() {
        tracing::info!("Built-in AirPlay control endpoint is already running");
        return Ok(());
    }

    let _pairing_code = setup_code();
    let media_foundation = match decoder::MediaFoundationRuntime::startup() {
        Ok(runtime) => Some(Arc::new(runtime)),
        Err(error) => {
            tracing::warn!(%error, "Media Foundation unavailable; AirPlay control remains available");
            None
        }
    };
    if let Some(runtime) = media_foundation.as_ref() {
        let inventory_runtime = Arc::clone(runtime);
        match std::thread::spawn(move || inventory_runtime.decoder_inventory()).join() {
            Ok(Ok(inventory)) => tracing::info!(
                h264_decoders = inventory.h264,
                hevc_decoders = inventory.hevc,
                "Media Foundation video decoder inventory"
            ),
            Ok(Err(error)) => {
                tracing::warn!(%error, "Could not enumerate Media Foundation decoders")
            }
            Err(_) => tracing::warn!("Media Foundation inventory worker panicked"),
        }
    }
    let video_frames = Arc::new(video::LatestFrameMailbox::new());
    let server = server::ControlServer::start()?;
    let advertisement = discovery::Advertisement::start()?;
    *runtime = Some(ReceiverRuntime {
        server,
        advertisement,
        _media_foundation: media_foundation,
        video_frames,
    });
    tracing::info!(
        "Built-in AirPlay discovery/control endpoint started; secure mirroring is not implemented yet"
    );
    Ok(())
}

/// Clone the resources needed by a newly negotiated mirror media worker.
#[cfg(windows)]
pub(super) fn media_pipeline_context() -> anyhow::Result<(
    Option<Arc<decoder::MediaFoundationRuntime>>,
    Arc<video::LatestFrameMailbox>,
)> {
    let runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
    let runtime = runtime
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("AirPlay receiver is not running"))?;
    Ok((
        runtime._media_foundation.clone(),
        Arc::clone(&runtime.video_frames),
    ))
}

/// Publish a decoded BGRA frame for the desktop presentation layer.
#[cfg(windows)]
pub fn publish_video_frame(frame: BgraFrame) -> anyhow::Result<u64> {
    let runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
    let runtime = runtime
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("AirPlay receiver is not running"))?;
    runtime
        .video_frames
        .publish(frame)
        .map_err(|error| anyhow::anyhow!(error))
}

/// Take the newest decoded frame for presentation. Older pending frames are
/// replaced by the mailbox, so consumers never build up an unbounded backlog.
#[cfg(windows)]
pub fn take_latest_video_frame() -> anyhow::Result<Option<FrameSnapshot>> {
    let runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
    let Some(runtime) = runtime.as_ref() else {
        return Ok(None);
    };
    runtime
        .video_frames
        .take_latest()
        .map_err(|error| anyhow::anyhow!(error))
}

#[cfg(windows)]
pub fn stop() -> anyhow::Result<()> {
    let mut runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
    if let Some(runtime) = runtime.take() {
        runtime
            .video_frames
            .clear()
            .map_err(|error| anyhow::anyhow!(error))?;
        tracing::info!("Built-in AirPlay control endpoint stopped");
    }
    Ok(())
}
