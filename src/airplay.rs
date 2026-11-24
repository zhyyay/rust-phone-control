//! Built-in AirPlay receiver protocol implementation (in progress).
//!
//! The endpoint publishes mDNS, handles RTSP control and pairing exchanges,
//! negotiates session/event/timing channels, and accepts the screen-mirroring
//! TCP data stream. The RTSP media worker still cannot decrypt sender video
//! until FairPlay key recovery is implemented; the GPUI preview consumes the
//! latest-frame mailbox once a decoded frame is published.
//! Only the screen-mirroring discovery bit is advertised; audio, FairPlay
//! key recovery, PTP synchronization, and other unsupported features remain disabled.

mod config;
#[cfg(windows)]
#[allow(dead_code)]
mod decoder;
mod discovery;
#[allow(dead_code)]
mod event;
#[allow(dead_code)]
mod fairplay;
pub use fairplay::{\n    FairPlayChallenge, FairPlayKeys, FairPlayMessage, FairPlayParseError, FairPlayProviderError,\n    FairPlaySapProvider, MessagePhase,\n    parse_message as parse_fairplay_message,\n};\n#[allow(dead_code)]
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
mod srp_ct;
#[allow(dead_code)]
mod timing;
mod tlv8;
#[allow(dead_code)]
mod video;

#[cfg(windows)]
use sha2::Digest;
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

// Serialize start/stop transitions without holding the receiver data lock
// while network workers are joined. RTSP workers only need RECEIVER, never
// this lifecycle mutex.
#[cfg(windows)]
static RECEIVER_LIFECYCLE: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(windows)]
fn receiver_lifecycle() -> &'static Mutex<()> {
    RECEIVER_LIFECYCLE.get_or_init(|| Mutex::new(()))
}

#[cfg(windows)]
static PAIRING_CODE: OnceLock<String> = OnceLock::new();

#[cfg(windows)]
static PENDING_CONTROLLERS: OnceLock<Mutex<Vec<[u8; 32]>>> = OnceLock::new();

#[cfg(windows)]
fn pending_controllers() -> &'static Mutex<Vec<[u8; 32]>> {
    PENDING_CONTROLLERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Queue a cryptographically verified but not yet approved controller.
#[cfg(windows)]
pub(super) fn queue_pending_controller(public_key: [u8; 32]) -> Result<(), String> {
    if pair_setup::is_controller_public_key_paired(&public_key)? {
        return Ok(());
    }
    let mut pending = pending_controllers()
        .lock()
        .map_err(|_| "pending AirPlay controller lock is poisoned")?;
    if !pending.contains(&public_key) {
        if pending.len() >= 8 {
            return Err("too many pending AirPlay controller approvals".into());
        }
        pending.push(public_key);
        tracing::info!(
            fingerprint = %controller_fingerprint_label(&public_key),
            "AirPlay controller is waiting for local approval"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn controller_fingerprint_label(public_key: &[u8; 32]) -> String {
    let digest = sha2::Sha256::digest(public_key);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(windows)]
pub fn pending_controller_approval() -> Option<String> {
    let pending = pending_controllers().lock().ok()?;
    pending.first().map(controller_fingerprint_label)
}

#[cfg(windows)]
pub fn approve_pending_controller() -> Result<bool, String> {
    let public_key = {
        let pending = pending_controllers()
            .lock()
            .map_err(|_| "pending AirPlay controller lock is poisoned")?;
        let Some(key) = pending.first() else {
            return Ok(false);
        };
        *key
    };
    pair_setup::trust_legacy_controller(public_key)?;
    let mut pending = pending_controllers()
        .lock()
        .map_err(|_| "pending AirPlay controller lock is poisoned")?;
    if pending.first() == Some(&public_key) {
        pending.remove(0);
    }
    tracing::info!(
        fingerprint = %controller_fingerprint_label(&public_key),
        "AirPlay controller approved and persisted"
    );
    Ok(true)
}

#[cfg(windows)]
pub fn reject_pending_controller() -> Result<bool, String> {
    let rejected = {
        let pending = pending_controllers()
            .lock()
            .map_err(|_| "pending AirPlay controller lock is poisoned")?;
        let Some(key) = pending.first() else {
            return Ok(false);
        };
        *key
    };
    pair_setup::deny_legacy_controller(rejected)?;
    let mut pending = pending_controllers()
        .lock()
        .map_err(|_| "pending AirPlay controller lock is poisoned")?;
    if pending.first() == Some(&rejected) {
        pending.remove(0);
    }
    tracing::info!(
        fingerprint = %controller_fingerprint_label(&rejected),
        "AirPlay controller denial persisted"
    );
    Ok(true)
}

#[cfg(windows)]
fn receiver_slot() -> &'static Mutex<Option<ReceiverRuntime>> {
    RECEIVER.get_or_init(|| Mutex::new(None))
}

/// Return the approved AirPlay controller fingerprints shown in the desktop UI.
#[cfg(windows)]
pub fn trusted_controller_fingerprints() -> Result<Vec<String>, String> {
    pair_setup::trusted_controller_fingerprints()
}

/// Revoke a previously approved controller using its public-key fingerprint.
#[cfg(windows)]
pub fn revoke_trusted_controller(fingerprint: &str) -> Result<bool, String> {
    pair_setup::revoke_legacy_controller(fingerprint)
}

/// Return denied controller fingerprints shown in the desktop device-management UI.
#[cfg(windows)]
pub fn denied_controller_fingerprints() -> Result<Vec<String>, String> {
    pair_setup::denied_controller_fingerprints()
}

/// Remove a denial; the controller must still pass first-time approval before connecting.
#[cfg(windows)]
pub fn clear_denied_controller(fingerprint: &str) -> Result<bool, String> {
    pair_setup::clear_legacy_denial(fingerprint)
}

#[cfg(windows)]
pub fn setup_code() -> String {
    PAIRING_CODE
        .get_or_init(pairing::generate_setup_code)
        .clone()
}

#[cfg(windows)]
pub fn start() -> anyhow::Result<()> {
    start_inner(None)
}

/// Start the built-in receiver with an authorized FairPlay SAP provider.
/// The ordinary start() entry point remains fail-closed when no provider is
/// configured.
#[cfg(windows)]
pub fn start_with_fairplay_provider(
    provider: Arc<dyn FairPlaySapProvider>,
) -> anyhow::Result<()> {
    start_inner(Some(provider))
}

#[cfg(windows)]
fn start_inner(
    fairplay_provider: Option<Arc<dyn FairPlaySapProvider>>,
) -> anyhow::Result<()> {
    let _lifecycle = receiver_lifecycle()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay lifecycle lock is poisoned"))?;
    {
        let runtime = receiver_slot()
            .lock()
            .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
        if runtime.is_some() {
            tracing::info!("Built-in AirPlay control endpoint is already running");
            return Ok(());
        }
    }

    // Do slow platform initialization and start worker-owning services without
    // holding the runtime data lock. A newly accepted RTSP client may need to
    // inspect the runtime while startup is still completing.
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
    let server = match fairplay_provider {\n        Some(provider) => server::ControlServer::start_with_fairplay_provider(provider)?,\n        None => server::ControlServer::start()?,\n    };
    let advertisement = discovery::Advertisement::start()?;

    let mut runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
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
    let _lifecycle = receiver_lifecycle()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay lifecycle lock is poisoned"))?;
    // Detach the runtime while holding the global lock, then release the lock
    // before joining network workers. A client may still be finishing a
    // request that needs to inspect the runtime; joining while locked could
    // otherwise deadlock shutdown.
    let runtime = {
        let mut slot = receiver_slot()
            .lock()
            .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
        slot.take()
    };

    let Some(runtime) = runtime else {
        tracing::debug!("AirPlay stop requested while receiver is already stopped");
        return Ok(());
    };

    tracing::info!("AirPlay shutdown: clearing pending video frame");
    let frame_clear_error = runtime.video_frames.clear().err();

    let ReceiverRuntime {
        server,
        advertisement,
        _media_foundation,
        video_frames: _,
    } = runtime;

    tracing::info!("AirPlay shutdown: stopping control server and client workers");
    drop(server);
    tracing::info!("AirPlay shutdown: control server stopped");

    drop(advertisement);
    tracing::info!("AirPlay shutdown: DNS-SD advertisement stopped");

    drop(_media_foundation);
    tracing::info!("AirPlay shutdown: Media Foundation runtime released");
    tracing::info!("Built-in AirPlay control endpoint stopped");

    if let Some(error) = frame_clear_error {
        return Err(anyhow::anyhow!(
            "could not clear the pending AirPlay video frame during shutdown: {error}"
        ));
    }
    Ok(())
}
