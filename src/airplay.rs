//! Built-in AirPlay receiver protocol implementation (in progress).
//!
//! The endpoint publishes mDNS, handles RTSP control and pairing exchanges,
//! negotiates session/event/timing channels, and binds the screen-mirroring UDP
//! data port. It parses media packet envelopes but does not yet decrypt video,
//! reassemble frames, decode H.264/HEVC, or render frames in the GPUI window.
//! PTP synchronization and unsupported AirPlay feature bits remain disabled.

mod config;
#[cfg(windows)]
#[allow(dead_code)]
mod decoder;
mod discovery;
#[allow(dead_code)]
mod fairplay;
#[allow(dead_code)]
mod event;
#[allow(dead_code)]
mod media;
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
mod tlv8;
#[allow(dead_code)]
mod timing;
#[allow(dead_code)]
mod video;

#[cfg(windows)]
use std::sync::{Mutex, OnceLock};

#[cfg(windows)]
struct ReceiverRuntime {
    server: server::ControlServer,
    advertisement: discovery::Advertisement,\n    _media_foundation: Option<decoder::MediaFoundationRuntime>,
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
    let server = server::ControlServer::start()?;
    let advertisement = discovery::Advertisement::start()?;
    *runtime = Some(ReceiverRuntime {
        server,
        advertisement,
    });
    tracing::info!(
        "Built-in AirPlay discovery/control endpoint started; secure mirroring is not implemented yet"
    );
    Ok(())
}

#[cfg(windows)]
pub fn stop() -> anyhow::Result<()> {
    let mut runtime = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay runtime lock is poisoned"))?;
    if runtime.take().is_some() {
        tracing::info!("Built-in AirPlay control endpoint stopped");
    }
    Ok(())
}
