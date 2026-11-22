//! Built-in AirPlay control-plane prototype.
//!
//! Modules are intentionally separated by responsibility. The current code
//! provides mDNS publication, a TCP listener, OPTIONS, /server-info, and basic binary-plist /info handling.
//! Pair-Setup currently handles the SRP M1-M4 exchange only. Pair-Setup M5/M6,
//! Pair-Verify, FairPlay, encrypted media, and video decoding are not implemented.
//! The endpoint advertises zero feature bits rather than claiming unsupported capabilities.

mod config;
mod discovery;
mod plist;
mod pairing;
mod rtsp;
mod srp;
mod tlv8;
mod server;

#[cfg(windows)]
use std::sync::{Mutex, OnceLock};

#[cfg(windows)]
struct ReceiverRuntime {
    // Drop the TCP listener before withdrawing its discovery record.
    server: server::ControlServer,
    advertisement: discovery::Advertisement,
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
