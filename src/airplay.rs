//! Optional external AirPlay receiver process integration.
//!
//! The receiver is kept as a separate executable to avoid linking GPL-3.0 code into this app.
#[cfg(windows)]
use std::{
    path::PathBuf,
    process::{Child, Command},
    sync::{Mutex, OnceLock},
};

#[cfg(windows)]
static RECEIVER: OnceLock<Mutex<Option<Child>>> = OnceLock::new();

#[cfg(windows)]
fn receiver_slot() -> &'static Mutex<Option<Child>> {
    RECEIVER.get_or_init(|| Mutex::new(None))
}

#[cfg(windows)]
fn receiver_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("AIRBRIDGE_EXE") {
        let path = PathBuf::from(path);
        anyhow::ensure!(path.is_file(), "AIRBRIDGE_EXE does not point to a file: {}", path.display());
        return Ok(path);
    }

    let executable = std::env::current_exe()?;
    let sibling = executable
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("airbridge.exe");
    anyhow::ensure!(
        sibling.is_file(),
        "AirBridge was not found. Set AIRBRIDGE_EXE to the full path of airbridge.exe, or place airbridge.exe beside phone-desktop.exe."
    );
    Ok(sibling)
}

#[cfg(windows)]
pub fn start() -> anyhow::Result<()> {
    let mut receiver = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay receiver process lock is poisoned"))?;

    if let Some(child) = receiver.as_mut() {
        if child.try_wait()?.is_none() {
            tracing::info!("AirPlay receiver is already running");
            return Ok(());
        }
        *receiver = None;
    }

    let path = receiver_path()?;
    let child = Command::new(&path)
        .spawn()
        .map_err(|error| anyhow::anyhow!("failed to launch {}: {error}", path.display()))?;
    tracing::info!(path = %path.display(), pid = child.id(), "AirPlay receiver started");
    *receiver = Some(child);
    Ok(())
}

#[cfg(windows)]
pub fn stop() -> anyhow::Result<()> {
    let mut receiver = receiver_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("AirPlay receiver process lock is poisoned"))?;

    if let Some(mut child) = receiver.take() {
        if child.try_wait()?.is_none() {
            child.kill()?;
            child.wait()?;
            tracing::info!("AirPlay receiver stopped");
        }
    }
    Ok(())
}
