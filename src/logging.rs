use anyhow::{Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use tracing_subscriber::EnvFilter;

/// Writes a minimal startup breadcrumb without depending on tracing.
/// This remains useful when GPUI crashes before the normal logger flushes.
pub fn startup_checkpoint(stage: &str) {
    let _ = fs::create_dir_all("logs");
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new("logs").join("startup.log"))
    {
        let _ = writeln!(file, "{stage}");
        let _ = file.flush();
    }
}

pub fn init_logging() -> Result<()> {
    startup_checkpoint("logging: initializing");
    let log_dir = Path::new("logs");
    fs::create_dir_all(log_dir).context("create logs directory")?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("app.log"))
        .context("open logs/app.log")?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,mdns_sd=debug")),
        )
        .with_ansi(false)
        .with_writer(file)
        .init();

    tracing::info!("Rust Phone Control started");
    startup_checkpoint("logging: initialized");
    Ok(())
}
