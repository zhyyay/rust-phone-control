use anyhow::{Context, Result};
use std::{fs::{self, OpenOptions}, path::Path};
use tracing_subscriber::EnvFilter;

pub fn init_logging() -> Result<()> {
    let log_dir = Path::new("logs");
    fs::create_dir_all(log_dir).context("create logs directory")?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("app.log"))
        .context("open logs/app.log")?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_ansi(false)
        .with_writer(file)
        .init();

    tracing::info!("Rust Phone Control started");
    Ok(())
}
