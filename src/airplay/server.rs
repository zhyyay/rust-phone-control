//! TCP listener lifecycle for the AirPlay control endpoint.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

use super::{config, rtsp};

pub struct ControlServer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ControlServer {
    pub fn start() -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", config::TCP_PORT))
            .with_context(|| format!("bind AirPlay TCP port {}", config::TCP_PORT))?;
        listener
            .set_nonblocking(true)
            .context("set AirPlay listener nonblocking")?;

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("airplay-control".to_owned())
            .spawn(move || run_listener(listener, worker_stop))
            .context("spawn AirPlay control listener")?;

        tracing::info!(port = config::TCP_PORT, "AirPlay control listener started");
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                tracing::warn!("AirPlay control listener thread panicked");
            }
        }
        tracing::info!("AirPlay control listener stopped");
    }
}

fn run_listener(listener: TcpListener, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                tracing::info!(%peer, "AirPlay control connection accepted");
                let _ = thread::Builder::new()
                    .name("airplay-client".to_owned())
                    .spawn(move || handle_client(stream, peer));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(30));
            }
            Err(error) => {
                tracing::error!(error = %error, "AirPlay listener accept failed");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle_client(stream: TcpStream, peer: std::net::SocketAddr) {
    if let Err(error) = rtsp::serve(stream) {
        tracing::debug!(%peer, error = %error, "AirPlay control connection ended");
    }
}
