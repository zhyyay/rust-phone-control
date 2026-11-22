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
                tracing::info!(%peer, "AirPlay TCP client accepted; starting handler");
                match thread::Builder::new()
                    .name("airplay-client".to_owned())
                    .spawn(move || handle_client(stream, peer))
                {
                    Ok(_) => tracing::debug!(%peer, "AirPlay client handler thread spawned"),
                    Err(error) => {
                        tracing::error!(%peer, error = %error, "Failed to spawn AirPlay client handler");
                    }
                }
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
    // On Windows, accepted sockets can retain the listener's nonblocking
    // mode. RTSP uses blocking reads with explicit timeouts, so switch each
    // client connection back to blocking mode before handing it to the parser.
    if let Err(error) = stream.set_nonblocking(false) {
        tracing::error!(
            %peer,
            error_kind = ?error.kind(),
            error = %error,
            "Failed to set AirPlay client socket to blocking mode"
        );
        return;
    }

    tracing::info!(%peer, "AirPlay client handler entered");
    match rtsp::serve(stream) {
        Ok(()) => tracing::info!(%peer, "AirPlay client handler completed normally"),
        Err(error) => {
            tracing::error!(
                %peer,
                error_kind = ?error.kind(),
                error = %error,
                "AirPlay RTSP client handler failed"
            );
        }
    }
}
