//! Reverse TCP event channel advertised during AirPlay SETUP.
//!
//! The listener accepts and keeps the sender's event connection alive. Event
//! payload semantics are intentionally not interpreted until that protocol
//! layer is implemented.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(super) struct EventChannel {
    local_addr: SocketAddr,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl EventChannel {
    pub(super) fn bind(expected_peer_ip: std::net::IpAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", 0))?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker = thread::Builder::new()
            .name("airplay-event-channel".to_owned())
            .spawn(move || accept_events(listener, worker_running, expected_peer_ip))?;

        tracing::info!(%local_addr, "AirPlay event channel listening");
        Ok(Self {
            local_addr,
            running,
            worker: Some(worker),
        })
    }

    pub(super) fn port(&self) -> u16 {
        self.local_addr.port()
    }
}

impl Drop for EventChannel {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                tracing::warn!("AirPlay event channel worker panicked");
            }
        }
        tracing::debug!(%self.local_addr, "AirPlay event channel stopped");
    }
}

fn accept_events(listener: TcpListener, running: Arc<AtomicBool>, expected_peer_ip: std::net::IpAddr) {
    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if peer.ip() != expected_peer_ip {
                    tracing::warn!(
                        %peer,
                        %expected_peer_ip,
                        "Rejecting unexpected AirPlay reverse event peer"
                    );
                    continue;
                }
                tracing::info!(%peer, "AirPlay reverse event connection accepted");
                handle_event_stream(stream, &running, peer);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                tracing::warn!(%error, "AirPlay event listener accept failed");
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

fn handle_event_stream(mut stream: TcpStream, running: &AtomicBool, peer: SocketAddr) {
    if let Err(error) = stream.set_nonblocking(false) {
        tracing::warn!(%peer, %error, "Could not make AirPlay event socket blocking");
        return;
    }
    if let Err(error) = stream.set_read_timeout(Some(POLL_INTERVAL)) {
        tracing::warn!(%peer, %error, "Could not configure AirPlay event socket");
        return;
    }

    let mut buffer = [0u8; 4096];
    while running.load(Ordering::Acquire) {
        match stream.read(&mut buffer) {
            Ok(0) => {
                tracing::info!(%peer, "AirPlay event connection closed");
                return;
            }
            Ok(length) => {
                tracing::debug!(%peer, bytes = length, "Received AirPlay event-channel data");
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                tracing::warn!(%peer, %error, "AirPlay event-channel read failed");
                return;
            }
        }
    }
}
