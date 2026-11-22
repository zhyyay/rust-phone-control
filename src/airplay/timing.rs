//! AirPlay NTP-style timing exchange used by single-device mirroring.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const REQUEST_INTERVAL: Duration = Duration::from_secs(3);
const NTP_EPOCH_DELTA: u64 = 2_208_988_800;

pub(super) struct TimingClient {
    local_addr: SocketAddr,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl TimingClient {
    pub(super) fn start(peer_ip: IpAddr, peer_port: u16) -> std::io::Result<Self> {
        let bind_addr = match peer_ip {
            IpAddr::V4(_) => "0.0.0.0:0".parse().expect("valid IPv4 wildcard address"),
            IpAddr::V6(_) => "[::]:0".parse().expect("valid IPv6 wildcard address"),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(POLL_INTERVAL))?;
        let local_addr = socket.local_addr()?;
        let remote_addr = SocketAddr::new(peer_ip, peer_port);
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker = thread::Builder::new()
            .name("airplay-ntp-timing".to_owned())
            .spawn(move || timing_loop(socket, remote_addr, worker_running))?;

        tracing::info!(%local_addr, %remote_addr, "AirPlay NTP timing client started");
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

impl Drop for TimingClient {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                tracing::warn!("AirPlay NTP timing worker panicked");
            }
        }
        tracing::debug!(%self.local_addr, "AirPlay NTP timing client stopped");
    }
}

fn timing_loop(socket: UdpSocket, remote_addr: SocketAddr, running: Arc<AtomicBool>) {
    let mut buffer = [0u8; 256];
    let mut sequence = 0u16;
    let mut next_request = Instant::now();

    while running.load(Ordering::Acquire) {
        if Instant::now() >= next_request {
            sequence = sequence.wrapping_add(1);
            let request = build_timing_request(sequence);
            if let Err(error) = socket.send_to(&request, remote_addr) {
                tracing::warn!(%remote_addr, %error, "AirPlay NTP timing request failed");
            } else {
                tracing::trace!(%remote_addr, sequence, "AirPlay NTP timing request sent");
            }
            next_request = Instant::now() + REQUEST_INTERVAL;
        }

        match socket.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                if peer == remote_addr && is_timing_response(&buffer[..length], sequence) {
                    tracing::debug!(%peer, sequence, "AirPlay NTP timing response received");
                } else {
                    tracing::trace!(%peer, bytes = length, "Ignoring unrelated timing datagram");
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                tracing::warn!(%remote_addr, %error, "AirPlay NTP timing socket failed");
                break;
            }
        }
    }
}

fn build_timing_request(sequence: u16) -> [u8; 32] {
    let mut packet = [0u8; 32];
    packet[0] = 0x80;
    packet[1] = 0xD2;
    packet[2..4].copy_from_slice(&sequence.to_be_bytes());
    packet[24..32].copy_from_slice(&ntp_timestamp().to_be_bytes());
    packet
}

fn is_timing_response(packet: &[u8], sequence: u16) -> bool {
    packet.len() == 32
        && packet[0] == 0x80
        && packet[1] == 0xD3
        && u16::from_be_bytes([packet[2], packet[3]]) == sequence
}

fn ntp_timestamp() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = elapsed.as_secs().saturating_add(NTP_EPOCH_DELTA);
    let fraction = ((u128::from(elapsed.subsec_nanos()) << 32) / 1_000_000_000) as u32;
    (seconds << 32) | u64::from(fraction)
}

#[cfg(test)]
mod tests {
    use super::{build_timing_request, is_timing_response, ntp_timestamp};

    #[test]
    fn builds_airplay_timing_request() {
        let packet = build_timing_request(7);
        assert_eq!(packet.len(), 32);
        assert_eq!(&packet[..4], &[0x80, 0xD2, 0, 7]);
        assert_ne!(&packet[24..32], &[0; 8]);
    }

    #[test]
    fn accepts_only_matching_timing_reply() {
        let mut reply = [0u8; 32];
        reply[0] = 0x80;
        reply[1] = 0xD3;
        reply[2..4].copy_from_slice(&17u16.to_be_bytes());
        assert!(is_timing_response(&reply, 17));
        assert!(!is_timing_response(&reply, 18));
        reply[1] = 0xD2;
        assert!(!is_timing_response(&reply, 17));
    }

    #[test]
    fn ntp_timestamp_uses_1900_epoch() {
        assert!(ntp_timestamp() >> 32 > 2_208_988_800);
    }

    #[test]
    fn timing_client_sends_request_and_accepts_reply() {
        use std::net::UdpSocket;
        use std::time::Duration;

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind fake sender");
        sender
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set sender timeout");
        let sender_addr = sender.local_addr().expect("sender address");
        let client = super::TimingClient::start(sender_addr.ip(), sender_addr.port())
            .expect("start timing client");

        let mut request = [0u8; 64];
        let (length, peer) = sender.recv_from(&mut request).expect("receive timing request");
        assert_eq!(length, 32);
        assert_eq!(&request[..2], &[0x80, 0xD2]);
        assert_eq!(peer.port(), client.port());

        let mut response = [0u8; 32];
        response[0] = 0x80;
        response[1] = 0xD3;
        response[2..4].copy_from_slice(&request[2..4]);
        sender.send_to(&response, peer).expect("send timing response");
    }
}
