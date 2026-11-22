//! Bounded AirPlay media packet parsing and UDP receive lifecycle.
//!
//! Screen-mirroring datagrams use a 128-byte AirPlay-specific header. The RTP
//! parser remains available for RTP-based streams. Neither parser decrypts,
//! authenticates, reassembles, or decodes media payloads.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A parsed RTP version 2 packet. All byte slices borrow from the input packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extension: Option<RtpExtension<'a>>,
    pub payload: &'a [u8],
    pub padding_len: usize,
}

/// The optional RTP header extension, excluding its four-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpExtension<'a> {
    pub profile: u16,
    pub data: &'a [u8],
}

/// Why an RTP packet could not be parsed safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpParseError {
    TruncatedHeader,
    UnsupportedVersion(u8),
    TruncatedCsrcList,
    TruncatedExtensionHeader,
    TruncatedExtensionData,
    InvalidPadding,
}

impl fmt::Display for RtpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("RTP fixed header is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported RTP version {version}")
            }
            Self::TruncatedCsrcList => f.write_str("RTP CSRC list is truncated"),
            Self::TruncatedExtensionHeader => f.write_str("RTP extension header is truncated"),
            Self::TruncatedExtensionData => f.write_str("RTP extension data is truncated"),
            Self::InvalidPadding => f.write_str("RTP padding length is invalid"),
        }
    }
}

impl std::error::Error for RtpParseError {}

/// Parse one complete RTP v2 packet without reading beyond the supplied slice.
///
/// The parser validates the fixed header, CSRC list, optional extension and
/// padding. Payload interpretation and AirPlay-specific decryption happen in
/// later pipeline stages.
pub fn parse_rtp_packet(packet: &[u8]) -> Result<RtpPacket<'_>, RtpParseError> {
    if packet.len() < 12 {
        return Err(RtpParseError::TruncatedHeader);
    }

    let version = packet[0] >> 6;
    if version != 2 {
        return Err(RtpParseError::UnsupportedVersion(version));
    }

    let has_padding = packet[0] & 0x20 != 0;
    let has_extension = packet[0] & 0x10 != 0;
    let csrc_count = usize::from(packet[0] & 0x0f);
    let payload_type = packet[1] & 0x7f;
    let marker = packet[1] & 0x80 != 0;

    let csrc_bytes = csrc_count * 4;
    let mut offset = 12usize;
    let csrc_end = offset + csrc_bytes;
    if csrc_end > packet.len() {
        return Err(RtpParseError::TruncatedCsrcList);
    }

    let mut csrcs = Vec::with_capacity(csrc_count);
    for chunk in packet[offset..csrc_end].chunks_exact(4) {
        csrcs.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    offset = csrc_end;

    let extension = if has_extension {
        if packet.len().saturating_sub(offset) < 4 {
            return Err(RtpParseError::TruncatedExtensionHeader);
        }
        let profile = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let words = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        let extension_bytes = words * 4;
        let data_start = offset + 4;
        let data_end = data_start
            .checked_add(extension_bytes)
            .ok_or(RtpParseError::TruncatedExtensionData)?;
        if data_end > packet.len() {
            return Err(RtpParseError::TruncatedExtensionData);
        }
        offset = data_end;
        Some(RtpExtension {
            profile,
            data: &packet[data_start..data_end],
        })
    } else {
        None
    };

    let padding_len = if has_padding {
        let padding = usize::from(*packet.last().ok_or(RtpParseError::InvalidPadding)?);
        if padding == 0 || padding > packet.len().saturating_sub(offset) {
            return Err(RtpParseError::InvalidPadding);
        }
        padding
    } else {
        0
    };

    let payload_end = packet.len() - padding_len;
    if payload_end < offset {
        return Err(RtpParseError::InvalidPadding);
    }

    Ok(RtpPacket {
        marker,
        payload_type,
        sequence_number: u16::from_be_bytes([packet[2], packet[3]]),
        timestamp: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        ssrc: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        csrcs,
        extension,
        payload: &packet[offset..payload_end],
        padding_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_rtp_packet() {
        let bytes = [
            0x80, 0xE0, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0xA0, 0xB0, 0xC0, 0xD0, 0xDE, 0xAD,
        ];
        let parsed = parse_rtp_packet(&bytes).expect("valid RTP packet");
        assert!(parsed.marker);
        assert_eq!(parsed.payload_type, 96);
        assert_eq!(parsed.sequence_number, 0x1234);
        assert_eq!(parsed.timestamp, 0x0102_0304);
        assert_eq!(parsed.ssrc, 0xA0B0_C0D0);
        assert_eq!(parsed.payload, &[0xDE, 0xAD]);
        assert!(parsed.csrcs.is_empty());
        assert!(parsed.extension.is_none());
    }

    #[test]
    fn parses_csrc_and_header_extension() {
        let bytes = [
            0x91, 0x60, 0, 7, 0, 0, 0, 9, 0, 0, 0, 11, 0x11, 0x11, 0x22, 0x22, 0xBE, 0xDE, 0, 1,
            0xAA, 0xBB, 0xCC, 0xDD, 0xFE,
        ];
        let parsed = parse_rtp_packet(&bytes).expect("valid extended RTP packet");
        assert_eq!(parsed.csrcs, vec![0x1111_2222]);
        let extension = parsed.extension.expect("extension present");
        assert_eq!(extension.profile, 0xBEDE);
        assert_eq!(extension.data, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(parsed.payload, &[0xFE]);
    }

    #[test]
    fn excludes_valid_padding_from_payload() {
        let bytes = [0xA0, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0x10, 0x20, 0, 2];
        let parsed = parse_rtp_packet(&bytes).expect("valid padded RTP packet");
        assert_eq!(parsed.payload, &[0x10, 0x20]);
        assert_eq!(parsed.padding_len, 2);
    }

    #[test]
    fn rejects_truncated_and_invalid_packets() {
        assert_eq!(
            parse_rtp_packet(&[0; 11]),
            Err(RtpParseError::TruncatedHeader)
        );

        let mut wrong_version = [0u8; 12];
        wrong_version[0] = 0x40;
        assert_eq!(
            parse_rtp_packet(&wrong_version),
            Err(RtpParseError::UnsupportedVersion(1))
        );

        let mut truncated_csrc = [0u8; 12];
        truncated_csrc[0] = 0x81;
        assert_eq!(
            parse_rtp_packet(&truncated_csrc),
            Err(RtpParseError::TruncatedCsrcList)
        );

        let mut zero_padding = [0u8; 13];
        zero_padding[0] = 0xA0;
        assert_eq!(
            parse_rtp_packet(&zero_padding),
            Err(RtpParseError::InvalidPadding)
        );
    }
}

/// Fixed AirPlay screen-mirroring packet header size.
pub const SCREEN_MIRROR_HEADER_SIZE: usize = 128;

/// Packet kind in the AirPlay screen-mirroring data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenMirrorPacketType {
    Video,
    CodecConfiguration,
    Heartbeat,
}

/// A validated screen-mirroring packet. The payload remains borrowed and may
/// still be encrypted; this parser does not decrypt or decode it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenMirrorPacket<'a> {
    pub packet_type: ScreenMirrorPacketType,
    pub payload_size: usize,
    pub timestamp: u64,
    pub payload: &'a [u8],
}

/// Errors produced while parsing the screen-mirroring packet envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenMirrorParseError {
    TruncatedHeader,
    UnsupportedPacketType(u16),
    InvalidPayloadLength,
}

impl fmt::Display for ScreenMirrorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("screen-mirroring packet header is truncated"),
            Self::UnsupportedPacketType(kind) => {
                write!(f, "unsupported screen-mirroring packet type {kind}")
            }
            Self::InvalidPayloadLength => {
                f.write_str("screen-mirroring payload length exceeds datagram size")
            }
        }
    }
}

impl std::error::Error for ScreenMirrorParseError {}

/// Parse the 128-byte AirPlay screen-mirroring packet envelope.
pub fn parse_screen_mirror_packet(
    packet: &[u8],
) -> Result<ScreenMirrorPacket<'_>, ScreenMirrorParseError> {
    if packet.len() < SCREEN_MIRROR_HEADER_SIZE {
        return Err(ScreenMirrorParseError::TruncatedHeader);
    }

    let payload_size = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    let raw_type = u16::from_le_bytes([packet[4], packet[5]]);
    let packet_type = match raw_type {
        0 => ScreenMirrorPacketType::Video,
        1 => ScreenMirrorPacketType::CodecConfiguration,
        2 => ScreenMirrorPacketType::Heartbeat,
        other => return Err(ScreenMirrorParseError::UnsupportedPacketType(other)),
    };
    let payload_end = SCREEN_MIRROR_HEADER_SIZE
        .checked_add(payload_size)
        .ok_or(ScreenMirrorParseError::InvalidPayloadLength)?;
    if payload_end > packet.len() {
        return Err(ScreenMirrorParseError::InvalidPayloadLength);
    }

    let timestamp = u64::from_le_bytes([
        packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
        packet[15],
    ]);

    Ok(ScreenMirrorPacket {
        packet_type,
        payload_size,
        timestamp,
        payload: &packet[SCREEN_MIRROR_HEADER_SIZE..payload_end],
    })
}

/// An owned, validated media packet delivered to the processing pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMediaPacket {
    pub peer_addr: SocketAddr,
    pub packet_type: ScreenMirrorPacketType,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

/// Maximum UDP datagram buffer. This is large enough for the maximum IPv4 UDP
/// payload and avoids allocating based on untrusted packet contents.
const MAX_UDP_DATAGRAM_SIZE: usize = 65_535;
const RECEIVE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A stoppable UDP socket that validates incoming screen-mirroring packets.
///
/// The caller must provide the negotiated media address. This receiver is not
/// started by the AirPlay runtime until RTSP stream setup supplies that address.
pub struct UdpMediaReceiver {
    local_addr: SocketAddr,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl UdpMediaReceiver {
    /// Bind and parse datagrams without forwarding their payloads.
    pub fn bind(bind_addr: SocketAddr, expected_peer_ip: IpAddr) -> io::Result<Self> {
        Self::bind_inner(bind_addr, expected_peer_ip, None)
    }

    /// Bind and forward validated packets to a bounded processing queue.
    ///
    /// The receive thread never blocks on downstream processing. If the queue
    /// is full, the newest packet is dropped and counted in the log.
    pub fn bind_with_sender(
        bind_addr: SocketAddr,
        expected_peer_ip: IpAddr,
        sender: SyncSender<ReceivedMediaPacket>,
    ) -> io::Result<Self> {
        Self::bind_inner(bind_addr, expected_peer_ip, Some(sender))
    }

    fn bind_inner(
        bind_addr: SocketAddr,
        expected_peer_ip: IpAddr,
        sender: Option<SyncSender<ReceivedMediaPacket>>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(RECEIVE_POLL_INTERVAL))?;
        let local_addr = socket.local_addr()?;
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);

        let worker = thread::Builder::new()
            .name("airplay-udp-media".to_owned())
            .spawn(move || receive_media_loop(socket, worker_running, expected_peer_ip, sender))?;

        tracing::info!(%local_addr, "AirPlay UDP media receiver bound");
        Ok(Self {
            local_addr,
            running,
            worker: Some(worker),
        })
    }

    /// Return the actual local address, including an OS-assigned port for :0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the receive loop and wait for its worker thread to exit.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                tracing::warn!("AirPlay UDP media receiver worker panicked");
            }
        }
        tracing::debug!(local_addr = %self.local_addr, "AirPlay UDP media receiver stopped");
    }
}

impl Drop for UdpMediaReceiver {
    fn drop(&mut self) {
        self.stop();
    }
}

fn receive_media_loop(
    socket: UdpSocket,
    running: Arc<AtomicBool>,
    expected_peer_ip: IpAddr,
    sender: Option<SyncSender<ReceivedMediaPacket>>,
) {
    let mut buffer = [0u8; MAX_UDP_DATAGRAM_SIZE];

    while running.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((length, peer_addr)) => {
                if peer_addr.ip() != expected_peer_ip {
                    tracing::debug!(
                        %peer_addr,
                        %expected_peer_ip,
                        "Ignoring media datagram from an unexpected host"
                    );
                    continue;
                }
                match parse_screen_mirror_packet(&buffer[..length]) {
                    Ok(packet) => {
                        tracing::debug!(
                            %peer_addr,
                            packet_type = ?packet.packet_type,
                            timestamp = packet.timestamp,
                            payload_bytes = packet.payload_size,
                            "Received AirPlay screen-mirroring datagram"
                        );
                        if let Some(sender) = sender.as_ref() {
                            let owned = ReceivedMediaPacket {
                                peer_addr,
                                packet_type: packet.packet_type,
                                timestamp: packet.timestamp,
                                payload: packet.payload.to_vec(),
                            };
                            match sender.try_send(owned) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    tracing::warn!(
                                        %peer_addr,
                                        "AirPlay media processing queue is full; dropping packet"
                                    );
                                }
                                Err(TrySendError::Disconnected(_)) => {
                                    tracing::debug!(
                                        "AirPlay media processing queue disconnected; stopping forwarding"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            %peer_addr,
                            %error,
                            datagram_bytes = length,
                            "Discarding invalid screen-mirroring datagram"
                        );
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                tracing::error!(%error, "AirPlay UDP media socket failed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod receiver_tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn parses_screen_mirroring_video_and_heartbeat_packets() {
        let mut video = vec![0u8; SCREEN_MIRROR_HEADER_SIZE + 3];
        video[0..4].copy_from_slice(&3u32.to_le_bytes());
        video[4..6].copy_from_slice(&0u16.to_le_bytes());
        video[8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        video[128..].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let parsed = parse_screen_mirror_packet(&video).expect("valid video packet");
        assert_eq!(parsed.packet_type, ScreenMirrorPacketType::Video);
        assert_eq!(parsed.timestamp, 0x0102_0304_0506_0708);
        assert_eq!(parsed.payload, &[0xAA, 0xBB, 0xCC]);

        let mut heartbeat = vec![0u8; SCREEN_MIRROR_HEADER_SIZE];
        heartbeat[4..6].copy_from_slice(&2u16.to_le_bytes());
        let parsed = parse_screen_mirror_packet(&heartbeat).expect("valid heartbeat");
        assert_eq!(parsed.packet_type, ScreenMirrorPacketType::Heartbeat);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn rejects_invalid_screen_mirroring_datagrams() {
        assert_eq!(
            parse_screen_mirror_packet(&[0; 127]),
            Err(ScreenMirrorParseError::TruncatedHeader)
        );

        let mut unsupported = vec![0u8; SCREEN_MIRROR_HEADER_SIZE];
        unsupported[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            parse_screen_mirror_packet(&unsupported),
            Err(ScreenMirrorParseError::UnsupportedPacketType(99))
        );

        let mut oversized = vec![0u8; SCREEN_MIRROR_HEADER_SIZE];
        oversized[0..4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_screen_mirror_packet(&oversized),
            Err(ScreenMirrorParseError::InvalidPayloadLength)
        );
    }

    #[test]
    fn udp_receiver_forwards_validated_packets_to_bounded_queue() {
        use std::sync::mpsc::sync_channel;
        use std::time::Duration;

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback address");
        let (sender, receiver) = sync_channel(2);
        let receiver_handle = UdpMediaReceiver::bind_with_sender(
            bind_addr,
            "127.0.0.1".parse().expect("loopback IP"),
            sender,
        )
        .expect("receiver binds");
        let socket = UdpSocket::bind("127.0.0.1:0").expect("sender socket binds");
        let mut datagram = vec![0u8; SCREEN_MIRROR_HEADER_SIZE + 3];
        datagram[0..4].copy_from_slice(&3u32.to_le_bytes());
        datagram[4..6].copy_from_slice(&0u16.to_le_bytes());
        datagram[8..16].copy_from_slice(&42u64.to_le_bytes());
        datagram[SCREEN_MIRROR_HEADER_SIZE..].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        socket
            .send_to(&datagram, receiver_handle.local_addr())
            .expect("send datagram");

        let packet = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("packet forwarded");
        assert_eq!(packet.packet_type, ScreenMirrorPacketType::Video);
        assert_eq!(packet.timestamp, 42);
        assert_eq!(packet.payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(
            packet.peer_addr.ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn udp_receiver_does_not_block_when_processing_queue_is_full() {
        use std::sync::mpsc::sync_channel;
        use std::time::Duration;

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback address");
        let (sender, receiver) = sync_channel(1);
        let mut receiver_handle = UdpMediaReceiver::bind_with_sender(
            bind_addr,
            "127.0.0.1".parse().expect("loopback IP"),
            sender,
        )
        .expect("receiver binds");
        let socket = UdpSocket::bind("127.0.0.1:0").expect("sender socket binds");
        let mut datagram = vec![0u8; SCREEN_MIRROR_HEADER_SIZE + 1];
        datagram[0..4].copy_from_slice(&1u32.to_le_bytes());
        datagram[4..6].copy_from_slice(&0u16.to_le_bytes());
        for value in [1u8, 2u8] {
            datagram[SCREEN_MIRROR_HEADER_SIZE] = value;
            socket
                .send_to(&datagram, receiver_handle.local_addr())
                .expect("send datagram");
        }

        // Keep the bounded queue full while the UDP worker processes both
        // datagrams. Reading before stop would free a slot and make the test
        // race with the second send.
        thread::sleep(Duration::from_millis(100));
        receiver_handle.stop();

        let first = receiver
            .try_recv()
            .expect("the first packet remains in the one-slot queue");
        assert_eq!(first.payload, vec![1]);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn udp_receiver_binds_and_stops_cleanly() {
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback address");
        let mut receiver =
            UdpMediaReceiver::bind(bind_addr, "127.0.0.1".parse().expect("loopback IP"))
                .expect("receiver binds");
        assert_ne!(receiver.local_addr().port(), 0);
        assert_eq!(receiver.local_addr().ip(), bind_addr.ip());
        receiver.stop();
        assert!(receiver.worker.is_none());
    }
}
