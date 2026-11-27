//! Bounded RTSP/HTTP control parser for the AirPlay endpoint.
//!
//! The handler supports persistent RTSP connections, bounded request bodies,
//! OPTIONS, /info, Pair-Setup, Pair-Verify, FairPlay message framing, session
//! and stream SETUP, RECORD, feedback, and TEARDOWN. With an authorized SAP
//! provider, the media worker decrypts ordered access units and feeds H.264 to
//! Media Foundation; decoded frames are then published to the desktop preview.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    mpsc::{self, Receiver},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use super::{
    config,
    event::EventChannel,
    media::{ReceivedMediaPacket, SCREEN_MIRROR_HEADER_SIZE, parse_screen_mirror_packet},
    pair_setup,
    pair_verify::{self, PairVerifySession},
    pairing, plist,
    setup::{self, SetupRequest},
    srp::SrpServer,
    timing::TimingClient,
    tlv8::{self, Tlv},
};
use ::plist::{Dictionary, Value};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 2048;
// Bound queued media payload memory to 128 MiB at the maximum packet size.
// A count-only queue of 128 packets could otherwise retain up to 2 GiB.
const MEDIA_PACKET_QUEUE_CAPACITY: usize = 8;
const MAX_MIRROR_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MEDIA_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
// Release a stale mirror TCP client that connects but never sends a packet.
const MIRROR_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Report a stalled post-recovery keyframe wait without dropping encrypted
// packets or abandoning the synchronized stream cipher.
const IDR_WAIT_WARNING_INTERVAL: Duration = Duration::from_secs(10);
// A decoder that accepted an IDR but emitted no frame is considered stalled
// after this interval; recovery remains bounded by DecoderRecoveryPolicy.
const IDR_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(15);

/// Keep the timeout decision deterministic and safe when a timer is absent
/// or an unexpected future instant is supplied.
fn first_frame_wait_timed_out(started_at: Option<Instant>, now: Instant) -> bool {
    started_at
        .and_then(|started_at| now.checked_duration_since(started_at))
        .is_some_and(|elapsed| elapsed >= IDR_FIRST_FRAME_TIMEOUT)
}

#[cfg(windows)]
static ACTIVE_RTSP_SESSIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Keeps the global pipeline label in the waiting state after the final
/// control connection exits, without allowing one client to reset another
/// client's active protocol stage.
#[cfg(windows)]
struct RtspPipelineSessionGuard;

#[cfg(windows)]
impl RtspPipelineSessionGuard {
    fn new() -> Self {
        ACTIVE_RTSP_SESSIONS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self
    }
}

#[cfg(windows)]
impl Drop for RtspPipelineSessionGuard {
    fn drop(&mut self) {
        if ACTIVE_RTSP_SESSIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
            super::set_pipeline_stage(1);
            tracing::info!(
                "Last AirPlay RTSP control session ended; receiver is waiting for iPhone"
            );
        }
    }
}

/// Per-stream cryptographic context. The shared secret is retained only in
/// memory and is never formatted into logs or debug output.
enum MediaWorkerMessage {
    Packet(ReceivedMediaPacket),
    /// FIFO marker after the final packet from one mirror TCP peer.
    StreamDisconnected,
}

struct MirrorStreamContext {
    connection_id: Option<u64>,
    pair_verify_shared_secret: Option<Zeroizing<[u8; 32]>>,
    fairplay_video_key: Option<Zeroizing<[u8; 16]>>,
    media_foundation: Option<Arc<super::decoder::MediaFoundationRuntime>>,
    frames: Arc<super::video::LatestFrameMailbox>,
}

/// Owns the negotiated TCP screen-mirroring listener and its bounded worker.
/// The worker reads each 128-byte packet header and its declared payload,
/// validates avcC configuration, initializes the H.264 decoder, and—when
/// authenticated FairPlay keys are supplied—decrypts and submits access units.
struct MediaSession {
    local_addr: std::net::SocketAddr,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    frames: Arc<super::video::LatestFrameMailbox>,
    accepted_clients: Arc<std::sync::atomic::AtomicU64>,
    disconnected_clients: Arc<std::sync::atomic::AtomicU64>,
    accept_worker: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
}

impl MediaSession {
    /// Start a media listener without negotiated stream crypto context.
    /// Kept as a simple entry point for tests and non-paired sessions.
    fn start(peer_ip: std::net::IpAddr) -> io::Result<Self> {
        Self::start_with_context(
            peer_ip,
            MirrorStreamContext {
                connection_id: None,
                pair_verify_shared_secret: None,
                fairplay_video_key: None,
                media_foundation: None,
                frames: Arc::new(super::video::LatestFrameMailbox::new()),
            },
        )
    }

    /// Start a media listener with the cryptographic context negotiated by RTSP.
    fn start_with_context(
        peer_ip: std::net::IpAddr,
        stream_context: MirrorStreamContext,
    ) -> io::Result<Self> {
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("0.0.0.0:0")?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let frames = Arc::clone(&stream_context.frames);
        let accepted_clients = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let disconnected_clients = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_accepted_clients = Arc::clone(&accepted_clients);
        let worker_disconnected_clients = Arc::clone(&disconnected_clients);
        let (sender, packets) = mpsc::sync_channel(MEDIA_PACKET_QUEUE_CAPACITY);

        let processing_running = Arc::clone(&running);
        let worker = thread::Builder::new()
            .name("airplay-media-process".to_owned())
            .spawn(move || process_media_packets(packets, stream_context, processing_running))?;
        let accept_worker = match thread::Builder::new()
            .name("airplay-mirror-tcp".to_owned())
            .spawn(move || {
                accept_mirror_connections(
                    listener,
                    worker_running,
                    peer_ip,
                    sender,
                    worker_accepted_clients,
                    worker_disconnected_clients,
                )
            }) {
            Ok(worker) => worker,
            Err(error) => {
                running.store(false, Ordering::Release);
                let _ = worker.join();
                return Err(error);
            }
        };

        tracing::info!(%local_addr, "AirPlay screen-mirroring TCP listener bound");
        Ok(Self {
            local_addr,
            running,
            frames,
            accepted_clients,
            disconnected_clients,
            accept_worker: Some(accept_worker),
            worker: Some(worker),
        })
    }

    fn port(&self) -> u16 {
        self.local_addr.port()
    }

    fn stop(&mut self) {
        use std::sync::atomic::Ordering;

        self.running.store(false, Ordering::Release);
        tracing::info!(%self.local_addr, "Stopping AirPlay media session");

        // Invalidate snapshots immediately so UI work already holding a frame
        // cannot present it while the workers are being joined. Clear again
        // after joining because a worker may have been finishing a publish
        // concurrently with this first invalidation.
        if let Err(error) = self.frames.clear() {
            tracing::warn!(%self.local_addr, %error, "Could not invalidate decoded frames at media session shutdown");
        }

        if let Some(worker) = self.accept_worker.take() {
            if worker.join().is_err() {
                tracing::warn!("AirPlay mirror TCP accept worker panicked");
            } else {
                tracing::debug!("AirPlay mirror TCP accept worker joined");
            }
        }

        // The accept worker owns the packet sender. Once it exits, the
        // receiver drains any already-queued packets and then observes channel
        // closure, allowing decoder COM interfaces to be released on their
        // owning media worker thread before the runtime Arc is dropped.
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                tracing::warn!("AirPlay media processing worker panicked");
            } else {
                tracing::debug!("AirPlay media processing worker joined");
            }
        }

        match self.frames.clear() {
            Ok(()) => {
                tracing::debug!(%self.local_addr, "Cleared pending decoded frames after media session stop")
            }
            Err(error) => {
                tracing::warn!(%self.local_addr, %error, "Could not clear decoded frames after media session stop")
            }
        }
        let accepted_clients = self.accepted_clients.load(Ordering::Relaxed);
        let disconnected_clients = self.disconnected_clients.load(Ordering::Relaxed);
        tracing::info!(
            %self.local_addr,
            accepted_clients,
            disconnected_clients,
            active_clients = accepted_clients.saturating_sub(disconnected_clients),
            "AirPlay media session client summary"
        );
        tracing::info!(%self.local_addr, "AirPlay media session stopped");
    }
}

impl Drop for MediaSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_mirror_connections(
    listener: TcpListener,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    expected_peer_ip: std::net::IpAddr,
    sender: mpsc::SyncSender<MediaWorkerMessage>,
    accepted_clients: Arc<std::sync::atomic::AtomicU64>,
    disconnected_clients: Arc<std::sync::atomic::AtomicU64>,
) {
    use std::sync::atomic::Ordering;

    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                if peer_addr.ip() != expected_peer_ip {
                    tracing::warn!(%peer_addr, %expected_peer_ip, "Rejecting unexpected AirPlay mirror TCP peer");
                    continue;
                }
                if let Err(error) = stream.set_read_timeout(Some(Duration::from_millis(100))) {
                    tracing::warn!(%error, "Could not set AirPlay mirror TCP read timeout");
                    continue;
                }
                let accepted = accepted_clients.fetch_add(1, Ordering::Relaxed) + 1;
                #[cfg(windows)]
                super::advance_pipeline_stage(9);
                tracing::info!(%peer_addr, accepted, "AirPlay mirror TCP client connected");
                read_mirror_stream(stream, peer_addr, &sender, &running);
                // FIFO ordering ensures all packets from this peer are processed
                // before the worker clears its preview at the disconnect boundary.
                if !send_packet_while_running(
                    &sender,
                    MediaWorkerMessage::StreamDisconnected,
                    &running,
                ) {
                    tracing::debug!(%peer_addr, "AirPlay media worker stopped before disconnect marker");
                    break;
                }
                // The listener remains available for reconnects, but a closed
                // media TCP peer is no longer an active sender connection.
                #[cfg(windows)]
                super::set_pipeline_stage(7);
                let disconnected = disconnected_clients.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::info!(%peer_addr, disconnected, "AirPlay mirror TCP client disconnected");
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(MEDIA_ACCEPT_POLL_INTERVAL);
            }
            Err(error) => {
                tracing::error!(%error, "AirPlay mirror TCP listener failed");
                break;
            }
        }
    }
}

fn read_mirror_stream(
    mut stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    sender: &mpsc::SyncSender<MediaWorkerMessage>,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    let mut received = 0u64;
    let mut received_bytes = 0u64;
    while running.load(Ordering::Acquire) {
        let mut header = [0u8; SCREEN_MIRROR_HEADER_SIZE];
        match read_exact_while_running(
            &mut stream,
            &mut header,
            running,
            MIRROR_CLIENT_IDLE_TIMEOUT,
        ) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                if error.kind() != io::ErrorKind::UnexpectedEof {
                    tracing::debug!(%peer_addr, %error, "AirPlay mirror TCP header read ended");
                }
                break;
            }
        }

        let payload_size =
            u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if payload_size > MAX_MIRROR_PAYLOAD_BYTES {
            tracing::warn!(%peer_addr, payload_size, "Rejecting oversized AirPlay mirror payload");
            break;
        }

        let mut packet_bytes = Vec::with_capacity(SCREEN_MIRROR_HEADER_SIZE + payload_size);
        packet_bytes.extend_from_slice(&header);
        packet_bytes.resize(SCREEN_MIRROR_HEADER_SIZE + payload_size, 0);
        if payload_size > 0
            && !matches!(
                read_exact_while_running(
                    &mut stream,
                    &mut packet_bytes[SCREEN_MIRROR_HEADER_SIZE..],
                    running,
                    MIRROR_CLIENT_IDLE_TIMEOUT,
                ),
                Ok(true)
            )
        {
            break;
        }

        let parsed = match parse_screen_mirror_packet(&packet_bytes) {
            Ok(packet) => packet,
            Err(error) => {
                tracing::warn!(%peer_addr, %error, "Discarding invalid AirPlay mirror TCP packet");
                break;
            }
        };
        let owned = ReceivedMediaPacket {
            peer_addr,
            packet_type: parsed.packet_type,
            timestamp: parsed.timestamp,
            payload: parsed.payload.to_vec(),
        };
        // TCP mirror payloads must remain in receive order. In particular,
        // dropping one encrypted packet would advance the sender's CTR stream
        // without advancing the receiver's cipher, corrupting every later
        // packet. A bounded blocking send applies backpressure instead.
        let packet_bytes_received = packet_bytes.len() as u64;
        if !send_packet_while_running(sender, MediaWorkerMessage::Packet(owned), running) {
            break;
        }
        if received == 0 {
            #[cfg(windows)]
            super::advance_pipeline_stage(10);
            tracing::info!(
                %peer_addr,
                packet_type = ?parsed.packet_type,
                payload_bytes = payload_size,
                "First AirPlay media packet accepted into ordered processing queue"
            );
        }
        received = received.saturating_add(1);
        received_bytes = received_bytes.saturating_add(packet_bytes_received);
    }
    tracing::info!(
        %peer_addr,
        received_packets = received,
        received_bytes,
        "AirPlay mirror TCP stream reader stopped"
    );
}

fn send_packet_while_running(
    sender: &mpsc::SyncSender<MediaWorkerMessage>,
    mut packet: MediaWorkerMessage,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> bool {
    use std::sync::atomic::Ordering;
    let blocked_at = Instant::now();
    let mut reported_backpressure = false;
    loop {
        if !running.load(Ordering::Acquire) {
            return false;
        }
        match sender.try_send(packet) {
            Ok(()) => {
                if reported_backpressure {
                    tracing::debug!(
                        blocked_ms = blocked_at.elapsed().as_millis() as u64,
                        "AirPlay media queue backpressure cleared"
                    );
                }
                return true;
            }
            Err(mpsc::TrySendError::Full(returned)) => {
                packet = returned;
                if !reported_backpressure && blocked_at.elapsed() >= Duration::from_millis(100) {
                    reported_backpressure = true;
                    tracing::warn!(
                        "AirPlay media queue is saturated; applying TCP backpressure without dropping encrypted packets"
                    );
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn read_exact_while_running<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    idle_timeout: Duration,
) -> io::Result<bool> {
    use std::sync::atomic::Ordering;

    let mut offset = 0;
    let mut last_progress = Instant::now();
    while offset < buffer.len() && running.load(Ordering::Acquire) {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mirror stream closed",
                ));
            }
            Ok(read) => {
                offset += read;
                last_progress = Instant::now();
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if last_progress.elapsed() >= idle_timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "mirror peer exceeded its packet idle timeout",
                    ));
                }
                // A peer may stall halfway through a packet. Avoid spinning
                // one CPU core while preserving prompt cancellation.
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(offset == buffer.len())
}

fn recover_stalled_decoder(
    idr_recovery_gate: &mut super::video::IdrRecoveryGate,
    idr_wait_started_at: &mut Option<Instant>,
    first_frame_wait_started_at: &mut Option<Instant>,
    last_idr_wait_warning: &mut Option<Instant>,
    frame_pipeline: &mut Option<super::decoder::H264FramePipeline<'_>>,
    processor: &super::video::MirrorStreamProcessor,
    frames: &super::video::LatestFrameMailbox,
    now: Instant,
) -> bool {
    if !idr_recovery_gate.is_awaiting_first_frame()
        || !first_frame_wait_timed_out(*first_frame_wait_started_at, now)
    {
        return false;
    }

    // The decoder accepted an IDR but failed to publish any output. Rebuild
    // with the existing bounded retry budget, then require a fresh IDR.
    idr_recovery_gate.begin_wait();
    *idr_wait_started_at = Some(now);
    *first_frame_wait_started_at = None;
    *last_idr_wait_warning = None;

    let recovery = match (frame_pipeline.as_mut(), processor.configuration()) {
        (Some(pipeline), Some(configuration)) => match configuration.video_dimensions() {
            Ok(Some(dimensions)) => pipeline.rebuild_decoder(dimensions.width, dimensions.height),
            Ok(None) => Err(super::decoder::MediaFoundationError::MissingSps),
            Err(error) => Err(super::decoder::MediaFoundationError::InvalidAvcConfiguration(error)),
        },
        _ => Err(super::decoder::MediaFoundationError::MissingSps),
    };

    match recovery {
        Ok(()) => tracing::warn!(
            timeout_ms = IDR_FIRST_FRAME_TIMEOUT.as_millis() as u64,
            "AirPlay decoder produced no frame after IDR; rebuilt pipeline and waiting for another IDR"
        ),
        Err(recovery_error) => {
            *frame_pipeline = None;
            if let Err(clear_error) = frames.clear() {
                tracing::warn!(%clear_error, "Could not clear preview after stalled decoder recovery");
            }
            tracing::warn!(
                %recovery_error,
                "AirPlay decoder first-frame recovery exhausted; waiting for a new codec configuration"
            );
        }
    }
    true
}

fn process_media_packets(
    packets: Receiver<MediaWorkerMessage>,
    stream_context: MirrorStreamContext,
    running: Arc<std::sync::atomic::AtomicBool>,
) {
    let stream_connection_id = stream_context.connection_id;
    tracing::info!(
        stream_connection_id = ?stream_connection_id,
        pair_verify_complete = stream_context.pair_verify_shared_secret.is_some(),
        "AirPlay media worker initialized with negotiated stream context"
    );
    let processing_started_at = Instant::now();
    let mut received = 0u64;
    let mut received_payload_bytes = 0u64;
    let mut codec_configuration_bytes = 0u64;
    let mut video_payload_bytes = 0u64;
    let mut codec_configurations = 0u64;
    let mut invalid_codec_configurations = 0u64;
    let mut video_packets = 0u64;
    let mut packets_waiting_for_fairplay = 0u64;
    let mut decode_errors = 0u64;
    let mut decoder_initialization_successes = 0u64;
    let mut decoder_initialization_failures = 0u64;
    let mut decrypted_access_units_submitted = 0u64;
    let mut decrypted_access_units_discarded = 0u64;
    let mut decoded_frames_published = 0u64;
    let mut heartbeat_packets = 0u64;
    let pair_verify_shared_secret = stream_context.pair_verify_shared_secret;
    let fairplay_video_key = stream_context.fairplay_video_key;
    let media_foundation = stream_context.media_foundation;
    let frames = stream_context.frames;
    let mut mirror_cipher = match (fairplay_video_key.as_ref(), stream_connection_id) {
        (Some(video_key), Some(connection_id)) => {
            let pair_secret = pair_verify_shared_secret
                .as_ref()
                .map(|secret| secret.as_ref());
            match super::mirror_crypto::derive_mirror_stream_keys(
                video_key.as_ref(),
                pair_secret,
                connection_id,
            ) {
                Ok(material) => {
                    tracing::info!(
                        stream_connection_id = connection_id,
                        pair_verify_complete = pair_secret.is_some(),
                        "FairPlay video key installed for mirror stream"
                    );
                    Some(super::mirror_crypto::MirrorStreamCipher::new(&material))
                }
                Err(error) => {
                    tracing::error!(%error, "Could not derive AirPlay mirror stream cipher");
                    None
                }
            }
        }
        (Some(_), None) => {
            tracing::warn!("FairPlay video key received without a stream connection ID");
            None
        }
        (None, _) => {
            tracing::debug!(
                "FairPlay video key unavailable; encrypted mirror packets will be held"
            );
            None
        }
    };
    let mut frame_pipeline: Option<super::decoder::H264FramePipeline<'_>> = None;
    // A rebuilt MFT has no reference pictures; decrypt every packet to keep
    // CTR synchronized, but do not submit delta pictures until an IDR arrives.
    let mut idr_recovery_gate = super::video::IdrRecoveryGate::default();
    let mut idr_wait_started_at: Option<Instant> = None;
    let mut first_frame_wait_started_at: Option<Instant> = None;
    let mut last_idr_wait_warning: Option<Instant> = None;
    let mut decoder_init_policy = super::video::DecoderInitializationPolicy::default();
    let mut processor = super::video::MirrorStreamProcessor::new();
    loop {
        // Stop promptly instead of draining stale encrypted packets during
        // teardown. Decoder/MFT resources still drop on this owning worker.
        if !running.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let message = match packets.recv_timeout(Duration::from_millis(250)) {
            Ok(message) => message,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                recover_stalled_decoder(
                    &mut idr_recovery_gate,
                    &mut idr_wait_started_at,
                    &mut first_frame_wait_started_at,
                    &mut last_idr_wait_warning,
                    &mut frame_pipeline,
                    &processor,
                    &frames,
                    Instant::now(),
                );
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        // Shutdown may race with recv_timeout returning a queued packet.
        if !running.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let mut packet = match message {
            MediaWorkerMessage::Packet(packet) => packet,
            MediaWorkerMessage::StreamDisconnected => {
                // Keep the negotiated cipher/configuration continuous across a
                // TCP reconnect, but never leave the previous peer's frame on
                // screen. Rebuild decoder references and wait for a fresh IDR.
                if let Err(error) = frames.clear() {
                    tracing::warn!(%error, "Could not clear preview after mirror TCP disconnect");
                }
                // A TCP reconnect invalidates the decoder's reference-picture
                // state regardless of whether rebuilding the existing MFT succeeds.
                // Keep the IDR gate active while recovery is attempted.
                idr_recovery_gate.begin_wait();
                idr_wait_started_at = Some(Instant::now());
                first_frame_wait_started_at = None;
                last_idr_wait_warning = None;
                if let (Some(pipeline), Some(configuration)) =
                    (frame_pipeline.as_mut(), processor.configuration())
                {
                    match configuration.video_dimensions() {
                        Ok(Some(dimensions)) => {
                            if let Err(error) = pipeline.rebuild_decoder_after_reconnect(
                                dimensions.width,
                                dimensions.height,
                            ) {
                                tracing::warn!(%error, "Could not rebuild decoder after mirror TCP reconnect");
                                frame_pipeline = None;
                            }
                        }
                        Ok(None) => {
                            frame_pipeline = None;
                            tracing::warn!(
                                "Cannot resume mirror preview after reconnect without SPS dimensions"
                            );
                        }
                        Err(error) => {
                            frame_pipeline = None;
                            tracing::warn!(%error, "Cannot resume mirror preview after reconnect with invalid SPS");
                        }
                    }
                } else {
                    idr_recovery_gate.begin_wait();
                    idr_wait_started_at = Some(Instant::now());
                    first_frame_wait_started_at = None;
                    last_idr_wait_warning = None;
                }
                tracing::info!(
                    "AirPlay mirror TCP connection ended; preview cleared and decoder awaiting a fresh IDR"
                );
                continue;
            }
        };
        received = received.saturating_add(1);
        let packet_payload_bytes = packet.payload.len() as u64;
        received_payload_bytes = received_payload_bytes.saturating_add(packet_payload_bytes);
        if packet.packet_type == super::media::ScreenMirrorPacketType::CodecConfiguration {
            codec_configuration_bytes =
                codec_configuration_bytes.saturating_add(packet_payload_bytes);
        }
        // Video packets are the hot path; only clone codec metadata when
        // the packet can actually replace that metadata.
        let is_codec_configuration =
            packet.packet_type == super::media::ScreenMirrorPacketType::CodecConfiguration;
        let previous_configuration = is_codec_configuration
            .then(|| processor.configuration().cloned())
            .flatten();
        let outcome = processor.process_packet(packet.packet_type, &packet.payload);
        let duplicate_configuration = is_codec_configuration
            && matches!(
                &outcome,
                super::video::MirrorPacketOutcome::CodecConfigurationUpdated { .. }
            )
            && previous_configuration.as_ref() == processor.configuration();

        let initialize_decoder = decoder_init_policy.should_initialize(
            is_codec_configuration,
            duplicate_configuration,
            frame_pipeline.is_some(),
        );

        if duplicate_configuration && !initialize_decoder {
            tracing::trace!(
                %packet.peer_addr,
                timestamp = packet.timestamp,
                received,
                attempts = decoder_init_policy.attempts(),
                "Ignoring duplicate AirPlay H.264 codec configuration"
            );
            continue;
        }
        if duplicate_configuration {
            tracing::debug!(
                %packet.peer_addr,
                timestamp = packet.timestamp,
                attempts = decoder_init_policy.attempts(),
                "Retrying H.264 decoder initialization after duplicate codec configuration"
            );
        }
        match outcome {
            super::video::MirrorPacketOutcome::CodecConfigurationUpdated {
                profile,
                level,
                nal_length_size,
                sps_count,
                pps_count,
            } => {
                codec_configurations = codec_configurations.saturating_add(1);
                // A newly accepted avcC record supersedes the previous decoder
                // configuration. Never keep decoding with stale dimensions or
                // parameter sets if the new stream configuration is unusable.
                frame_pipeline = None;
                // A new avcC configuration invalidates the decoder's reference
                // pictures. Even when the replacement decoder initializes
                // successfully below, the next usable picture must be an IDR;
                // otherwise a delta frame would be submitted against an empty
                // reference state and the preview could remain blank.
                idr_recovery_gate.begin_wait();
                idr_wait_started_at = Some(Instant::now());
                first_frame_wait_started_at = None;
                last_idr_wait_warning = None;
                if let Err(error) = frames.clear() {
                    tracing::warn!(%error, "Could not clear stale AirPlay preview frame");
                }
                tracing::info!(
                    %packet.peer_addr,
                    profile,
                    level,
                    nal_length_size,
                    sps_count,
                    pps_count,
                    timestamp = packet.timestamp,
                    received,
                    "AirPlay H.264 codec configuration accepted"
                );
                if initialize_decoder {
                    if let Some(configuration) = processor.configuration() {
                        match configuration.video_dimensions() {
                            Ok(Some(dimensions)) => tracing::info!(
                                width = dimensions.width,
                                height = dimensions.height,
                                "AirPlay H.264 SPS dimensions parsed"
                            ),
                            Ok(None) => tracing::warn!("AirPlay AVC configuration has no SPS"),
                            Err(error) => tracing::warn!(
                                %error,
                                "Could not read dimensions from AirPlay H.264 SPS"
                            ),
                        }
                        if let Some(runtime) = media_foundation.as_ref() {
                            match super::decoder::H264FramePipeline::from_avc_configuration(
                                runtime,
                                configuration,
                                Arc::clone(&frames),
                            ) {
                                Ok(pipeline) => {
                                    decoder_initialization_successes =
                                        decoder_initialization_successes.saturating_add(1);
                                    decoder_init_policy.record_success();
                                    frame_pipeline = Some(pipeline);
                                    tracing::info!(
                                        "Windows H.264 decoder pipeline initialized from stream SPS"
                                    );
                                }
                                Err(error) => {
                                    decoder_initialization_failures =
                                        decoder_initialization_failures.saturating_add(1);
                                    tracing::warn!(
                                        %error,
                                        attempts = decoder_init_policy.attempts(),
                                        "Could not initialize Windows H.264 decoder pipeline"
                                    );
                                }
                            }
                        } else {
                            tracing::warn!(
                                attempts = decoder_init_policy.attempts(),
                                "Media Foundation is unavailable; decoded-frame preview cannot start"
                            );
                        }
                    }
                }
            }
            super::video::MirrorPacketOutcome::InvalidCodecConfiguration(error) => {
                invalid_codec_configurations = invalid_codec_configurations.saturating_add(1);
                // An invalid replacement configuration must not leave the
                // previous decoder or its last frame visible as if it still
                // represented the active sender stream.
                frame_pipeline = None;
                decoder_init_policy.reset();
                // An invalid replacement configuration also ends the previous
                // decoder reference state. If a valid avcC record arrives later,
                // require a fresh IDR instead of feeding a delta picture into
                // the newly initialized decoder.
                idr_recovery_gate.begin_wait();
                idr_wait_started_at = Some(Instant::now());
                first_frame_wait_started_at = None;
                last_idr_wait_warning = None;
                if let Err(clear_error) = frames.clear() {
                    tracing::warn!(
                        %clear_error,
                        "Could not clear preview after invalid codec reconfiguration"
                    );
                }
                tracing::warn!(
                    %packet.peer_addr,
                    %error,
                    timestamp = packet.timestamp,
                    "Rejected invalid AirPlay H.264 codec configuration"
                );
            }
            super::video::MirrorPacketOutcome::VideoWaitingForDecryption {
                payload_bytes,
                has_configuration,
            } => {
                video_packets = video_packets.saturating_add(1);
                video_payload_bytes = video_payload_bytes.saturating_add(packet_payload_bytes);
                if let Some(cipher) = mirror_cipher.as_mut() {
                    recover_stalled_decoder(
                        &mut idr_recovery_gate,
                        &mut idr_wait_started_at,
                        &mut first_frame_wait_started_at,
                        &mut last_idr_wait_warning,
                        &mut frame_pipeline,
                        &processor,
                        &frames,
                        Instant::now(),
                    );
                    if let Some(pipeline) = frame_pipeline.as_mut() {
                        let submit_result = if idr_recovery_gate.is_waiting() {
                            if let Some(started_at) = idr_wait_started_at {
                                let elapsed = started_at.elapsed();
                                let should_warn = last_idr_wait_warning
                                    .map(|last| last.elapsed() >= IDR_WAIT_WARNING_INTERVAL)
                                    .unwrap_or(elapsed >= IDR_WAIT_WARNING_INTERVAL);
                                if should_warn {
                                    tracing::warn!(
                                        %packet.peer_addr,
                                        waited_ms = elapsed.as_millis() as u64,
                                        "AirPlay decoder is still waiting for an H.264 IDR; continuing to decrypt packets to preserve cipher synchronization"
                                    );
                                    last_idr_wait_warning = Some(Instant::now());
                                }
                            }
                            processor
                                .decrypt_video_packet(cipher, &packet.payload)
                                .map_err(super::decoder::MediaFoundationError::VideoDecryption)
                                .and_then(|access_unit| {
                                    if idr_recovery_gate.should_submit(super::video::access_unit_contains_h264_idr(&access_unit)) {
                                        // Keep the recovery gate closed until the replacement
                                        // decoder actually accepts the IDR. Clearing it before
                                        // submission would let following delta frames through
                                        // when this first keyframe is rejected by the MFT.
                                        let published = pipeline.submit_access_unit(&access_unit)?;
                                        idr_recovery_gate.record_idr_submitted();
                                        idr_wait_started_at = None;
                                        first_frame_wait_started_at = Some(Instant::now());
                                        last_idr_wait_warning = None;
                                        tracing::info!(
                                            %packet.peer_addr,
                                            timestamp = packet.timestamp,
                                            published_frames = published,
                                            "H.264 IDR submitted; waiting for first decoded frame after recovery"
                                        );
                                        Ok(Some(published))
                                    } else {
                                        Ok(None)
                                    }
                                })
                        } else {
                            pipeline
                                .submit_encrypted_access_unit(&processor, cipher, &packet.payload)
                                .map(Some)
                        };
                        match submit_result {
                            Ok(None) => {
                                decrypted_access_units_discarded =
                                    decrypted_access_units_discarded.saturating_add(1);
                                tracing::trace!(
                                    %packet.peer_addr,
                                    timestamp = packet.timestamp,
                                    payload_bytes,
                                    received,
                                    "Discarded decrypted H.264 delta access unit while waiting for IDR"
                                );
                            }
                            Ok(Some(published_frames)) => {
                                if published_frames > 0
                                    && idr_recovery_gate.is_awaiting_first_frame()
                                {
                                    idr_recovery_gate.record_frame_published();
                                    first_frame_wait_started_at = None;
                                    tracing::info!(
                                        %packet.peer_addr,
                                        timestamp = packet.timestamp,
                                        published_frames,
                                        "First decoded frame published after H.264 recovery"
                                    );
                                }
                                decrypted_access_units_submitted =
                                    decrypted_access_units_submitted.saturating_add(1);
                                decoded_frames_published = decoded_frames_published
                                    .saturating_add(published_frames as u64);
                                if published_frames > 0
                                    && decoded_frames_published == published_frames as u64
                                {
                                    let sequence = frames.stats().ok().map(|stats| stats.published);
                                    #[cfg(windows)]
                                    if let Some(sequence) = sequence {
                                        super::mark_video_decoded(sequence);
                                    }
                                    tracing::info!(
                                        published_frames,
                                        sequence,
                                        "First decoded AirPlay video frame published to preview mailbox"
                                    );
                                }
                                tracing::debug!(
                                %packet.peer_addr,
                                timestamp = packet.timestamp,
                                payload_bytes,
                                published_frames,
                                received,
                                "Decrypted and submitted AirPlay H.264 access unit"
                                )
                            }
                            Err(error) => {
                                decode_errors = decode_errors.saturating_add(1);

                                // A cryptographic counter failure may have left
                                // the stream cipher partially advanced. In that
                                // case fail closed. AVC framing or decoder errors
                                // happen after successful packet decryption, so
                                // the next packet can still use the continuous CTR
                                // position while the MFT is rebuilt.
                                let cipher_state_lost = error.invalidates_mirror_cipher();
                                if cipher_state_lost {
                                    mirror_cipher = None;
                                }

                                let recovery = if cipher_state_lost {
                                    Err(super::decoder::MediaFoundationError::DecoderRecoveryLimitReached)
                                } else if let Some(configuration) = processor.configuration() {
                                    match configuration.video_dimensions() {
                                        Ok(Some(dimensions)) => pipeline.rebuild_decoder(
                                            dimensions.width,
                                            dimensions.height,
                                        ),
                                        Ok(None) => Err(
                                            super::decoder::MediaFoundationError::MissingSps,
                                        ),
                                        Err(error) => Err(
                                            super::decoder::MediaFoundationError::InvalidAvcConfiguration(error),
                                        ),
                                    }
                                } else {
                                    Err(super::decoder::MediaFoundationError::MissingSps)
                                };

                                match recovery {
                                    Ok(()) => {
                                        idr_recovery_gate.begin_wait();
                                        idr_wait_started_at = Some(Instant::now());
                                        first_frame_wait_started_at = None;
                                        last_idr_wait_warning = None;
                                        tracing::warn!(
                                        %packet.peer_addr,
                                        timestamp = packet.timestamp,
                                        %error,
                                        "AirPlay decoder failed; rebuilt Media Foundation pipeline and retained stream cipher; waiting for IDR"
                                        )
                                    }
                                    Err(recovery_error) => {
                                        // A replacement decoder has no reference pictures.
                                        // If it is initialized again after this failure, require
                                        // a fresh IDR before submitting any delta access units.
                                        idr_recovery_gate.begin_wait();
                                        idr_wait_started_at = Some(Instant::now());
                                        first_frame_wait_started_at = None;
                                        last_idr_wait_warning = None;
                                        // Do not keep submitting packets to a decoder whose
                                        // recovery failed. Dropping it lets a later duplicate
                                        // avcC configuration consume the one bounded retry.
                                        frame_pipeline = None;
                                        if let Err(clear_error) = frames.clear() {
                                            tracing::warn!(%clear_error, "Could not clear preview after decoder failure");
                                        }
                                        tracing::warn!(
                                            %packet.peer_addr,
                                            timestamp = packet.timestamp,
                                            %error,
                                            %recovery_error,
                                            cipher_state_lost,
                                            "AirPlay media access unit failed; decoder recovery unavailable"
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        // Keep the per-stream CTR position synchronized even when
                        // Media Foundation is unavailable or codec setup is pending.
                        if let Err(error) = cipher.decrypt_packet(&mut packet.payload) {
                            mirror_cipher = None;
                            tracing::warn!(
                                %packet.peer_addr,
                                timestamp = packet.timestamp,
                                %error,
                                "AirPlay mirror cipher failed while advancing an unrendered packet"
                            );
                        } else {
                            decrypted_access_units_discarded =
                                decrypted_access_units_discarded.saturating_add(1);
                            tracing::trace!(
                                %packet.peer_addr,
                                timestamp = packet.timestamp,
                                payload_bytes,
                                has_configuration,
                                received,
                                "Decrypted and discarded AirPlay packet because decoder is not ready"
                            );
                        }
                    }
                } else {
                    packets_waiting_for_fairplay = packets_waiting_for_fairplay.saturating_add(1);
                    tracing::debug!(
                        %packet.peer_addr,
                        timestamp = packet.timestamp,
                        payload_bytes,
                        has_configuration,
                        decoder_ready = frame_pipeline.is_some(),
                        received,
                        "AirPlay video packet received; waiting for FairPlay media key"
                    );
                }
            }
            super::video::MirrorPacketOutcome::Heartbeat => {
                heartbeat_packets = heartbeat_packets.saturating_add(1);
                tracing::trace!(%packet.peer_addr, "AirPlay mirror heartbeat received");
            }
        }
    }
    if let Err(error) = frames.clear() {
        tracing::warn!(%error, "Could not clear final AirPlay preview frame");
    }

    // Release the MFT pipeline on this worker thread before releasing its
    // Media Foundation runtime reference. H264Decoder owns thread-bound COM
    // interfaces, so this ordering must remain explicit during teardown.
    drop(frame_pipeline);
    drop(media_foundation);

    let mailbox_stats = frames.stats().ok();
    tracing::info!(
        stream_connection_id = ?stream_connection_id,
        received,
        received_payload_bytes,
        codec_configuration_bytes,
        video_packets,
        video_payload_bytes,
        processing_elapsed_ms = processing_started_at.elapsed().as_millis() as u64,
        codec_configurations,
        invalid_codec_configurations,
        packets_waiting_for_fairplay,
        decode_errors,
        decoder_initialization_successes,
        decoder_initialization_failures,
        decrypted_access_units_submitted,
        decrypted_access_units_discarded,
        decoded_frames_published,
        heartbeat_packets,
        mailbox_published = mailbox_stats.map(|stats| stats.published),
        mailbox_consumed = mailbox_stats.map(|stats| stats.consumed),
        mailbox_replaced = mailbox_stats.map(|stats| stats.replaced_before_consumption),
        "AirPlay media processing worker stopped with pipeline summary"
    );
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    protocol: String,
    cseq: String,
    connection_close: bool,
    headers: Vec<(String, String)>,
    body: Zeroizing<Vec<u8>>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn stop_session_channels(
    event_channel: &mut Option<EventChannel>,
    timing_client: &mut Option<TimingClient>,
    media_receiver: &mut Option<MediaSession>,
) {
    // Stop media reception first so no new video packets are accepted while
    // the control-side channels are being released. MediaSession::drop joins
    // both workers before the timing/event sockets are released.
    if media_receiver.is_some() {
        tracing::info!("AirPlay RTSP session: stopping media pipeline");
    }
    media_receiver.take();
    tracing::debug!("AirPlay RTSP session: media pipeline released");
    timing_client.take();
    event_channel.take();
    tracing::debug!("AirPlay RTSP session channels released");
}

pub fn serve(stream: TcpStream) -> std::io::Result<()> {
    serve_with_fairplay_provider(stream, None)
}

/// Serve one RTSP connection with an optional authorized FairPlay SAP provider.
/// The default listener deliberately supplies no provider and therefore fails
/// closed for FairPlay requests until a licensed implementation is configured.
pub fn serve_with_fairplay_provider(
    mut stream: TcpStream,
    fairplay_provider: Option<Arc<dyn super::fairplay::FairPlaySapProvider>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let peer_ip = stream.peer_addr()?.ip();
    #[cfg(windows)]
    let _pipeline_session = RtspPipelineSessionGuard::new();
    #[cfg(windows)]
    super::set_pipeline_stage(2);
    let mut pending = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut pair_setup_srp: Option<SrpServer> = None;
    let mut pair_setup_session_key: Option<Zeroizing<[u8; 64]>> = None;
    let mut pair_verify_session: Option<PairVerifySession> = None;
    let mut pair_verify_shared_secret: Option<Zeroizing<[u8; 32]>> = None;
    let mut fairplay_ekey: Option<Zeroizing<[u8; 72]>> = None;
    let mut fairplay_eiv: Option<Zeroizing<[u8; 16]>> = None;
    let mut fairplay_video_key: Option<Zeroizing<[u8; 16]>> = None;
    let mut fairplay_session: Option<super::fairplay::FairPlaySession> = None;
    let mut fairplay_initial: Option<super::fairplay::FairPlayMessage> = None;
    let mut fairplay_challenge: Option<super::fairplay::FairPlayChallenge> = None;
    let mut event_channel: Option<EventChannel> = None;
    let mut timing_client: Option<TimingClient> = None;
    let mut media_receiver: Option<MediaSession> = None;
    // RECORD and stream-level SETUP may arrive in either order on iOS.
    let mut record_received = false;
    tracing::info!("AirPlay RTSP session started");

    loop {
        let Some(request) = read_request(&mut stream, &mut pending)? else {
            tracing::info!("AirPlay RTSP peer closed the session");
            stop_session_channels(&mut event_channel, &mut timing_client, &mut media_receiver);
            return Ok(());
        };

        tracing::info!(
            method = %request.method,
            path = %request.path,
            protocol = %request.protocol,
            cseq = %request.cseq,
            body_bytes = request.body.len(),
            transport = ?request.header("Transport"),
            content_type = ?request.header("Content-Type"),
            user_agent = ?request.header("User-Agent"),
            "AirPlay RTSP request parsed"
        );

        let close_after_response = request.connection_close
            || request.protocol == "HTTP/1.1"
            || request.protocol == "HTTP/1.0";

        match (
            request.method.as_str(),
            request.path.as_str(),
            request.protocol.as_str(),
        ) {
            ("OPTIONS", _, "RTSP/1.0") => {
                let response = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nPublic: OPTIONS, GET, POST, SETUP, RECORD, TEARDOWN, fp-setup\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                write_response(&mut stream, &response, 200)?;
            }
            ("GET", "/server-info", "HTTP/1.1") | ("GET", "/server-info", "RTSP/1.0") => {
                let body = server_info_plist();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                write_response(&mut stream, &response, 200)?;
                return Ok(());
            }
            ("POST", "/pair-setup", "RTSP/1.0") => {
                // iOS uses transient (no-PIN) Pair-Setup when the receiver
                // does not advertise pw=true. That wire format is a raw
                // 32-byte Ed25519 public key, not a HomeKit TLV8/SRP message.
                let transient_pair_setup = request.body.len() == 32
                    && request.header("Content-Type").is_some_and(|value| {
                        value.eq_ignore_ascii_case("application/octet-stream")
                    });
                let setup_code = super::setup_code();
                let response_body = if transient_pair_setup {
                    super::pair_setup::accessory_public_key()
                        .map(|key| key.to_vec())
                        .map_err(|reason| PairSetupFailure::unavailable(reason))
                } else {
                    handle_pair_setup(
                        &request.body,
                        &mut pair_setup_srp,
                        &mut pair_setup_session_key,
                        Some(&setup_code),
                    )
                };
                match response_body {
                    Ok(body) => {
                        if transient_pair_setup {
                            tracing::info!(
                                controller_key_bytes = request.body.len(),
                                "AirPlay transient Pair-Setup accepted"
                            );
                        }
                        let header = format!(
                            "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                            request.cseq,
                            body.len()
                        );
                        stream.write_all(header.as_bytes())?;
                        stream.write_all(&body)?;
                        stream.flush()?;
                    }
                    Err(error) => {
                        // Only expose the first four bytes: enough to identify the
                        // TLV envelope/state and diagnose framing, without logging
                        // controller keys, SRP material, or encrypted payloads.
                        let body_prefix = request
                            .body
                            .iter()
                            .take(4)
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let content_type = request.header("Content-Type").unwrap_or("missing");
                        tracing::warn!(
                            status = error.status,
                            reason = %error.reason,
                            body_bytes = request.body.len(),
                            body_prefix = %body_prefix,
                            content_type,
                            "Pair-Setup request rejected"
                        );
                        let reason = if error.status == 503 {
                            "Service Unavailable"
                        } else {
                            "Bad Request"
                        };
                        let response = format!(
                            "RTSP/1.0 {} {}\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                            error.status, reason, request.cseq
                        );
                        write_response(&mut stream, &response, error.status)?;
                    }
                }
            }
            ("POST", "/fp-setup", "RTSP/1.0") => {
                // Never log the full M3 payload: it may contain SAP key material.
                let record_prefix = request
                    .body
                    .iter()
                    .take(16)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                tracing::info!(
                    body_prefix_hex = %record_prefix,
                    x_apple_et = ?request.header("X-Apple-ET"),
                    content_type = ?request.header("Content-Type"),
                    "AirPlay FairPlay request header"
                );

                match super::fairplay::parse_message(&request.body) {
                    Ok(message) if message.phase == super::fairplay::MessagePhase::Initial => {
                        // A new M1 starts a new negotiation on this RTSP
                        // connection. Stop any media worker that already copied
                        // the previous key before invalidating the key material;
                        // otherwise the old stream could keep decoding after
                        // this connection has begun a fresh FairPlay exchange.
                        media_receiver = None;
                        fairplay_ekey = None;
                        fairplay_eiv = None;
                        fairplay_video_key = None;
                        fairplay_initial = None;
                        fairplay_challenge = None;
                        fairplay_session = None;

                        let Some(provider) = fairplay_provider.as_ref() else {
                            #[cfg(windows)]
                            super::set_pipeline_stage(4);
                            tracing::warn!(
                                "FairPlay SAP unavailable: no authorized provider configured"
                            );
                            let response =
                                fairplay_error_response(501, "Not Implemented", &request.cseq);
                            write_response(&mut stream, &response, 501)?;
                            continue;
                        };

                        match provider.begin(&message) {
                            Ok(challenge) => {
                                let mut session = super::fairplay::FairPlaySession::new();
                                if let Err(error) = session.accept(message.clone()).and_then(|_| {
                                    session
                                        .mark_challenge_sent(challenge.mode, *challenge.challenge)
                                }) {
                                    tracing::warn!(%error, "FairPlay provider returned an invalid challenge");
                                    #[cfg(windows)]
                                    super::set_pipeline_stage(3);
                                    let response = fairplay_error_response(
                                        500,
                                        "Internal Server Error",
                                        &request.cseq,
                                    );
                                    write_response(&mut stream, &response, 500)?;
                                    continue;
                                }

                                let response_body =
                                    super::fairplay::build_m2(challenge.mode, &challenge.challenge);
                                fairplay_initial = Some(message);
                                fairplay_challenge = Some(challenge);
                                fairplay_session = Some(session);
                                #[cfg(windows)]
                                super::set_pipeline_stage(5);
                                write_binary_response(&mut stream, &request.cseq, &response_body)?;
                                tracing::info!("FairPlay SAP provider produced an M2 challenge");
                            }
                            Err(error) => {
                                let status = fairplay_provider_error_status(&error);
                                tracing::warn!(%error, status, "FairPlay SAP provider rejected M1");
                                #[cfg(windows)]
                                super::set_pipeline_stage(3);
                                let reason = reason_phrase(status);
                                let response =
                                    fairplay_error_response(status, reason, &request.cseq);
                                write_response(&mut stream, &response, status)?;
                            }
                        }
                    }
                    Ok(message) if message.phase == super::fairplay::MessagePhase::KeyMessage => {
                        let (Some(provider), Some(initial), Some(challenge), Some(session)) = (
                            fairplay_provider.as_ref(),
                            fairplay_initial.as_ref(),
                            fairplay_challenge.as_ref(),
                            fairplay_session.as_mut(),
                        ) else {
                            tracing::warn!(
                                "FairPlay M3 received without an active authenticated SAP negotiation"
                            );
                            #[cfg(windows)]
                            super::set_pipeline_stage(3);
                            // A late or unsolicited M3 cannot inherit any
                            // wrapped key material from an earlier exchange.
                            media_receiver = None;
                            fairplay_ekey = None;
                            fairplay_eiv = None;
                            fairplay_video_key = None;
                            fairplay_initial = None;
                            fairplay_challenge = None;
                            fairplay_session = None;
                            let response = fairplay_error_response(403, "Forbidden", &request.cseq);
                            write_response(&mut stream, &response, 403)?;
                            continue;
                        };

                        let state_validation = session.accept(message.clone());
                        if let Err(error) = state_validation {
                            tracing::warn!(%error, "FairPlay M3 state validation failed");
                            #[cfg(windows)]
                            super::set_pipeline_stage(3);
                            // A rejected M3 invalidates every piece of material
                            // from this exchange, including the wrapped key and IV.
                            media_receiver = None;
                            fairplay_ekey = None;
                            fairplay_eiv = None;
                            fairplay_video_key = None;
                            fairplay_initial = None;
                            fairplay_challenge = None;
                            fairplay_session = None;
                            let response =
                                fairplay_error_response(400, "Bad Request", &request.cseq);
                            write_response(&mut stream, &response, 400)?;
                            continue;
                        }

                        match provider.finish(initial, challenge, &message) {
                            Ok(keys) => {
                                let response_body =
                                    super::fairplay::build_m4(&keys.acknowledgement);
                                fairplay_video_key = Some(keys.video_key);
                                #[cfg(windows)]
                                super::set_pipeline_stage(6);
                                write_binary_response(&mut stream, &request.cseq, &response_body)?;
                                tracing::info!(
                                    has_fairplay_ekey = fairplay_ekey.is_some(),
                                    has_fairplay_eiv = fairplay_eiv.is_some(),
                                    "FairPlay SAP provider authenticated M3 and installed session keys"
                                );
                            }
                            Err(error) => {
                                // Authentication failure invalidates the entire
                                // exchange, not just its derived media key.
                                media_receiver = None;
                                fairplay_ekey = None;
                                fairplay_eiv = None;
                                fairplay_video_key = None;
                                fairplay_initial = None;
                                fairplay_challenge = None;
                                fairplay_session = None;
                                let status = fairplay_provider_error_status(&error);
                                tracing::warn!(%error, status, "FairPlay SAP provider rejected M3");
                                #[cfg(windows)]
                                super::set_pipeline_stage(3);
                                let response = fairplay_error_response(
                                    status,
                                    reason_phrase(status),
                                    &request.cseq,
                                );
                                write_response(&mut stream, &response, status)?;
                            }
                        }
                    }
                    Ok(message) => {
                        tracing::warn!(
                            phase = message.phase as u8,
                            "Unexpected receiver-originated FairPlay phase from sender"
                        );
                        #[cfg(windows)]
                        super::set_pipeline_stage(3);
                        // An out-of-order record invalidates the in-flight
                        // negotiation. Do not leave previously derived keys
                        // available after a protocol violation.
                        media_receiver = None;
                        fairplay_ekey = None;
                        fairplay_eiv = None;
                        fairplay_video_key = None;
                        fairplay_initial = None;
                        fairplay_challenge = None;
                        fairplay_session = None;
                        let response = fairplay_error_response(400, "Bad Request", &request.cseq);
                        write_response(&mut stream, &response, 400)?;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "AirPlay FairPlay setup framing rejected");
                        #[cfg(windows)]
                        super::set_pipeline_stage(3);
                        // Malformed FairPlay input is a hard boundary: discard
                        // every key and negotiation object from this exchange.
                        media_receiver = None;
                        fairplay_ekey = None;
                        fairplay_eiv = None;
                        fairplay_video_key = None;
                        fairplay_initial = None;
                        fairplay_challenge = None;
                        fairplay_session = None;
                        let response = fairplay_error_response(400, "Bad Request", &request.cseq);
                        write_response(&mut stream, &response, 400)?;
                    }
                }
            }
            ("POST", "/pair-verify", "RTSP/1.0") => {
                // A new Pair-Verify M1 starts a fresh authenticated transport
                // context. Do not tear it down again when the matching M3 arrives.
                if pair_verify_session.is_none() {
                    tracing::info!("Pair-Verify starting a new authentication context");
                    stop_session_channels(
                        &mut event_channel,
                        &mut timing_client,
                        &mut media_receiver,
                    );
                    pair_verify_shared_secret = None;
                    fairplay_ekey = None;
                    fairplay_eiv = None;
                    fairplay_video_key = None;
                    fairplay_initial = None;
                    fairplay_challenge = None;
                    fairplay_session = None;
                }

                let response_body =
                    match handle_pair_verify(&request.body, &mut pair_verify_session) {
                        Ok((body, Some(shared_secret))) => {
                            #[cfg(windows)]
                            super::set_pipeline_stage(3);
                            pair_verify_shared_secret = Some(shared_secret);
                            body
                        }
                        Ok((body, None)) => {
                            pair_verify_shared_secret = None;
                            body
                        }
                        Err(error) => {
                            tracing::warn!(%error, "Pair-Verify exchange rejected");
                            // A failed exchange must not leave workers or key
                            // material bound to an earlier authentication context.
                            stop_session_channels(
                                &mut event_channel,
                                &mut timing_client,
                                &mut media_receiver,
                            );
                            pair_verify_session = None;
                            pair_verify_shared_secret = None;
                            fairplay_ekey = None;
                            fairplay_eiv = None;
                            fairplay_video_key = None;
                            fairplay_initial = None;
                            fairplay_challenge = None;
                            fairplay_session = None;
                            pair_verify::error_response()
                        }
                    };
                let header = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                    request.cseq,
                    response_body.len()
                );
                stream.write_all(header.as_bytes())?;
                stream.write_all(&response_body)?;
                stream.flush()?;
            }
            ("GET", "/info", "RTSP/1.0") | ("POST", "/info", "RTSP/1.0") => {
                match build_info_response(&request.body) {
                    Ok(body) => {
                        let header = format!(
                            "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
                            request.cseq,
                            body.len()
                        );
                        stream.write_all(header.as_bytes())?;
                        stream.write_all(&body)?;
                        stream.flush()?;
                    }
                    Err(reason) => {
                        tracing::warn!(%reason, "Rejected invalid AirPlay /info plist request");
                        let response = format!(
                            "RTSP/1.0 400 Bad Request\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                            request.cseq
                        );
                        write_response(&mut stream, &response, 400)?;
                    }
                }
            }
            ("SETUP", _, "RTSP/1.0") => {
                match handle_setup_request(
                    &request.body,
                    peer_ip,
                    &mut event_channel,
                    &mut timing_client,
                    &mut media_receiver,
                    &mut fairplay_ekey,
                    &mut fairplay_eiv,
                    fairplay_video_key.as_ref(),
                    pair_verify_shared_secret.as_deref(),
                ) {
                    Ok(body) => {
                        // Session-level SETUP only negotiates event/timing
                        // channels. Advance the media stage only after the
                        // stream-level SETUP has actually created its listener.
                        if media_receiver.is_some() {
                            #[cfg(windows)]
                            super::advance_pipeline_stage(if record_received { 8 } else { 7 });
                        } else {
                            // A successful session-level SETUP replaces the
                            // previous RTSP media session. RECORD from that
                            // older session must not leak into this one.
                            record_received = false;
                            #[cfg(windows)]
                            super::set_pipeline_stage(if fairplay_video_key.is_some() {
                                6
                            } else {
                                3
                            });
                        }
                        write_binary_plist_response(&mut stream, &request.cseq, &body)?;
                    }
                    Err((status, reason)) => {
                        tracing::warn!(status, %reason, "AirPlay SETUP request rejected");
                        let reason_phrase = match status {
                            455 => "Method Not Valid in This State",
                            501 => "Not Implemented",
                            503 => "Service Unavailable",
                            _ => "Bad Request",
                        };
                        let response = format!(
                            "RTSP/1.0 {status} {reason_phrase}\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                            request.cseq
                        );
                        write_response(&mut stream, &response, status)?;
                    }
                }
            }
            ("RECORD", _, "RTSP/1.0") => {
                let response = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                record_received = true;
                if media_receiver.is_some() {
                    tracing::info!(
                        media_listener_active = true,
                        stream_setup_complete = true,
                        "AirPlay RECORD accepted; negotiated media listener is ready"
                    );
                    #[cfg(windows)]
                    super::advance_pipeline_stage(8);
                } else {
                    // Some senders issue RECORD before stream-level SETUP.
                    // A successful RECORD response alone is not proof that a
                    // media listener exists, so retain the previous protocol
                    // stage until SETUP actually creates that listener.
                    tracing::info!(
                        stream_setup_complete = false,
                        "AirPlay RECORD accepted; awaiting stream-level SETUP before media reception"
                    );
                }
                write_response(&mut stream, &response, 200)?;
            }
            ("POST", "/feedback", "RTSP/1.0") => {
                let response = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                write_response(&mut stream, &response, 200)?;
            }
            ("TEARDOWN", _, "RTSP/1.0") => {
                stop_session_channels(&mut event_channel, &mut timing_client, &mut media_receiver);
                let response = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                write_response(&mut stream, &response, 200)?;
                return Ok(());
            }
            _ => {
                tracing::warn!(
                    method = %request.method,
                    path = %request.path,
                    protocol = %request.protocol,
                    "AirPlay control method is not implemented"
                );
                let protocol = if request.protocol == "RTSP/1.0" {
                    "RTSP/1.0"
                } else {
                    "HTTP/1.1"
                };
                let response = format!(
                    "{protocol} 501 Not Implemented\r\nCSeq: {}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n",
                    request.cseq
                );
                write_response(&mut stream, &response, 501)?;
            }
        }

        if close_after_response {
            stop_session_channels(&mut event_channel, &mut timing_client, &mut media_receiver);
            return Ok(());
        }
    }
}

/// Read one complete request and retain bytes belonging to a subsequent request.
fn read_request(stream: &mut TcpStream, pending: &mut Vec<u8>) -> std::io::Result<Option<Request>> {
    let mut chunk = [0u8; READ_CHUNK_BYTES];

    let header_end = loop {
        if let Some(index) = find_header_end(pending) {
            break index + 4;
        }
        if pending.len() >= MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AirPlay request headers exceeded size limit",
            ));
        }

        let count = stream.read(&mut chunk)?;
        if count == 0 {
            if pending.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before completing AirPlay request headers",
            ));
        }
        pending.extend_from_slice(&chunk[..count]);
    };

    if header_end > MAX_HEADER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AirPlay request headers exceeded size limit",
        ));
    }

    let header_text = String::from_utf8_lossy(&pending[..header_end - 4]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let protocol = parts.next().unwrap_or_default().to_owned();

    if method.is_empty() || path.is_empty() || protocol.is_empty() || parts.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid AirPlay request line",
        ));
    }

    let mut content_length = 0usize;
    let mut content_length_seen = false;
    let mut cseq = "0".to_owned();
    let mut cseq_seen = false;
    let mut connection_close = false;
    let mut headers = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, raw_value) = line.split_once(':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed AirPlay request header",
            )
        })?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid AirPlay request header name",
            ));
        }
        let value = raw_value.trim();
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid control character in AirPlay request header",
            ));
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length_seen {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate AirPlay Content-Length header",
                ));
            }
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid AirPlay Content-Length",
                ));
            }
            content_length_seen = true;
            content_length = value.parse().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid AirPlay Content-Length",
                )
            })?;
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AirPlay Transfer-Encoding is not supported",
            ));
        } else if name.eq_ignore_ascii_case("CSeq") {
            if cseq_seen {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate AirPlay CSeq header",
                ));
            }
            if value.is_empty()
                || value.len() > 10
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || value.parse::<u32>().is_err()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid AirPlay CSeq",
                ));
            }
            cseq_seen = true;
            cseq = value.to_owned();
        } else if name.eq_ignore_ascii_case("Connection") {
            connection_close = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"));
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }

    if protocol == "RTSP/1.0" && !cseq_seen {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RTSP request is missing required CSeq header",
        ));
    }

    if content_length > MAX_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AirPlay request body exceeded size limit",
        ));
    }

    let request_end = header_end.checked_add(content_length).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AirPlay request size overflow",
        )
    })?;

    while pending.len() < request_end {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before completing AirPlay request body",
            ));
        }
        pending.extend_from_slice(&chunk[..count]);
    }

    // Keep the owned request body in a zeroizing allocation, then erase the
    // consumed bytes from the reusable connection buffer before draining it.
    let body = Zeroizing::new(pending[header_end..request_end].to_vec());
    pending[header_end..request_end].zeroize();
    pending.drain(..request_end);

    Ok(Some(Request {
        method,
        path,
        protocol,
        cseq,
        connection_close,
        headers,
        body,
    }))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_binary_plist_response(
    stream: &mut TcpStream,
    cseq: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: RustPhoneControl/0.1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    tracing::info!(cseq, body_bytes = body.len(), "AirPlay SETUP response sent");
    Ok(())
}

fn handle_setup_request(
    body: &[u8],
    peer_ip: std::net::IpAddr,
    event_channel: &mut Option<EventChannel>,
    timing_client: &mut Option<TimingClient>,
    media_receiver: &mut Option<MediaSession>,
    fairplay_ekey: &mut Option<Zeroizing<[u8; 72]>>,
    fairplay_eiv: &mut Option<Zeroizing<[u8; 16]>>,
    fairplay_video_key: Option<&Zeroizing<[u8; 16]>>,
    pair_verify_shared_secret: Option<&[u8; 32]>,
) -> Result<Vec<u8>, (u16, String)> {
    let setup = setup::parse_setup_request(body).map_err(|reason| (400, reason))?;
    match setup {
        SetupRequest::Session(session) => {
            // Validate and start the requested clock protocol before allocating
            // the event listener. Unsupported or malformed timing requests must
            // not create transient sockets or disturb the active session.
            let new_timing_client = match session.timing_protocol.as_deref() {
                Some("NTP") => {
                    let sender_port = session.timing_port.ok_or_else(|| {
                        (400, "NTP SETUP is missing the sender timingPort".to_owned())
                    })?;
                    Some(TimingClient::start(peer_ip, sender_port).map_err(|error| {
                        (503, format!("could not start NTP timing client: {error}"))
                    })?)
                }
                Some("PTP") => {
                    return Err((
                        501,
                        "PTP clock synchronization is not implemented by this receiver".to_owned(),
                    ));
                }
                Some(other) => return Err((400, format!("unsupported timing protocol {other}"))),
                None => None,
            };
            let channel = EventChannel::bind(peer_ip)
                .map_err(|error| (503, format!("could not bind event channel: {error}")))?;
            let event_port = channel.port();
            let timing_port = new_timing_client.as_ref().map_or(0, TimingClient::port);

            tracing::info!(
                session_uuid_present = session.session_uuid.is_some(),
                screen_mirroring = session.screen_mirroring,
                timing_protocol = ?session.timing_protocol,
                sender_timing_port = ?session.timing_port,
                event_port,
                timing_port,
                "AirPlay session-level SETUP accepted; awaiting stream-level SETUP"
            );

            // Retain only validated key material for this RTSP session. The
            // wrapped key is not a usable AES key until FairPlay is completed.
            *fairplay_ekey = session.fairplay_ekey;
            *fairplay_eiv = session.fairplay_eiv;
            tracing::info!(
                has_fairplay_ekey = fairplay_ekey.is_some(),
                has_fairplay_eiv = fairplay_eiv.is_some(),
                "AirPlay SETUP FairPlay key material parsed"
            );

            let mut response = Dictionary::new();
            response.insert("eventPort".into(), Value::Integer(event_port.into()));
            response.insert("timingPort".into(), Value::Integer(timing_port.into()));
            // A fresh session-level SETUP starts a new RTSP session.
            // Stop any previous stream listener before publishing the new
            // event/timing channels so stale media workers cannot outlive it.
            *media_receiver = None;
            *event_channel = Some(channel);
            *timing_client = new_timing_client;
            plist::encode_binary(&Value::Dictionary(response)).map_err(|error| {
                (
                    503,
                    format!("could not encode session SETUP response: {error}"),
                )
            })
        }
        SetupRequest::Streams(streams) => {
            if event_channel.is_none() {
                return Err((455, "stream SETUP received before session SETUP".to_owned()));
            }
            if streams.len() != 1 {
                return Err((
                    501,
                    "only one media stream per RTSP session is supported".to_owned(),
                ));
            }
            let stream = &streams[0];
            if stream.stream_type != 110 {
                return Err((
                    501,
                    format!(
                        "media stream type {} is not supported; only screen mirroring type 110 is accepted",
                        stream.stream_type
                    ),
                ));
            }

            let Some(video_key) = fairplay_video_key else {
                return Err((
                    455,
                    "screen mirroring stream SETUP requires completed FairPlay authentication"
                        .to_owned(),
                ));
            };

            // Stream-level SETUP may be repeated within one RTSP session.
            // Join the previous media workers before creating another decoder
            // pipeline against the shared frame mailbox; otherwise the old
            // worker could clear or publish frames after the replacement starts.
            *media_receiver = None;

            let (media_foundation, frames) =
                super::media_pipeline_context().unwrap_or_else(|error| {
                    tracing::warn!(%error, "Could not obtain AirPlay decoder presentation context");
                    (None, Arc::new(super::video::LatestFrameMailbox::new()))
                });
            let receiver = MediaSession::start_with_context(
                peer_ip,
                MirrorStreamContext {
                    connection_id: stream.connection_id,
                    pair_verify_shared_secret: pair_verify_shared_secret
                        .map(|secret| Zeroizing::new(*secret)),
                    fairplay_video_key: Some(Zeroizing::new(**video_key)),
                    media_foundation,
                    frames,
                },
            )
            .map_err(|error| {
                (
                    503,
                    format!("could not start video media pipeline: {error}"),
                )
            })?;
            let data_port = receiver.port();

            let mut stream_response = Dictionary::new();
            stream_response.insert("type".into(), Value::Integer(stream.stream_type.into()));
            stream_response.insert("dataPort".into(), Value::Integer(data_port.into()));

            let mut response = Dictionary::new();
            response.insert(
                "streams".into(),
                Value::Array(vec![Value::Dictionary(stream_response)]),
            );
            *media_receiver = Some(receiver);
            tracing::info!(
                data_port,
                stream_connection_id = ?stream.connection_id,
                pair_verify_complete = pair_verify_shared_secret.is_some(),
                "AirPlay screen-mirroring TCP media port negotiated"
            );
            plist::encode_binary(&Value::Dictionary(response)).map_err(|error| {
                (
                    503,
                    format!("could not encode stream SETUP response: {error}"),
                )
            })
        }
    }
}

fn write_binary_response(stream: &mut TcpStream, cseq: &str, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "RTSP/1.0 200 OK\\r\\nCSeq: {}\\r\\nServer: RustPhoneControl/0.1\\r\\nContent-Type: application/octet-stream\\r\\nContent-Length: {}\\r\\n\\r\\n",
        cseq,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn fairplay_provider_error_status(error: &super::fairplay::FairPlayProviderError) -> u16 {
    match error {
        super::fairplay::FairPlayProviderError::Unavailable => 503,
        super::fairplay::FairPlayProviderError::UnsupportedMode(_) => 501,
        super::fairplay::FairPlayProviderError::InvalidMessage => 400,
        super::fairplay::FairPlayProviderError::AuthenticationFailed => 403,
        super::fairplay::FairPlayProviderError::Internal(_) => 500,
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

fn fairplay_error_response(status: u16, reason: &str, cseq: &str) -> String {
    format!(
        "RTSP/1.0 {status} {reason}\r\nCSeq: {cseq}\r\nServer: RustPhoneControl/0.1\r\nContent-Length: 0\r\n\r\n"
    )
}

fn write_response(stream: &mut TcpStream, response: &str, status: u16) -> std::io::Result<()> {
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    tracing::info!(
        status,
        response_bytes = response.len(),
        "AirPlay RTSP response sent"
    );
    Ok(())
}

#[derive(Debug)]
struct PairSetupFailure {
    status: u16,
    reason: String,
}

impl PairSetupFailure {
    fn bad_request(reason: impl Into<String>) -> Self {
        Self {
            status: 400,
            reason: reason.into(),
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: 503,
            reason: reason.into(),
        }
    }
}

/// Handle Pair-Setup M1/M3/M5 on one persistent RTSP connection.
/// The setup code is supplied by the application and is never logged.
fn handle_pair_setup(
    body: &[u8],
    srp_state: &mut Option<SrpServer>,
    session_key: &mut Option<Zeroizing<[u8; 64]>>,
    setup_code: Option<&str>,
) -> Result<Vec<u8>, PairSetupFailure> {
    let fields = match tlv8::decode(body) {
        Ok(fields) => fields,
        Err(error) => {
            *srp_state = None;
            *session_key = None;
            return Err(PairSetupFailure::bad_request(error.to_string()));
        }
    };
    let mut states = fields.iter().filter(|field| field.kind == 0x06);
    let Some(state) = states.next() else {
        *srp_state = None;
        *session_key = None;
        return Err(PairSetupFailure::bad_request("missing Pair-Setup State"));
    };
    if states.next().is_some() || state.value.len() != 1 {
        *srp_state = None;
        *session_key = None;
        return Err(PairSetupFailure::bad_request(
            "invalid Pair-Setup State field",
        ));
    }

    match state.value[0] {
        1 => {
            // A fresh M1 always replaces any abandoned exchange, even when
            // the new request later fails validation.
            *srp_state = None;
            *session_key = None;
            pairing::parse_m1(body)
                .map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;
            let code = setup_code.ok_or_else(|| {
                PairSetupFailure::unavailable("the receiver has no generated pairing code")
            })?;
            if !pairing::is_valid_setup_code(code) {
                return Err(PairSetupFailure::unavailable(
                    "the generated pairing code has an invalid format",
                ));
            }

            let server = SrpServer::new(code)
                .map_err(|error| PairSetupFailure::unavailable(error.to_string()))?;
            let response = tlv8::encode(&[
                Tlv {
                    kind: 0x06,
                    value: vec![0x02],
                },
                Tlv {
                    kind: 0x03,
                    value: server
                        .public_key()
                        .map_err(|error| PairSetupFailure::unavailable(error.to_string()))?,
                },
                Tlv {
                    kind: 0x02,
                    value: server.salt().to_vec(),
                },
            ]);
            *srp_state = Some(server);
            *session_key = None;
            Ok(response)
        }
        5 => {
            let encrypted_data = fields
                .iter()
                .filter(|field| field.kind == 0x05)
                .collect::<Vec<_>>();
            if encrypted_data.len() != 1 {
                *session_key = None;
                return Ok(tlv8::encode(&[
                    Tlv {
                        kind: 0x06,
                        value: vec![0x06],
                    },
                    Tlv {
                        kind: 0x07,
                        value: vec![0x02],
                    },
                ]));
            }
            let key = session_key.take().ok_or_else(|| {
                PairSetupFailure::bad_request(
                    "Pair-Setup M5 received without a verified M3 exchange",
                )
            })?;
            match pair_setup::handle_m5(&key, &encrypted_data[0].value) {
                Ok(response) => Ok(response),
                Err(error) => {
                    tracing::warn!(%error, "Pair-Setup M5 identity exchange rejected");
                    Ok(tlv8::encode(&[
                        Tlv {
                            kind: 0x06,
                            value: vec![0x06],
                        },
                        Tlv {
                            kind: 0x07,
                            value: vec![0x02],
                        },
                    ]))
                }
            }
        }
        3 => {
            // Consume the pending exchange before parsing M3 so malformed or
            // unauthenticated retries cannot reuse its SRP state or session key.
            *session_key = None;
            let server = srp_state.take().ok_or_else(|| {
                PairSetupFailure::bad_request("Pair-Setup M3 received without an M1 exchange")
            })?;
            let message = pairing::parse_m3(body)
                .map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;

            match server.verify_client(&message.public_key, &message.proof) {
                Ok(result) => {
                    let response = tlv8::encode(&[
                        Tlv {
                            kind: 0x06,
                            value: vec![0x04],
                        },
                        Tlv {
                            kind: 0x04,
                            value: result.proof.to_vec(),
                        },
                    ]);
                    *session_key = Some(Zeroizing::new(result.session_key));
                    Ok(response)
                }
                Err(error) => {
                    tracing::warn!(%error, "Pair-Setup SRP proof rejected");
                    *session_key = None;
                    Ok(tlv8::encode(&[
                        Tlv {
                            kind: 0x06,
                            value: vec![0x04],
                        },
                        Tlv {
                            kind: 0x07,
                            value: vec![0x02],
                        },
                    ]))
                }
            }
        }
        other => {
            *srp_state = None;
            *session_key = None;
            Err(PairSetupFailure::bad_request(format!(
                "unsupported Pair-Setup state {other}"
            )))
        }
    }
}

/// Handle one Pair-Verify state transition on the current RTSP connection.
///
/// Legacy AirPlay Pair-Verify is a fixed 68-byte binary envelope, not TLV8.
/// Dispatch it before attempting to decode a HAP State field.
fn handle_pair_verify(
    body: &[u8],
    session: &mut Option<PairVerifySession>,
) -> Result<(Vec<u8>, Option<Zeroizing<[u8; 32]>>), String> {
    if body.len() == 68 && body[..4] == [1, 0, 0, 0] {
        if session.is_some() {
            return Err("Legacy Pair-Verify M1 received while another exchange is active".into());
        }
        let (new_session, response) = PairVerifySession::start(body)?;
        *session = Some(new_session);
        return Ok((response, None));
    }

    if body.len() == 68 && body[..4] == [0, 0, 0, 0] {
        let current = session
            .take()
            .ok_or_else(|| "Legacy Pair-Verify M3 received without M1".to_owned())?;
        let completion = current.finish(body)?;
        if pair_setup::is_controller_public_key_denied(&completion.controller_public_key)? {
            return Err("Legacy Pair-Verify controller was previously denied".into());
        }
        if !pair_setup::is_controller_public_key_paired(&completion.controller_public_key)? {
            super::queue_pending_controller(completion.controller_public_key)?;
            return Err("Legacy Pair-Verify controller is awaiting local approval".into());
        }
        tracing::info!("Legacy Pair-Verify authenticated an approved controller");
        return Ok((completion.response, Some(completion.shared_secret)));
    }

    // HAP Pair-Verify uses TLV8 with State=1 for M1 and State=3 for M3.
    let fields = tlv8::decode(body).map_err(|error| error.to_string())?;
    let mut states = fields.iter().filter(|field| field.kind == 0x06);
    let state = states
        .next()
        .ok_or_else(|| "Pair-Verify request is missing State".to_owned())?;
    if states.next().is_some() || state.value.len() != 1 {
        return Err("Pair-Verify request has an invalid State field".into());
    }

    match state.value[0] {
        1 => {
            if session.is_some() {
                return Err("Pair-Verify M1 received while another exchange is active".into());
            }
            let (new_session, response) = PairVerifySession::start(body)?;
            *session = Some(new_session);
            Ok((response, None))
        }
        3 => {
            let current = session
                .take()
                .ok_or_else(|| "Pair-Verify M3 received without M1".to_owned())?;
            let completion = current.finish(body)?;
            if pair_setup::is_controller_public_key_denied(&completion.controller_public_key)? {
                return Err("Pair-Verify controller was previously denied".into());
            }
            if !pair_setup::is_controller_public_key_paired(&completion.controller_public_key)? {
                super::queue_pending_controller(completion.controller_public_key)?;
                return Err("Pair-Verify controller is awaiting local approval".into());
            }
            tracing::info!("HAP Pair-Verify authenticated an approved controller");
            Ok((completion.response, Some(completion.shared_secret)))
        }
        other => Err(format!("unsupported Pair-Verify state {other}")),
    }
}

fn pair_verify_error_response() -> Vec<u8> {
    tlv8::encode(&[
        Tlv {
            kind: 0x06,
            value: vec![4],
        },
        Tlv {
            kind: 0x07,
            value: vec![2],
        },
    ])
}

fn server_info_features() -> i64 {
    let mut parts = config::FEATURES.split(',');
    let low = parts
        .next()
        .and_then(|part| u32::from_str_radix(part.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0) as u64;
    let high = parts
        .next()
        .and_then(|part| u32::from_str_radix(part.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0) as u64;

    ((high << 32) | low) as i64
}

fn server_info_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>deviceid</key><string>{}</string><key>features</key><integer>{}</integer><key>model</key><string>{}</string><key>protovers</key><string>1.0</string><key>srcvers</key><string>{}</string></dict></plist>",
        config::device_id(),
        server_info_features(),
        config::MODEL,
        config::SOURCE_VERSION
    )
}

fn build_info_response(request_body: &[u8]) -> Result<Vec<u8>, String> {
    let response = if request_body.is_empty() {
        // Unqualified /info asks for baseline playback information.
        let mut dictionary = Dictionary::new();
        dictionary.insert("initialVolume".into(), Value::Integer((-120).into()));
        dictionary
    } else {
        let request = plist::decode(request_body).map_err(|error| error.to_string())?;
        let dictionary = request
            .as_dictionary()
            .ok_or_else(|| "AirPlay /info request root must be a dictionary".to_owned())?;

        let qualifier = dictionary
            .get("qualifier")
            .ok_or_else(|| "AirPlay /info request is missing qualifier".to_owned())?
            .as_array()
            .ok_or_else(|| "AirPlay /info qualifier must be an array".to_owned())?;

        if qualifier.iter().any(|value| value.as_string().is_none()) {
            return Err("AirPlay /info qualifier entries must be strings".to_owned());
        }

        let asks_for_txt = qualifier
            .iter()
            .filter_map(Value::as_string)
            .any(|value| value == "txtAirPlay");

        if asks_for_txt {
            txt_airplay_dictionary()
        } else {
            return Err("unsupported AirPlay /info qualifier".to_owned());
        }
    };

    plist::encode_binary(&Value::Dictionary(response)).map_err(|error| error.to_string())
}

/// Return the conservative properties also published in the mDNS TXT record.
fn txt_airplay_dictionary() -> Dictionary {
    let mut dictionary = Dictionary::new();
    dictionary.insert("deviceid".into(), Value::String(config::device_id()));
    dictionary.insert("features".into(), Value::String(config::FEATURES.into()));
    dictionary.insert("model".into(), Value::String(config::MODEL.into()));
    dictionary.insert(
        "srcvers".into(),
        Value::String(config::SOURCE_VERSION.into()),
    );
    dictionary.insert("flags".into(), Value::String(config::STATUS_FLAGS.into()));
    dictionary
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_frame_timeout_requires_a_valid_elapsed_interval() {
        use std::time::{Duration, Instant};

        let now = Instant::now();
        assert!(!super::first_frame_wait_timed_out(None, now));
        assert!(!super::first_frame_wait_timed_out(
            Some(now + Duration::from_secs(1)),
            now
        ));
        assert!(!super::first_frame_wait_timed_out(
            Some(now - Duration::from_secs(14)),
            now
        ));
        assert!(super::first_frame_wait_timed_out(
            Some(now - Duration::from_secs(15)),
            now
        ));
        assert!(super::first_frame_wait_timed_out(
            Some(now - Duration::from_secs(30)),
            now
        ));
    }

    use super::MediaWorkerMessage;
    use super::SrpServer;
    use super::Zeroizing;
    use super::plist;
    use super::{
        Request, SCREEN_MIRROR_HEADER_SIZE, TcpStream, build_info_response, find_header_end,
        handle_pair_setup, handle_pair_verify, handle_setup_request, server_info_plist,
    };
    use crate::airplay::tlv8::{self, Tlv};
    use ::plist::{Dictionary, Value};

    fn read_request_from_bytes(bytes: &[u8]) -> std::io::Result<Option<Request>> {
        use std::io::Write;
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(1)))?;
        client.write_all(bytes)?;
        client.shutdown(std::net::Shutdown::Write)?;
        let mut pending = Vec::new();
        super::read_request(&mut server, &mut pending)
    }

    #[test]
    fn fairplay_m1_fails_closed_without_sap_provider() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind RTSP test listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept RTSP test client");
            super::serve(stream).expect("serve FairPlay request");
        });

        let mut client = TcpStream::connect(address).expect("connect RTSP test client");
        let mut body = vec![0u8; 16];
        body[..4].copy_from_slice(b"FPLY");
        body[4..8].copy_from_slice(&[3, 1, 1, 0]);
        body[8..12].copy_from_slice(&4u32.to_be_bytes());
        body[12..16].copy_from_slice(&[0x02, 0x00, 0x02, 0xbb]);

        let request = format!(
            "POST /fp-setup RTSP/1.0\r\nCSeq: 77\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        client
            .write_all(request.as_bytes())
            .expect("write RTSP headers");
        client.write_all(&body).expect("write FairPlay M1 body");

        let mut response = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let read = client.read(&mut chunk).expect("read RTSP response");
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("RTSP/1.0 501 Not Implemented"),
            "unexpected FairPlay response: {response}"
        );

        drop(client);
        server.join().expect("RTSP server thread exits");
    }

    #[test]
    fn teardown_releases_media_event_and_timing_channels_together() {
        use super::super::video::{BgraFrame, LatestFrameMailbox};
        use std::net::{TcpListener, UdpSocket};
        use std::sync::Arc;

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let frames = Arc::new(LatestFrameMailbox::new());
        frames
            .publish(BgraFrame {
                width: 1,
                height: 1,
                stride: 4,
                data: vec![0; 4],
            })
            .expect("publish a pending frame before teardown");
        let mut event_channel =
            Some(super::super::event::EventChannel::bind(peer_ip).expect("event channel"));
        let mut timing_client =
            Some(super::super::timing::TimingClient::start(peer_ip, 9).expect("timing client"));
        let mut media_receiver = Some(
            super::MediaSession::start_with_context(
                peer_ip,
                super::MirrorStreamContext {
                    connection_id: None,
                    pair_verify_shared_secret: None,
                    fairplay_video_key: None,
                    media_foundation: None,
                    frames: Arc::clone(&frames),
                },
            )
            .expect("media session"),
        );

        let event_port = event_channel.as_ref().expect("event channel").port();
        let timing_port = timing_client.as_ref().expect("timing client").port();
        let media_port = media_receiver.as_ref().expect("media session").port();

        super::stop_session_channels(&mut event_channel, &mut timing_client, &mut media_receiver);

        assert!(event_channel.is_none());
        assert!(timing_client.is_none());
        assert!(media_receiver.is_none());
        assert!(
            !frames
                .has_pending_frame()
                .expect("read mailbox after teardown")
        );
        assert!(
            TcpListener::bind(("0.0.0.0", event_port)).is_ok(),
            "event TCP port must be released"
        );
        assert!(
            UdpSocket::bind(("0.0.0.0", timing_port)).is_ok(),
            "timing UDP port must be released"
        );
        assert!(
            TcpListener::bind(("0.0.0.0", media_port)).is_ok(),
            "media TCP port must be released"
        );
    }

    #[test]
    fn media_session_stop_interrupts_an_idle_partial_mirror_packet() {
        use super::super::video::LatestFrameMailbox;
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let frames = Arc::new(LatestFrameMailbox::new());
        let mut media = super::MediaSession::start_with_context(
            peer_ip,
            super::MirrorStreamContext {
                connection_id: None,
                pair_verify_shared_secret: None,
                fairplay_video_key: None,
                media_foundation: None,
                frames: Arc::clone(&frames),
            },
        )
        .expect("start media session");
        frames
            .publish(super::super::video::BgraFrame {
                width: 1,
                height: 1,
                stride: 4,
                data: vec![7; 4],
            })
            .expect("publish frame before session teardown");
        let stale_snapshot = frames
            .take_latest()
            .expect("take frame before session teardown")
            .expect("frame snapshot");
        let port = media.port();
        let mut client =
            TcpStream::connect(("127.0.0.1", port)).expect("connect mirror TCP client");
        client
            .write_all(&[0x00])
            .expect("send an incomplete mirror packet header");

        // Let the accept worker enter its bounded header read before stopping.
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        media.stop();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stopping an idle mirror client must not block shutdown"
        );
        assert!(
            frames
                .stats()
                .expect("read mailbox teardown stats")
                .clear_events
                >= 1,
            "stopping the media session must publish a mailbox clear event"
        );
        assert!(
            !frames.is_generation_current(stale_snapshot.generation),
            "stopping a media session must invalidate already-consumed frame snapshots"
        );
        frames
            .publish(super::super::video::BgraFrame {
                width: 1,
                height: 1,
                stride: 4,
                data: vec![9; 4],
            })
            .expect("publish frame in replacement session generation");
        let replacement_snapshot = frames
            .take_latest()
            .expect("take replacement session frame")
            .expect("replacement frame snapshot");
        assert_ne!(
            replacement_snapshot.generation, stale_snapshot.generation,
            "replacement session frames must not reuse the stopped session generation"
        );
        assert!(frames.is_generation_current(replacement_snapshot.generation));
        assert!(
            TcpListener::bind(("0.0.0.0", port)).is_ok(),
            "media listener port must be released after stopping an active client"
        );
        drop(client);
    }

    #[test]
    fn media_session_accepts_a_new_client_after_previous_client_disconnects() {
        use super::super::video::LatestFrameMailbox;
        use std::io::Write;
        use std::net::Shutdown;
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        fn wait_for_counter(
            counter: &std::sync::atomic::AtomicU64,
            expected: u64,
            description: &str,
        ) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while counter.load(Ordering::Acquire) < expected && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                counter.load(Ordering::Acquire) >= expected,
                "timed out waiting for {description}"
            );
        }

        fn wait_for_clear_events(frames: &LatestFrameMailbox, expected: u64, description: &str) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while frames.stats().expect("read mailbox stats").clear_events < expected
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                frames.stats().expect("read mailbox stats").clear_events >= expected,
                "timed out waiting for {description}"
            );
        }

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let frames = Arc::new(LatestFrameMailbox::new());
        let mut media = super::MediaSession::start_with_context(
            peer_ip,
            super::MirrorStreamContext {
                connection_id: None,
                pair_verify_shared_secret: None,
                fairplay_video_key: None,
                media_foundation: None,
                frames: Arc::clone(&frames),
            },
        )
        .expect("start media session");
        let port = media.port();

        let mut first =
            TcpStream::connect(("127.0.0.1", port)).expect("connect first mirror client");
        first.write_all(&[0x00]).expect("send partial first packet");
        wait_for_counter(&media.accepted_clients, 1, "first client acceptance");
        first
            .shutdown(Shutdown::Both)
            .expect("close first mirror client");
        wait_for_counter(&media.disconnected_clients, 1, "first client disconnection");
        wait_for_clear_events(&frames, 1, "first disconnect boundary processing");
        drop(first);

        let mut second = TcpStream::connect(("127.0.0.1", port))
            .expect("connect second mirror client after disconnect");
        second
            .write_all(&[0x00])
            .expect("send partial second packet");
        wait_for_counter(&media.accepted_clients, 2, "second client acceptance");
        second
            .shutdown(Shutdown::Both)
            .expect("close second mirror client");
        wait_for_counter(
            &media.disconnected_clients,
            2,
            "second client disconnection",
        );
        wait_for_clear_events(&frames, 2, "second disconnect boundary processing");
        media.stop();
    }

    #[test]
    fn mirror_reader_times_out_when_peer_stops_mid_packet() {
        use std::net::TcpListener;
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
        let client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("connect local client");
        let (mut server, _) = listener.accept().expect("accept local client");
        server
            .set_read_timeout(Some(Duration::from_millis(5)))
            .expect("set short read timeout");
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let mut packet_header = [0u8; 16];

        let error = super::read_exact_while_running(
            &mut server,
            &mut packet_header,
            &running,
            Duration::from_millis(20),
        )
        .expect_err("idle peer must be disconnected");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        client
            .shutdown(std::net::Shutdown::Both)
            .expect("close idle test client");
    }

    #[test]
    fn rejects_peer_disconnect_before_request_headers_are_complete() {
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1";
        let error = read_request_from_bytes(request).expect_err("truncated headers rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_peer_disconnect_before_request_body_is_complete() {
        let request = b"POST /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 5\r\n\r\nab";
        let error = read_request_from_bytes(request).expect_err("truncated body rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parses_back_to_back_rtsp_requests_without_losing_buffered_bytes() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let mut client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("connect loopback");
        let (mut server, _) = listener.accept().expect("accept loopback");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set read timeout");

        client
            .write_all(
                b"OPTIONS * RTSP/1.0\r\nCSeq: 10\r\n\r\nOPTIONS * RTSP/1.0\r\nCSeq: 11\r\n\r\n",
            )
            .expect("write pipelined requests");

        let mut pending = Vec::new();
        let first = super::read_request(&mut server, &mut pending)
            .expect("read first request")
            .expect("first request exists");
        assert_eq!(first.cseq, "10");

        let second = super::read_request(&mut server, &mut pending)
            .expect("read second request")
            .expect("second request exists");
        assert_eq!(second.cseq, "11");
        assert!(pending.is_empty());
    }

    #[test]
    fn rejects_duplicate_and_malformed_cseq_headers() {
        let duplicate = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nCSeq: 2\r\n\r\n";
        let error = read_request_from_bytes(duplicate).expect_err("duplicate CSeq rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let malformed = b"OPTIONS * RTSP/1.0\r\nCSeq: one\r\n\r\n";
        let error = read_request_from_bytes(malformed).expect_err("non-numeric CSeq rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_signed_content_length() {
        let request = b"POST /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: +1\r\n\r\n";
        let error = read_request_from_bytes(request).expect_err("signed content length rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_control_characters_in_header_values() {
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nX-Test: bad\x01value\r\n\r\n";
        let error = read_request_from_bytes(request).expect_err("control character rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_rtsp_request_without_cseq() {
        let request = b"OPTIONS * RTSP/1.0\r\n\r\n";
        let error =
            read_request_from_bytes(request).expect_err("RTSP request without CSeq rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_ambiguous_body_framing_headers() {
        let duplicate_length =
            b"POST /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n";
        let error = read_request_from_bytes(duplicate_length)
            .expect_err("duplicate content length rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let transfer_encoding =
            b"POST /info RTSP/1.0\r\nCSeq: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let error =
            read_request_from_bytes(transfer_encoding).expect_err("transfer encoding rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_request_body_larger_than_configured_limit() {
        let request = b"POST /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 65537\r\n\r\n";
        let error = read_request_from_bytes(request).expect_err("oversized body rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_cseq_values_outside_rfc_integer_range() {
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 4294967296\r\n\r\n";
        let error = read_request_from_bytes(request).expect_err("overflowing CSeq rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_extra_tokens_in_request_line() {
        let request = b"OPTIONS * RTSP/1.0 ignored\r\nCSeq: 1\r\n\r\n";
        let error = read_request_from_bytes(request).expect_err("extra request token rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn parses_valid_request_after_strict_request_line_validation() {
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 42\r\n\r\n";
        let parsed = read_request_from_bytes(request)
            .expect("valid request read")
            .expect("request present");
        assert_eq!(parsed.method, "OPTIONS");
        assert_eq!(parsed.cseq, "42");
    }

    #[test]
    fn finds_header_terminator() {
        let request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        assert_eq!(
            find_header_end(request),
            Some(b"OPTIONS * RTSP/1.0\r\nCSeq: 1".len())
        );
        assert_eq!(find_header_end(b"OPTIONS * RTSP/1.0\r\n"), None);
    }
    #[test]
    fn request_header_lookup_is_case_insensitive() {
        let request = Request {
            method: "SETUP".into(),
            path: "/stream".into(),
            protocol: "RTSP/1.0".into(),
            cseq: "7".into(),
            connection_close: false,
            headers: vec![("transport".into(), "RTP/AVP/UDP;unicast".into())],
            body: Zeroizing::default(),
        };
        assert_eq!(request.header("Transport"), Some("RTP/AVP/UDP;unicast"));
    }

    #[test]
    fn mirror_tcp_stream_reads_128_byte_header_and_payload() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP listener binds");
        let mut client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("TCP client connects");
        let (server, peer_addr) = listener.accept().expect("accept TCP client");
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set read timeout");

        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let (sender, receiver) = mpsc::sync_channel(2);
        let worker = thread::spawn(move || {
            super::read_mirror_stream(server, peer_addr, &sender, &worker_running);
        });

        let mut packet = vec![0u8; SCREEN_MIRROR_HEADER_SIZE + 3];
        packet[0..4].copy_from_slice(&3u32.to_le_bytes());
        packet[4..6].copy_from_slice(&0u16.to_le_bytes());
        packet[8..16].copy_from_slice(&123u64.to_le_bytes());
        packet[SCREEN_MIRROR_HEADER_SIZE..].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        client
            .write_all(&packet)
            .expect("write framed mirror packet");

        let received = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("TCP packet forwarded");
        let MediaWorkerMessage::Packet(received) = received else {
            panic!("expected a framed media packet");
        };
        assert_eq!(
            received.packet_type,
            super::super::media::ScreenMirrorPacketType::Video
        );
        assert_eq!(received.timestamp, 123);
        assert_eq!(received.payload, vec![0xAA, 0xBB, 0xCC]);

        running.store(false, Ordering::Release);
        worker.join().expect("TCP stream worker exits");
    }

    #[test]
    fn mirror_reader_stops_when_session_is_cancelled_mid_header() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP listener binds");
        let client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("TCP client connects");
        let (server, peer_addr) = listener.accept().expect("accept TCP client");
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set read timeout");

        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let (sender, _receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            super::read_mirror_stream(server, peer_addr, &sender, &worker_running);
        });

        thread::sleep(Duration::from_millis(10));
        running.store(false, Ordering::Release);
        worker
            .join()
            .expect("mirror reader exits after session cancellation");
        drop(client);
    }

    #[test]
    fn mirror_listener_accepts_a_new_client_after_disconnect() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mirror listener");
        listener
            .set_nonblocking(true)
            .expect("make mirror listener nonblocking");
        let address = listener.local_addr().expect("listener address");
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let (sender, receiver) = mpsc::sync_channel(4);
        let accepted_clients = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let disconnected_clients = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_accepted_clients = Arc::clone(&accepted_clients);
        let worker_disconnected_clients = Arc::clone(&disconnected_clients);
        let worker = thread::spawn(move || {
            super::accept_mirror_connections(
                listener,
                worker_running,
                address.ip(),
                sender,
                worker_accepted_clients,
                worker_disconnected_clients,
            );
        });

        let mut heartbeat = [0u8; super::SCREEN_MIRROR_HEADER_SIZE];
        heartbeat[4..6].copy_from_slice(&2u16.to_le_bytes());

        let mut first = TcpStream::connect(address).expect("first mirror client connects");
        first
            .write_all(&heartbeat)
            .expect("first client sends heartbeat");
        drop(first);

        let mut second = TcpStream::connect(address).expect("reconnected mirror client connects");
        second
            .write_all(&heartbeat)
            .expect("reconnected client sends heartbeat");
        drop(second);

        let first_packet = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("first client packet is received");
        let second_packet = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("disconnect marker follows first client packet");
        let third_message = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("second client packet is received after reconnect");

        running.store(false, Ordering::Release);
        worker.join().expect("mirror listener stops");
        assert!(matches!(
            first_packet,
            super::MediaWorkerMessage::Packet(ref packet)
                if packet.packet_type == crate::airplay::media::ScreenMirrorPacketType::Heartbeat
        ));
        assert!(matches!(
            second_packet,
            super::MediaWorkerMessage::StreamDisconnected
        ));
        assert!(matches!(
            third_message,
            super::MediaWorkerMessage::Packet(ref packet)
                if packet.packet_type == crate::airplay::media::ScreenMirrorPacketType::Heartbeat
        ));
    }

    #[test]
    fn media_session_starts_and_stops_its_workers() {
        use std::net::TcpListener;

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let mut session = super::MediaSession::start(peer_ip).expect("start media session");
        let port = session.port();
        assert_ne!(port, 0);
        assert!(
            TcpStream::connect((peer_ip, port)).is_ok(),
            "media listener must accept connections before stop"
        );

        session.stop();
        assert!(
            TcpListener::bind(("0.0.0.0", port)).is_ok(),
            "media listener port must be released after stop"
        );
        assert!(session.accept_worker.is_none());
        assert!(session.worker.is_none());

        // Stop is intentionally idempotent so TEARDOWN and Drop may both
        // release the same session without joining a worker twice.
        session.stop();
        assert!(session.accept_worker.is_none());
        assert!(session.worker.is_none());
    }

    #[test]
    fn screen_stream_setup_requires_completed_fairplay_authentication() {
        let mut session = Dictionary::new();
        session.insert("sessionUUID".into(), Value::String("test-session".into()));
        session.insert("isScreenMirroringSession".into(), Value::Boolean(true));
        let session_body =
            plist::encode_binary(&Value::Dictionary(session)).expect("encode session setup");

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let mut event = None;
        let mut timing = None;
        let mut media = None;
        handle_setup_request(
            &session_body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("session SETUP");

        let mut stream = Dictionary::new();
        stream.insert("type".into(), Value::Integer(110.into()));
        stream.insert("streamConnectionID".into(), Value::Integer(42.into()));
        let mut root = Dictionary::new();
        root.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(stream)]),
        );
        let stream_body =
            plist::encode_binary(&Value::Dictionary(root)).expect("encode stream setup");

        let error = handle_setup_request(
            &stream_body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect_err("stream SETUP without FairPlay must fail closed");
        assert_eq!(error.0, 455);
        assert!(media.is_none());
    }

    fn session_and_video_stream_setup_negotiate_ephemeral_ports() {
        let mut session = Dictionary::new();
        session.insert("sessionUUID".into(), Value::String("test-session".into()));
        session.insert("isScreenMirroringSession".into(), Value::Boolean(true));
        let session_body =
            plist::encode_binary(&Value::Dictionary(session)).expect("encode session setup");

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let mut event = None;
        let mut timing = None;
        let mut media = None;
        let response = handle_setup_request(
            &session_body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("session SETUP");
        let value = plist::decode(&response).expect("decode session response");
        let dictionary = value.as_dictionary().expect("session response dictionary");
        let event_port = dictionary
            .get("eventPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("event port");
        assert!(event_port > 0);
        assert_eq!(
            dictionary.get("timingPort").and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            }),
            Some(0)
        );
        assert!(event.is_some());

        let mut stream = Dictionary::new();
        stream.insert("type".into(), Value::Integer(110.into()));
        stream.insert("streamConnectionID".into(), Value::Integer(42.into()));
        let mut root = Dictionary::new();
        root.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(stream)]),
        );
        let stream_body =
            plist::encode_binary(&Value::Dictionary(root)).expect("encode stream setup");

        let response = handle_setup_request(
            &stream_body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("screen stream SETUP");
        let value = plist::decode(&response).expect("decode stream response");
        let dictionary = value.as_dictionary().expect("stream response dictionary");
        let streams = dictionary
            .get("streams")
            .and_then(Value::as_array)
            .expect("response streams");
        let negotiated = streams[0].as_dictionary().expect("stream response item");
        let data_port = negotiated
            .get("dataPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("data port");
        assert!(data_port > 0);
        assert_eq!(
            negotiated.get("type").and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            }),
            Some(110)
        );
        assert!(media.is_some());

        // A repeated stream SETUP replaces the previous listener rather than
        // leaving two media endpoints alive for one RTSP session.
        let old_port = data_port as u16;
        let response = handle_setup_request(
            &stream_body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("repeated screen stream SETUP");
        let value = plist::decode(&response).expect("decode replacement stream response");
        let dictionary = value
            .as_dictionary()
            .expect("replacement stream dictionary");
        let streams = dictionary
            .get("streams")
            .and_then(Value::as_array)
            .expect("replacement response streams");
        let replacement = streams[0]
            .as_dictionary()
            .expect("replacement stream response item");
        let new_port = replacement
            .get("dataPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("replacement data port") as u16;
        assert_ne!(old_port, new_port);
        assert!(
            TcpStream::connect((peer_ip, old_port)).is_err(),
            "previous media listener must be closed after replacement"
        );
        assert!(TcpStream::connect((peer_ip, new_port)).is_ok());
    }

    #[test]
    fn repeated_session_setup_releases_previous_event_and_timing_ports() {
        use std::net::{TcpListener, UdpSocket};

        let sender_one = UdpSocket::bind("127.0.0.1:0").expect("bind first timing sender");
        let sender_two = UdpSocket::bind("127.0.0.1:0").expect("bind second timing sender");
        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let make_body = |session_id: &str, sender_port: u16| {
            let mut session = Dictionary::new();
            session.insert("sessionUUID".into(), Value::String(session_id.into()));
            session.insert("timingProtocol".into(), Value::String("NTP".into()));
            session.insert("timingPort".into(), Value::Integer(sender_port.into()));
            plist::encode_binary(&Value::Dictionary(session)).expect("encode session SETUP")
        };

        let mut event = None;
        let mut timing = None;
        let mut media = None;
        let first = handle_setup_request(
            &make_body("first-session", sender_one.local_addr().unwrap().port()),
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("first session SETUP");
        let first = plist::decode(&first).expect("decode first session response");
        let first = first.as_dictionary().expect("first session dictionary");
        let old_event_port = first
            .get("eventPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("first event port") as u16;
        let old_timing_port = first
            .get("timingPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("first timing port") as u16;

        let second = handle_setup_request(
            &make_body("second-session", sender_two.local_addr().unwrap().port()),
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("replacement session SETUP");
        let second = plist::decode(&second).expect("decode replacement session response");
        let second = second
            .as_dictionary()
            .expect("replacement session dictionary");
        let new_event_port = second
            .get("eventPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("replacement event port") as u16;
        let new_timing_port = second
            .get("timingPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("replacement timing port") as u16;

        assert_ne!(old_event_port, new_event_port);
        assert_ne!(old_timing_port, new_timing_port);
        assert!(
            TcpListener::bind(("0.0.0.0", old_event_port)).is_ok(),
            "previous event listener must be released after session replacement"
        );
        assert!(
            UdpSocket::bind(("0.0.0.0", old_timing_port)).is_ok(),
            "previous timing socket must be released after session replacement"
        );
        assert!(TcpStream::connect((peer_ip, new_event_port)).is_ok());
        assert!(UdpSocket::bind(("0.0.0.0", new_timing_port)).is_err());
    }

    #[test]
    fn rtsp_peer_disconnect_releases_event_and_timing_channels_without_fairplay() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, UdpSocket};
        use std::thread;
        use std::time::Duration;

        fn send_request(stream: &mut TcpStream, cseq: u32, body: &[u8]) {
            let header = format!(
                "SETUP * RTSP/1.0\r\nCSeq: {cseq}\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream
                .write_all(header.as_bytes())
                .expect("write RTSP headers");
            stream.write_all(body).expect("write RTSP body");
            stream.flush().expect("flush RTSP request");
        }

        fn read_response_body(stream: &mut TcpStream) -> Vec<u8> {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while !header.ends_with(b"\r\n\r\n") {
                stream
                    .read_exact(&mut byte)
                    .expect("read RTSP response header");
                header.push(byte[0]);
                assert!(header.len() < 16 * 1024, "RTSP response header too large");
            }
            let header = String::from_utf8(header).expect("RTSP response header is ASCII");
            let content_length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content length"))
                })
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            stream
                .read_exact(&mut body)
                .expect("read RTSP response body");
            body
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind RTSP listener");
        let address = listener.local_addr().expect("RTSP listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept RTSP peer");
            // A peer disconnect during a response is expected in this test;
            // the assertion below verifies that session-owned sockets are released.
            let _ = super::serve(stream);
        });
        let mut client = TcpStream::connect(address).expect("connect RTSP peer");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set RTSP response timeout");

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind timing sender");
        let mut session = Dictionary::new();
        session.insert(
            "sessionUUID".into(),
            Value::String("disconnect-test".into()),
        );
        session.insert("isScreenMirroringSession".into(), Value::Boolean(true));
        session.insert("timingProtocol".into(), Value::String("NTP".into()));
        session.insert(
            "timingPort".into(),
            Value::Integer(sender.local_addr().expect("sender address").port().into()),
        );
        let session_body =
            plist::encode_binary(&Value::Dictionary(session)).expect("encode session SETUP");
        send_request(&mut client, 1, &session_body);
        let session_response =
            plist::decode(&read_response_body(&mut client)).expect("decode session response");
        let session_response = session_response
            .as_dictionary()
            .expect("session response dictionary");
        let event_port = session_response
            .get("eventPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("event port") as u16;
        let timing_port = session_response
            .get("timingPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("timing port") as u16;

        let mut stream_descriptor = Dictionary::new();
        stream_descriptor.insert("type".into(), Value::Integer(110.into()));
        let mut stream_setup = Dictionary::new();
        stream_setup.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(stream_descriptor)]),
        );
        let stream_body =
            plist::encode_binary(&Value::Dictionary(stream_setup)).expect("encode stream SETUP");
        send_request(&mut client, 2, &stream_body);
        // Screen mirroring must not allocate a media listener until a valid
        // FairPlay video key has been established. Disconnect after sending
        // the rejected SETUP and verify the other session channels are closed.

        drop(client);
        server.join().expect("RTSP server thread");

        assert!(
            TcpListener::bind(("0.0.0.0", event_port)).is_ok(),
            "event listener must be released after peer disconnect"
        );
        assert!(
            UdpSocket::bind(("0.0.0.0", timing_port)).is_ok(),
            "timing socket must be released after peer disconnect"
        );
    }

    #[test]
    fn ntp_session_setup_returns_live_timing_port() {
        use std::net::UdpSocket;
        use std::time::Duration;

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind fake timing sender");
        sender
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timing sender timeout");
        let sender_port = sender.local_addr().expect("sender address").port();

        let mut session = Dictionary::new();
        session.insert("sessionUUID".into(), Value::String("ntp-test".into()));
        session.insert("timingProtocol".into(), Value::String("NTP".into()));
        session.insert("timingPort".into(), Value::Integer(sender_port.into()));
        let body = plist::encode_binary(&Value::Dictionary(session)).expect("encode NTP setup");

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let mut event = None;
        let mut timing = None;
        let mut media = None;
        let response = handle_setup_request(
            &body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("NTP session SETUP");
        let value = plist::decode(&response).expect("decode NTP response");
        let dictionary = value.as_dictionary().expect("NTP response dictionary");
        let timing_port = dictionary
            .get("timingPort")
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("receiver timing port");
        assert!(timing_port > 0);

        let mut request = [0u8; 64];
        let (length, peer) = sender
            .recv_from(&mut request)
            .expect("receive NTP timing request");
        assert_eq!(length, 32);
        assert_eq!(&request[..2], &[0x80, 0xD2]);
        assert_eq!(peer.port(), timing_port as u16);

        let mut reply = [0u8; 32];
        reply[0] = 0x80;
        reply[1] = 0xD3;
        reply[2..4].copy_from_slice(&request[2..4]);
        sender.send_to(&reply, peer).expect("send NTP timing reply");
    }

    #[test]
    fn rejected_ptp_replacement_keeps_active_session_channels() {
        use std::net::{TcpStream, UdpSocket};

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind NTP sender");
        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let make_session = |protocol: &str, session_id: &str| {
            let mut session = Dictionary::new();
            session.insert("sessionUUID".into(), Value::String(session_id.into()));
            session.insert("timingProtocol".into(), Value::String(protocol.into()));
            if protocol == "NTP" {
                session.insert(
                    "timingPort".into(),
                    Value::Integer(sender.local_addr().unwrap().port().into()),
                );
            }
            plist::encode_binary(&Value::Dictionary(session)).expect("encode session SETUP")
        };

        let mut event = None;
        let mut timing = None;
        let mut media = None;
        handle_setup_request(
            &make_session("NTP", "active-session"),
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("initial NTP session");

        let event_port = event.as_ref().expect("active event channel").port();
        let timing_port = timing.as_ref().expect("active timing client").port();
        let error = handle_setup_request(
            &make_session("PTP", "unsupported-replacement"),
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect_err("PTP is not implemented");
        assert_eq!(error.0, 501);
        assert_eq!(
            event.as_ref().expect("event channel retained").port(),
            event_port
        );
        assert_eq!(
            timing.as_ref().expect("timing client retained").port(),
            timing_port
        );
        assert!(TcpStream::connect((peer_ip, event_port)).is_ok());
        assert!(UdpSocket::bind(("0.0.0.0", timing_port)).is_err());
    }

    #[test]
    fn stream_setup_requires_session_setup_and_rejects_other_types() {
        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let mut event = None;
        let mut timing = None;
        let mut media = None;
        let mut stream = Dictionary::new();
        stream.insert("type".into(), Value::Integer(96.into()));
        let mut root = Dictionary::new();
        root.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(stream)]),
        );
        let body = plist::encode_binary(&Value::Dictionary(root)).expect("encode stream setup");

        assert_eq!(
            handle_setup_request(
                &body,
                peer_ip,
                &mut event,
                &mut timing,
                &mut media,
                &mut None,
                &mut None,
                None,
                None,
            )
            .unwrap_err()
            .0,
            455
        );

        let mut session = Dictionary::new();
        session.insert("sessionUUID".into(), Value::String("test-session".into()));
        let body = plist::encode_binary(&Value::Dictionary(session)).expect("encode session setup");
        handle_setup_request(
            &body,
            peer_ip,
            &mut event,
            &mut timing,
            &mut media,
            &mut None,
            &mut None,
            None,
            None,
        )
        .expect("session setup");

        let mut unsupported_stream = Dictionary::new();
        unsupported_stream.insert("type".into(), Value::Integer(96.into()));
        let mut root = Dictionary::new();
        root.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(unsupported_stream)]),
        );
        let body =
            plist::encode_binary(&Value::Dictionary(root)).expect("encode audio stream setup");
        assert_eq!(
            handle_setup_request(
                &body,
                peer_ip,
                &mut event,
                &mut timing,
                &mut media,
                &mut None,
                &mut None,
                None,
                None,
            )
            .unwrap_err()
            .0,
            501
        );
    }

    #[test]
    fn pair_verify_state_machine_rejects_invalid_transitions_and_discards_failed_m3() {
        use crate::airplay::pair_verify::PairVerifySession;
        use x25519_dalek::{PublicKey, StaticSecret};

        let m3_without_m1 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![3],
            },
            Tlv {
                kind: 0x05,
                value: vec![0; 32],
            },
        ]);
        let mut session: Option<PairVerifySession> = None;
        let error = handle_pair_verify(&m3_without_m1, &mut session)
            .expect_err("M3 without M1 must be rejected");
        assert!(error.contains("M3 received without M1"));
        assert!(session.is_none());

        let controller_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let controller_public = PublicKey::from(&controller_secret);
        let m1 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![1],
            },
            Tlv {
                kind: 0x03,
                value: controller_public.as_bytes().to_vec(),
            },
        ]);
        handle_pair_verify(&m1, &mut session).expect("valid M1 starts exchange");
        assert!(session.is_some());

        let error =
            handle_pair_verify(&m1, &mut session).expect_err("duplicate M1 must be rejected");
        assert!(error.contains("another exchange is active"));
        assert!(session.is_some());

        let invalid_m3 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![3],
            },
            Tlv {
                kind: 0x05,
                value: vec![0xA5; 32],
            },
        ]);
        let error = handle_pair_verify(&invalid_m3, &mut session)
            .expect_err("unauthenticated M3 must be rejected");
        assert!(error.contains("authentication tag verification failed"));
        assert!(
            session.is_none(),
            "failed M3 must consume the pending session"
        );
    }

    #[test]
    fn fairplay_error_responses_use_real_crlf_line_endings() {
        for (status, reason) in [
            (501, "Not Implemented"),
            (403, "Forbidden"),
            (400, "Bad Request"),
        ] {
            let response = super::fairplay_error_response(status, reason, "3");
            assert!(response.starts_with(&format!("RTSP/1.0 {status} {reason}\r\n")));
            assert!(response.ends_with("\r\n\r\n"));
            assert!(response.contains("\r\nCSeq: 3\r\n"));
        }
    }

    #[test]
    fn server_info_contains_declared_model_and_advertised_features() {
        let body = server_info_plist();
        assert!(body.contains(&format!(
            "<key>features</key><integer>{}</integer>",
            super::server_info_features()
        )));
        assert!(body.contains(&format!(
            "<key>model</key><string>{}</string>",
            super::config::MODEL
        )));
    }

    #[test]
    fn unqualified_info_returns_initial_volume() {
        let bytes = build_info_response(&[]).expect("build /info response");
        assert!(bytes.starts_with(b"bplist00"));
        let value = plist::decode(&bytes).expect("decode response");
        let dict = value.as_dictionary().expect("response dictionary");
        assert!(matches!(dict.get("initialVolume"), Some(Value::Integer(_))));
    }

    #[test]
    fn txt_airplay_qualifier_returns_mdns_properties_as_strings() {
        let mut request = Dictionary::new();
        request.insert(
            "qualifier".into(),
            Value::Array(vec![Value::String("txtAirPlay".into())]),
        );
        let bytes = plist::encode_binary(&Value::Dictionary(request)).expect("encode request");
        let response = build_info_response(&bytes).expect("build TXT response");
        let value = plist::decode(&response).expect("decode response");
        let dict = value.as_dictionary().expect("response dictionary");

        for key in ["deviceid", "features", "model", "srcvers", "flags"] {
            assert!(
                matches!(dict.get(key), Some(Value::String(_))),
                "missing string key {key}"
            );
        }
        assert_eq!(
            dict.get("features").and_then(Value::as_string),
            Some(super::config::FEATURES)
        );
        assert_eq!(
            dict.get("flags").and_then(Value::as_string),
            Some(super::config::STATUS_FLAGS)
        );
    }

    #[test]
    fn pair_setup_m1_returns_srp_challenge() {
        let request = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let response = handle_pair_setup(&request, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("M1 response");
        let fields = tlv8::decode(&response).expect("decode M2");
        assert_eq!(
            fields
                .iter()
                .find(|field| field.kind == 0x06)
                .unwrap()
                .value,
            [0x02]
        );
        assert_eq!(
            fields
                .iter()
                .find(|field| field.kind == 0x02)
                .unwrap()
                .value
                .len(),
            16
        );
        assert_eq!(
            fields
                .iter()
                .find(|field| field.kind == 0x03)
                .unwrap()
                .value
                .len(),
            384
        );
        assert!(srp.is_some());
    }

    #[test]
    fn pair_setup_requires_explicit_setup_code() {
        let request = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let error = handle_pair_setup(&request, &mut srp, &mut session_key, None)
            .expect_err("missing code must not start pairing");
        assert_eq!(error.status, 503);
        assert!(srp.is_none());
    }

    #[test]
    fn pair_setup_duplicate_and_unsupported_states_clear_pending_material() {
        for request in [
            tlv8::encode(&[
                Tlv {
                    kind: 0x06,
                    value: vec![0x01],
                },
                Tlv {
                    kind: 0x06,
                    value: vec![0x03],
                },
            ]),
            tlv8::encode(&[Tlv {
                kind: 0x06,
                value: vec![0x09],
            }]),
        ] {
            let mut srp = Some(SrpServer::new("518-08-582").expect("create SRP server"));
            let mut session_key = Some(Zeroizing::new([0xA5; 64]));
            let error = handle_pair_setup(&request, &mut srp, &mut session_key, Some("518-08-582"))
                .expect_err("invalid Pair-Setup state must be rejected");
            assert_eq!(error.status, 400);
            assert!(srp.is_none(), "invalid state must discard SRP state");
            assert!(
                session_key.is_none(),
                "invalid state must discard the session key"
            );
        }
    }

    #[test]
    fn pair_setup_fresh_m1_replaces_abandoned_exchange_before_validation() {
        let old_server = SrpServer::new("518-08-582").expect("create abandoned SRP server");
        let old_public_key = old_server
            .public_key()
            .expect("read abandoned SRP public key");
        let mut srp = Some(old_server);
        let mut session_key = Some(Zeroizing::new([0xA5; 64]));
        let invalid_m1 = tlv8::encode(&[Tlv {
            kind: 0x06,
            value: vec![0x01],
        }]);

        let error = handle_pair_setup(&invalid_m1, &mut srp, &mut session_key, Some("518-08-582"))
            .expect_err("M1 without method must be rejected");
        assert_eq!(error.status, 400);
        assert!(
            srp.is_none(),
            "invalid fresh M1 must discard the old SRP exchange"
        );
        assert!(
            session_key.is_none(),
            "invalid fresh M1 must discard the old session key"
        );

        let valid_m1 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        handle_pair_setup(&valid_m1, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("valid M1 starts a fresh exchange");
        let new_public_key = srp
            .as_ref()
            .expect("fresh SRP exchange exists")
            .public_key()
            .expect("read fresh SRP public key");
        assert_ne!(new_public_key, old_public_key);
        assert!(session_key.is_none());
    }

    #[test]
    fn pair_setup_missing_state_discards_pending_exchange_material() {
        let request = tlv8::encode(&[Tlv {
            kind: 0x00,
            value: vec![0x00],
        }]);
        let mut srp = Some(SrpServer::new("518-08-582").expect("create SRP server"));
        let mut session_key = Some(Zeroizing::new([0xA5; 64]));

        let error = handle_pair_setup(&request, &mut srp, &mut session_key, Some("518-08-582"))
            .expect_err("missing State must be rejected");
        assert_eq!(error.status, 400);
        assert!(srp.is_none());
        assert!(session_key.is_none());
    }

    #[test]
    fn malformed_pair_setup_messages_discard_pending_exchange_material() {
        let mut srp = Some(SrpServer::new("518-08-582").expect("create SRP server"));
        let mut session_key = Some(Zeroizing::new([0xA5; 64]));
        let malformed_tlv = [0x06, 0x02, 0x01];
        let error = handle_pair_setup(
            &malformed_tlv,
            &mut srp,
            &mut session_key,
            Some("518-08-582"),
        )
        .expect_err("malformed TLV must be rejected");
        assert_eq!(error.status, 400);
        assert!(srp.is_none());
        assert!(session_key.is_none());

        let m1 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        handle_pair_setup(&m1, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("valid M1 starts a new exchange");
        assert!(srp.is_some());

        let malformed_m3 = tlv8::encode(&[Tlv {
            kind: 0x06,
            value: vec![0x03],
        }]);
        session_key = Some(Zeroizing::new([0x5A; 64]));
        let error = handle_pair_setup(
            &malformed_m3,
            &mut srp,
            &mut session_key,
            Some("518-08-582"),
        )
        .expect_err("malformed M3 must be rejected");
        assert_eq!(error.status, 400);
        assert!(srp.is_none());
        assert!(session_key.is_none());
    }

    #[test]
    fn pair_setup_rejects_m3_without_m1() {
        let request = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x03],
            },
            Tlv {
                kind: 0x03,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x04,
                value: vec![0x00; 64],
            },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let error = handle_pair_setup(&request, &mut srp, &mut session_key, None)
            .expect_err("M3 without M1 must fail");
        assert_eq!(error.status, 400);
    }

    #[test]
    fn pair_setup_rejects_invalid_setup_code_format() {
        let request = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        let mut srp = None;
        let mut session_key = None;
        let error = handle_pair_setup(&request, &mut srp, &mut session_key, Some("12345678"))
            .expect_err("invalid code format must fail");
        assert_eq!(error.status, 503);
        assert!(srp.is_none());
    }

    #[test]
    fn pair_setup_returns_authentication_error_for_bad_m3_proof() {
        let m1 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x00,
                value: vec![0x00],
            },
        ]);
        let m3 = tlv8::encode(&[
            Tlv {
                kind: 0x06,
                value: vec![0x03],
            },
            Tlv {
                kind: 0x03,
                value: vec![0x01],
            },
            Tlv {
                kind: 0x04,
                value: vec![0x00; 64],
            },
        ]);
        let mut srp = None;
        let mut session_key = None;
        handle_pair_setup(&m1, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("M1 should create SRP challenge");
        let response = handle_pair_setup(&m3, &mut srp, &mut session_key, Some("518-08-582"))
            .expect("bad proof is represented as an M4 TLV error");
        let fields = tlv8::decode(&response).expect("decode M4 error");
        assert!(
            fields
                .iter()
                .any(|field| field.kind == 0x06 && field.value == [0x04])
        );
        assert!(
            fields
                .iter()
                .any(|field| field.kind == 0x07 && field.value == [0x02])
        );
        assert!(session_key.is_none());
        assert!(
            srp.is_none(),
            "failed SRP proof must consume the exchange state"
        );
    }

    #[test]
    fn media_packet_backpressure_exits_promptly_after_teardown() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::thread;
        use std::time::Duration;

        let (sender, _receiver) = mpsc::sync_channel(1);
        let packet = || super::ReceivedMediaPacket {
            peer_addr: "127.0.0.1:1234".parse().expect("peer address"),
            packet_type: crate::airplay::media::ScreenMirrorPacketType::Heartbeat,
            timestamp: 1,
            payload: Vec::new(),
        };
        sender
            .try_send(super::MediaWorkerMessage::Packet(packet()))
            .expect("fill bounded queue");
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker_sender = sender.clone();
        let worker = thread::spawn(move || {
            super::send_packet_while_running(
                &worker_sender,
                super::MediaWorkerMessage::Packet(packet()),
                &worker_running,
            )
        });

        thread::sleep(Duration::from_millis(20));
        let stopped_at = std::time::Instant::now();
        running.store(false, Ordering::Release);
        assert!(!worker.join().expect("backpressure worker exits"));
        assert!(stopped_at.elapsed() < Duration::from_millis(100));
        assert!(!running.load(Ordering::Acquire));
    }

    #[test]
    fn disconnect_marker_waits_for_queue_capacity_and_preserves_fifo_boundary() {
        use std::sync::{Arc, atomic::AtomicBool, mpsc};
        use std::thread;
        use std::time::Duration;

        let (sender, receiver) = mpsc::sync_channel(1);
        let packet = super::ReceivedMediaPacket {
            peer_addr: "127.0.0.1:1234".parse().expect("peer address"),
            packet_type: crate::airplay::media::ScreenMirrorPacketType::Heartbeat,
            timestamp: 77,
            payload: Vec::new(),
        };
        sender
            .try_send(super::MediaWorkerMessage::Packet(packet))
            .expect("fill queue with final packet from disconnected peer");

        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker_sender = sender.clone();
        let worker = thread::spawn(move || {
            super::send_packet_while_running(
                &worker_sender,
                super::MediaWorkerMessage::StreamDisconnected,
                &worker_running,
            )
        });

        thread::sleep(Duration::from_millis(20));
        let final_packet = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("drain final packet to make room for disconnect marker");
        let super::MediaWorkerMessage::Packet(final_packet) = final_packet else {
            panic!("final packet must precede disconnect marker");
        };
        assert_eq!(final_packet.timestamp, 77);

        assert!(worker.join().expect("disconnect marker sender exits"));
        let marker = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("disconnect marker is queued after the final packet");
        assert!(matches!(
            marker,
            super::MediaWorkerMessage::StreamDisconnected
        ));
    }

    #[test]
    fn reconnect_packets_are_ordered_after_the_disconnect_boundary() {
        use std::sync::mpsc;

        let (sender, receiver) = mpsc::sync_channel(3);
        let old_peer_packet = super::ReceivedMediaPacket {
            peer_addr: "127.0.0.1:1234".parse().expect("old peer address"),
            packet_type: crate::airplay::media::ScreenMirrorPacketType::Video,
            timestamp: 10,
            payload: vec![1, 2, 3],
        };
        let new_peer_packet = super::ReceivedMediaPacket {
            peer_addr: "127.0.0.1:5678".parse().expect("new peer address"),
            packet_type: crate::airplay::media::ScreenMirrorPacketType::CodecConfiguration,
            timestamp: 20,
            payload: vec![4, 5, 6],
        };

        sender
            .send(super::MediaWorkerMessage::Packet(old_peer_packet))
            .expect("queue final old-peer packet");
        sender
            .send(super::MediaWorkerMessage::StreamDisconnected)
            .expect("queue old-peer disconnect boundary");
        sender
            .send(super::MediaWorkerMessage::Packet(new_peer_packet))
            .expect("queue first new-peer packet");

        let old = receiver.recv().expect("old-peer packet");
        let boundary = receiver.recv().expect("disconnect boundary");
        let new = receiver.recv().expect("new-peer packet");
        let super::MediaWorkerMessage::Packet(old) = old else {
            panic!("old peer's final packet must be processed first");
        };
        assert_eq!(old.peer_addr.port(), 1234);
        assert_eq!(old.timestamp, 10);
        assert!(matches!(
            boundary,
            super::MediaWorkerMessage::StreamDisconnected
        ));
        let super::MediaWorkerMessage::Packet(new) = new else {
            panic!("new peer's first packet must follow the disconnect boundary");
        };
        assert_eq!(new.peer_addr.port(), 5678);
        assert_eq!(new.timestamp, 20);
        assert_eq!(
            new.packet_type,
            crate::airplay::media::ScreenMirrorPacketType::CodecConfiguration
        );
    }

    #[test]
    fn mirror_tcp_reader_preserves_packet_boundaries_across_fragmented_and_coalesced_writes() {
        use std::io::Write;
        use std::net::{Shutdown, TcpListener};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::thread;
        use std::time::Duration;

        fn packet(timestamp: u64, payload: &[u8]) -> Vec<u8> {
            let mut bytes = vec![0u8; SCREEN_MIRROR_HEADER_SIZE + payload.len()];
            bytes[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes[4..6].copy_from_slice(&0u16.to_le_bytes());
            bytes[8..16].copy_from_slice(&timestamp.to_le_bytes());
            bytes[SCREEN_MIRROR_HEADER_SIZE..].copy_from_slice(payload);
            bytes
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP listener");
        let mut client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("connect TCP client");
        let (server, peer_addr) = listener.accept().expect("accept TCP client");
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set read timeout");

        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let (sender, receiver) = mpsc::sync_channel(4);
        let worker = thread::spawn(move || {
            super::read_mirror_stream(server, peer_addr, &sender, &worker_running);
        });

        let first = packet(101, &[0x10, 0x11, 0x12, 0x13]);
        let second = packet(202, &[0x20, 0x21]);
        // Deliberately split the fixed header and payload over separate writes.
        client
            .write_all(&first[..17])
            .expect("write partial header");
        client
            .write_all(&first[17..SCREEN_MIRROR_HEADER_SIZE])
            .expect("finish first header");
        client
            .write_all(&first[SCREEN_MIRROR_HEADER_SIZE..SCREEN_MIRROR_HEADER_SIZE + 1])
            .expect("write partial first payload");
        // Coalesce the rest of packet one and all of packet two in one TCP write.
        let mut tail = first[SCREEN_MIRROR_HEADER_SIZE + 1..].to_vec();
        tail.extend_from_slice(&second);
        client
            .write_all(&tail)
            .expect("write coalesced packet tail");
        client.shutdown(Shutdown::Write).expect("finish TCP stream");

        let received_first = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("receive first framed packet");
        let received_second = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("receive second framed packet");
        let MediaWorkerMessage::Packet(received_first) = received_first else {
            panic!("expected first framed media packet");
        };
        let MediaWorkerMessage::Packet(received_second) = received_second else {
            panic!("expected second framed media packet");
        };
        assert_eq!(received_first.timestamp, 101);
        assert_eq!(received_first.payload, vec![0x10, 0x11, 0x12, 0x13]);
        assert_eq!(received_second.timestamp, 202);
        assert_eq!(received_second.payload, vec![0x20, 0x21]);

        running.store(false, Ordering::Release);
        worker.join().expect("mirror TCP reader exits");
    }

    #[test]
    fn unsupported_info_qualifier_is_rejected() {
        let mut request = Dictionary::new();
        request.insert(
            "qualifier".into(),
            Value::Array(vec![Value::String("unknownCapability".into())]),
        );
        let bytes = plist::encode_binary(&Value::Dictionary(request)).expect("encode request");
        assert!(build_info_response(&bytes).is_err());
    }
}
