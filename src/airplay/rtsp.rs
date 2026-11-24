//! Bounded RTSP/HTTP control parser for the AirPlay endpoint.
//!
//! The handler supports persistent RTSP connections, bounded request bodies,
//! OPTIONS, /info, Pair-Setup, Pair-Verify, FairPlay framing, session and stream
//! SETUP, RECORD, feedback, and TEARDOWN. FairPlay cryptographic responses
//! and sender media decryption are not implemented; the decoder can be
//! initialized from avcC metadata but is not yet fed real video access units.

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

/// Per-stream cryptographic context. The shared secret is retained only in
/// memory and is never formatted into logs or debug output.
struct MirrorStreamContext {
    connection_id: Option<u64>,
    pair_verify_shared_secret: Option<Zeroizing<[u8; 32]>>,
    media_foundation: Option<Arc<super::decoder::MediaFoundationRuntime>>,
    frames: Arc<super::video::LatestFrameMailbox>,
}

/// Owns the negotiated TCP screen-mirroring listener and its bounded worker.
/// The worker reads each 128-byte packet header and its declared payload,
/// validates avcC configuration, and initializes an H.264 decoder from SPS
/// dimensions. It cannot decrypt sender video or submit frames without a
/// recovered FairPlay key and verified access-unit framing.
struct MediaSession {
    local_addr: std::net::SocketAddr,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
        let (sender, packets) = mpsc::sync_channel(MEDIA_PACKET_QUEUE_CAPACITY);

        let worker = thread::Builder::new()
            .name("airplay-media-process".to_owned())
            .spawn(move || process_media_packets(packets, stream_context))?;
        let accept_worker = match thread::Builder::new()
            .name("airplay-mirror-tcp".to_owned())
            .spawn(move || accept_mirror_connections(listener, worker_running, peer_ip, sender))
        {
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
    sender: mpsc::SyncSender<ReceivedMediaPacket>,
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
                tracing::info!(%peer_addr, "AirPlay mirror TCP client connected");
                read_mirror_stream(stream, peer_addr, &sender, &running);
                tracing::info!(%peer_addr, "AirPlay mirror TCP client disconnected");
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
    sender: &mpsc::SyncSender<ReceivedMediaPacket>,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    let mut received = 0u64;
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
        if !send_packet_while_running(sender, owned, running) {
            break;
        }
        received = received.saturating_add(1);
    }
    tracing::debug!(%peer_addr, received, "AirPlay mirror TCP stream reader stopped");
}

fn send_packet_while_running(
    sender: &mpsc::SyncSender<ReceivedMediaPacket>,
    mut packet: ReceivedMediaPacket,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> bool {
    use std::sync::atomic::Ordering;
    loop {
        if !running.load(Ordering::Acquire) {
            return false;
        }
        match sender.try_send(packet) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Full(returned)) => {
                packet = returned;
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

fn process_media_packets(
    packets: Receiver<ReceivedMediaPacket>,
    stream_context: MirrorStreamContext,
) {
    let stream_connection_id = stream_context.connection_id;
    tracing::info!(
        stream_connection_id = ?stream_connection_id,
        pair_verify_complete = stream_context.pair_verify_shared_secret.is_some(),
        "AirPlay media worker initialized with negotiated stream context"
    );
    let mut received = 0u64;
    let media_foundation = stream_context.media_foundation;
    let frames = stream_context.frames;
    let mut frame_pipeline = None;
    let mut decoder_init_policy = super::video::DecoderInitializationPolicy::default();
    let mut processor = super::video::MirrorStreamProcessor::new();
    while let Ok(packet) = packets.recv() {
        received = received.saturating_add(1);
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

        let initialize_decoder = if duplicate_configuration {
            // Repeated avcC packets must not churn a healthy decoder. If
            // initialization previously failed, reserve one bounded retry.
            if frame_pipeline.is_some() {
                false
            } else {
                decoder_init_policy.begin_attempt()
            }
        } else if is_codec_configuration {
            decoder_init_policy.reset();
            decoder_init_policy.begin_attempt()
        } else {
            false
        };

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
                // A newly accepted avcC record supersedes the previous decoder
                // configuration. Never keep decoding with stale dimensions or
                // parameter sets if the new stream configuration is unusable.
                frame_pipeline = None;
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
                                    frame_pipeline = Some(pipeline);
                                    tracing::info!(
                                        "Windows H.264 decoder pipeline initialized from stream SPS"
                                    );
                                }
                                Err(error) => {
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
                // An invalid replacement configuration must not leave the
                // previous decoder or its last frame visible as if it still
                // represented the active sender stream.
                frame_pipeline = None;
                decoder_init_policy.reset();
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
            } => tracing::debug!(
                %packet.peer_addr,
                timestamp = packet.timestamp,
                payload_bytes,
                has_configuration,
                decoder_ready = frame_pipeline.is_some(),
                received,
                "AirPlay video packet received; waiting for FairPlay media decryption"
            ),
            super::video::MirrorPacketOutcome::Heartbeat => {
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

    tracing::info!(
        stream_connection_id = ?stream_connection_id,
        received,
        "AirPlay media processing worker stopped"
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

pub fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let peer_ip = stream.peer_addr()?.ip();
    let mut pending = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut pair_setup_srp: Option<SrpServer> = None;
    let mut pair_setup_session_key: Option<Zeroizing<[u8; 64]>> = None;
    let mut pair_verify_session: Option<PairVerifySession> = None;
    let mut pair_verify_shared_secret: Option<Zeroizing<[u8; 32]>> = None;
    let mut fairplay_ekey: Option<Zeroizing<[u8; 72]>> = None;
    let mut fairplay_eiv: Option<Zeroizing<[u8; 16]>> = None;
    let mut event_channel: Option<EventChannel> = None;
    let mut timing_client: Option<TimingClient> = None;
    let mut media_receiver: Option<MediaSession> = None;
    tracing::info!("AirPlay RTSP session started");

    loop {
        let Some(request) = read_request(&mut stream, &mut pending)? else {
            tracing::info!("AirPlay RTSP peer closed the session");
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
                // The first 16 bytes contain only the public FPLY record header,
                // sequence and phase-1 selector bytes. Never log the full 164-byte M3.
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
                    Ok(message) => {
                        let phase = message.phase;
                        if phase == super::fairplay::MessagePhase::Initial {
                            // Never send random challenge bytes or acknowledge an
                            // unauthenticated M3. The SAP crypto provider is not
                            // implemented yet, so fail closed until it can produce
                            // a session-aware, independently verified response.
                            tracing::error!(
                                sender_phase1_capabilities = ?message.initial_capabilities,
                                sender_phase1_parameters = ?message.initial_parameters,
                                "FairPlay SAP unavailable: refusing placeholder M2"
                            );
                            let response =
                                fairplay_error_response(501, "Not Implemented", &request.cseq);
                            write_response(&mut stream, &response, 501)?;
                        } else {
                            tracing::warn!(
                                phase = phase as u8,
                                "FairPlay message received but no authenticated SAP session exists"
                            );
                            let response = fairplay_error_response(403, "Forbidden", &request.cseq);
                            write_response(&mut stream, &response, 403)?;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "AirPlay FairPlay setup framing rejected");
                        let response = fairplay_error_response(400, "Bad Request", &request.cseq);
                        write_response(&mut stream, &response, 400)?;
                    }
                }
            }
            ("POST", "/pair-verify", "RTSP/1.0") => {
                let response_body =
                    match handle_pair_verify(&request.body, &mut pair_verify_session) {
                        Ok((body, Some(shared_secret))) => {
                            pair_verify_shared_secret = Some(shared_secret);
                            body
                        }
                        Ok((body, None)) => {
                            pair_verify_shared_secret = None;
                            body
                        }
                        Err(error) => {
                            tracing::warn!(%error, "Pair-Verify exchange rejected");
                            pair_verify_session = None;
                            pair_verify_shared_secret = None;
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
                    pair_verify_shared_secret.as_deref(),
                ) {
                    Ok(body) => write_binary_plist_response(&mut stream, &request.cseq, &body)?,
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
                if media_receiver.is_some() {
                    tracing::info!(
                        "AirPlay RECORD request accepted; media listener is active, but media decryption/decoding is not active"
                    );
                } else {
                    // Apple senders may issue RECORD before the stream-level
                    // SETUP. Keep the session open and wait for that SETUP.
                    tracing::info!(
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
    let fields =
        tlv8::decode(body).map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;
    let mut states = fields.iter().filter(|field| field.kind == 0x06);
    let state = states
        .next()
        .ok_or_else(|| PairSetupFailure::bad_request("missing Pair-Setup State"))?;
    if states.next().is_some() || state.value.len() != 1 {
        return Err(PairSetupFailure::bad_request(
            "invalid Pair-Setup State field",
        ));
    }

    match state.value[0] {
        1 => {
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
            let message = pairing::parse_m3(body)
                .map_err(|error| PairSetupFailure::bad_request(error.to_string()))?;
            let server = srp_state.take().ok_or_else(|| {
                PairSetupFailure::bad_request("Pair-Setup M3 received without an M1 exchange")
            })?;

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
        other => Err(PairSetupFailure::bad_request(format!(
            "unsupported Pair-Setup state {other}"
        ))),
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
    use super::Zeroizing;
    use super::plist;
    use super::{
        Request, SCREEN_MIRROR_HEADER_SIZE, TcpStream, build_info_response, find_header_end,
        handle_pair_setup, handle_setup_request, server_info_plist,
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
        use std::net::{TcpListener, UdpSocket};

        let peer_ip = "127.0.0.1".parse().expect("loopback IP");
        let mut event_channel =
            Some(super::super::event::EventChannel::bind(peer_ip).expect("event channel"));
        let mut timing_client =
            Some(super::super::timing::TimingClient::start(peer_ip, 9).expect("timing client"));
        let mut media_receiver = Some(super::MediaSession::start(peer_ip).expect("media session"));

        let event_port = event_channel.as_ref().expect("event channel").port();
        let timing_port = timing_client.as_ref().expect("timing client").port();
        let media_port = media_receiver.as_ref().expect("media session").port();

        super::stop_session_channels(&mut event_channel, &mut timing_client, &mut media_receiver);

        assert!(event_channel.is_none());
        assert!(timing_client.is_none());
        assert!(media_receiver.is_none());
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
        let worker = thread::spawn(move || {
            super::accept_mirror_connections(listener, worker_running, address.ip(), sender);
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

        let first_packet = receiver.recv_timeout(Duration::from_secs(2));
        let second_packet = receiver.recv_timeout(Duration::from_secs(2));

        running.store(false, Ordering::Release);
        worker.join().expect("mirror listener stops");

        let first_packet = first_packet.expect("first client packet is received");
        let second_packet =
            second_packet.expect("second client packet is received after reconnect");
        assert_eq!(
            first_packet.packet_type,
            crate::airplay::media::ScreenMirrorPacketType::Heartbeat
        );
        assert_eq!(
            second_packet.packet_type,
            crate::airplay::media::ScreenMirrorPacketType::Heartbeat
        );
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
    fn rtsp_peer_disconnect_releases_event_timing_and_media_channels() {
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
            super::serve(stream).expect("serve RTSP session");
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
        let stream_response =
            plist::decode(&read_response_body(&mut client)).expect("decode stream response");
        let media_port = stream_response
            .as_dictionary()
            .and_then(|root| root.get("streams"))
            .and_then(Value::as_array)
            .and_then(|streams| streams.first())
            .and_then(Value::as_dictionary)
            .and_then(|stream| stream.get("dataPort"))
            .and_then(|value| match value {
                Value::Integer(integer) => integer.as_unsigned(),
                _ => None,
            })
            .expect("media port") as u16;

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
        assert!(
            TcpListener::bind(("0.0.0.0", media_port)).is_ok(),
            "media listener must be released after peer disconnect"
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
                None
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
                None
            )
            .unwrap_err()
            .0,
            501
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
        sender.try_send(packet()).expect("fill bounded queue");
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker_sender = sender.clone();
        let worker = thread::spawn(move || {
            super::send_packet_while_running(&worker_sender, packet(), &worker_running)
        });

        thread::sleep(Duration::from_millis(20));
        let stopped_at = std::time::Instant::now();
        running.store(false, Ordering::Release);
        assert!(!worker.join().expect("backpressure worker exits"));
        assert!(stopped_at.elapsed() < Duration::from_millis(100));
        assert!(!running.load(Ordering::Acquire));
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
