#[cfg(windows)]
use gpui::MouseButton;
use gpui_kit::component::{
    button::{Button, ButtonVariants},
    input::{Input, InputState},
    label::Label,
};
use gpui_kit::*;
#[cfg(windows)]
use rust_phone_control::input::{InputEvent, MouseButtons};

#[cfg(windows)]
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(windows)]
struct FallbackConversionInFlightGuard(Option<Arc<AtomicBool>>);

#[cfg(windows)]
impl FallbackConversionInFlightGuard {
    fn disarm(mut self) {
        let _ = self.0.take();
    }
}

#[cfg(windows)]
impl Drop for FallbackConversionInFlightGuard {
    fn drop(&mut self) {
        if let Some(in_flight) = self.0.as_ref() {
            in_flight.store(false, Ordering::Release);
        }
    }
}

#[cfg(all(test, windows))]
mod fallback_worker_guard_tests {
    use super::FallbackConversionInFlightGuard;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn dropping_worker_guard_releases_in_flight_ownership() {
        let in_flight = Arc::new(AtomicBool::new(true));

        drop(FallbackConversionInFlightGuard(Some(in_flight.clone())));

        assert!(!in_flight.load(Ordering::Acquire));
    }

    #[test]
    fn disarmed_worker_guard_does_not_release_already_transferred_ownership() {
        let in_flight = Arc::new(AtomicBool::new(true));

        FallbackConversionInFlightGuard(Some(in_flight.clone())).disarm();

        assert!(in_flight.load(Ordering::Acquire));
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq)]
struct PreviewSurfaceBounds {
    /// Preview rectangle origin relative to the GPUI client-area origin, in device pixels.
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

/// A completed CPU fallback may be shown only while its frame is still the
/// newest observed frame and its stream generation remains active.
fn fallback_result_is_eligible(
    mailbox_cleared: bool,
    newer_frame_pending: bool,
    sequence: u64,
    latest_observed_sequence: u64,
    generation_current: bool,
) -> bool {
    !mailbox_cleared
        && !newer_frame_pending
        && sequence >= latest_observed_sequence
        && generation_current
}

#[cfg(test)]
mod fallback_result_tests {
    use super::fallback_result_is_eligible;

    #[test]
    fn accepts_current_or_equal_sequence_when_stream_is_active() {
        assert!(fallback_result_is_eligible(false, false, 42, 42, true));
        assert!(fallback_result_is_eligible(false, false, 43, 42, true));
    }

    #[test]
    fn rejects_result_after_mailbox_clear() {
        assert!(!fallback_result_is_eligible(true, false, 42, 42, true));
    }

    #[test]
    fn rejects_result_when_a_newer_frame_is_waiting() {
        assert!(!fallback_result_is_eligible(false, true, 42, 42, true));
    }

    #[test]
    fn rejects_older_sequence() {
        assert!(!fallback_result_is_eligible(false, false, 41, 42, true));
    }

    #[test]
    fn rejects_result_from_inactive_stream_generation() {
        assert!(!fallback_result_is_eligible(false, false, 42, 42, false));
    }
}

#[derive(Default)]
pub struct PhoneControlApp {
    airplay_status: String,
    ble_connection_status: String,
    #[cfg(windows)]
    pending_airplay_controller: Option<String>,
    #[cfg(windows)]
    trusted_airplay_controllers: Vec<String>,
    #[cfg(windows)]
    denied_airplay_controllers: Vec<String>,
    #[cfg(windows)]
    airplay_approval_status: String,
    #[cfg(windows)]
    preview_image: Option<Arc<Image>>,
    #[cfg(windows)]
    preview_status: String,
    pipeline_status: String,
    d3d11_metrics_label: String,
    /// Persistent GPUI text field used to send ASCII keyboard input over BLE HID.
    keyboard_input: Option<Entity<InputState>>,
    /// Latest measured preview rectangle, shared with the future native-surface host.
    #[cfg(windows)]
    preview_surface_bounds: Arc<Mutex<Option<PreviewSurfaceBounds>>>,
    /// Last pointer location while a left-button drag is active in the preview.
    #[cfg(windows)]
    preview_pointer_position: Option<(f32, f32)>,
    #[cfg(windows)]
    renderer_init_attempted: bool,
    #[cfg(windows)]
    frame_poll_task: Option<Task<()>>,
    #[cfg(windows)]
    fallback_worker_cancel: Arc<AtomicBool>,
    #[cfg(windows)]
    quit_subscription: Option<Subscription>,
}

impl PhoneControlApp {
    /// Creates the application view with its persistent keyboard input state.
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut app = Self::default();
        app.keyboard_input = Some(cx.new(|cx| {
            InputState::new(window, cx).placeholder("输入 ASCII 文本，按发送传到 iPhone")
        }));
        app
    }
}

impl Drop for PhoneControlApp {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            tracing::info!("PhoneControlApp teardown: begin");
            // Signal detached fallback workers before releasing UI-owned state.
            // Conversion already in progress is allowed to finish, but it must
            // not publish a result after application teardown has begun.
            self.fallback_worker_cancel.store(true, Ordering::Release);
            // Drop the task explicitly so its cancellation point is visible in
            // the log. The task is cancelled before the image it may publish.
            if let Some(task) = self.frame_poll_task.take() {
                tracing::debug!("PhoneControlApp teardown: cancelling GPUI frame poll task");
                drop(task);
                tracing::debug!("PhoneControlApp teardown: GPUI frame poll task cancelled");
            } else {
                tracing::debug!("PhoneControlApp teardown: no GPUI frame poll task");
            }

            if let Some(image) = self.preview_image.take() {
                tracing::debug!("PhoneControlApp teardown: releasing preview image");
                drop(image);
                tracing::debug!("PhoneControlApp teardown: preview image released");
            } else {
                tracing::debug!("PhoneControlApp teardown: no preview image to release");
            }
            tracing::info!("PhoneControlApp teardown: complete");
        }
    }
}

impl Render for PhoneControlApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        crate::logging::startup_checkpoint("render: entered");
        #[cfg(windows)]
        if !self.renderer_init_attempted {
            self.renderer_init_attempted = true;
            match crate::video_renderer::initialize_for_window(window) {
                Ok(hwnd) => tracing::info!(
                    hwnd = format!("{hwnd:#x}"),
                    "GPUI native HWND resolved; D3D11 render-thread device is ready"
                ),
                Err(error) => tracing::warn!(
                    error = %format!("{error:#}"),
                    "Could not initialize the native D3D11 renderer; GPUI image fallback remains active"
                ),
            }
        }
        #[cfg(windows)]
        crate::logging::startup_checkpoint("render: before quit subscription");
        #[cfg(windows)]
        if self.quit_subscription.is_none() {
            tracing::debug!(
                "Registering GPUI application-quit cleanup for AirPlay preview resources"
            );
            self.quit_subscription = Some(cx.on_app_quit(|this, _cx| {
                tracing::info!("GPUI application-quit cleanup: begin");
                this.fallback_worker_cancel.store(true, Ordering::Release);

                // GPUI invokes quit observers before clearing its window map,
                crate::video_renderer::destroy_native_video_surface();
                // but awaits their returned futures only after the windows have
                // been cleared. Release window-backed preview resources now,
                // synchronously in the observer, rather than in the future.
                if let Some(task) = this.frame_poll_task.take() {
                    tracing::debug!("GPUI application-quit cleanup: cancelling frame poll task");
                    drop(task);
                    tracing::debug!("GPUI application-quit cleanup: frame poll task cancelled");
                }
                if let Some(image) = this.preview_image.take() {
                    tracing::debug!("GPUI application-quit cleanup: releasing preview image");
                    drop(image);
                    tracing::debug!("GPUI application-quit cleanup: preview image released");
                }

                tracing::info!("GPUI application-quit cleanup: complete");
                async {}
            }));
            crate::logging::startup_checkpoint("render: quit subscription registered");
        }
        #[cfg(windows)]
        crate::logging::startup_checkpoint("render: after quit subscription");

        #[cfg(windows)]
        if self.frame_poll_task.is_none() {
            tracing::debug!("Starting GPUI AirPlay frame and device-state poll task");
            crate::logging::startup_checkpoint("render: before frame poll spawn");
            let fallback_worker_cancel = self.fallback_worker_cancel.clone();
            self.frame_poll_task = Some(cx.spawn(async move |this, cx| {
                let mut pairing_refresh_ticks = 0u8;
                // Once native presentation fails, prepare subsequent bitmap
                // fallback frames on the background executor rather than
                // converting NV12/BGRA while the GPUI thread is blocked.
                // A native-present success invalidates any in-flight bitmap fallback.
                let mut fallback_conversion_cancel: Option<Arc<AtomicBool>> = None;
                // At most one CPU fallback conversion may run at a time.
                // The render loop never awaits it; completed results are
                // consumed on a later tick and stale sequences are discarded.
                let fallback_conversion_in_flight = Arc::new(AtomicBool::new(false));
                // A single replaceable slot keeps only the newest frame that arrived
                // while the fallback worker was busy; it never builds an unbounded queue.
                let fallback_pending_frame: Arc<
                    crate::airplay::LatestPendingSlot<(
                        u64,
                        u64,
                        u32,
                        u32,
                        Arc<crate::airplay::DecodedVideoFrame>,
                        Arc<AtomicBool>,
                    )>,
                > = Arc::new(crate::airplay::LatestPendingSlot::default());
                let worker_cancel = fallback_worker_cancel;
                let fallback_conversion_result: Arc<
                    Mutex<Option<(u64, u64, u32, u32, Result<Vec<u8>, &'static str>, Duration)>>,
                > = Arc::new(Mutex::new(None));
                let mut mailbox_stats_log_at = Instant::now();
                let mut last_mailbox_published = 0u64;
                let mut last_mailbox_replaced = 0u64;
                let mut last_mailbox_consumed = 0u64;
                let mut last_mailbox_cleared = 0u64;
                let mut last_mailbox_clear_events = 0u64;
                let mut last_metrics_mailbox_published = 0u64;
                let mut last_metrics_mailbox_consumed = 0u64;
                let mut last_metrics_mailbox_replaced = 0u64;
                let mut last_metrics_mailbox_cleared = 0u64;
                let mut last_presented_frames = 0u64;
                let mut last_metrics_at = Instant::now();
                let mut mailbox_age_total_ms = 0.0f64;
                let mut mailbox_age_max_ms = 0.0f64;
                let mut mailbox_age_samples = 0u64;
                let mut stale_frames_dropped = 0u64;
                // Mailbox sequence numbers are monotonic for this receiver
                // lifetime. Keep the newest observed value even when its
                // frame is rejected as stale, so an older async fallback can
                // never replace a newer (but intentionally dropped) frame.
                let mut latest_observed_frame_sequence = 0u64;
                // Track the dimensions of the bitmap currently visible in the GPUI fallback.
                // A resolution switch must not leave the previous-size frame on screen while
                // the replacement bitmap is being converted asynchronously.
                let mut fallback_displayed_dimensions: Option<(u32, u32)> = None;
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(33))
                        .await;

                    if worker_cancel.load(Ordering::Acquire) {
                        tracing::debug!("Fallback conversion worker cancellation observed by frame poll task");
                        break;
                    }

                    // Video preview remains responsive at ~30 FPS, while the
                    // DPAPI-backed pairing registry is refreshed only twice
                    // per second instead of being read on every frame tick.
                    pairing_refresh_ticks = pairing_refresh_ticks.wrapping_add(1);
                    let refresh_pairing = pairing_refresh_ticks >= 15;
                    if refresh_pairing {
                        pairing_refresh_ticks = 0;
                    }

                    // Session teardown clears the mailbox even when its last frame was
                    // already consumed. Observe that event to remove the texture and
                    // any asynchronous bitmap fallback left by the previous session.
                    let mailbox_cleared = match crate::airplay::video_frame_mailbox_stats() {
                        Ok(Some(stats)) => {
                            let cleared = stats.clear_events != last_mailbox_clear_events;
                            last_mailbox_clear_events = stats.clear_events;
                            cleared
                        }
                        Ok(None) => false,
                        Err(error) => {
                            tracing::debug!(%error, "Could not observe video mailbox clear events");
                            false
                        }
                    };

                    // Keep decoder output in its native format. Do not spend CPU
                    // converting every frame into a GPUI bitmap: the bitmap is
                    // created only if native D3D11 presentation actually fails.
                    let prepared_frame = match crate::airplay::take_latest_video_frame() {
                        Ok(Some(snapshot)) => {
                            latest_observed_frame_sequence =
                                latest_observed_frame_sequence.max(snapshot.sequence);
                            let mailbox_age = snapshot.enqueued_at.elapsed();
                            let mailbox_age_ms = mailbox_age.as_secs_f64() * 1000.0;
                            if mailbox_age > Duration::from_millis(250) {
                                stale_frames_dropped = stale_frames_dropped.saturating_add(1);
                                tracing::warn!(
                                    sequence = snapshot.sequence,
                                    mailbox_age_ms = mailbox_age.as_millis() as u64,
                                    "Dropping stale AirPlay preview frame instead of presenting delayed video"
                                );
                                None
                            } else {
                                mailbox_age_total_ms += mailbox_age_ms;
                                mailbox_age_max_ms = mailbox_age_max_ms.max(mailbox_age_ms);
                                mailbox_age_samples = mailbox_age_samples.saturating_add(1);
                                Some((snapshot.sequence, snapshot.generation, snapshot.frame, mailbox_age))
                            }
                        }
                        Ok(None) => None,
                        Err(error) => {
                            tracing::warn!(%error, "Could not read decoded AirPlay frame");
                            None
                        }
                    };

                    if mailbox_stats_log_at.elapsed() >= Duration::from_secs(1) {
                        match crate::airplay::video_frame_mailbox_stats() {
                            Ok(Some(stats)) => {
                                tracing::info!(
                                    published_per_sec = stats.published.saturating_sub(last_mailbox_published),
                                    replaced_per_sec = stats.replaced_before_consumption
                                        .saturating_sub(last_mailbox_replaced),
                                    consumed_per_sec = stats.consumed.saturating_sub(last_mailbox_consumed),
                                    cleared_per_sec = stats.cleared.saturating_sub(last_mailbox_cleared),
                                    pending = stats.pending,
                                    "Decoded video frame mailbox"
                                );
                                last_mailbox_published = stats.published;
                                last_mailbox_replaced = stats.replaced_before_consumption;
                                last_mailbox_consumed = stats.consumed;
                                last_mailbox_cleared = stats.cleared;
                            }
                            Ok(None) => {}
                            Err(error) => tracing::debug!(%error, "Could not read video frame mailbox stats"),
                        }
                        mailbox_stats_log_at = Instant::now();
                    }

                    // A fallback conversion may take longer than one video
                    // frame interval. Do not require it to match the newest
                    // sequence exactly, or slow conversions can be starved
                    // forever at normal camera frame rates.
                    let completed_fallback = fallback_conversion_result
                        .lock()
                        .ok()
                        .and_then(|mut result| result.take());
                    // A frame may arrive after this tick consumed its mailbox
                    // snapshot but before the completed fallback is published.
                    // Treat a pending frame as newer and let the next tick
                    // decide whether it is fresh enough to present.
                    let newer_frame_pending = if completed_fallback.is_some() {
                        crate::airplay::has_pending_video_frame().unwrap_or(true)
                    } else {
                        false
                    };
                    let completed_fallback = completed_fallback.filter(
                        |(sequence, generation, _, _, _, _)| {
                            fallback_result_is_eligible(
                                mailbox_cleared,
                                newer_frame_pending,
                                *sequence,
                                latest_observed_frame_sequence,
                                crate::airplay::is_video_frame_generation_current(*generation)
                                    .unwrap_or(false),
                            )
                        },
                    );

                    let metrics = if refresh_pairing {
                        let (presented, uploaded, recoveries, recovery_failures, render_errors) =
                            crate::video_renderer::preview_metrics();
                        let elapsed = last_metrics_at.elapsed().as_secs_f64().max(0.001);
                        let fps = presented.saturating_sub(last_presented_frames) as f64 / elapsed;
                        let (decoded_fps, consumed_fps, replaced_fps, cleared_fps) =
                            crate::airplay::video_frame_mailbox_stats()
                                .ok()
                                .flatten()
                                .map(|stats| {
                                    let published = stats
                                        .published
                                        .saturating_sub(last_metrics_mailbox_published);
                                    let consumed = stats
                                        .consumed
                                        .saturating_sub(last_metrics_mailbox_consumed);
                                    let replaced = stats
                                        .replaced_before_consumption
                                        .saturating_sub(last_metrics_mailbox_replaced);
                                    let cleared = stats
                                        .cleared
                                        .saturating_sub(last_metrics_mailbox_cleared);
                                    last_metrics_mailbox_published = stats.published;
                                    last_metrics_mailbox_consumed = stats.consumed;
                                    last_metrics_mailbox_replaced = stats.replaced_before_consumption;
                                    last_metrics_mailbox_cleared = stats.cleared;
                                    (
                                        published as f64 / elapsed,
                                        consumed as f64 / elapsed,
                                        replaced as f64 / elapsed,
                                        cleared as f64 / elapsed,
                                    )
                                })
                                .unwrap_or((0.0, 0.0, 0.0, 0.0));
                        let mailbox_age_avg_ms = if mailbox_age_samples == 0 {
                            0.0
                        } else {
                            mailbox_age_total_ms / mailbox_age_samples as f64
                        };
                        let mailbox_age_peak_ms = mailbox_age_max_ms;
                        let stale_drops_per_sec = stale_frames_dropped as f64 / elapsed;
                        mailbox_age_total_ms = 0.0;
                        mailbox_age_max_ms = 0.0;
                        mailbox_age_samples = 0;
                        stale_frames_dropped = 0;
                        last_presented_frames = presented;
                        last_metrics_at = Instant::now();
                        Some(format!(
                            "D3D11 · {:.1} FPS · 解码 {:.1}/s · 消费 {:.1}/s · 覆盖 {:.1}/s · 清空 {:.1}/s · 等帧 {:.1}/{:.1}ms · 过期丢弃 {:.1}/s · Present {} · 上传 {} · 重建 {} · 重建失败 {} · 错误 {}",
                            fps, decoded_fps, consumed_fps, replaced_fps, cleared_fps, mailbox_age_avg_ms, mailbox_age_peak_ms, stale_drops_per_sec, presented, uploaded, recoveries, recovery_failures, render_errors
                        ))
                    } else {
                        None
                    };

                    let updated = this.update(cx, |this, cx| {
                        let mut changed = false;
                        let connection_status = match rust_phone_control::input::ble::desktop::connection_state() {
                            rust_phone_control::input::ble::BleConnectionState::Disconnected => "未订阅 HID 报告",
                            rust_phone_control::input::ble::BleConnectionState::PartiallySubscribed => "部分 HID 报告已订阅",
                            rust_phone_control::input::ble::BleConnectionState::Suspended => "HID 输入已暂停",
                            rust_phone_control::input::ble::BleConnectionState::Ready => "HID 鼠标和键盘输入就绪",
                        };
                        let ble_status = format!(
                            "{} · {}",
                            rust_phone_control::input::ble::desktop::lifecycle_status(),
                            connection_status
                        );
                        if this.ble_connection_status != ble_status {
                            this.ble_connection_status = ble_status.clone();
                            changed = true;
                        }
                        if mailbox_cleared {
                            crate::video_renderer::hide_native_video_surface();
                            if let Some(cancel) = fallback_conversion_cancel.take() {
                                cancel.store(true, Ordering::Release);
                            }
                            fallback_pending_frame.clear_pending().ok();
                            if let Ok(mut result) = fallback_conversion_result.lock() {
                                *result = None;
                            }
                            this.preview_image = None;
                            fallback_displayed_dimensions = None;
                            this.preview_status = "镜像已断开，等待 iPhone 重新投屏".to_owned();
                            tracing::debug!("Cleared native and bitmap preview after mirror session teardown");
                            changed = true;
                        }
                        if let Some(label) = metrics {
                            if this.d3d11_metrics_label != label {
                                this.d3d11_metrics_label = label;
                                changed = true;
                            }
                        }
                        if refresh_pairing {
                            let status = crate::airplay::pipeline_status_label().to_owned();
                            if this.pipeline_status != status {
                                this.pipeline_status = status;
                                changed = true;
                            }
                        }
                        if refresh_pairing {
                            let pending = crate::airplay::pending_controller_approval();
                            let trusted = crate::airplay::trusted_controller_fingerprints()
                                .unwrap_or_default();
                            let denied = crate::airplay::denied_controller_fingerprints()
                                .unwrap_or_default();
                            if this.pending_airplay_controller != pending {
                                this.pending_airplay_controller = pending;
                                changed = true;
                            }
                            if this.trusted_airplay_controllers != trusted {
                                this.trusted_airplay_controllers = trusted;
                                changed = true;
                            }
                            if this.denied_airplay_controllers != denied {
                                this.denied_airplay_controllers = denied;
                                changed = true;
                            }
                        }
                        if let Some((sequence, generation, width, height, result, conversion_elapsed)) =
                            completed_fallback
                        {
                            match result {
                                Ok(bytes)
                                    if crate::airplay::is_video_frame_generation_current(generation)
                                        .unwrap_or(false) =>
                                {
                                    this.preview_image = Some(Arc::new(Image::from_bytes(
                                        ImageFormat::Bmp,
                                        bytes,
                                    )));
                                    fallback_displayed_dimensions = Some((width, height));
                                    crate::airplay::mark_video_rendered(sequence);
                                    this.preview_status = format!(
                                        "GPUI 图像回退（D3D11 不可用） · {width} × {height} · sequence {sequence}"
                                    );
                                    tracing::trace!(
                                        sequence,
                                        generation,
                                        conversion_ms = conversion_elapsed.as_secs_f64() * 1000.0,
                                        "Published completed asynchronous fallback frame"
                                    );
                                    changed = true;
                                }
                                Ok(_) => {
                                    tracing::debug!(sequence, generation, "Discarding fallback frame from an inactive stream generation");
                                }
                                Err(error) if crate::airplay::is_video_frame_generation_current(generation)
                                    .unwrap_or(false) => {
                                    tracing::warn!(
                                        %error,
                                        sequence,
                                        "Could not convert failed native frame for GPUI fallback"
                                    );
                                    // Do not leave an older bitmap on screen as if it
                                    // represented the current stream after conversion failed.
                                    this.preview_image = None;
                                    fallback_displayed_dimensions = None;
                                    this.preview_status = format!(
                                        "GPUI 图像回退失败 · sequence {sequence} · {error}"
                                    );
                                    changed = true;
                                }
                                Err(_) => {
                                    tracing::debug!(sequence, generation, "Discarding failed fallback from an inactive stream generation");
                                }
                            }
                        }

                        if let Some((sequence, generation, frame, mailbox_age)) = prepared_frame
                            .filter(|(_, generation, _, _)| {
                                crate::airplay::is_video_frame_generation_current(*generation)
                                    .unwrap_or(false)
                            })
                        {
                            let (width, height) = match frame.as_ref() {
                                crate::airplay::DecodedVideoFrame::Bgra(frame) => {
                                    (frame.width, frame.height)
                                }
                                crate::airplay::DecodedVideoFrame::Nv12(frame) => {
                                    (frame.width, frame.height)
                                }
                            };
                            let upload_started = Instant::now();

                            // Entity::update runs on GPUI's foreground executor.
                            // D3D11 immediate-context calls stay on the GPUI
                            // thread that initialized the native renderer.
                            let native_present = if crate::airplay::is_video_frame_generation_current(generation)
                                .unwrap_or(false)
                            {
                                match frame.as_ref() {
                                crate::airplay::DecodedVideoFrame::Bgra(frame) => {
                                    crate::video_renderer::upload_bgra_frame(
                                        width,
                                        height,
                                        frame.stride,
                                        &frame.data,
                                    )
                                }
                                crate::airplay::DecodedVideoFrame::Nv12(frame) => {
                                    crate::video_renderer::upload_nv12_frame(
                                        width,
                                        height,
                                        frame.y_stride,
                                        frame.uv_stride,
                                        &frame.data,
                                        frame.color_matrix,
                                    )
                                }
                                }
                            } else {
                                Err(anyhow::anyhow!("frame belongs to an inactive stream generation"))
                            };
                            let upload_elapsed = upload_started.elapsed();
                            let (display_path, used_fallback, conversion_elapsed) =
                                match native_present {
                                    Ok(()) if crate::airplay::is_video_frame_generation_current(generation)
                                        .unwrap_or(false) => {
                                        crate::airplay::mark_video_rendered(sequence);
                                        // The native child surface owns the visible image.
                                        // Cancel stale CPU conversion work and discard any
                                        // completed bitmap that raced with native recovery.
                                        if let Some(cancel) = fallback_conversion_cancel.take() {
                                            cancel.store(true, Ordering::Release);
                                        }
                                        fallback_pending_frame.clear_pending().ok();
                                        if let Ok(mut result) = fallback_conversion_result.lock() {
                                            *result = None;
                                        }
                                        this.preview_image = None;
                                        fallback_displayed_dimensions = None;
                                        ("D3D11 原生预览", false, Duration::ZERO)
                                    }
                                    Ok(()) | Err(_) if !crate::airplay::is_video_frame_generation_current(generation)
                                        .unwrap_or(false) => {
                                        crate::video_renderer::hide_native_video_surface();
                                        this.preview_image = None;
                                        ("等待当前投屏会话的视频帧", false, Duration::ZERO)
                                    }
                                    Ok(()) => {
                                        crate::video_renderer::hide_native_video_surface();
                                        this.preview_image = None;
                                        ("等待当前投屏会话的视频帧", false, Duration::ZERO)
                                    }
                                    Err(error) => {
                                        crate::video_renderer::hide_native_video_surface();
                                        // Do not keep a bitmap from the previous resolution
                                        // visible while the new frame is converted in the
                                        // background. Same-resolution fallback may retain its
                                        // last frame to avoid flicker during normal conversion.
                                        if fallback_displayed_dimensions
                                            .is_some_and(|displayed| displayed != (width, height))
                                        {
                                            this.preview_image = None;
                                            fallback_displayed_dimensions = None;
                                        }
                                        tracing::debug!(
                                            %error,
                                            sequence,
                                            "D3D11 frame upload unavailable; scheduling bounded asynchronous GPUI fallback conversion"
                                        );
                                        let conversion_cancel = Arc::new(AtomicBool::new(false));
                                        if let Some(previous) =
                                            fallback_conversion_cancel.replace(conversion_cancel.clone())
                                        {
                                            // Stop converting an obsolete frame immediately; the
                                            // worker will continue with the newest pending request.
                                            previous.store(true, Ordering::Release);
                                        }
                                        let pending_frame = (
                                            sequence,
                                            generation,
                                            width,
                                            height,
                                            frame.clone(),
                                            conversion_cancel,
                                        );
                                        let pending_slot = fallback_pending_frame.clone();
                                        // Coalesce to one pending item. The slot and in-flight
                                        // flag are coordinated under one lock to avoid lost wakeups.
                                        let should_spawn = pending_slot.submit(
                                            pending_frame.clone(),
                                            &fallback_conversion_in_flight,
                                        );
                                        if should_spawn {
                                            let result_slot = fallback_conversion_result.clone();
                                            let in_flight = fallback_conversion_in_flight.clone();
                                            let pending_slot = fallback_pending_frame.clone();
                                            let cancel = worker_cancel.clone();
                                            let spawn = std::thread::Builder::new()
                                                .name("airplay-fallback-convert".to_owned())
                                                .spawn(move || {
                                                    let _in_flight_guard =
                                                        FallbackConversionInFlightGuard(Some(in_flight.clone()));
                                                    let mut current = Some(pending_frame);
                                                    while let Some((
                                                        sequence,
                                                        generation,
                                                        width,
                                                        height,
                                                        frame,
                                                        frame_cancel,
                                                    )) = current.take()
                                                    {
                                                        if cancel.load(Ordering::Acquire) {
                                                            let _ = pending_slot.clear_and_release(&in_flight);
                                                            _in_flight_guard.disarm();
                                                            return;
                                                        }
                                                        if !frame_cancel.load(Ordering::Acquire) {
                                                            let started = Instant::now();
                                                            let result = decoded_frame_to_bmp(
                                                                frame.as_ref(),
                                                                || cancel.load(Ordering::Acquire)
                                                                    || frame_cancel.load(Ordering::Acquire),
                                                            );
                                                            let elapsed = started.elapsed();
                                                            if !cancel.load(Ordering::Acquire)
                                                                && !frame_cancel.load(Ordering::Acquire)
                                                                && crate::airplay::is_video_frame_generation_current(generation).unwrap_or(false)
                                                            {
                                                                if let Ok(mut slot) = result_slot.lock() {
                                                                    if !cancel.load(Ordering::Acquire)
                                                                        && !frame_cancel.load(Ordering::Acquire)
                                                                        && crate::airplay::is_video_frame_generation_current(generation).unwrap_or(false)
                                                                    {
                                                                        *slot = Some((sequence, generation, width, height, result, elapsed));
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        // A per-frame cancellation (for example, native
                                                        // D3D11 recovery) skips only that frame. A newer
                                                        // pending request has its own token and remains valid.
                                                        match pending_slot.take_or_release(&in_flight) {
                                                            Ok(Some(next)) => current = Some(next),
                                                            Ok(None) => {
                                                                _in_flight_guard.disarm();
                                                                return;
                                                            }
                                                            Err(()) => break,
                                                        }
                                                    }
                                                });
                                            if let Err(error) = spawn {
                                                fallback_pending_frame.clear_and_release(&fallback_conversion_in_flight).ok();
                                                fallback_conversion_in_flight.store(false, Ordering::Release);
                                                tracing::warn!(
                                                    %error,
                                                    sequence,
                                                    "Could not spawn bounded GPUI fallback conversion worker"
                                                );
                                            }
                                        }
                                        if this.preview_image.is_some() {
                                            (
                                                "GPUI 图像回退（等待最新帧）",
                                                false,
                                                Duration::ZERO,
                                            )
                                        } else {
                                            (
                                                "GPUI 回退准备中",
                                                false,
                                                Duration::ZERO,
                                            )
                                        }
                                    }
                                };
                            tracing::trace!(
                                sequence,
                                mailbox_age_ms = mailbox_age.as_secs_f64() * 1000.0,
                                fallback_conversion_ms = conversion_elapsed.as_secs_f64() * 1000.0,
                                d3d11_upload_ms = upload_elapsed.as_secs_f64() * 1000.0,
                                fallback_frame = used_fallback,
                                "Video frame pipeline latency"
                            );

                            this.preview_status = format!(
                                "{display_path} · {width} × {height} · sequence {sequence}"
                            );
                            changed = true;
                        }
                        if changed {
                            cx.notify();
                        }
                        ()
                    });
                    match updated {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::debug!("Stopping GPUI AirPlay poll task because its app entity is no longer available");
                            break;
                        }
                    }
                }
            }));
            crate::logging::startup_checkpoint("render: frame poll spawned");
        }
        #[cfg(windows)]
        crate::logging::startup_checkpoint("render: after frame poll setup");

        // Build each major region in its own function. Keeping the opaque GPUI
        // element types shallow avoids a single enormous nested builder tree.
        let header = render_header(self);
        crate::logging::startup_checkpoint("render: header built");
        let workspace = render_workspace(self, cx);
        crate::logging::startup_checkpoint("render: workspace built");
        let footer = render_footer();
        crate::logging::startup_checkpoint("render: footer built");

        let root = div()
            .flex()
            .flex_col()
            .size_full()
            .p_2()
            .gap_2()
            .bg(gpui_kit::rgb(0xF4F5F8))
            .text_color(gpui_kit::rgb(0x253047))
            .child(header)
            .child(workspace)
            .child(footer);
        crate::logging::startup_checkpoint("render: element tree built");
        root
    }
}

fn render_header(app: &PhoneControlApp) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_between()
        .h(px(42.))
        .p_2()
        .rounded_lg()
        .bg(gpui_kit::rgb(0xFFFFFF))
        .border_1()
        .border_color(gpui_kit::rgb(0xE1E5ED))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(Label::new("🔵"))
                .child(Label::new("MirrorDeck")),
        )
        .child(Label::new(if app.airplay_status.contains("Running") {
            "● 发现服务运行中 · 安全镜像未就绪"
        } else {
            "● 接收服务未启动"
        }))
        .child(Label::new("⚙"))
}

fn render_workspace(app: &PhoneControlApp, cx: &Context<PhoneControlApp>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .flex_1()
        .gap_2()
        // Keep device approval above the tall phone preview so the user can
        // see and act on a first-time pairing request without scrolling.
        .child(pending_airplay_approval_panel(app, cx))
        .child(
            div()
                .flex()
                .flex_1()
                .gap_2()
                .child(render_left_sidebar(app, cx))
                .child(render_preview_column(app, cx))
                .child(render_right_controls(app, cx)),
        )
}

fn render_left_sidebar(app: &PhoneControlApp, cx: &Context<PhoneControlApp>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .w(px(205.))
        .p_2()
        .gap_2()
        .rounded_lg()
        .bg(gpui_kit::rgb(0xFFFFFF))
        .border_1()
        .border_color(gpui_kit::rgb(0xE1E5ED))
        .child(
            Button::new("connect-new-device")
                .primary()
                .label("+ 连接新设备")
                .on_click(|_, _, _| tracing::info!("Connect-new-device entry selected")),
        )
        .child(Label::new("我的设备"))
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .p_2()
                .rounded_lg()
                .bg(gpui_kit::rgb(0xEEF0FF))
                .border_1()
                .border_color(gpui_kit::rgb(0xC9CCFF))
                .child(Label::new("📱  iPhone"))
                .child(Label::new(if app.airplay_status.contains("Running") {
                    "发现服务运行中 · 等待镜像握手"
                } else {
                    "等待手机连接"
                })),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .p_2()
                .rounded_lg()
                .bg(gpui_kit::rgb(0xF7F8FA))
                .border_1()
                .border_color(gpui_kit::rgb(0xE8EBF1))
                .child(Label::new("  iPhone · BLE"))
                .child(Label::new("蓝牙 HID 控制"))
                .child(Label::new(app.ble_connection_status.as_str())),
        )
        .child(
            div()
                .flex()
                .gap_1()
                .child(
                    Button::new("ble-start")
                        .primary()
                        .label("启动蓝牙")
                        .on_click(|_, _, _| start_ble()),
                )
                .child(
                    Button::new("ble-stop")
                        .label("停止蓝牙")
                        .on_click(|_, _, _| stop_ble()),
                ),
        )
        .child(Label::new("连接方式"))
        .child(
            div()
                .flex()
                .gap_1()
                .child(
                    Button::new("connection-wireless")
                        .primary()
                        .label("启动 AirPlay")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.airplay_status = start_airplay_status();
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("connection-usb")
                        .label("USB")
                        .on_click(|_, _, _| {
                            tracing::info!("USB transport adapter is not wired yet")
                        }),
                )
                .child(
                    Button::new("connection-qr")
                        .label("扫码")
                        .on_click(|_, _, _| tracing::info!("QR pairing entry selected")),
                ),
        )
        .child(div().flex_1())
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .p_2()
                .rounded_lg()
                .bg(gpui_kit::rgb(0xF7F8FA))
                .child(Label::new("设备状态"))
                .child(Label::new("电量  —"))
                .child(Label::new("存储  —")),
        )
}

fn render_preview_column(app: &PhoneControlApp, cx: &Context<PhoneControlApp>) -> impl IntoElement {
    #[cfg(windows)]
    let preview_surface_bounds = Arc::clone(&app.preview_surface_bounds);

    div()
        .flex()
        .flex_col()
        .flex_1()
        .gap_2()
        .rounded_lg()
        .bg(gpui_kit::rgb(0xFFFFFF))
        .border_1()
        .border_color(gpui_kit::rgb(0xE1E5ED))
        .child(Label::new(app.pipeline_status.as_str()))
        .child(Label::new(app.d3d11_metrics_label.as_str()))
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_2()
                .p_2()
                .child(
                    Button::new("mirror-refresh")
                        .label("⟳")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.airplay_status = start_airplay_status();
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("mirror-screenshot")
                        .label("▣")
                        .on_click(|_, _, _| tracing::info!("Screenshot action requested")),
                )
                .child(
                    Button::new("mirror-start")
                        .primary()
                        .label("启动")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.airplay_status = start_airplay_status();
                            cx.notify();
                        })),
                )
                .child(Button::new("mirror-stop").label("Ⅱ").on_click(cx.listener(
                    |this, _, _, cx| {
                        this.airplay_status = stop_airplay_status();
                        cx.notify();
                    },
                )))
                .child(
                    Button::new("mirror-copy-code")
                        .label("配对码")
                        .on_click(|_, _, cx| copy_airplay_pairing_code(cx)),
                ),
        )
        .child(
            div()
                .flex()
                .flex_1()
                .items_center()
                .justify_center()
                .p_2()
                .child(preview_panel_for_app(app))
                .on_children_prepainted(move |children, window, _cx| {
                    let next = children.first().map(|bounds| {
                        let scale = window.scale_factor();
                        PreviewSurfaceBounds {
                            x: (bounds.origin.x.as_f32() * scale).round() as i32,
                            y: (bounds.origin.y.as_f32() * scale).round() as i32,
                            width: (bounds.size.width.as_f32() * scale).round() as i32,
                            height: (bounds.size.height.as_f32() * scale).round() as i32,
                        }
                    });

                    if let Ok(mut current) = preview_surface_bounds.lock() {
                        if *current != next {
                            *current = next;
                            if let Some(bounds) = next {
                                tracing::debug!(
                                    x = bounds.x,
                                    y = bounds.y,
                                    width = bounds.width,
                                    height = bounds.height,
                                    "Measured GPUI video preview bounds in client-area device pixels"
                                );
                            } else {
                                tracing::debug!("GPUI video preview bounds are not currently available");
                            }
                        }
                    }

                    match next {
                        Some(bounds) => {
                            if let Err(error) = crate::video_renderer::sync_native_video_surface(
                                bounds.x, bounds.y, bounds.width, bounds.height,
                            ) {
                                tracing::warn!(error = %format!("{error:#}"), "Native video child surface synchronization failed");
                            }
                        }
                        None => crate::video_renderer::destroy_native_video_surface(),
                    }
                })
                .on_mouse_down(MouseButton::Left, cx.listener(|this, event: &MouseDownEvent, _, _| {
                    this.preview_pointer_position = Some((
                        event.position.x.as_f32(),
                        event.position.y.as_f32(),
                    ));
                    queue_ble(rust_phone_control::input::ble::desktop::dispatch_event(
                        InputEvent::PointerButtons(MouseButtons::LEFT),
                    ));
                }))
                .on_mouse_move(cx.listener(|this, event: &MouseMoveEvent, _, _| {
                    if !event.dragging() {
                        return;
                    }
                    let current = (event.position.x.as_f32(), event.position.y.as_f32());
                    if let Some(previous) = this.preview_pointer_position {
                        let dx = (current.0 - previous.0)
                            .round()
                            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
                        let dy = (current.1 - previous.1)
                            .round()
                            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
                        if dx != 0 || dy != 0 {
                            queue_ble(rust_phone_control::input::ble::desktop::dispatch_event(
                                InputEvent::PointerMove { dx, dy },
                            ));
                        }
                    }
                    this.preview_pointer_position = Some(current);
                }))
                .on_mouse_up(MouseButton::Left, cx.listener(|this, _: &MouseUpEvent, _, _| {
                    this.preview_pointer_position = None;
                    queue_ble(rust_phone_control::input::ble::desktop::dispatch_event(
                        InputEvent::PointerButtons(MouseButtons::NONE),
                    ));
                }))
                .on_mouse_up_out(MouseButton::Left, cx.listener(|this, _: &gpui::MouseUpEvent, _, _| {
                    this.preview_pointer_position = None;
                    queue_ble(rust_phone_control::input::ble::desktop::dispatch_event(
                        InputEvent::PointerButtons(MouseButtons::NONE),
                    ));
                }))
                .on_mouse_exit(cx.listener(|this, _: &MouseExitEvent, _, _| {
                    if this.preview_pointer_position.take().is_some() {
                        queue_ble(rust_phone_control::input::ble::desktop::dispatch_event(
                            InputEvent::PointerButtons(MouseButtons::NONE),
                        ));
                    }
                })),
        )
        .child(Label::new(if app.preview_status.is_empty() {
            "等待手机画面 · FairPlay 尚未配置，当前无法完成安全镜像"
        } else {
            app.preview_status.as_str()
        }))
}

fn render_right_controls(app: &PhoneControlApp, cx: &Context<PhoneControlApp>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .w(px(250.))
        .p_2()
        .gap_2()
        .rounded_lg()
        .bg(gpui_kit::rgb(0xFFFFFF))
        .border_1()
        .border_color(gpui_kit::rgb(0xE1E5ED))
        .child(Label::new("鼠标控制"))
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .child(move_button("mouse-up", "↑", 0, -24)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_2()
                .child(move_button("mouse-left", "←", -24, 0))
                .child(
                    Button::new("mouse-click")
                        .primary()
                        .label("点击")
                        .on_click(|_, _, _| left_click_ble()),
                )
                .child(move_button("mouse-right", "→", 24, 0)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .child(move_button("mouse-down", "↓", 0, 24)),
        )
        .child(
            div()
                .flex()
                .gap_2()
                .child(
                    Button::new("mouse-scroll-up")
                        .label("滚轮上")
                        .on_click(|_, _, _| scroll_ble(-3)),
                )
                .child(
                    Button::new("mouse-scroll-down")
                        .label("滚轮下")
                        .on_click(|_, _, _| scroll_ble(3)),
                ),
        )
        .child(Label::new("电脑键盘输入到手机"))
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .p_2()
                .rounded_lg()
                .bg(gpui_kit::rgb(0xF6F7FB))
                .border_1()
                .border_color(gpui_kit::rgb(0xE5E8F0))
                .child(if let Some(input) = app.keyboard_input.as_ref() {
                    div().child(Input::new(input).w_full())
                } else {
                    div().child(Label::new("键盘输入未初始化"))
                })
                .child(
                    Button::new("keyboard-send-text")
                        .primary()
                        .label("发送到手机")
                        .on_click(cx.listener(|this, _, window, cx| {
                            let Some(input) = this.keyboard_input.as_ref() else {
                                return;
                            };
                            let text = input.read(cx).value().to_string();
                            if text.is_empty() || !send_text_ble(text) {
                                return;
                            }
                            input.update(cx, |state, cx| state.set_value("", window, cx));
                        })),
                ),
        )
        .child(Label::new("文件传输"))
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .h(px(88.))
                .p_2()
                .rounded_lg()
                .bg(gpui_kit::rgb(0xF5F5FF))
                .border_1()
                .border_color(gpui_kit::rgb(0xDCDFFF))
                .child(Label::new("☁"))
                .child(Label::new("拖拽文件到此处发送到手机")),
        )
        .child(Label::new("控制选项"))
        .child(Label::new("鼠标控制手机"))
        .child(Label::new("同步剪贴板"))
        .child(Label::new("投屏时熄灭手机屏幕"))
        .child(Label::new("显示触控点"))
        .child(
            Button::new("airplay-disconnect")
                .label("断开连接")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.airplay_status = stop_airplay_status();
                    cx.notify();
                })),
        )
}

fn render_footer() -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .gap_3()
        .h(px(28.))
        .rounded_lg()
        .bg(gpui_kit::rgb(0xFFFFFF))
        .border_1()
        .border_color(gpui_kit::rgb(0xE1E5ED))
        .child(Label::new("◉ 延迟 —"))
        .child(Label::new("▦ FPS —"))
        .child(Label::new("▥ 码率 —"))
        .child(Label::new("🔒 本地加密"))
}

#[cfg(windows)]
fn pending_airplay_approval_panel(
    app: &PhoneControlApp,
    cx: &Context<PhoneControlApp>,
) -> impl IntoElement {
    let mut panel = div()
        .flex()
        .flex_col()
        .gap_2()
        .p_2()
        .rounded_lg()
        .border_1()
        .border_color(gpui_kit::rgb(0xB7791F))
        .child(Label::new("AirPlay 设备授权"));

    if let Some(fingerprint) = app.pending_airplay_controller.as_ref() {
        panel = panel
            .child(Label::new("检测到新的 iPhone，正在等待你在此电脑上批准。"))
            .child(Label::new(format!("设备身份指纹：{fingerprint}")))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("airplay-approve-controller")
                            .primary()
                            .label("允许此设备")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.airplay_approval_status =
                                    match crate::airplay::approve_pending_controller() {
                                        Ok(true) => "设备已批准。请在 iPhone 上重新选择此接收器连接。".into(),
                                        Ok(false) => "当前没有等待批准的设备。".into(),
                                        Err(error) => format!("批准失败：{error}"),
                                    };
                                tracing::info!(status = %this.airplay_approval_status, "AirPlay approval action");
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("airplay-reject-controller")
                            .label("拒绝")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.airplay_approval_status =
                                    match crate::airplay::reject_pending_controller() {
                                        Ok(true) => "设备已拒绝；解除拒绝后仍需重新批准。".into(),
                                        Ok(false) => "当前没有等待拒绝的设备。".into(),
                                        Err(error) => format!("拒绝设备失败：{error}"),
                                    };
                                tracing::info!(status = %this.airplay_approval_status, "AirPlay rejection action");
                                cx.notify();
                            })),
                    ),
            );
    } else {
        panel = panel.child(Label::new("当前没有等待授权的新设备。"));
    }

    panel = panel.child(Label::new("已批准设备"));
    if app.trusted_airplay_controllers.is_empty() {
        panel = panel.child(Label::new("暂无已批准设备。"));
    } else {
        for (index, fingerprint) in app.trusted_airplay_controllers.iter().enumerate() {
            let target = fingerprint.clone();
            panel =
                panel.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .child(Label::new(fingerprint.clone()))
                        .child(
                            Button::new(format!("airplay-revoke-controller-{index}"))
                                .label("撤销授权")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.airplay_approval_status =
                                        match crate::airplay::revoke_trusted_controller(&target) {
                                            Ok(true) => format!("Authorization revoked for {target}. Reconnection requires approval."),
                                            Ok(false) => format!("Authorization for {target} was already absent."),
                                            Err(error) => format!("Could not revoke {target}: {error}"),
                                        };
                                    tracing::info!(status = %this.airplay_approval_status, "AirPlay revoke action");
                                    cx.notify();
                                })),
                        ),
                );
        }
    }

    panel = panel.child(Label::new("已拒绝设备"));
    if app.denied_airplay_controllers.is_empty() {
        panel = panel.child(Label::new("暂无已拒绝设备。"));
    } else {
        for (index, fingerprint) in app.denied_airplay_controllers.iter().enumerate() {
            let target = fingerprint.clone();
            panel = panel.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(Label::new(fingerprint.clone()))
                    .child(
                        Button::new(format!("airplay-clear-denial-{index}"))
                            .label("解除拒绝")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.airplay_approval_status =
                                    match crate::airplay::clear_denied_controller(&target) {
                                        Ok(true) => format!("Denial cleared for {target}. The device must still be approved."),
                                        Ok(false) => format!("Denial for {target} was already absent."),
                                        Err(error) => format!("Could not clear denial for {target}: {error}"),
                                    };
                                tracing::info!(status = %this.airplay_approval_status, "AirPlay clear-denial action");
                                cx.notify();
                            })),
                    ),
            );
        }
    }

    if !app.airplay_approval_status.is_empty() {
        panel = panel.child(Label::new(app.airplay_approval_status.clone()));
    }
    panel
}

#[cfg(not(windows))]
fn pending_airplay_approval_panel(
    _: &PhoneControlApp,
    _: &Context<PhoneControlApp>,
) -> impl IntoElement {
    Label::new("AirPlay 设备授权仅在 Windows 上可用")
}

#[cfg(windows)]
fn preview_panel_for_app(app: &PhoneControlApp) -> impl IntoElement {
    preview_panel(app.preview_image.clone(), app.preview_status.clone())
}

#[cfg(not(windows))]
fn preview_panel_for_app(_: &PhoneControlApp) -> impl IntoElement {
    Label::new("AirPlay live preview is available on Windows")
}

#[cfg(windows)]
fn preview_panel(image: Option<Arc<Image>>, status: String) -> impl IntoElement {
    let mut shell = div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .w(px(248.))
        .h(px(500.))
        .p_2()
        .rounded_lg()
        .bg(gpui_kit::rgb(0x11131A))
        .border_1()
        .border_color(gpui_kit::rgb(0x090A0E));
    let screen = if let Some(image) = image {
        div()
            .flex()
            .items_center()
            .justify_center()
            .w_full()
            .h_full()
            .rounded_lg()
            .child(img(image).w_full().h_full().object_fit(ObjectFit::Contain))
    } else {
        div()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .w_full()
            .h_full()
            .gap_2()
            .rounded_lg()
            .bg(gpui_kit::rgb(0x24283A))
            .child(Label::new("MirrorDeck"))
            .child(Label::new("等待手机投屏"))
            .child(Label::new(if status.is_empty() {
                "启动 AirPlay 后连接 iPhone"
            } else {
                status.as_str()
            }))
    };
    shell = shell.child(screen);
    shell
}

#[cfg(windows)]
fn decoded_frame_to_bmp(
    frame: &crate::airplay::DecodedVideoFrame,
    is_cancelled: impl Fn() -> bool + Copy,
) -> Result<Vec<u8>, &'static str> {
    if is_cancelled() {
        return Err("frame conversion cancelled");
    }
    match frame {
        crate::airplay::DecodedVideoFrame::Bgra(frame) => bgra_frame_to_bmp(frame, is_cancelled),
        crate::airplay::DecodedVideoFrame::Nv12(frame) => crate::airplay::Nv12Frame {
            width: frame.width,
            height: frame.height,
            y_stride: frame.y_stride,
            uv_stride: frame.uv_stride,
            data: &frame.data,
        }
        .to_bgra_cancellable(is_cancelled)
        .map_err(|_| "NV12 fallback conversion failed")
        .and_then(|bgra| bgra_frame_to_bmp(&bgra, is_cancelled)),
    }
}

#[cfg(windows)]
fn bgra_frame_to_bmp(
    frame: &crate::airplay::BgraFrame,
    is_cancelled: impl Fn() -> bool + Copy,
) -> Result<Vec<u8>, &'static str> {
    let width = usize::try_from(frame.width).map_err(|_| "frame width overflow")?;
    let height = usize::try_from(frame.height).map_err(|_| "frame height overflow")?;
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return Err("frame dimensions are invalid");
    }

    let row_bytes = width.checked_mul(4).ok_or("frame row size overflow")?;
    if frame.stride < row_bytes {
        return Err("BGRA stride is smaller than the pixel row");
    }
    let source_bytes = frame
        .stride
        .checked_mul(height)
        .ok_or("BGRA source size overflow")?;
    if frame.data.len() < source_bytes {
        return Err("BGRA frame buffer is truncated");
    }
    let pixel_bytes = row_bytes
        .checked_mul(height)
        .ok_or("BMP image size overflow")?;
    const MAX_FALLBACK_BITMAP_BYTES: usize = 128 * 1024 * 1024;
    if pixel_bytes > MAX_FALLBACK_BITMAP_BYTES {
        return Err("fallback bitmap exceeds 128 MiB");
    }
    let file_bytes = 54usize
        .checked_add(pixel_bytes)
        .ok_or("BMP file size overflow")?;
    let file_bytes_u32 = u32::try_from(file_bytes).map_err(|_| "BMP file exceeds 4 GiB")?;
    let width_i32 = i32::try_from(width).map_err(|_| "BMP width overflow")?;
    let height_i32 = i32::try_from(height).map_err(|_| "BMP height overflow")?;

    let mut bmp = Vec::with_capacity(file_bytes);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_bytes_u32.to_le_bytes());
    bmp.extend_from_slice(&[0; 4]);
    bmp.extend_from_slice(&54u32.to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&width_i32.to_le_bytes());
    bmp.extend_from_slice(&(-height_i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&32u16.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes());
    bmp.extend_from_slice(&[0; 8]);

    for row in 0..height {
        if is_cancelled() {
            return Err("frame conversion cancelled");
        }
        let start = row
            .checked_mul(frame.stride)
            .ok_or("BGRA row offset overflow")?;
        bmp.extend_from_slice(&frame.data[start..start + row_bytes]);
    }
    Ok(bmp)
}

fn move_button(id: &'static str, label: &'static str, dx: i32, dy: i32) -> impl IntoElement {
    Button::new(id)
        .label(label)
        .on_click(move |_, _, _| move_ble(dx, dy))
}

#[cfg(windows)]
fn start_ble() {
    queue_ble(rust_phone_control::input::ble::desktop::start());
}

#[cfg(not(windows))]
fn start_ble() {
    tracing::warn!("BLE HID desktop controls are only available on Windows");
}

#[cfg(windows)]
fn stop_ble() {
    queue_ble(rust_phone_control::input::ble::desktop::stop());
}

#[cfg(not(windows))]
fn stop_ble() {
    tracing::warn!("BLE HID desktop controls are only available on Windows");
}

#[cfg(windows)]
fn queue_ble(result: anyhow::Result<()>) {
    if let Err(error) = result {
        tracing::error!(error = %format!("{error:#}"), "Could not queue BLE desktop command");
    }
}

#[cfg(not(windows))]
fn queue_ble(_: ()) {}

#[cfg(windows)]
fn move_ble(dx: i32, dy: i32) {
    queue_ble(rust_phone_control::input::ble::desktop::move_mouse(dx, dy));
}
#[cfg(not(windows))]
fn move_ble(_: i32, _: i32) {}

#[cfg(windows)]
fn left_click_ble() {
    queue_ble(rust_phone_control::input::ble::desktop::left_click());
}
#[cfg(not(windows))]
fn left_click_ble() {}

#[cfg(windows)]
fn scroll_ble(amount: i32) {
    queue_ble(rust_phone_control::input::ble::desktop::scroll(amount));
}
#[cfg(not(windows))]
fn scroll_ble(_: i32) {}

#[cfg(windows)]
fn send_text_ble(text: String) -> bool {
    match rust_phone_control::input::ble::desktop::type_text(text) {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "Could not queue BLE keyboard text");
            false
        }
    }
}

#[cfg(not(windows))]
fn send_text_ble(_: String) -> bool {
    tracing::warn!("BLE keyboard input is only available on Windows");
    false
}

#[cfg(windows)]
fn type_sample_ble() {
    queue_ble(rust_phone_control::input::ble::desktop::type_sample());
}
#[cfg(not(windows))]
fn type_sample_ble() {}

#[cfg(windows)]
fn copy_airplay_pairing_code(cx: &mut App) {
    cx.write_to_clipboard(ClipboardItem::new_string(crate::airplay::setup_code()));
}

#[cfg(not(windows))]
fn copy_airplay_pairing_code(_: &mut App) {}

#[cfg(windows)]
fn airplay_pairing_code_label() -> String {
    format!("iPhone pairing code: {}", crate::airplay::setup_code())
}

#[cfg(not(windows))]
fn airplay_pairing_code_label() -> String {
    "iPhone pairing code: Windows only".to_owned()
}

#[cfg(windows)]
fn start_airplay_status() -> String {
    match crate::airplay::start() {
        Ok(()) => {
            tracing::info!("AirPlay start button completed successfully");
            "Running · TCP 7000 · AirPlay discovery active · FairPlay provider unavailable"
                .to_owned()
        }
        Err(error) => {
            let message = format!("{error:#}");
            tracing::error!(error = %message, "Could not start AirPlay receiver");
            format!("Start failed: {message}")
        }
    }
}

#[cfg(not(windows))]
fn start_airplay_status() -> String {
    "Unavailable · Windows only".to_owned()
}

#[cfg(windows)]
fn stop_airplay_status() -> String {
    match crate::airplay::stop() {
        Ok(()) => {
            tracing::info!("AirPlay stop button completed successfully");
            "Stopped".to_owned()
        }
        Err(error) => {
            let message = format!("{error:#}");
            tracing::error!(error = %message, "Could not stop AirPlay receiver");
            format!("Stop failed: {message}")
        }
    }
}

#[cfg(not(windows))]
fn stop_airplay_status() -> String {
    "Unavailable · Windows only".to_owned()
}
