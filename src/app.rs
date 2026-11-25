use gpui_kit::component::{
    button::{Button, ButtonVariants},
    label::Label,
};
use gpui_kit::*;

#[cfg(windows)]
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq)]
struct PreviewSurfaceBounds {
    /// Preview rectangle origin relative to the GPUI client-area origin, in device pixels.
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

#[derive(Default)]
pub struct PhoneControlApp {
    airplay_status: String,
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
    /// Latest measured preview rectangle, shared with the future native-surface host.
    #[cfg(windows)]
    preview_surface_bounds: Arc<Mutex<Option<PreviewSurfaceBounds>>>,
    #[cfg(windows)]
    renderer_init_attempted: bool,
    #[cfg(windows)]
    frame_poll_task: Option<Task<()>>,
    #[cfg(windows)]
    fallback_worker_cancel: Arc<AtomicBool>,
    #[cfg(windows)]
    quit_subscription: Option<Subscription>,
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
                let mut fallback_mode = false;
                // At most one CPU fallback conversion may run at a time.
                // The render loop never awaits it; completed results are
                // consumed on a later tick and stale sequences are discarded.
                let fallback_conversion_in_flight = Arc::new(AtomicBool::new(false));
                let worker_cancel = fallback_worker_cancel;
                let fallback_conversion_result: Arc<
                    Mutex<Option<(u64, u32, u32, Result<Vec<u8>, &'static str>, Duration)>>,
                > = Arc::new(Mutex::new(None));
                let mut mailbox_stats_log_at = Instant::now();
                let mut last_mailbox_published = 0u64;
                let mut last_mailbox_replaced = 0u64;
                let mut last_mailbox_consumed = 0u64;
                let mut last_metrics_mailbox_published = 0u64;
                let mut last_metrics_mailbox_consumed = 0u64;
                let mut last_metrics_mailbox_replaced = 0u64;
                let mut last_presented_frames = 0u64;
                let mut last_metrics_at = Instant::now();
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

                    // Keep decoder output in its native format. Do not spend CPU
                    // converting every frame into a GPUI bitmap: the bitmap is
                    // created only if native D3D11 presentation actually fails.
                    let prepared_frame = match crate::airplay::take_latest_video_frame() {
                        Ok(Some(snapshot)) => Some((
                            snapshot.sequence,
                            snapshot.frame,
                            snapshot.enqueued_at.elapsed(),
                        )),
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
                                    pending = stats.pending,
                                    "Decoded video frame mailbox"
                                );
                                last_mailbox_published = stats.published;
                                last_mailbox_replaced = stats.replaced_before_consumption;
                                last_mailbox_consumed = stats.consumed;
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

                    let metrics = if refresh_pairing {
                        let (presented, uploaded, recoveries, render_errors) =
                            crate::video_renderer::preview_metrics();
                        let elapsed = last_metrics_at.elapsed().as_secs_f64().max(0.001);
                        let fps = presented.saturating_sub(last_presented_frames) as f64 / elapsed;
                        let (decoded_fps, consumed_fps, replaced_fps) =
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
                                    last_metrics_mailbox_published = stats.published;
                                    last_metrics_mailbox_consumed = stats.consumed;
                                    last_metrics_mailbox_replaced = stats.replaced_before_consumption;
                                    (
                                        published as f64 / elapsed,
                                        consumed as f64 / elapsed,
                                        replaced as f64 / elapsed,
                                    )
                                })
                                .unwrap_or((0.0, 0.0, 0.0));
                        last_presented_frames = presented;
                        last_metrics_at = Instant::now();
                        Some(format!(
                            "D3D11 · {:.1} FPS · 解码 {:.1}/s · 消费 {:.1}/s · 覆盖 {:.1}/s · Present {} · 上传 {} · 重建 {} · 错误 {}",
                            fps, decoded_fps, consumed_fps, replaced_fps, presented, uploaded, recoveries, render_errors
                        ))
                    } else {
                        None
                    };

                    let updated = this.update(cx, |this, cx| {
                        let mut changed = false;
                        let mut next_fallback_mode = fallback_mode;
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
                        if let Some((sequence, width, height, result, conversion_elapsed)) =
                            completed_fallback
                        {
                            match result {
                                Ok(bytes) => {
                                    this.preview_image = Some(Arc::new(Image::from_bytes(
                                        ImageFormat::Bmp,
                                        bytes,
                                    )));
                                    this.preview_status = format!(
                                        "GPUI 图像回退（D3D11 不可用） · {width} × {height} · sequence {sequence}"
                                    );
                                    tracing::trace!(
                                        sequence,
                                        conversion_ms = conversion_elapsed.as_secs_f64() * 1000.0,
                                        "Published completed asynchronous fallback frame"
                                    );
                                    changed = true;
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        %error,
                                        sequence,
                                        "Could not convert failed native frame for GPUI fallback"
                                    );
                                }
                            }
                        }

                        if let Some((sequence, frame, mailbox_age)) = prepared_frame {
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
                            let native_present = match frame.as_ref() {
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
                                        frame.stride,
                                        &frame.data,
                                    )
                                }
                            };
                            let upload_elapsed = upload_started.elapsed();
                            let (display_path, used_fallback, conversion_elapsed) =
                                match native_present {
                                    Ok(()) => {
                                        // The native child surface owns the visible
                                        // image now; discard the previous GPUI bitmap.
                                        this.preview_image = None;
                                        next_fallback_mode = false;
                                        ("D3D11 原生预览", false, Duration::ZERO)
                                    }
                                    Err(error) => {
                                        crate::video_renderer::hide_native_video_surface();
                                        next_fallback_mode = true;
                                        tracing::debug!(
                                            %error,
                                            sequence,
                                            "D3D11 frame upload unavailable; scheduling bounded asynchronous GPUI fallback conversion"
                                        );
                                        if !fallback_conversion_in_flight
                                            .swap(true, Ordering::AcqRel)
                                        {
                                            let frame_for_conversion = frame.clone();
                                            let result_slot = fallback_conversion_result.clone();
                                            let in_flight = fallback_conversion_in_flight.clone();
                                            let cancel = worker_cancel.clone();
                                            let width_for_conversion = width;
                                            let height_for_conversion = height;
                                            let spawn = std::thread::Builder::new()
                                                .name("airplay-fallback-convert".to_owned())
                                                .spawn(move || {
                                                    // Avoid starting expensive CPU work if shutdown
                                                    // raced with thread scheduling.
                                                    if cancel.load(Ordering::Acquire) {
                                                        in_flight.store(false, Ordering::Release);
                                                        return;
                                                    }
                                                    let started = Instant::now();
                                                    let result = decoded_frame_to_bmp(
                                                        frame_for_conversion.as_ref(),
                                                    );
                                                    let elapsed = started.elapsed();
                                                    // Conversion itself is synchronous and cannot
                                                    // be interrupted, but a completed frame is never
                                                    // published once shutdown has been requested.
                                                    if !cancel.load(Ordering::Acquire) {
                                                        if let Ok(mut slot) = result_slot.lock() {
                                                            if !cancel.load(Ordering::Acquire) {
                                                                *slot = Some((
                                                                    sequence,
                                                                    width_for_conversion,
                                                                    height_for_conversion,
                                                                    result,
                                                                    elapsed,
                                                                ));
                                                            }
                                                        }
                                                    }
                                                    in_flight.store(false, Ordering::Release);
                                                });
                                            if let Err(error) = spawn {
                                                fallback_conversion_in_flight
                                                    .store(false, Ordering::Release);
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
                        next_fallback_mode
                    });
                    match updated {
                        Ok(next) => fallback_mode = next,
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
                .child(render_right_controls(cx)),
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
                .child(Label::new("蓝牙 HID 控制")),
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
                }),
        )
        .child(Label::new(if app.preview_status.is_empty() {
            "等待手机画面 · FairPlay 尚未配置，当前无法完成安全镜像"
        } else {
            app.preview_status.as_str()
        }))
}

fn render_right_controls(cx: &Context<PhoneControlApp>) -> impl IntoElement {
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
                .child(Label::new("输入文字并发送到手机…"))
                .child(
                    Button::new("keyboard-send-sample")
                        .primary()
                        .label("发送测试文字")
                        .on_click(|_, _, _| type_sample_ble()),
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
) -> Result<Vec<u8>, &'static str> {
    match frame {
        crate::airplay::DecodedVideoFrame::Bgra(frame) => bgra_frame_to_bmp(frame),
        crate::airplay::DecodedVideoFrame::Nv12(frame) => crate::airplay::Nv12Frame {
            width: frame.width,
            height: frame.height,
            y_stride: frame.stride,
            uv_stride: frame.stride,
            data: &frame.data,
        }
        .to_bgra()
        .map_err(|_| "NV12 fallback conversion failed")
        .and_then(|bgra| bgra_frame_to_bmp(&bgra)),
    }
}

#[cfg(windows)]
fn bgra_frame_to_bmp(frame: &crate::airplay::BgraFrame) -> Result<Vec<u8>, &'static str> {
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
