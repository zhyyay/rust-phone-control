use gpui_kit::component::{
    button::{Button, ButtonVariants},
    label::Label,
};
use gpui_kit::*;

#[cfg(windows)]
use std::{sync::Arc, time::Duration};

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
    #[cfg(windows)]
    frame_poll_task: Option<Task<()>>,
    #[cfg(windows)]
    quit_subscription: Option<Subscription>,
}

impl Drop for PhoneControlApp {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            tracing::info!("PhoneControlApp teardown: begin");
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
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        crate::logging::startup_checkpoint("render: entered");
        #[cfg(windows)]
        crate::logging::startup_checkpoint("render: before quit subscription");
        #[cfg(windows)]
        if self.quit_subscription.is_none() {
            tracing::debug!(
                "Registering GPUI application-quit cleanup for AirPlay preview resources"
            );
            self.quit_subscription = Some(cx.on_app_quit(|this, _cx| {
                tracing::info!("GPUI application-quit cleanup: begin");
                // Move owned resources out while the model borrow is active;
                // the returned future must not retain GPUI's borrowed model.
                let task = this.frame_poll_task.take();
                let image = this.preview_image.take();
                async move {
                    if let Some(task) = task {
                        tracing::debug!(
                            "GPUI application-quit cleanup: cancelling frame poll task"
                        );
                        drop(task);
                        tracing::debug!("GPUI application-quit cleanup: frame poll task cancelled");
                    }
                    if let Some(image) = image {
                        tracing::debug!("GPUI application-quit cleanup: releasing preview image");
                        drop(image);
                        tracing::debug!("GPUI application-quit cleanup: preview image released");
                    }
                    tracing::info!("GPUI application-quit cleanup: complete");
                }
            }));
            crate::logging::startup_checkpoint("render: quit subscription registered");
        }
        #[cfg(windows)]
        crate::logging::startup_checkpoint("render: after quit subscription");

        #[cfg(windows)]
        if self.frame_poll_task.is_none() {
            tracing::debug!("Starting GPUI AirPlay frame and device-state poll task");
            crate::logging::startup_checkpoint("render: before frame poll spawn");
            self.frame_poll_task = Some(cx.spawn(async move |this, cx| {
                let mut pairing_refresh_ticks = 0u8;
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(33))
                        .await;

                    // Video preview remains responsive at ~30 FPS, while the
                    // DPAPI-backed pairing registry is refreshed only twice
                    // per second instead of being read on every frame tick.
                    pairing_refresh_ticks = pairing_refresh_ticks.wrapping_add(1);
                    let refresh_pairing = pairing_refresh_ticks >= 15;
                    if refresh_pairing {
                        pairing_refresh_ticks = 0;
                    }

                    let updated = this.update(cx, |this, cx| {
                        let mut changed = false;
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
                        match crate::airplay::take_latest_video_frame() {
                            Ok(Some(snapshot)) => match bgra_frame_to_bmp(&snapshot.frame) {
                                Ok(bytes) => {
                                    this.preview_status = format!(
                                        "Frame {} × {} · sequence {}",
                                        snapshot.frame.width,
                                        snapshot.frame.height,
                                        snapshot.sequence
                                    );
                                    this.preview_image = Some(Arc::new(Image::from_bytes(
                                        ImageFormat::Bmp,
                                        bytes,
                                    )));
                                    changed = true;
                                }
                                Err(error) => {
                                    tracing::warn!(%error, "Could not prepare decoded frame for GPUI");
                                }
                            },
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(%error, "Could not read decoded AirPlay frame");
                            }
                        }
                        if changed {
                            cx.notify();
                        }
                    });
                    if updated.is_err() {
                        tracing::debug!("Stopping GPUI AirPlay poll task because its app entity is no longer available");
                        break;
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
                        "● 已连接 · AirPlay"
                    } else {
                        "● 等待连接"
                    }))
                    .child(Label::new("⚙"))
}

fn render_workspace(
    app: &PhoneControlApp,
    cx: &Context<PhoneControlApp>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_1()
        .gap_2()
        .child(render_left_sidebar(app, cx))
        .child(render_preview_column(app, cx))
        .child(render_right_controls(cx))
}

fn render_left_sidebar(
    app: &PhoneControlApp,
    cx: &Context<PhoneControlApp>,
) -> impl IntoElement {
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
                                    .on_click(|_, _, _| {
                                        tracing::info!("Connect-new-device entry selected")
                                    }),
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
                                    .child(Label::new(
                                        if app.airplay_status.contains("Running") {
                                            "投屏中 · AirPlay"
                                        } else {
                                            "等待连接"
                                        },
                                    )),
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
                                            .label("无线")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.airplay_status = start_airplay_status();
                                                cx.notify();
                                            })),
                                    )
                                    .child(Button::new("connection-usb").label("USB").on_click(
                                        |_, _, _| {
                                            tracing::info!("USB transport adapter is not wired yet")
                                        },
                                    ))
                                    .child(Button::new("connection-qr").label("扫码").on_click(
                                        |_, _, _| tracing::info!("QR pairing entry selected"),
                                    )),
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
                                    .child(Label::new("存储  —"))
}

fn render_preview_column(
    app: &PhoneControlApp,
    cx: &Context<PhoneControlApp>,
) -> impl IntoElement {
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .gap_2()
                            .rounded_lg()
                            .bg(gpui_kit::rgb(0xFFFFFF))
                            .border_1()
                            .border_color(gpui_kit::rgb(0xE1E5ED))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .gap_2()
                                    .p_2()
                                    .child(Button::new("mirror-refresh").label("⟳").on_click(
                                        cx.listener(|this, _, _, cx| {
                                            this.airplay_status = start_airplay_status();
                                            cx.notify();
                                        }),
                                    ))
                                    .child(Button::new("mirror-screenshot").label("▣").on_click(
                                        |_, _, _| tracing::info!("Screenshot action requested"),
                                    ))
                                    .child(
                                        Button::new("mirror-start").primary().label("●").on_click(
                                            cx.listener(|this, _, _, cx| {
                                                this.airplay_status = start_airplay_status();
                                                cx.notify();
                                            }),
                                        ),
                                    )
                                    .child(Button::new("mirror-stop").label("Ⅱ").on_click(
                                        cx.listener(|this, _, _, cx| {
                                            this.airplay_status = stop_airplay_status();
                                            cx.notify();
                                        }),
                                    ))
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
                                    .child(preview_panel_for_app(app)),
                            )
                            .child(Label::new(if app.preview_status.is_empty() {
                                "等待手机画面 · AirPlay"
                            } else {
                                app.preview_status.as_str()
                            }))
                            .child(pending_airplay_approval_panel(app, cx))
}

fn render_right_controls(
    cx: &Context<PhoneControlApp>,
) -> impl IntoElement {
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
        .child(Label::new("AirPlay device authorization"));

    if let Some(fingerprint) = app.pending_airplay_controller.as_ref() {
        panel = panel
            .child(Label::new("A new iPhone has completed identity verification and is waiting for your approval."))
            .child(Label::new(format!("Device key fingerprint: {fingerprint}")))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("airplay-approve-controller")
                            .primary()
                            .label("Allow this device")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.airplay_approval_status =
                                    match crate::airplay::approve_pending_controller() {
                                        Ok(true) => "Device approved. It can reconnect automatically.".into(),
                                        Ok(false) => "No pending device to approve.".into(),
                                        Err(error) => format!("Approval failed: {error}"),
                                    };
                                tracing::info!(status = %this.airplay_approval_status, "AirPlay approval action");
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("airplay-reject-controller")
                            .label("Reject")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.airplay_approval_status =
                                    match crate::airplay::reject_pending_controller() {
                                        Ok(true) => "Device blocked. It cannot reconnect until you clear the denial.".into(),
                                        Ok(false) => "No pending device to reject.".into(),
                                        Err(error) => format!("Could not block device: {error}"),
                                    };
                                tracing::info!(status = %this.airplay_approval_status, "AirPlay rejection action");
                                cx.notify();
                            })),
                    ),
            );
    } else {
        panel = panel.child(Label::new("No new device is waiting for authorization."));
    }

    panel = panel.child(Label::new("Approved devices"));
    if app.trusted_airplay_controllers.is_empty() {
        panel = panel.child(Label::new("No approved devices."));
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
                                .label("Revoke")
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

    panel = panel.child(Label::new("Blocked devices"));
    if app.denied_airplay_controllers.is_empty() {
        panel = panel.child(Label::new("No blocked devices."));
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
    Label::new("AirPlay device authorization is available on Windows")
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
            "Running · TCP 7000 · AirPlay + RAOP discovery queued".to_owned()
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
