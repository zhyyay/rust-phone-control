use gpui_kit::component::ActiveTheme as _;
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
    airplay_approval_status: String,
    #[cfg(windows)]
    preview_image: Option<Arc<Image>>,
    #[cfg(windows)]
    preview_status: String,
    #[cfg(windows)]
    frame_poll_task: Option<Task<()>>,
}

impl Render for PhoneControlApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        #[cfg(windows)]
        if self.frame_poll_task.is_none() {
            self.frame_poll_task = Some(cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(33))
                        .await;
                    let updated = this.update(cx, |this, cx| {
                        let pending = crate::airplay::pending_controller_approval();
                        let trusted = crate::airplay::trusted_controller_fingerprints()
                            .unwrap_or_default();
                        let mut changed = false;
                        if this.pending_airplay_controller != pending {
                            this.pending_airplay_controller = pending;
                            changed = true;
                        }
                        if this.trusted_airplay_controllers != trusted {
                            this.trusted_airplay_controllers = trusted;
                            changed = true;
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
                        break;
                    }
                }
            }));
        }

        div()
            .flex()
            .flex_col()
            .size_full()
            .p_3()
            .gap_2()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(Label::new("Rust Phone Control"))
                    .child(Label::new("Phase 1 · BLE HID")),
            )
            .child(Label::new("iPhone wireless control"))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .p_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("AirPlay screen mirror"))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(Label::new(airplay_pairing_code_label()))
                            .child(
                                Button::new("airplay-copy-code")
                                    .label("Copy code")
                                    .on_click(|_, _, cx| copy_airplay_pairing_code(cx)),
                            ),
                    )
                    .child(
                        Button::new("airplay-start")
                            .primary()
                            .label("Start mirror")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.airplay_status = start_airplay_status();
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("airplay-stop")
                            .label("Stop mirror")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.airplay_status = stop_airplay_status();
                                cx.notify();
                            })),
                    )
                    .child(Label::new(if self.airplay_status.is_empty() {
                        "AirPlay status: stopped".to_owned()
                    } else {
                        format!("AirPlay status: {}", self.airplay_status)
                    })),
            )
            .child(pending_airplay_approval_panel(self))
            .child(preview_panel_for_app(self))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("Bluetooth · connect iPhone AssistiveTouch to danna"))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("ble-start")
                                    .primary()
                                    .label("Start BLE")
                                    .on_click(|_, _, _| start_ble()),
                            )
                            .child(
                                Button::new("ble-stop")
                                    .label("Stop BLE")
                                    .on_click(|_, _, _| stop_ble()),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("Mouse · relative pointer movement"))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(move_button("mouse-up", "↑", 0, -35))
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(move_button("mouse-left", "←", -35, 0))
                            .child(move_button("mouse-down", "↓", 0, 35))
                            .child(move_button("mouse-right", "→", 35, 0))
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("mouse-click")
                                    .primary()
                                    .label("Left click")
                                    .on_click(|_, _, _| left_click_ble()),
                            )
                            .child(
                                Button::new("mouse-scroll-up")
                                    .label("Scroll up")
                                    .on_click(|_, _, _| scroll_ble(-3)),
                            )
                            .child(
                                Button::new("mouse-scroll-down")
                                    .label("Scroll down")
                                    .on_click(|_, _, _| scroll_ble(3)),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("Keyboard · type into the focused iPhone field"))
                    .child(
                        Button::new("keyboard-test")
                            .primary()
                            .label("Type BLE OK")
                            .on_click(|_, _, _| type_sample_ble()),
                    ),
            )
            .child(Label::new("AirPlay discovery and RTSP control · waiting for FairPlay media-key recovery before video packets can be decrypted and decoded into the preview."))
    }
}

#[cfg(windows)]
fn pending_airplay_approval_panel(app: &PhoneControlApp) -> impl IntoElement {
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
                            .on_click(|_, _, _| {
                                match crate::airplay::approve_pending_controller() {
                                    Ok(true) => tracing::info!("AirPlay device approval saved"),
                                    Ok(false) => tracing::warn!("No pending AirPlay device to approve"),
                                    Err(error) => tracing::error!(%error, "Could not approve AirPlay device"),
                                }
                            }),
                    )
                    .child(
                        Button::new("airplay-reject-controller")
                            .label("Reject")
                            .on_click(|_, _, _| {
                                match crate::airplay::reject_pending_controller() {
                                    Ok(true) => tracing::info!("AirPlay device denial saved"),
                                    Ok(false) => tracing::warn!("No pending AirPlay device to reject"),
                                    Err(error) => tracing::error!(%error, "Could not persist AirPlay device denial"),
                                }
                            }),
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
            panel = panel.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(Label::new(fingerprint.clone()))
                    .child(
                        Button::new(format!("airplay-revoke-controller-{index}"))
                            .label("Revoke")
                            .on_click(move |_, _, _| {
                                match crate::airplay::revoke_trusted_controller(&target) {
                                    Ok(true) => tracing::info!(
                                        fingerprint = %target,
                                        "AirPlay controller authorization revoked"
                                    ),
                                    Ok(false) => tracing::warn!(
                                        fingerprint = %target,
                                        "AirPlay controller authorization was already absent"
                                    ),
                                    Err(error) => tracing::error!(
                                        fingerprint = %target,
                                        %error,
                                        "Could not revoke AirPlay controller authorization"
                                    ),
                                }
                            }),
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
fn pending_airplay_approval_panel(_: &PhoneControlApp) -> impl IntoElement {
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
    let mut panel = div()
        .flex()
        .flex_col()
        .gap_2()
        .p_2()
        .rounded_lg()
        .border_1()
        .border_color(gpui_kit::rgb(0x555555))
        .child(Label::new("AirPlay live preview"));

    let surface = if let Some(image) = image {
        div()
            .w_full()
            .h(px(360.))
            .child(img(image).w_full().h_full().object_fit(ObjectFit::Contain))
    } else {
        div()
            .w_full()
            .h(px(180.))
            .flex()
            .items_center()
            .justify_center()
            .child(Label::new(if status.is_empty() {
                "Waiting for decoded video frames".to_owned()
            } else {
                status
            }))
    };
    panel = panel.child(surface);
    panel
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
