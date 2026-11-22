use gpui_kit::component::ActiveTheme as _;
use gpui_kit::component::{
    button::{Button, ButtonVariants},
    label::Label,
};
use gpui_kit::*;

#[derive(Default)]
pub struct PhoneControlApp {
    airplay_status: String,
}

impl Render for PhoneControlApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
            .child(Label::new("AirPlay RTSP SETUP and UDP media reception · decryption, frame decoding, and video rendering are not implemented."))
    }
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
            "Running · TCP 7000 · mDNS published".to_owned()
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
