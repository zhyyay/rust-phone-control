use gpui_kit::component::ActiveTheme as _;
use gpui_kit::component::{
    button::{Button, ButtonVariants},
    label::Label,
};
use gpui_kit::*;

#[derive(Default)]
pub struct PhoneControlApp;

impl Render for PhoneControlApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .size_full()
            .p_6()
            .gap_4()
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
            .child(Label::new("iPhone wireless input control"))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("1. Bluetooth connection"))
                    .child(Label::new(
                        "Start BLE advertising, then on iPhone open Settings → Accessibility → Touch → AssistiveTouch → Devices → Bluetooth Devices and connect to danna.",
                    ))
                    .child(Label::new(
                        "The app starts the HID service on this PC. Keep this app open while controlling the phone.",
                    ))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("ble-start")
                                    .primary()
                                    .label("Start / Connect")
                                    .on_click(|_, _, _| start_ble()),
                            )
                            .child(
                                Button::new("ble-stop")
                                    .label("Disconnect / Stop")
                                    .on_click(|_, _, _| stop_ble()),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("2. Mouse"))
                    .child(Label::new(
                        "Use the direction buttons for small relative movements. These are pointer movements, not absolute touchscreen taps.",
                    ))
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
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("3. Keyboard"))
                    .child(Label::new(
                        "Send a short ASCII test string to the focused text field on iPhone.",
                    ))
                    .child(
                        Button::new("keyboard-test")
                            .primary()
                            .label("Type BLE OK")
                            .on_click(|_, _, _| type_sample_ble()),
                    ),
            )
            .child(Label::new(
                "Tip: start advertising first, connect the iPhone in AssistiveTouch, then use the controls above. Check logs/app.log for command errors.",
            ))
    }
}

fn move_button(id: &'static str, label: &'static str, dx: i32, dy: i32) -> impl IntoElement {
    Button::new(id)
        .label(label)
        .on_click(move |_, _, _| move_ble(dx, dy))
}

#[cfg(windows)]
fn start_ble() {
    queue_ble(crate::input::ble::desktop::start());
}

#[cfg(not(windows))]
fn start_ble() {
    tracing::warn!("BLE HID desktop controls are only available on Windows");
}

#[cfg(windows)]
fn stop_ble() {
    queue_ble(crate::input::ble::desktop::stop());
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
    queue_ble(crate::input::ble::desktop::move_mouse(dx, dy));
}
#[cfg(not(windows))]
fn move_ble(_: i32, _: i32) {}

#[cfg(windows)]
fn left_click_ble() {
    queue_ble(crate::input::ble::desktop::left_click());
}
#[cfg(not(windows))]
fn left_click_ble() {}

#[cfg(windows)]
fn scroll_ble(amount: i32) {
    queue_ble(crate::input::ble::desktop::scroll(amount));
}
#[cfg(not(windows))]
fn scroll_ble(_: i32) {}

#[cfg(windows)]
fn type_sample_ble() {
    queue_ble(crate::input::ble::desktop::type_sample());
}
#[cfg(not(windows))]
fn type_sample_ble() {}
