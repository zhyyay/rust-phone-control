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
                    .child(Label::new("Phase 1 · Foundation")),
            )
            .child(Label::new("iPhone wireless automation workbench"))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(Label::new("Device connection"))
                    .child(Label::new("Configure your iPhone LAN address and start iCTRL Runner."))
                    .child(Label::new("Default iCTRL port: 8200 · Remote Access must be enabled on the phone.")),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("docs")
                            .primary()
                            .label("Connection instructions")
                            .on_click(|_, _, _| println!("See docs/DEVELOPMENT.md for iCTRL setup.")),
                    )
                    .child(
                        Button::new("probe")
                            .label("Probe from terminal")
                            .on_click(|_, _, _| println!("Run: cargo run --bin ictrl-probe -- http://PHONE-IP:8200")),
                    ),
            )
            .child(Label::new(
                "Security: no plaintext control commands are sent. Pairing and encrypted RPC must follow the official iCTRL protocol.",
            ))
    }
}
