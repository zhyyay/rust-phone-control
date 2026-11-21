#[cfg(windows)]
mod airplay;
mod app;
mod logging;

use anyhow::Result;
use gpui_kit::*;

fn main() -> Result<()> {
    logging::init_logging()?;
    application().with_assets(assets::Assets).run(|cx| {
        init(cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(680.), px(700.)), cx)),
            ..Default::default()
        };
        open_window(options, cx, |_, cx| {
            cx.new(|_| app::PhoneControlApp::default())
        })
        .expect("failed to open Rust Phone Control window");
    });
    Ok(())
}
