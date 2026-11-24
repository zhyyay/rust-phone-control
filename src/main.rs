#[cfg(windows)]
mod airplay;
mod app;
mod logging;

#[cfg(windows)]
mod platform;

use anyhow::Result;
use gpui_kit::*;

fn main() -> Result<()> {
    logging::init_logging()?;
    tracing::info!("Starting GPUI application");
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
    tracing::info!("GPUI application event loop returned; beginning process shutdown");
    #[cfg(windows)]
    {
        tracing::info!("Process shutdown: stopping AirPlay receiver");
        if let Err(error) = airplay::stop() {
            tracing::warn!(error = %format!("{error:#}"), "Could not stop AirPlay receiver during shutdown");
        }
        tracing::info!("Process shutdown: AirPlay receiver stop completed");
    }
    Ok(())
}
