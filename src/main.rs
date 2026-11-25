#[cfg(windows)]
mod airplay;
mod app;
mod logging;

#[cfg(windows)]
mod platform;

#[cfg(windows)]
#[allow(dead_code)]
mod video_renderer;

use anyhow::Result;
use gpui_kit::*;

fn main() -> Result<()> {
    logging::startup_checkpoint("main: entered");
    logging::init_logging()?;
    logging::startup_checkpoint("main: logger ready");
    tracing::info!("Starting GPUI application");
    logging::startup_checkpoint("main: creating GPUI application");
    application().with_assets(assets::Assets).run(|cx| {
        logging::startup_checkpoint("gpui: run callback entered");
        init(cx);
        logging::startup_checkpoint("gpui: init completed");
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(1180.), px(760.)), cx)),
            ..Default::default()
        };
        logging::startup_checkpoint("gpui: opening window");
        open_window(options, cx, |_, cx| {
            logging::startup_checkpoint("window: entity factory entered");
            cx.new(|_| {
                logging::startup_checkpoint("window: PhoneControlApp constructed");
                app::PhoneControlApp::default()
            })
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
