//! Background worker that owns the Windows BLE HID controller for the desktop UI.
//!
//! Keeping WinRT GATT objects on one dedicated Tokio runtime avoids blocking the GPUI
//! event loop and keeps callback tasks alive while the UI is idle.

use std::{
    sync::{
        OnceLock,
        mpsc::{self, Sender},
    },
    thread,
};

use super::BleInputController;
use crate::input::MouseButtons;
use anyhow::{Context, Result};

#[derive(Debug)]
enum Command {
    Start,
    Stop,
    Move(i32, i32),
    LeftClick,
    Scroll(i32),
    TypeText(String),
}

static COMMANDS: OnceLock<Sender<Command>> = OnceLock::new();

fn sender() -> Result<&'static Sender<Command>> {
    if let Some(sender) = COMMANDS.get() {
        return Ok(sender);
    }

    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("ble-hid-controller".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!("Could not start BLE controller runtime: {error}");
                    return;
                }
            };

            let mut controller: Option<BleInputController> = None;
            while let Ok(command) = rx.recv() {
                let result: Result<()> = runtime.block_on(async {
                    match command {
                        Command::Start => {
                            if controller.is_some() {
                                tracing::info!("BLE HID controller is already running");
                                return Ok(());
                            }
                            let started = BleInputController::start()
                                .await
                                .context("starting BLE HID controller")?;
                            tracing::info!(
                                status = %started.advertising_status()?,
                                "BLE HID controller started; connect from iPhone AssistiveTouch"
                            );
                            controller = Some(started);
                        }
                        Command::Stop => {
                            if let Some(running) = controller.take() {
                                running.release_all().await?;
                                running.stop()?;
                                tracing::info!("BLE HID advertising stopped");
                            }
                        }
                        Command::Move(dx, dy) => {
                            active(&controller)?.move_mouse(dx, dy).await?;
                        }
                        Command::LeftClick => {
                            active(&controller)?.click(MouseButtons::LEFT).await?;
                        }
                        Command::Scroll(amount) => {
                            active(&controller)?.scroll(amount).await?;
                        }
                        Command::TypeText(value) => {
                            active(&controller)?.type_text(&value).await?;
                        }
                    }
                    Ok(())
                });

                if let Err(error) = result {
                    tracing::error!(error = %format!("{error:#}"), "BLE desktop command failed");
                }
            }

            if let Some(running) = controller {
                let _ = runtime.block_on(running.release_all());
                let _ = running.stop();
            }
        })
        .context("starting BLE controller worker thread")?;

    let _ = COMMANDS.set(tx);
    COMMANDS
        .get()
        .context("BLE command channel was not initialized")
}

fn active(controller: &Option<BleInputController>) -> Result<&BleInputController> {
    controller
        .as_ref()
        .context("BLE is not started; click Connect first")
}

fn send(command: Command) -> Result<()> {
    sender()?
        .send(command)
        .context("BLE controller worker is unavailable")
}

/// Start Windows BLE HID advertising. Connect the iPhone from AssistiveTouch.
pub fn start() -> Result<()> {
    sender()?.send(Command::Start).context("queue BLE start")
}

/// Stop advertising and release any held inputs.
pub fn stop() -> Result<()> {
    sender()?.send(Command::Stop).context("queue BLE stop")
}

/// Move the relative pointer by the requested number of HID units.
pub fn move_mouse(dx: i32, dy: i32) -> Result<()> {
    send(Command::Move(dx, dy))
}

/// Send a left mouse click.
pub fn left_click() -> Result<()> {
    send(Command::LeftClick)
}

/// Scroll vertically. Positive values scroll down; negative values scroll up.
pub fn scroll(amount: i32) -> Result<()> {
    send(Command::Scroll(amount))
}

/// Type basic ASCII text on the connected HID host.
////
//// The complete payload is validated by the controller before the first key is sent.
//// Keep the queue bounded so an accidental huge paste cannot monopolize the worker.
pub fn type_text(text: impl Into<String>) -> Result<()> {
    let text = text.into();
    if text.chars().count() > 512 {
        anyhow::bail!("BLE text input is limited to 512 characters per command");
    }
    send(Command::TypeText(text))
}

/// Type a short basic ASCII sample string.
pub fn type_sample() -> Result<()> {
    type_text("BLE OK")
}
