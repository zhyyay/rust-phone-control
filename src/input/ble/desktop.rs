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
use crate::input::{InputEvent, MouseButtons};
use anyhow::{Context, Result};

#[derive(Debug)]
enum Command {
    Start,
    Stop,
    Dispatch(InputEvent),
    LeftClick,
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
                        Command::Dispatch(event) => {
                            active(&controller)?.dispatch(event).await?;
                        }
                        Command::LeftClick => {
                            let active = active(&controller)?;
                            active
                                .dispatch(InputEvent::PointerButtons(MouseButtons::LEFT))
                                .await?;
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            active
                                .dispatch(InputEvent::PointerButtons(MouseButtons::NONE))
                                .await?;
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
    let mut remaining_x = dx;
    let mut remaining_y = dy;
    while remaining_x != 0 || remaining_y != 0 {
        let step_x = remaining_x.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        let step_y = remaining_y.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        dispatch_event(InputEvent::PointerMove {
            dx: step_x,
            dy: step_y,
        })?;
        remaining_x -= step_x as i32;
        remaining_y -= step_y as i32;
    }
    Ok(())
}

/// Queue one platform-independent HID input event for the active BLE controller.
pub fn dispatch_event(event: InputEvent) -> Result<()> {
    send(Command::Dispatch(event))
}

/// Press or release the requested keyboard modifier keys.
pub fn set_key_modifiers(modifiers: crate::input::KeyModifiers) -> Result<()> {
    dispatch_event(InputEvent::KeyModifiers(modifiers))
}

/// Tap one USB HID keyboard usage, preserving currently held modifiers.
pub fn tap_key_usage(usage: u8) -> Result<()> {
    dispatch_event(InputEvent::KeyUsage(usage))
}

/// Release every held mouse button and keyboard key.
pub fn release_all_inputs() -> Result<()> {
    dispatch_event(InputEvent::ReleaseAll)
}

/// Send a left mouse click.
pub fn left_click() -> Result<()> {
    send(Command::LeftClick)
}

/// Scroll vertically. Positive values scroll down; negative values scroll up.
pub fn scroll(amount: i32) -> Result<()> {
    let mut remaining = amount;
    while remaining != 0 {
        let step = remaining.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        dispatch_event(InputEvent::Scroll { vertical: step })?;
        remaining -= step as i32;
    }
    Ok(())
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
