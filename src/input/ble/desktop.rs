//! Background worker that owns the Windows BLE HID controller for the desktop UI.
//!
//! Keeping WinRT GATT objects on one dedicated Tokio runtime avoids blocking the GPUI
//! event loop and keeps callback tasks alive while the UI is idle.

use std::{
    collections::VecDeque,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU8, AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use super::BleInputController;
use crate::input::{InputEvent, MouseButtons};
use anyhow::{Context, Result};

#[derive(Debug)]
enum Command {
    Start,
    Stop,
    ReleaseAll(u64),
    PointerMove(u64),
    Dispatch(InputEvent, u64),
    LeftClick(u64),
    TypeText(String, u64),
}

struct WorkerSenders {
    normal: SyncSender<Command>,
    control: SyncSender<Command>,
}

#[derive(Debug)]
struct PointerMoveBatch {
    id: u64,
    generation: u64,
    dx: i64,
    dy: i64,
}

#[derive(Default)]
struct PointerMoveQueue {
    next_id: u64,
    open_batch: Option<u64>,
    batches: VecDeque<PointerMoveBatch>,
}

static POINTER_MOVES: OnceLock<Mutex<PointerMoveQueue>> = OnceLock::new();

fn pointer_moves() -> &'static Mutex<PointerMoveQueue> {
    POINTER_MOVES.get_or_init(|| Mutex::new(PointerMoveQueue::default()))
}

static COMMANDS: OnceLock<std::sync::Mutex<Option<WorkerSenders>>> = OnceLock::new();
const COMMAND_QUEUE_CAPACITY: usize = 256;
const CONTROL_QUEUE_CAPACITY: usize = 8;
// Bound coalesced motion backlog to roughly 17 signed-7-bit HID reports per axis.
const POINTER_MOVE_BATCH_LIMIT: i64 = 2_048;
static CONNECTION_STATE: AtomicU8 = AtomicU8::new(0);
static SUBSCRIPTION_GENERATION: AtomicU64 = AtomicU64::new(0);
static WORKER_STATE: AtomicU8 = AtomicU8::new(0);

const WORKER_STOPPED: u8 = 0;
const WORKER_STARTING: u8 = 1;
const WORKER_ADVERTISING: u8 = 2;
const WORKER_STOPPING: u8 = 3;
const WORKER_ERROR: u8 = 4;

/// Returns the latest BLE worker lifecycle state for the desktop status panel.
pub fn lifecycle_status() -> &'static str {
    match WORKER_STATE.load(Ordering::Acquire) {
        WORKER_STARTING => "蓝牙正在启动",
        WORKER_ADVERTISING => "蓝牙广播中，等待 iPhone HID 订阅",
        WORKER_STOPPING => "蓝牙正在停止",
        WORKER_ERROR => "蓝牙操作失败，请查看日志后重试",
        _ => "蓝牙已停止",
    }
}

fn publish_connection_state(controller: &Option<BleInputController>) {
    let generation = controller
        .as_ref()
        .map(BleInputController::subscription_generation)
        .unwrap_or(0);
    SUBSCRIPTION_GENERATION.store(generation, Ordering::Release);
    let state = controller
        .as_ref()
        .map(BleInputController::connection_state)
        .unwrap_or(super::BleConnectionState::Disconnected);
    let encoded = match state {
        super::BleConnectionState::Disconnected => 0,
        super::BleConnectionState::PartiallySubscribed => 1,
        super::BleConnectionState::Suspended => 2,
        super::BleConnectionState::Ready => 3,
    };
    CONNECTION_STATE.store(encoded, Ordering::Release);
}

/// Returns the most recently observed HID report subscription generation.
/// The native preview uses this to discard per-connection pointer and wheel state.
pub fn subscription_generation() -> u64 {
    SUBSCRIPTION_GENERATION.load(Ordering::Acquire)
}

/// Returns the most recently observed HID report subscription state without blocking the UI.
pub fn connection_state() -> super::BleConnectionState {
    match CONNECTION_STATE.load(Ordering::Acquire) {
        1 => super::BleConnectionState::PartiallySubscribed,
        2 => super::BleConnectionState::Suspended,
        3 => super::BleConnectionState::Ready,
        _ => super::BleConnectionState::Disconnected,
    }
}

fn command_sender() -> &'static std::sync::Mutex<Option<WorkerSenders>> {
    COMMANDS.get_or_init(|| std::sync::Mutex::new(None))
}

fn spawn_worker() -> Result<WorkerSenders> {
    let (tx, rx) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
    let (control_tx, control_rx) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<std::result::Result<(), String>>(1);
    let worker = thread::Builder::new()
        .name("ble-hid-controller".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let message = error.to_string();
                    let _ = ready_tx.send(Err(message.clone()));
                    tracing::error!("Could not start BLE controller runtime: {message}");
                    return;
                }
            };

            if ready_tx.send(Ok(())).is_err() {
                return;
            }

            let mut controller: Option<BleInputController> = None;
            publish_connection_state(&controller);
            loop {
                // Control commands use a separate reserved channel and are checked first,
                // so Stop and ReleaseAll are not trapped behind pointer-motion traffic.
                let command = match control_rx.try_recv() {
                    Ok(command) => command,
                    Err(mpsc::TryRecvError::Disconnected | mpsc::TryRecvError::Empty) => {
                        match rx.recv_timeout(Duration::from_millis(20)) {
                            Ok(command) => command,
                            Err(RecvTimeoutError::Timeout) => {
                                publish_connection_state(&controller);
                                continue;
                            }
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                };
                // Refresh the generation immediately before consuming a queued command.
                // Commands tagged by an earlier HID subscription must never leak into a
                // newly connected phone.
                publish_connection_state(&controller);
                let result: Result<()> = runtime.block_on(async {
                    match command {
                        Command::Start => {
                            if controller.is_some() {
                                WORKER_STATE.store(WORKER_ADVERTISING, Ordering::Release);
                                tracing::info!("BLE HID controller is already running");
                                return Ok(());
                            }
                            WORKER_STATE.store(WORKER_STARTING, Ordering::Release);
                            let started = match BleInputController::start().await {
                                Ok(started) => started,
                                Err(error) => {
                                    WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                                    return Err(error).context("starting BLE HID controller");
                                }
                            };
                            let status = match started.advertising_status() {
                                Ok(status) => status,
                                Err(error) => {
                                    WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                                    return Err(error).context("reading BLE advertising status after start");
                                }
                            };
                            controller = Some(started);
                            WORKER_STATE.store(WORKER_ADVERTISING, Ordering::Release);
                            tracing::info!(
                                status = %status,
                                "BLE HID controller started; connect from iPhone AssistiveTouch"
                            );
                        }
                        Command::ReleaseAll(expected_generation) => {
                            if let Some(running) = controller.as_ref() {
                                if running.subscription_generation() == expected_generation {
                                    running.release_all().await?;
                                } else {
                                    tracing::debug!(expected_generation, actual_generation = running.subscription_generation(), "Discarded stale BLE release command");
                                }
                            }
                        }
                        Command::Stop => {
                            WORKER_STATE.store(WORKER_STOPPING, Ordering::Release);
                            if let Some(running) = controller.take() {
                                let release_result = running
                                    .release_all()
                                    .await
                                    .context("releasing BLE inputs before stop");
                                let stop_result =
                                    running.stop().context("stopping BLE HID advertising");

                                match (release_result, stop_result) {
                                    (Ok(()), Ok(())) => {
                                        tracing::info!("BLE HID advertising stopped");
                                        WORKER_STATE.store(WORKER_STOPPED, Ordering::Release);
                                    }
                                    (Err(release_error), Ok(())) => {
                                        WORKER_STATE.store(WORKER_STOPPED, Ordering::Release);
                                        return Err(release_error);
                                    }
                                    (Ok(()), Err(stop_error)) => {
                                        WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                                        return Err(stop_error);
                                    }
                                    (Err(release_error), Err(stop_error)) => {
                                        WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                                        return Err(anyhow::anyhow!(
                                            "{release_error:#}; BLE stop also failed: {stop_error:#}"
                                        ));
                                    }
                                }
                            } else {
                                WORKER_STATE.store(WORKER_STOPPED, Ordering::Release);
                            }

                            // Stop is prioritized over normal input. Drop anything that
                            // accumulated behind it so a rapid restart cannot replay old input.
                            let discarded = discard_pending_commands(&rx);
                            clear_pointer_moves();
                            if discarded > 0 {
                                tracing::debug!(
                                    discarded,
                                    "Discarded queued BLE input commands after stop"
                                );
                            }
                        }
                        Command::PointerMove(batch_id) => {
                            if let Some(batch) = take_pointer_move(batch_id) {
                                let running = active(&controller)?;
                                if running.subscription_generation() == batch.generation {
                                    let (mut dx, mut dy) = (batch.dx, batch.dy);
                                    while dx != 0 || dy != 0 {
                                        let step_x = dx.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
                                        let step_y = dy.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
                                        running.dispatch(InputEvent::PointerMove { dx: step_x, dy: step_y }).await?;
                                        dx -= step_x as i64;
                                        dy -= step_y as i64;
                                    }
                                } else {
                                    tracing::debug!(expected_generation = batch.generation, actual_generation = running.subscription_generation(), "Discarded stale coalesced BLE pointer movement");
                                }
                            }
                        }
                        Command::Dispatch(event, expected_generation) => {
                            let running = active(&controller)?;
                            if running.subscription_generation() == expected_generation {
                                running.dispatch(event).await?;
                            } else {
                                tracing::debug!(expected_generation, actual_generation = running.subscription_generation(), "Discarded stale BLE input command");
                            }
                        }
                        Command::LeftClick(expected_generation) => {
                            let running = active(&controller)?;
                            if running.subscription_generation() == expected_generation {
                                running.click(MouseButtons::LEFT).await?;
                            } else {
                                tracing::debug!(expected_generation, actual_generation = running.subscription_generation(), "Discarded stale BLE click command");
                            }
                        }
                        Command::TypeText(value, expected_generation) => {
                            let running = active(&controller)?;
                            if running.subscription_generation() == expected_generation {
                                running.type_text_for_generation(&value, expected_generation).await?;
                            } else {
                                tracing::debug!(expected_generation, actual_generation = running.subscription_generation(), "Discarded stale BLE text command");
                            }
                        }
                    }
                    Ok(())
                });

                publish_connection_state(&controller);
                if let Err(error) = result {
                    tracing::error!(error = %format!("{error:#}"), "BLE desktop command failed");
                    if let Some(active) = controller.as_ref() {
                        if let Err(release_error) =
                            runtime.block_on(active.dispatch(InputEvent::ReleaseAll))
                        {
                            tracing::error!(
                                error = %format!("{release_error:#}"),
                                "Could not release BLE inputs after command failure"
                            );
                        }
                    }
                }
            }

            if let Some(running) = controller {
                if let Err(error) = runtime.block_on(running.release_all()) {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "Could not release BLE inputs while shutting down worker"
                    );
                }
                if let Err(error) = running.stop() {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "Could not stop BLE advertising while shutting down worker"
                    );
                }
            }
            publish_connection_state(&None);
            WORKER_STATE.store(WORKER_STOPPED, Ordering::Release);
        })
        .context("starting BLE controller worker thread")?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(WorkerSenders {
            normal: tx,
            control: control_tx,
        }),
        Ok(Err(error)) => {
            let _ = worker.join();
            Err(anyhow::anyhow!(
                "BLE controller worker could not initialize its Tokio runtime: {error}"
            ))
        }
        Err(error) => {
            let _ = worker.join();
            Err(error).context("BLE controller worker exited before initialization")
        }
    }
}

fn take_pointer_move(batch_id: u64) -> Option<PointerMoveBatch> {
    let mut queue = pointer_moves()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let index = queue
        .batches
        .iter()
        .position(|batch| batch.id == batch_id)?;
    let batch = queue.batches.remove(index);
    if queue.open_batch == Some(batch_id) {
        queue.open_batch = None;
    }
    batch
}

fn clear_pointer_move_queue(queue: &mut PointerMoveQueue) {
    queue.open_batch = None;
    queue.batches.clear();
}

fn clear_pointer_moves() {
    let mut queue = pointer_moves()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_pointer_move_queue(&mut queue);
}

fn discard_pending_commands(receiver: &mpsc::Receiver<Command>) -> usize {
    let mut discarded = 0;
    while receiver.try_recv().is_ok() {
        discarded += 1;
    }
    discarded
}

fn accumulate_pointer_move(batch: &mut PointerMoveBatch, dx: i16, dy: i16) {
    batch.dx = batch
        .dx
        .saturating_add(dx as i64)
        .clamp(-POINTER_MOVE_BATCH_LIMIT, POINTER_MOVE_BATCH_LIMIT);
    batch.dy = batch
        .dy
        .saturating_add(dy as i64)
        .clamp(-POINTER_MOVE_BATCH_LIMIT, POINTER_MOVE_BATCH_LIMIT);
}

fn queue_pointer_move(dx: i16, dy: i16) -> Result<()> {
    let generation = SUBSCRIPTION_GENERATION.load(Ordering::Acquire);
    let mut queue = pointer_moves()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(open_id) = queue.open_batch
        && let Some(batch) = queue.batches.iter_mut().find(|batch| batch.id == open_id)
        && batch.generation == generation
    {
        accumulate_pointer_move(batch, dx, dy);
        return Ok(());
    }

    queue.next_id = queue.next_id.wrapping_add(1).max(1);
    let id = queue.next_id;
    queue.batches.push_back(PointerMoveBatch {
        id,
        generation,
        dx: dx as i64,
        dy: dy as i64,
    });
    queue.open_batch = Some(id);

    if let Err(error) = send(Command::PointerMove(id)) {
        queue.batches.retain(|batch| batch.id != id);
        if queue.open_batch == Some(id) {
            queue.open_batch = None;
        }
        return Err(error);
    }
    Ok(())
}

fn active(controller: &Option<BleInputController>) -> Result<&BleInputController> {
    controller
        .as_ref()
        .context("BLE is not started; click Connect first")
}

fn send_to_worker(
    sender: &WorkerSenders,
    command: Command,
) -> std::result::Result<(), TrySendError<Command>> {
    if is_control_command(&command) {
        sender.control.try_send(command)
    } else {
        sender.normal.try_send(command)
    }
}

fn is_control_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Start | Command::Stop | Command::ReleaseAll(_)
    )
}

fn send(command: Command) -> Result<()> {
    let mut slot = command_sender()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        match spawn_worker() {
            Ok(sender) => *slot = Some(sender),
            Err(error) => {
                CONNECTION_STATE.store(0, Ordering::Release);
                WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                return Err(error).context("initializing BLE controller worker");
            }
        }
    }

    let sender = slot.as_ref().expect("worker sender initialized");
    match send_to_worker(sender, command) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_command)) => Err(anyhow::anyhow!(
            "BLE command queue is full ({COMMAND_QUEUE_CAPACITY}); retry after pending input is processed"
        )),
        Err(TrySendError::Disconnected(command)) => {
            CONNECTION_STATE.store(0, Ordering::Release);
            WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
            *slot = None;
            let replacement = match spawn_worker() {
                Ok(replacement) => replacement,
                Err(spawn_error) => {
                    WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                    return Err(spawn_error).context("restarting failed BLE controller worker");
                }
            };
            if let Err(send_error) = send_to_worker(&replacement, command) {
                WORKER_STATE.store(WORKER_ERROR, Ordering::Release);
                return Err(anyhow::anyhow!(
                    "replacement BLE controller worker could not accept the command: {send_error}"
                ));
            }
            *slot = Some(replacement);
            Ok(())
        }
    }
}

/// Start Windows BLE HID advertising. Connect the iPhone from AssistiveTouch.
pub fn start() -> Result<()> {
    send(Command::Start).context("queue BLE start")
}

/// Stop advertising and release any held inputs.
pub fn stop() -> Result<()> {
    clear_pointer_moves();
    send(Command::Stop).context("queue BLE stop")
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
    let event = match event {
        InputEvent::PointerMove { dx, dy } => return queue_pointer_move(dx, dy),
        other => other,
    };

    if matches!(&event, InputEvent::ReleaseAll) {
        clear_pointer_moves();
        let generation = SUBSCRIPTION_GENERATION.load(Ordering::Acquire);
        return send(Command::ReleaseAll(generation));
    }

    let mut queue = pointer_moves()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.open_batch = None;
    let generation = SUBSCRIPTION_GENERATION.load(Ordering::Acquire);
    send(Command::Dispatch(event, generation))
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
    let mut queue = pointer_moves()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.open_batch = None;
    let generation = SUBSCRIPTION_GENERATION.load(Ordering::Acquire);
    send(Command::LeftClick(generation))
}

/// Scroll vertically. Positive values scroll down; negative values scroll up.
pub fn scroll(amount: i32) -> Result<()> {
    let mut remaining = amount;
    while remaining != 0 {
        let step = remaining.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        dispatch_event(InputEvent::Scroll {
            horizontal: 0,
            vertical: step,
        })?;
        remaining -= step as i32;
    }
    Ok(())
}

/// Scroll horizontally. Positive values pan right; negative values pan left.
pub fn scroll_horizontal(amount: i32) -> Result<()> {
    let mut remaining = amount;
    while remaining != 0 {
        let step = remaining.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        dispatch_event(InputEvent::Scroll {
            horizontal: step,
            vertical: 0,
        })?;
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
    let mut queue = pointer_moves()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    queue.open_batch = None;
    let generation = SUBSCRIPTION_GENERATION.load(Ordering::Acquire);
    send(Command::TypeText(text, generation))
}

/// Type a short basic ASCII sample string.
pub fn type_sample() -> Result<()> {
    type_text("BLE OK")
}

#[cfg(test)]
mod tests {
    use super::{Command, PointerMoveBatch, PointerMoveQueue};

    #[test]
    fn stopping_discards_commands_waiting_in_the_normal_queue() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        sender.send(Command::Start).unwrap();
        sender.send(Command::Stop).unwrap();

        assert_eq!(super::discard_pending_commands(&receiver), 2);
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn adjacent_pointer_moves_coalesce_with_bounded_accumulation() {
        let mut queue = PointerMoveQueue {
            next_id: 1,
            open_batch: Some(1),
            batches: std::collections::VecDeque::from([PointerMoveBatch {
                id: 1,
                generation: 7,
                dx: i16::MAX as i64,
                dy: -4,
            }]),
        };
        let batch = queue
            .batches
            .iter_mut()
            .find(|batch| batch.id == 1)
            .unwrap();
        super::accumulate_pointer_move(batch, 12, 9);
        assert_eq!(queue.batches[0].dx, 2_048);
        assert_eq!(queue.batches[0].dy, 5);
    }

    #[test]
    fn coalesced_pointer_motion_has_a_bounded_backlog() {
        let mut batch = PointerMoveBatch {
            id: 1,
            generation: 1,
            dx: 2_040,
            dy: -2_040,
        };
        super::accumulate_pointer_move(&mut batch, 100, -100);
        assert_eq!(batch.dx, 2_048);
        assert_eq!(batch.dy, -2_048);
    }

    #[test]
    fn clearing_pointer_moves_discards_batches_and_closes_open_batch() {
        let mut queue = PointerMoveQueue {
            next_id: 2,
            open_batch: Some(2),
            batches: std::collections::VecDeque::from([
                PointerMoveBatch {
                    id: 1,
                    generation: 4,
                    dx: 12,
                    dy: -8,
                },
                PointerMoveBatch {
                    id: 2,
                    generation: 4,
                    dx: 5,
                    dy: 3,
                },
            ]),
        };

        super::clear_pointer_move_queue(&mut queue);

        assert!(queue.batches.is_empty());
        assert_eq!(queue.open_batch, None);
    }

    #[test]
    fn sealed_pointer_batch_is_not_reused_for_later_motion() {
        let mut queue = PointerMoveQueue {
            next_id: 1,
            open_batch: Some(1),
            batches: std::collections::VecDeque::from([PointerMoveBatch {
                id: 1,
                generation: 3,
                dx: 10,
                dy: 5,
            }]),
        };
        queue.open_batch = None;
        queue.next_id += 1;
        queue.batches.push_back(PointerMoveBatch {
            id: queue.next_id,
            generation: 3,
            dx: 2,
            dy: 1,
        });
        assert_eq!(queue.batches.len(), 2);
        assert_ne!(queue.batches[0].id, queue.batches[1].id);
    }
}
