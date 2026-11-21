# Rust Phone Control

A Windows-first Rust desktop application for wireless iPhone screen viewing, Bluetooth input,
and Rust-based screen automation.

## Current status

The repository contains the GPUI Kit desktop shell, read-only iCTRL discovery, logging, normalized
input types, HID report encoders, a Windows WinRT BLE GATT peripheral implementation, and desktop
UI controls for starting/stopping BLE advertising plus mouse movement, click, scroll, and ASCII typing.

The Windows BLE implementation publishes:
- HID Service with a composite relative mouse + keyboard Report Map.
- Separate mouse and keyboard Input Report characteristics with Report Reference descriptors.
- HID Control Point suspend/resume handling.
- Battery Service (placeholder battery level).
- Device Information Service is not published by the app because Windows reserves UUID 0x180A for the system.
- Encrypted GATT access for HID, Battery, and Device Information characteristics.

This is a **Report Host** implementation. It intentionally does not publish Protocol Mode or Boot
Protocol characteristics. Windows reserves Device Information Service (0x180A), so this application does not attempt to publish a PnP ID characteristic.

**Validated on the developer's Windows laptop and iPhone:** BLE HID advertising, iPhone AssistiveTouch
connection, mouse movement, left click, vertical scrolling, and keyboard text input. The desktop UI
now exposes these controls through a dedicated background BLE worker. Reconnection lifecycle,
connection-state presentation, absolute touchscreen injection, and multi-device control remain future work.

An optional AirPlay receiver launcher is now exposed in the desktop UI. It starts/stops a separate
AirBridge executable; the video currently appears in the receiver's own window, not embedded in GPUI.
The GPUI frame bridge, screenshot pipeline, OCR automation, reconnect management, and multi-device
sessions are not implemented yet.

## Planned architecture

- **Video:** AirPlay receiver on the same Wi-Fi network. The current integration launches AirBridge as a separate process; decoded frames are not yet embedded in this app.
- **Input:** Windows BLE GATT HID peripheral, using iPhone AssistiveTouch for mouse/keyboard.
- **Automation:** Rust screenshot, coordinate mapping, OCR, and task execution APIs.
- **Optional backend:** iCTRL client remains separate and can be used when its official pairing and
  encrypted RPC protocol are available.

BLE HID input and AirPlay video are independent connections. A successful screen mirror does not
mean mouse control is connected, and relative HID mouse movement is not equivalent to precise
absolute touchscreen injection.

## AirPlay screen mirroring (Windows)

The desktop UI can launch an external AirPlay receiver. Download the **portable** AirBridge release
from https://github.com/30jannik06/AirBridge/releases and extract it. The receiver is not bundled
with this repository.

For development in PowerShell, set the executable path before starting the app:

```powershell
$env:AIRBRIDGE_EXE = "D:\tools\AirBridge\airbridge.exe"
cargo run --bin phone-desktop
```

Or place `airbridge.exe` beside the built `phone-desktop.exe`. Click **Start mirror**, then on
the iPhone open Control Center → Screen Mirroring and select **AirBridge**. Both devices must be on
the same Wi-Fi network. If Windows Firewall prompts, allow it only on a trusted Private network.

AirBridge listens on the local network and its default configuration does not require a PIN, so use
it only on a trusted network. It is GPL-3.0-only and is launched as a separate process; this project
does not link or redistribute its executable. Review its license before bundling or redistributing it.
The current integration opens a separate AirBridge video window; embedding frames into GPUI and
feeding them to the Rust screenshot/OCR pipeline is the next integration task.

## Build

```powershell
cargo fmt --all -- --check
cargo test --all-targets
cargo check --all-targets
cargo run --bin phone-desktop
```

To run the BLE peripheral diagnostic on Windows:

```powershell
cargo run --bin ble-probe
```

See `docs/DEVELOPMENT.md` for setup, hardware checks, and implementation boundaries.
