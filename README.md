# Rust Phone Control

A Windows-first Rust desktop application for wireless iPhone screen viewing, Bluetooth input,
and Rust-based screen automation.

## Current status

The repository contains the GPUI Kit desktop shell, read-only iCTRL discovery, logging, normalized
input types, HID report encoders, and an initial Windows WinRT BLE GATT peripheral implementation.

The Windows BLE implementation publishes:
- HID Service with a composite relative mouse + keyboard Report Map.
- Separate mouse and keyboard Input Report characteristics with Report Reference descriptors.
- HID Control Point suspend/resume handling.
- Battery Service (placeholder battery level).
- Device Information Service is not published by the app because Windows reserves UUID 0x180A for the system.
- Encrypted GATT access for HID, Battery, and Device Information characteristics.

This is a **Report Host** implementation. It intentionally does not publish Protocol Mode or Boot
Protocol characteristics. Windows reserves Device Information Service (0x180A), so this application does not attempt to publish a PnP ID characteristic.

**Not yet validated:** successful Windows advertising on the target adapter, iPhone discovery,
bonding/pairing, AssistiveTouch pointer behavior, and end-to-end mouse/keyboard input. Windows
Peripheral-role support and successful GATT service creation are capability checks, not proof that
iOS will pair with this implementation.

AirPlay receiver, live video renderer, screenshot pipeline, OCR automation, reconnect management,
and multi-device sessions are not implemented yet.

## Planned architecture

- **Video:** AirPlay receiver on the same Wi-Fi network; decode and render H.264.
- **Input:** Windows BLE GATT HID peripheral, using iPhone AssistiveTouch for mouse/keyboard.
- **Automation:** Rust screenshot, coordinate mapping, OCR, and task execution APIs.
- **Optional backend:** iCTRL client remains separate and can be used when its official pairing and
  encrypted RPC protocol are available.

BLE HID input and AirPlay video are independent connections. A successful screen mirror does not
mean mouse control is connected, and relative HID mouse movement is not equivalent to precise
absolute touchscreen injection.

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
