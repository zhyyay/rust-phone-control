# Rust Phone Control

A Windows-first Rust desktop application for wireless iPhone screen viewing, Bluetooth input,
and Rust-based screen automation.

## Current status

The repository currently contains the GPUI Kit desktop shell, read-only iCTRL discovery, logging,
and the first platform-independent HID-over-GATT protocol core. The HID core defines a composite
relative mouse + keyboard Report Map and tested report encoders.

**The Windows BLE GATT server, AirPlay receiver, live video renderer, screenshot pipeline, and OCR
automation are not implemented yet.** The protocol core does not claim that a PC can already pair
with or control an iPhone. BLE control depends on the local adapter supporting the peripheral role
and on successful iOS AssistiveTouch pairing.

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

See `docs/DEVELOPMENT.md` for setup, hardware checks, and implementation boundaries.
