# Rust Phone Control

A Windows-first Rust desktop application for iPhone control experiments, BLE HID input, and AirPlay receiver development.

## Current functionality

- GPUI Kit desktop application and structured logging.
- Windows BLE GATT HID peripheral with mouse and keyboard report handling.
- Desktop controls for starting/stopping BLE advertising and sending relative mouse movement, clicks, scrolling, and sample ASCII text.
- Built-in AirPlay control-plane prototype with mDNS discovery, RTSP/HTTP parsing, plist responses, Pair-Setup (SRP and encrypted identity exchange), and Pair-Verify.
- DPAPI-protected Windows storage for the AirPlay accessory identity and paired-controller registry.
- Optional read-only iCTRL discovery client.

BLE HID input and AirPlay video are independent connections. AssistiveTouch pointer control is not native touchscreen injection, and relative mouse movement is not precise absolute-coordinate control.

## AirPlay limitations

**This repository does not yet provide working iPhone screen mirroring.** FairPlay, encrypted media transport, stream setup, video reception, H.264/HEVC decoding, and GPUI frame rendering remain unimplemented. Pairing protocol code being present does not mean that a complete iPhone pairing or mirroring session has been validated.

The SRP implementation currently uses num-bigint modular exponentiation, which is variable-time. It is a development implementation and must not be treated as production-grade cryptography until secret-exponent operations are replaced with a reviewed constant-time implementation and the protocol is independently audited.

No GPL receiver is linked or launched. New dependencies must be checked for license compatibility; the project remains under Apache-2.0.

## Project layout

- src/input/: platform-independent input events and BLE HID implementation.
- src/platform/windows/: Windows-specific APIs, including DPAPI.
- src/airplay/: discovery, RTSP, plist, TLV8, pairing, persistence, and SRP modules.
- src/ictrl/: optional read-only iCTRL discovery client.
- src/app.rs: GPUI desktop interface.

## Build and test

Run from Windows PowerShell with the MSVC toolchain installed:

```powershell
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo run --bin phone-desktop
```

The BLE diagnostic utility can be run separately:

```powershell
cargo run --bin ble-probe
```

The optional iCTRL discovery utility is read-only:

```powershell
cargo run --bin ictrl-probe -- http://PHONE-IP:8200
```
