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

## AirPlay status and limitations

The built-in receiver now has mDNS discovery, RTSP request framing, Pair-Setup / Pair-Verify handling, controller approval, FairPlay message framing and an authorized-provider integration boundary, stream SETUP validation, bounded screen-mirroring TCP reception, H.264 access-unit parsing, a Windows Media Foundation decoder path, and a D3D11/GPUI frame presentation path.

**End-to-end wireless mirroring is not yet working.** The project does not contain an authorized FairPlay SAP provider, so it deliberately rejects FairPlay negotiation instead of fabricating challenges or media keys. Without authenticated FairPlay keys, encrypted iPhone video cannot be decrypted and displayed. A bound media port, RTSP RECORD response, or initialized decoder is not evidence of a visible mirror; acceptance requires real decoded frames reaching the preview.

The receiver status is intended to distinguish protocol milestones: discovery/listening → RTSP client → Pair-Verify → FairPlay M1/M2 → authenticated M3 → stream SETUP → RECORD/media listener → decoded frame → rendered frame. RECORD may arrive before stream-level SETUP and must not be reported as active media reception until the media listener exists.

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
