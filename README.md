# Rust Phone Control

A Windows-first Rust desktop application for wireless iPhone control, screen mirroring research,
and Rust-based screen automation.

## Current status

The repository contains the GPUI Kit desktop shell, read-only iCTRL discovery, logging, normalized
input types, HID report encoders, a Windows WinRT BLE GATT peripheral implementation, and desktop
UI controls for starting/stopping BLE advertising plus mouse movement, click, scroll, and ASCII typing.

**Validated on the developer's Windows laptop and iPhone:** BLE HID advertising, iPhone AssistiveTouch
connection, mouse movement, left click, vertical scrolling, and keyboard text input.

## AirPlay implementation status

The external AirBridge launcher has been removed. The built-in AirPlay code is separated by responsibility:

- `src/airplay/config.rs`: service identity, model and port configuration.
- `src/airplay/discovery.rs`: mDNS/DNS-SD service registration and shutdown.
- `src/airplay/server.rs`: TCP listener and connection lifecycle.
- `src/airplay/rtsp.rs`: bounded request parsing, RTSP OPTIONS, HTTP `/server-info`, and binary-plist `/info` responses.
- `src/airplay.rs`: receiver lifecycle orchestration.

The mDNS dependency `mdns-sd` is dual-licensed Apache-2.0 OR MIT and supports Windows.
The current endpoint deliberately advertises `features=0x0`: it does not claim to support
pairing, FairPlay, encrypted media, or mirroring. `/info` handles the `txtAirPlay` qualifier by
returning the conservative mDNS TXT properties as a binary plist, and returns a baseline
`initialVolume` for an unqualified request. Other control methods remain unimplemented and return
501. This is a control-plane foundation, **not a working screen mirror**.

Still required before iPhone mirroring can work:

1. Implement and test the AirPlay pairing / authentication handshake.
2. Implement the required key exchange and media decryption without importing GPL code or
   code with unclear FairPlay provenance.
3. Receive and parse the mirroring media stream.
4. Decode H.264 through Windows Media Foundation.
5. Publish decoded frames to a bounded latest-frame channel and render them in GPUI.
6. Verify the complete flow on the target iPhone and iOS version.

No GPL receiver is linked or launched, and the repository LICENSE is unchanged.

## Other architecture

- **Input:** Windows BLE GATT HID peripheral, using iPhone AssistiveTouch for mouse/keyboard.
- **Automation:** Rust screenshot, coordinate mapping, OCR, and task execution APIs.
- **Optional backend:** iCTRL client remains separate and can be used when its official pairing and
  encrypted RPC protocol are available.

BLE HID input and AirPlay video are independent connections. A successful screen mirror does
not mean mouse control is connected, and relative HID mouse movement is not equivalent to
precise absolute touchscreen injection.

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
