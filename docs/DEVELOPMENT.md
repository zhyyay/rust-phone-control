# Development

## Requirements

- Rust stable (Rust 1.92 or newer is recommended by the current GPUI Kit dependency graph).
- Windows development: MSVC toolchain and Visual Studio C++ Build Tools.
- BLE input: a Bluetooth LE adapter capable of the Peripheral role / GATT server.
- AirPlay experiments: Windows PC and iPhone on the same trusted Wi-Fi network.

## Build and test

Run from the repository root:

```powershell
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo run --bin phone-desktop
```

## Windows BLE HID

The Windows BLE implementation lives in src/input/ble/.

The current Report Host implementation publishes HID and Battery GATT services, including mouse and keyboard input reports. It intentionally does not claim Boot Protocol support. The desktop application can start/stop advertising and send relative mouse movement, click, scroll, and sample keyboard input.

Run the standalone diagnostic:

```powershell
cargo run --bin ble-probe
```

The probe checks adapter capability, starts the GATT HID peripheral, and can send a short test sequence after user input. A successful advertising status alone does not prove iPhone discovery, bonding, subscription, or end-to-end input delivery.

On iPhone, AssistiveTouch device pairing is generally under Settings → Accessibility → Touch → AssistiveTouch → Devices → Bluetooth Devices. Labels can vary by iOS version and language. This provides pointer-style accessibility input, not native touchscreen injection.

## AirPlay control-plane prototype

AirPlay code is organized under src/airplay/:

- config.rs: advertised identity and service configuration.
- discovery.rs: mDNS/DNS-SD advertisement lifecycle.
- server.rs: TCP listener and connection lifecycle.
- rtsp.rs: bounded RTSP/HTTP parsing and control routing.
- plist.rs and tlv8.rs: protocol serialization helpers.
- srp.rs and pair_setup.rs: Pair-Setup handshake.
- pair_verify.rs: Pair-Verify exchange.
- pairing_store.rs: Windows DPAPI-protected identity and controller persistence.

Pair-Setup and Pair-Verify code paths have unit tests, but this is not a complete or validated AirPlay receiver. FairPlay, encrypted media transport, stream setup, video reception, decoding, and GPUI frame rendering are not implemented. The SRP big-integer implementation uses variable-time modular exponentiation and is not production-ready.

## Optional iCTRL discovery

The separate read-only iCTRL client probes /status, /schema, and /skill:

```powershell
cargo run --bin ictrl-probe -- http://PHONE-IP:8200
```

It does not perform pairing or authenticated control. Do not expose an iCTRL service to the public internet; any future authenticated protocol must follow its official cryptographic specification.

## Engineering rules

- Keep Windows-specific APIs behind cfg(windows) and in src/platform/windows/ where practical.
- Keep protocol parsing, cryptography, persistence, transport, and UI responsibilities separated.
- Check every new dependency's license before adding it; do not introduce GPL code.
- Never claim screen mirroring works until a complete iPhone-to-GPUI media path is implemented and tested on the target devices.
