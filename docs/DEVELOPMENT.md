# Development

## Requirements

- Rust stable; Rust 1.92 or newer is recommended by the current GPUI Kit dependency graph.
- Windows: MSVC toolchain and Visual Studio C++ Build Tools.
- For wireless input: a Bluetooth LE adapter that supports the Peripheral role / GATT server.
- For wireless video: Windows PC and iPhone on the same trusted Wi-Fi network.

## Build and test

```powershell
cargo fmt --all -- --check
cargo test --all-targets
cargo check --all-targets
cargo run --bin phone-desktop
```

## BLE HID foundation

The platform-independent input layer lives in `src/input`.

- `event.rs`: normalized pointer, button, scroll, and keyboard events.
- `ble/descriptor.rs`: HID service/characteristic identifiers and a composite mouse + keyboard
  Report Map (mouse report ID 1, keyboard report ID 2).
- `ble/reports.rs`: fixed-layout report encoders, signed movement clamping, and release reports.
- `ble/capability.rs`: explicit capability states so an unavailable adapter is not confused with
  a failed capability probe.

The next implementation step is the Windows WinRT GATT server. It must publish the HID service,
HID Information, Report Map, Control Point, Protocol Mode, and separate Report characteristics
with Report Reference descriptors. The Windows adapter must be checked for BLE Peripheral/GATT
server support before advertising; Central-only adapters cannot host this service.

After the Windows service is implemented, pair from iPhone:
`Settings → Accessibility → Touch → AssistiveTouch → Devices → Bluetooth Devices`.
The exact labels may vary by iOS language/version. This is AssistiveTouch pointer control, not
native touchscreen injection. Relative mouse motion needs calibration; absolute-coordinate
automation is not promised by this backend.

## iCTRL discovery

The optional read-only discovery client probes `/status`, `/schema`, and `/skill`:

```powershell
cargo run --bin ictrl-probe -- http://PHONE-IP:8200
```

The runner defaults to port 8200. Remote Access is off by default. Do not expose this service to
the public internet. Pairing and authenticated RPC must follow the official encrypted protocol;
do not invent a handshake or send plaintext control requests.

## Implementation boundaries

Implemented:
- GPUI Kit desktop shell, logging, and read-only iCTRL discovery.
- Platform-independent mouse/keyboard event types.
- HID-over-GATT Report Map and mouse/keyboard report encoders with unit tests.

Not implemented:
- Windows BLE adapter capability probe and WinRT GATT service publisher.
- iPhone pairing, reconnect, suspend/resume, and real device input validation.
- AirPlay receiver, H.264 decoding/rendering, and live screenshot capture.
- OCR, screen-coordinate mapping, and automation task runner.

## Planned phases

1. **Phase 1-A:** Windows BLE capability probe, GATT HID service, iPhone AssistiveTouch pairing,
   and end-to-end mouse/keyboard validation.
2. **Phase 1-B:** AirPlay receiver process, H.264 frame transport, Windows decode, and GPUI display.
3. **Phase 1-C:** Unified device/session UI, reconnect handling, and emergency release of all keys.
4. **Phase 2:** Screenshot API, coordinate transforms, OCR, and Rust automation executor.
