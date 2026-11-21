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

## Windows BLE HID implementation

The Windows BLE implementation is in `src/input/ble/service.rs`.

Published services and characteristics:
- HID Service (0x1812): HID Information, Report Map, HID Control Point, mouse Input Report
  (report ID 1), and keyboard Input Report (report ID 2).
- Battery Service (0x180F): readable Battery Level (100% placeholder).
- Device Information Service (0x180A) is not published by this app: Windows reserves DIS for the system and returns `BluetoothError.DisabledByPolicy` when an app tries to create it.
- Report Reference descriptors identify each input report and its report ID.
- HID, Battery, and Device Information characteristic reads/writes require an encrypted link.

This implementation targets a **Report Host**. Protocol Mode and Boot Protocol characteristics
are intentionally not published because Boot Keyboard / Boot Mouse characteristics are not
implemented. The Report Host profile permits Protocol Mode to be absent. HID Control Point
Suspend and Exit Suspend commands suppress notifications while suspended and clear the last
reported input state.

Run the Windows BLE diagnostic:

```powershell
cargo run --bin ble-probe
```

The probe checks the default adapter's BLE Peripheral-role capability and whether Windows can
create a HID GATT service provider. The executable then attempts to publish HID, Battery, and
Device Information services and start advertising. A successful provider creation or advertising
status is not proof of successful iPhone discovery, bonding, or HID operation.

After advertising starts, try pairing from iPhone:
`Settings → Accessibility → Touch → AssistiveTouch → Devices → Bluetooth Devices`.
The exact labels may vary by iOS language/version. This is AssistiveTouch pointer control, not
native touchscreen injection. Relative mouse motion needs calibration; absolute-coordinate
automation is not promised by this backend.

**Not yet validated:** target-adapter advertising, iPhone discovery and bonding, AssistiveTouch
compatibility, notification subscription, and end-to-end input delivery. These require testing on
the actual Windows laptop and iPhone.

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
- Platform-independent mouse/keyboard input event types and report encoders.
- Initial Windows WinRT BLE HID Report Host and Battery GATT services and advertising implementation.
- HID suspend/resume handling and current input-report readback.

Not implemented or not yet validated:
- Boot Protocol support.
- Persistent pairing/bond management and reconnect lifecycle.
- Verified iPhone pairing and real device input delivery.
- AirPlay receiver, H.264 decoding/rendering, and live screenshot capture.
- OCR, screen-coordinate mapping, and automation task runner.
- Multi-device concurrent control; the first version is single-active-device.

## Planned phases

1. **Phase 1-A:** validate Windows BLE advertising, iPhone AssistiveTouch pairing, and end-to-end
   mouse/keyboard input.
2. **Phase 1-B:** AirPlay receiver process, H.264 frame transport, Windows decode, and GPUI display.
3. **Phase 1-C:** Unified device/session UI, reconnect handling, and emergency release of all keys.
4. **Phase 2:** Screenshot API, coordinate transforms, OCR, and Rust automation executor.
