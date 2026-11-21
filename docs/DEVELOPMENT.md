# Development

## Requirements

- Rust stable; Rust 1.92 or newer is recommended by the current GPUI Kit dependency graph.
- Windows: MSVC toolchain and Visual Studio C++ Build Tools.
- iPhone with the iCTRL UITest runner installed and running.
- iPhone and Windows PC on the same trusted Wi-Fi network.

## iCTRL setup

1. Start the iCTRL UITest runner on the iPhone.
2. Approve enabling Remote Access from the iCTRL notification.
3. Confirm Windows and iPhone are on the same LAN.
4. From PowerShell, run:

```powershell
curl.exe http://PHONE-IP:8200/schema
```

The runner defaults to port 8200. Remote Access is off by default. Do not expose this service to the public internet.

## Build

```powershell
cargo fmt --all -- --check
cargo check --all-targets
cargo run
```

Read-only iCTRL discovery:

```powershell
cargo run --bin ictrl-probe -- http://PHONE-IP:8200
```

## Phase 1 boundary

This commit provides the GPUI Kit desktop shell and read-only iCTRL discovery (`/status`, `/schema`, `/skill`). It deliberately does not invent a pairing handshake or send plaintext JSON-RPC commands. Authenticated control must use the exact encrypted envelope and pairing flow implemented by the official iCTRL reference client. The paired client, screenshot RPC, touch actions and stream decoder will be added after protocol conformance tests.

## Planned phases

- Phase 1: workspace foundation, desktop shell, config, logging, read-only device discovery.
- Phase 1b: official iCTRL pairing and encrypted RPC client, screenshot and touch commands.
- Phase 2: H.264 stream pipeline; Windows hardware decoder first, CPU fallback.
- Phase 3: GPUI live screen, pointer mapping, keyboard input.
- Phase 4: OCR and automation task runner.
