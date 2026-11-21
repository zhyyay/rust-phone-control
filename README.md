# Rust Phone Control

A Windows-first Rust desktop application for controlling an iPhone over Wi-Fi through the iCTRL automation runner, with GPUI Kit as the desktop UI framework.

## Status

Phase 1 foundation is being built. The initial milestone covers project structure, iCTRL discovery/schema inspection, a safe client boundary, configuration, logging, and a GPUI Kit shell. Encrypted pairing and RPC must follow the exact protocol exposed by the installed iCTRL runner/client; no plaintext control requests are sent.

## Planned stack

- Rust stable (MSVC on Windows)
- GPUI Kit 0.10
- Tokio + Reqwest
- iCTRL JSON-RPC API (port 8200 by default)
- H.264 stream decoding: hardware-first with software fallback (Phase 2)

## Safety

Only connect to iPhones you own or are authorized to administer. Keep iCTRL remote access disabled except while actively using the tool, and protect paired client credentials.

## Build

```powershell
cargo check --workspace
cargo run -p phone-desktop
```

See `docs/DEVELOPMENT.md` for setup and current implementation boundaries.
