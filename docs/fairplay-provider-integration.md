# FairPlay SAP provider integration

## Current support boundary

The built-in receiver advertises AirPlay discovery and accepts RTSP control
connections. It does **not** implement Apple's proprietary FairPlay SAP
cryptographic transform. A phone reaching `POST /fp-setup` and receiving
`501 Not Implemented` is an expected fail-closed result when no authorized
provider has been configured; it is not evidence that video mirroring works.

Do not replace this boundary with random challenges, captured responses,
hard-coded keys, or a mock provider in production. Those values cannot
authenticate a live sender and must never be used to unlock media decoding.

## Integration API

The public integration surface is:

- `FairPlaySapProvider::begin(&FairPlayMessage) -> FairPlayChallenge`
- `FairPlaySapProvider::finish(&FairPlayMessage, &FairPlayChallenge, &FairPlayMessage) -> FairPlayKeys`
- `ControlServer::start_with_fairplay_provider(Arc<dyn FairPlaySapProvider>)`
- `airplay::start_with_fairplay_provider(Arc<dyn FairPlaySapProvider>)`

The provider must be `Send + Sync` and must implement the actual, authorized
SAP exchange for the negotiated message mode.

### begin: sender M1

1. Accept only a parsed initial FPLY message with a supported SAP mode.
2. Validate all mode-specific lengths and fields before processing.
3. Generate the receiver challenge using the authorized SAP implementation.
4. Return the exact negotiated mode and 128-byte challenge in
   `FairPlayChallenge`.
5. Return a typed error for unsupported modes, malformed input, unavailable
   provider state, or internal failures. Never return placeholder bytes.

### finish: sender M3

1. Bind the operation to the exact M1 and challenge from this RTSP connection.
2. Authenticate and validate the sender's M3 using the authorized SAP
   implementation.
3. Return `FairPlayKeys` only after successful authentication.
4. Return `AuthenticationFailed` or another typed error on any failure.
5. Never reuse keys or exchange state across RTSP connections.

The `video_key` and `acknowledgement` fields are zeroizing buffers. Keep
provider-side temporary secrets in zeroizing/locked buffers where supported,
avoid logging payloads or key material, and release session state on teardown.

## Required validation before enabling a provider

- Verify the implementation's licensing/authorization and supported Apple
  protocol version/modes.
- Test valid M1/M3 exchanges using authorized test vectors or a vendor test
  harness; do not use captured user traffic as fixtures.
- Test malformed lengths, unsupported modes, tampered M3, replay across
  sessions, provider errors, and RTSP teardown.
- Confirm that a failed `finish` never creates a media cipher or submits
  encrypted bytes to the decoder.
- Confirm logs contain only safe metadata (phase, mode, result category), not
  full FPLY bodies, challenges, acknowledgements, or keys.
- Test against real sender devices and document the exact supported device
  and OS versions.

## Current runtime interpretation

| Log/result | Meaning |
| --- | --- |
| `AirPlay control listener started port=7000` | RTSP listener is running |
| DNS-SD `_airplay._tcp` and `_raop._tcp` registered | Receiver is discoverable on the LAN |
| `POST /pair-verify` | Sender has started the pairing verification exchange |
| `POST /fp-setup` | Sender has reached FairPlay setup |
| `501 Not Implemented` with no provider | Secure mirroring is intentionally unavailable |
| Authenticated provider completes M1/M3 | FairPlay setup may proceed; video transport and decoding still require separate validation |

A successful AirPlay discovery or Pair-Verify exchange alone must never be
reported as successful screen mirroring.
