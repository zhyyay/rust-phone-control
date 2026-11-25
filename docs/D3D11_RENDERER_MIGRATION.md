# GPUI + D3D11 video presentation migration

## Goal

Keep the existing GPUI application shell and replace the current encoded-frame-to-BMP
preview path with a native Windows video presentation surface. The design follows
the architectural separation visible in iPhoneMirror: bounded encoded-video
transport, a dedicated decode worker, a replaceable latest-frame handoff, and a
dedicated D3D11 presentation worker.

This document describes an independent implementation for this repository. It
does not copy or link iPhoneMirror's GPL-3.0-only code, UxPlay, or its vendored
native core. The repository's Apache-2.0 licensing goal remains unchanged.

## Current implementation

The current preview path is:

1. AirPlay media transport and packet parsing.
2. H.264 Media Foundation transform.
3. NV12 output copied into a Rust-owned Vec.
4. NV12 converted to BGRA on the decode worker.
5. LatestFrameMailbox retains the newest BGRA frame.
6. GPUI polls every 33 ms, converts BGRA to a BMP byte vector, creates a new
   GPUI Image, and invalidates the view.

The BMP encoding and repeated GPUI Image creation are presentation overhead.
The existing decoder is also currently configured around CPU-readable output;
it is not yet a D3D11-aware zero-copy Media Foundation decoder.

## Target architecture

- GPUI remains the owner of the main application window, controls, device list,
  settings, and preview layout.
- A Windows-only preview host owns a child HWND positioned over the GPUI preview
  rectangle. Its lifetime is tied to the GPUI window and it never owns the main
  application lifecycle.
- The preview host owns a D3D11 device, swap chain, render target, and a small
  shader pipeline. It draws the newest complete video frame, letterboxed or
  cropped according to the selected fit mode.
- A dedicated media worker owns Media Foundation COM objects and decoder state.
  No COM transform is called from the GPUI event thread.
- The first renderer milestone uploads decoded NV12/BGRA frames to D3D11
  textures. A later milestone negotiates a D3D11-aware Media Foundation output
  path and shares decoder surfaces where the selected MFT and driver support it.
- The frame handoff is bounded and replaceable: render lag drops stale frames
  rather than building an unbounded queue.
- Device removal, resize, suspend/resume, and window teardown are explicit
  renderer state transitions. D3D11 resources are released on their owning
  render thread.

## GPUI integration constraints

GPUI continues to lay out the preview area. The native child surface must be
synchronized with the preview element's client-space bounds after layout,
scrolling, window resize, DPI changes, and fullscreen transitions. Input hit
testing must not steal clicks from the GPUI controls. The child surface must be
hidden or destroyed before its parent window is torn down.

The exact GPUI platform-window handle and layout callback API must be verified
against the pinned gpui-kit/GPUI version before implementation; do not guess
window handles or create an unrelated top-level window as a substitute.

## Milestones

### M1 — renderer boundary and diagnostics

- Define a Windows-only renderer interface independent of AirPlay and GPUI.
- Define frame metadata (dimensions, pixel format, stride, sequence/timestamp).
- Add bounded latest-frame semantics and renderer diagnostics: submitted frames,
  dropped/replaced frames, device state, present failures, and frame dimensions.
- Keep the existing GPUI Image path as a fallback.

### M2 — D3D11 offscreen renderer

- Create a D3D11 device and swap-chain-backed preview host on a dedicated thread.
- Add validated NV12 and BGRA texture upload paths.
- Add aspect-fit rendering and resize/device-loss recovery.
- Test using synthetic frames before connecting a live decoder.

### M3 — GPUI child-surface integration

- Verify and use the real GPUI native HWND/platform handle.
- Position the child preview HWND using actual preview element bounds and DPI.
- Handle GPUI resize, hide/show, fullscreen, and teardown without stale HWNDs.
- Preserve all controls and the existing GPUI fallback path.

### M4 — Media Foundation GPU path

- Add D3D11 device-manager negotiation to the Media Foundation decoder.
- Prefer hardware transforms and GPU-backed NV12 output when supported.
- Fall back to the existing CPU-readable decoder path on unsupported hardware.
- Never report zero-copy unless the selected transform and texture path prove it.

### M5 — measurement and acceptance

- Measure decode time, upload time, render submission time, frame drops, and
  end-to-end presentation cadence separately.
- Validate on Intel UHD 620 and another available adapter.
- Compare CPU use and latency against the existing GPUI Image fallback.
- Require live-stream and resize/reconnect tests before enabling the new path by
  default.

## Non-goals

- Replacing GPUI or rebuilding the whole application UI.
- Copying GPL/LGPL implementation code from iPhoneMirror or UxPlay.
- Claiming hardware decoding or zero-copy based only on decoder enumeration.
- Treating a successful D3D11 Present as proof that an iPhone frame was received.
- Changing FairPlay behavior or bypassing Apple's authorization mechanisms.
