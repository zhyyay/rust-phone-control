//! Windows Direct3D 11 video presenter.
//!
//! Device, immediate context, swap chain, shaders, and frame textures stay on the GPUI render thread.
//! Decoded BGRA and NV12 frames are uploaded and presented by the native child surface.

use anyhow::{Context as _, anyhow, bail};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    marker::PhantomData,
    rc::Rc,
    slice,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use windows_062::Win32::Graphics::Direct3D::ID3DBlob;
use windows_062::Win32::{
    Foundation::{HMODULE, HWND},
    Graphics::{
        Direct3D::{
            D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP, D3D_FEATURE_LEVEL,
            D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
            Fxc::{D3DCOMPILE_ENABLE_STRICTNESS, D3DCompile},
        },
        Direct3D11::{
            D3D11_BIND_SHADER_RESOURCE, D3D11_COMPARISON_NEVER, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_SAMPLER_DESC, D3D11_SDK_VERSION,
            D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_VIEWPORT,
            D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11PixelShader,
            ID3D11RenderTargetView, ID3D11SamplerState, ID3D11ShaderResourceView, ID3D11Texture2D,
            ID3D11VertexShader,
        },
        Dxgi::{
            Common::{
                DXGI_ALPHA_MODE_IGNORE, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R8_UNORM,
                DXGI_FORMAT_R8G8_UNORM, DXGI_FORMAT_UNKNOWN, DXGI_SAMPLE_DESC,
            },
            DXGI_PRESENT, DXGI_SCALING_STRETCH, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_CHAIN_FLAG,
            DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL, DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGIAdapter,
            IDXGIDevice, IDXGIFactory2, IDXGISwapChain1,
        },
    },
    UI::{
        Input::KeyboardAndMouse::{ReleaseCapture, SetCapture},
        WindowsAndMessaging::{
            CallWindowProcW, CreateWindowExW, DefWindowProcW, DestroyWindow, GWLP_WNDPROC, SW_HIDE,
            SW_SHOW, SWP_NOACTIVATE, SWP_NOOWNERZORDER, SWP_NOREDRAW, SWP_NOZORDER,
            SetWindowLongPtrW, SetWindowPos, ShowWindow, WINDOW_EX_STYLE, WM_CAPTURECHANGED,
            WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_MOUSEWHEEL,
            WM_NCDESTROY, WM_RBUTTONDBLCLK, WM_RBUTTONDOWN, WM_RBUTTONUP, WNDPROC, WS_CHILD,
            WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
        },
    },
};
use windows_062::core::{BOOL, Interface, PCSTR, PCWSTR};

static PRESENTED_FRAMES: AtomicU64 = AtomicU64::new(0);
static UPLOADED_FRAMES: AtomicU64 = AtomicU64::new(0);
static DEVICE_RECOVERIES: AtomicU64 = AtomicU64::new(0);
static DEVICE_RECOVERY_FAILURES: AtomicU64 = AtomicU64::new(0);
static RENDER_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Return whether a device recreation deadline is still in the future.
/// Convert a signed Windows wheel delta into HID wheel steps while retaining
/// sub-detent motion between messages. Windows uses +120 for up; HID here uses
/// positive values for down.
fn accumulate_wheel_delta(remainder: &mut i32, delta: i32) -> i16 {
    let total = remainder.saturating_add(delta);
    let steps = total / 120;
    *remainder = total % 120;
    (-steps).clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

fn recovery_cooldown_active(now: Instant, retry_after: Option<Instant>) -> bool {
    retry_after.is_some_and(|deadline| now < deadline)
}

/// Calculate a centered aspect-fit viewport in surface pixel coordinates.
fn fit_video_viewport(
    surface_width: u32,
    surface_height: u32,
    frame_width: u32,
    frame_height: u32,
) -> Option<[f32; 4]> {
    if surface_width == 0 || surface_height == 0 || frame_width == 0 || frame_height == 0 {
        return None;
    }

    let surface_width = surface_width as f32;
    let surface_height = surface_height as f32;
    let surface_aspect = surface_width / surface_height;
    let frame_aspect = frame_width as f32 / frame_height as f32;
    let (width, height) = if frame_aspect > surface_aspect {
        (surface_width, surface_width / frame_aspect)
    } else {
        (surface_height * frame_aspect, surface_height)
    };

    Some([
        (surface_width - width) * 0.5,
        (surface_height - height) * 0.5,
        width,
        height,
    ])
}

/// Process-wide D3D11 counters; safe to read from the GPUI diagnostics poll.
pub(crate) fn preview_metrics() -> (u64, u64, u64, u64, u64) {
    (
        PRESENTED_FRAMES.load(Ordering::Relaxed),
        UPLOADED_FRAMES.load(Ordering::Relaxed),
        DEVICE_RECOVERIES.load(Ordering::Relaxed),
        DEVICE_RECOVERY_FAILURES.load(Ordering::Relaxed),
        RENDER_ERRORS.load(Ordering::Relaxed),
    )
}

thread_local! {
    /// Whether the native preview currently owns a left-button drag.
    static NATIVE_PREVIEW_DRAGGING: Cell<bool> = const { Cell::new(false) };
    /// Last client-space pointer coordinate while dragging.
    static NATIVE_PREVIEW_LAST_POINTER: Cell<Option<(i16, i16)>> = const { Cell::new(None) };
    /// Button currently held by a native preview drag, including right-button drags.
    static NATIVE_PREVIEW_ACTIVE_BUTTON: Cell<Option<crate::input::MouseButtons>> =
        const { Cell::new(None) };
    /// Accumulated high-resolution wheel delta until a complete HID wheel step is available.
    static NATIVE_PREVIEW_WHEEL_REMAINDER: Cell<i32> = const { Cell::new(0) };
    /// Original STATIC window procedure, restored before the child HWND is destroyed.
    static NATIVE_PREVIEW_ORIGINAL_WNDPROC: Cell<isize> = const { Cell::new(0) };
    /// D3D11 immediate contexts remain on the GPUI thread that first initializes them.
    static THREAD_RENDERER: RefCell<Option<D3d11Device>> = const { RefCell::new(None) };
    /// Borrowed GPUI parent HWND; never destroyed or re-parented by this module.
    static GPUI_PARENT_HWND: Cell<isize> = const { Cell::new(0) };
    /// Owned child HWND. It stays hidden until a SwapChain presenter is attached.
    static NATIVE_VIDEO_CHILD_HWND: Cell<isize> = const { Cell::new(0) };
    /// Parent HWND captured when the owned child was created. A recreated GPUI
    /// window invalidates the old child and requires a fresh native surface.
    static NATIVE_VIDEO_CHILD_PARENT_HWND: Cell<isize> = const { Cell::new(0) };
    /// Last applied child rectangle; avoids redundant SetWindowPos calls on
    /// every GPUI prepaint when the preview layout has not changed.
    static NATIVE_VIDEO_CHILD_BOUNDS: Cell<Option<(i32, i32, i32, i32)>> =
        const { Cell::new(None) };
    /// Prevent a removed device from triggering a rebuild attempt on every frame.
    static DEVICE_RECOVERY_RETRY_AFTER: Cell<Option<Instant>> = const { Cell::new(None) };
}

unsafe extern "system" fn native_preview_wndproc(
    hwnd: HWND,
    message: u32,
    wparam: windows_062::Win32::Foundation::WPARAM,
    lparam: windows_062::Win32::Foundation::LPARAM,
) -> windows_062::Win32::Foundation::LRESULT {
    use crate::input::{InputEvent, MouseButtons};

    let previous_proc = NATIVE_PREVIEW_ORIGINAL_WNDPROC.with(Cell::get);
    let x = (lparam.0 as u32 as u16) as i16;
    let y = ((lparam.0 as u32 >> 16) as u16) as i16;

    match message {
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK | WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => {
            let button = if matches!(message, WM_RBUTTONDOWN | WM_RBUTTONDBLCLK) {
                MouseButtons::RIGHT
            } else {
                MouseButtons::LEFT
            };
            NATIVE_PREVIEW_DRAGGING.with(|dragging| dragging.set(true));
            NATIVE_PREVIEW_ACTIVE_BUTTON.with(|active| active.set(Some(button)));
            NATIVE_PREVIEW_LAST_POINTER.with(|last| last.set(Some((x, y))));
            unsafe { SetCapture(hwnd) };
            if let Err(error) =
                crate::input::ble::desktop::dispatch_event(InputEvent::PointerButtons(button))
            {
                tracing::warn!(error = %error, "Could not dispatch native preview mouse-down");
            }
        }
        WM_MOUSEMOVE
            if NATIVE_PREVIEW_DRAGGING.with(Cell::get)
                && NATIVE_PREVIEW_ACTIVE_BUTTON.with(|active| match active.get() {
                    Some(button) if button == MouseButtons::LEFT => wparam.0 & 0x0001 != 0,
                    Some(button) if button == MouseButtons::RIGHT => wparam.0 & 0x0002 != 0,
                    _ => false,
                }) =>
        {
            let previous = NATIVE_PREVIEW_LAST_POINTER.with(|last| last.replace(Some((x, y))));
            if let Some((previous_x, previous_y)) = previous {
                let dx = x.saturating_sub(previous_x);
                let dy = y.saturating_sub(previous_y);
                if dx != 0 || dy != 0 {
                    if let Err(error) =
                        crate::input::ble::desktop::dispatch_event(InputEvent::PointerMove {
                            dx,
                            dy,
                        })
                    {
                        tracing::warn!(error = %error, "Could not dispatch native preview pointer movement");
                    }
                }
            }
        }
        WM_MOUSEWHEEL => {
            let delta = ((wparam.0 >> 16) as u16 as i16) as i32;
            let vertical = NATIVE_PREVIEW_WHEEL_REMAINDER.with(|remainder| {
                let mut accumulated = remainder.get();
                let steps = accumulate_wheel_delta(&mut accumulated, delta);
                remainder.set(accumulated);
                steps
            });
            if vertical != 0 {
                if let Err(error) =
                    crate::input::ble::desktop::dispatch_event(InputEvent::Scroll { vertical })
                {
                    tracing::warn!(error = %error, "Could not dispatch native preview wheel");
                }
            }
        }
        WM_LBUTTONUP | WM_RBUTTONUP => {
            NATIVE_PREVIEW_DRAGGING.with(|dragging| dragging.set(false));
            NATIVE_PREVIEW_ACTIVE_BUTTON.with(|active| active.set(None));
            NATIVE_PREVIEW_LAST_POINTER.with(|last| last.set(None));
            let _ = unsafe { ReleaseCapture() };
            if let Err(error) = crate::input::ble::desktop::dispatch_event(
                InputEvent::PointerButtons(MouseButtons::NONE),
            ) {
                tracing::warn!(error = %error, "Could not dispatch native preview mouse-up");
            }
        }
        WM_CAPTURECHANGED | WM_NCDESTROY => {
            let was_dragging = NATIVE_PREVIEW_DRAGGING.with(|dragging| dragging.replace(false));
            NATIVE_PREVIEW_ACTIVE_BUTTON.with(|active| active.set(None));
            NATIVE_PREVIEW_LAST_POINTER.with(|last| last.set(None));
            if message == WM_NCDESTROY {
                NATIVE_PREVIEW_WHEEL_REMAINDER.with(|remainder| remainder.set(0));
                NATIVE_PREVIEW_ORIGINAL_WNDPROC.with(|original| original.set(0));
                if previous_proc != 0 {
                    unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, previous_proc) };
                }
            }
            if was_dragging {
                if let Err(error) =
                    crate::input::ble::desktop::dispatch_event(InputEvent::ReleaseAll)
                {
                    tracing::warn!(error = %error, "Could not release native preview input capture");
                }
            }
        }
        _ => {}
    }

    if previous_proc != 0 {
        let previous: WNDPROC = unsafe { std::mem::transmute(previous_proc) };
        unsafe { CallWindowProcW(previous, hwnd, message, wparam, lparam) }
    } else {
        unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
    }
}

/// Attach mouse forwarding to the owned native child while preserving its STATIC procedure.
fn install_native_preview_input(hwnd: HWND) -> anyhow::Result<()> {
    let previous = unsafe {
        SetWindowLongPtrW(
            hwnd,
            GWLP_WNDPROC,
            native_preview_wndproc as *const () as isize,
        )
    };
    if previous == 0 {
        bail!("SetWindowLongPtrW failed for native preview input");
    }
    NATIVE_PREVIEW_ORIGINAL_WNDPROC.with(|original| original.set(previous));
    Ok(())
}

/// Resolve GPUI's current Windows window handle and initialize the thread-local D3D11 device.
///
/// The HWND is borrowed from GPUI and is never destroyed or re-parented by this module.
pub(crate) fn initialize_for_window(window: &gpui_kit::Window) -> anyhow::Result<isize> {
    let native_handle = HasWindowHandle::window_handle(window)
        .map_err(|error| anyhow!("GPUI did not expose a native window handle: {error:?}"))?;
    let hwnd = match native_handle.as_raw() {
        RawWindowHandle::Win32(handle) => handle.hwnd.get(),
        other => return Err(anyhow!("expected a Win32 window handle, got {other:?}")),
    };

    GPUI_PARENT_HWND.with(|parent| parent.set(hwnd as isize));

    THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        if renderer.is_none() {
            *renderer = Some(D3d11Device::create_hardware()?);
            tracing::info!("D3D11 device attached to the GPUI render thread");
        }
        Ok(hwnd)
    })
}

/// Create and synchronize the native child surface within the GPUI preview rectangle.
///
/// The child uses the built-in STATIC window class, avoiding a custom WndProc or
/// process-global class registration. It remains hidden until a valid frame has been
/// uploaded and presented; successful Present reveals it over the GPUI fallback.
pub(crate) fn sync_native_video_surface(
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> anyhow::Result<()> {
    if width <= 0 || height <= 0 {
        // A minimized/temporarily hidden preview is not a teardown. Keep the
        // child HWND so restoring the window can reuse it without churn.
        suspend_native_video_surface();
        return Ok(());
    }

    let parent = GPUI_PARENT_HWND.with(Cell::get);
    if parent == 0 {
        bail!("GPUI parent HWND is not initialized");
    }

    NATIVE_VIDEO_CHILD_HWND.with(|child_cell| {
        let mut child_raw = child_cell.get();
        let child_parent = NATIVE_VIDEO_CHILD_PARENT_HWND.with(Cell::get);
        if child_raw != 0 && child_parent != parent {
            // GPUI may recreate its top-level HWND (for example after a window
            // lifecycle transition). Never keep a child attached to a stale
            // parent; destroy it on this owning UI thread and recreate below.
            destroy_native_video_surface();
            child_raw = 0;
        }
        if child_raw == 0 {
            const STATIC_CLASS: &[u16] = &[83, 84, 65, 84, 73, 67, 0];
            const SURFACE_NAME: &[u16] = &[
                82, 117, 115, 116, 80, 104, 111, 110, 101, 86, 105, 100, 101, 111, 83, 117, 114,
                102, 97, 99, 101, 0,
            ];
            let parent_hwnd = HWND(parent as *mut c_void);
            // SAFETY: parent_hwnd is borrowed from the live GPUI window on its
            // UI thread. The predefined STATIC class requires no custom WndProc.
            let created = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(STATIC_CLASS.as_ptr()),
                    PCWSTR(SURFACE_NAME.as_ptr()),
                    WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
                    x,
                    y,
                    width,
                    height,
                    Some(parent_hwnd),
                    None,
                    None,
                    None,
                )
            }
            .context("CreateWindowExW failed for the native video child surface")?;
            if let Err(error) = install_native_preview_input(created) {
                // The HWND has not yet been stored in thread-local ownership;
                // destroy it here so a failed subclass install cannot leak it.
                unsafe { DestroyWindow(created) };
                return Err(error).context("could not install native preview mouse forwarding");
            }
            child_raw = created.0 as isize;
            child_cell.set(child_raw);
            NATIVE_VIDEO_CHILD_PARENT_HWND.with(|stored_parent| stored_parent.set(parent));
            NATIVE_VIDEO_CHILD_BOUNDS.with(|bounds| bounds.set(None));
            tracing::info!(
                hwnd = format!("{child_raw:#x}"),
                parent = format!("{parent:#x}"),
                "Created hidden native video child window"
            );
        }

        let child_hwnd = HWND(child_raw as *mut c_void);
        let requested_bounds = (x, y, width, height);
        let previous_bounds = NATIVE_VIDEO_CHILD_BOUNDS.with(Cell::get);
        if previous_bounds != Some(requested_bounds) {
            // SAFETY: child_hwnd is owned by this thread-local host and remains
            // parented to the current GPUI HWND.
            unsafe {
                SetWindowPos(
                    child_hwnd,
                    None,
                    x,
                    y,
                    width,
                    height,
                    SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOZORDER | SWP_NOREDRAW,
                )
            }
            .context("SetWindowPos failed while synchronizing the video child surface")?;
            NATIVE_VIDEO_CHILD_BOUNDS.with(|bounds| bounds.set(Some(requested_bounds)));
        }

        // Bring up the HWND-bound swap chain on the same GPUI thread as the
        // D3D11 immediate context. The surface remains hidden until the first
        // successful decoded-frame upload and Present.
        let surface_changed = THREAD_RENDERER.with(|renderer| {
            let renderer = renderer.borrow();
            let device = renderer
                .as_ref()
                .ok_or_else(|| anyhow!("D3D11 renderer is not initialized"))?;
            Ok::<_, anyhow::Error>(
                device.swap_chain.is_none()
                    || device.swap_chain_hwnd != child_raw
                    || device.swap_chain_size != Some((width as u32, height as u32))
                    || device.render_target_view.is_none(),
            )
        })?;

        if surface_changed {
            // Hide only while the HWND-bound back buffer is being created
            // or resized. sync_native_video_surface runs during layout;
            // hiding unconditionally here can blank a freshly presented
            // frame on the next GPUI prepaint and cause visible flicker.
            // SAFETY: child_hwnd is the owned native preview child.
            unsafe {
                ShowWindow(child_hwnd, SW_HIDE);
            }
        }

        ensure_swap_chain_with_recovery(child_hwnd, width as u32, height as u32)?;

        Ok(())
    })
}

/// Ensure the native surface's swap chain exists, rebuilding the device if
/// DXGI reports that it was removed while creating or resizing the chain.
///
/// Frame-upload recovery alone is insufficient: a device can be removed while
/// the window is being resized, before another frame reaches the upload path.
fn ensure_swap_chain_with_recovery(hwnd: HWND, width: u32, height: u32) -> anyhow::Result<()> {
    let initial_result = THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer is not initialized"))?;
        device.ensure_swap_chain(hwnd, width, height)
    });

    let Err(original_error) = initial_result else {
        return Ok(());
    };

    let removed_reason = THREAD_RENDERER.with(|renderer| {
        let renderer = renderer.borrow();
        renderer.as_ref().and_then(|device| {
            // GetDeviceRemovedReason returns S_OK while the device is healthy.
            unsafe { device.device.GetDeviceRemovedReason() }.err()
        })
    });
    let Some(reason) = removed_reason else {
        return Err(original_error);
    };

    let now = Instant::now();
    let cooling_down = DEVICE_RECOVERY_RETRY_AFTER
        .with(|retry_after| recovery_cooldown_active(now, retry_after.get()));
    if cooling_down {
        return Err(original_error);
    }
    DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| {
        retry_after.set(Some(now + Duration::from_secs(2)));
    });

    // Do not leave an old image visible while its device is being replaced.
    // SAFETY: hwnd is the owned native child surface on the GPUI thread.
    unsafe {
        ShowWindow(hwnd, SW_HIDE);
    }
    tracing::warn!(
        error = %reason,
        width,
        height,
        "D3D11 device was removed while ensuring the swap chain; rebuilding device"
    );

    let mut replacement = match D3d11Device::create_hardware()
        .context("could not recreate D3D11 device after swap-chain device removal")
    {
        Ok(device) => device,
        Err(error) => {
            DEVICE_RECOVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %format!("{error:#}"), "D3D11 device recovery failed");
            return Err(error);
        }
    };
    if let Err(error) = replacement.ensure_swap_chain(hwnd, width, height) {
        DEVICE_RECOVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
        tracing::error!(error = %format!("{error:#}"), "D3D11 swap-chain recovery failed");
        return Err(
            error.context("could not recreate the native video swap chain after device removal")
        );
    }

    THREAD_RENDERER.with(|renderer| {
        *renderer.borrow_mut() = Some(replacement);
    });
    DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| retry_after.set(None));
    DEVICE_RECOVERIES.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        width,
        height,
        "D3D11 device and swap chain recovered during surface synchronization"
    );
    Ok(())
}

/// Suspend the preview while its GPUI layout has no drawable area.
///
/// Keep the child HWND attached to its parent, but release the HWND-bound DXGI
/// resources. On restore, sync_native_video_surface reuses the child and
/// ensure_swap_chain creates a fresh chain for the new non-zero dimensions.
fn suspend_native_video_surface() {
    NATIVE_VIDEO_CHILD_HWND.with(|child_cell| {
        let child_raw = child_cell.get();
        NATIVE_VIDEO_CHILD_BOUNDS.with(|bounds| bounds.set(None));

        if child_raw != 0 {
            // SAFETY: this module owns the child HWND and this runs on its UI thread.
            unsafe { ShowWindow(HWND(child_raw as *mut c_void), SW_HIDE) };
        }

        THREAD_RENDERER.with(|renderer| {
            let mut renderer = renderer.borrow_mut();
            if let Some(device) = renderer.as_mut() {
                // The immediate context retains bound RTV references. Unbind
                // before releasing the back buffer and swap chain.
                // SAFETY: the RTV belongs to this renderer and its immediate context.
                unsafe {
                    device.immediate_context.OMSetRenderTargets(
                        None,
                        None::<&windows_062::Win32::Graphics::Direct3D11::ID3D11DepthStencilView>,
                    );
                }
                device.render_target_view = None;
                device.swap_chain = None;
                device.swap_chain_size = None;
                device.swap_chain_hwnd = 0;
            }
        });
    });
}

/// Hide the native surface so the GPUI bitmap fallback is not covered by a stale frame.
pub(crate) fn hide_native_video_surface() {
    NATIVE_VIDEO_CHILD_HWND.with(|child_cell| {
        let child_raw = child_cell.get();
        if child_raw == 0 {
            return;
        }
        // SAFETY: the HWND is owned by this module and this runs on its UI thread.
        unsafe { ShowWindow(HWND(child_raw as *mut c_void), SW_HIDE) };
    });
}

/// Destroy only the native child owned by this module; the GPUI parent is borrowed.
pub(crate) fn destroy_native_video_surface() {
    NATIVE_VIDEO_CHILD_HWND.with(|child_cell| {
        let child_raw = child_cell.replace(0);
        NATIVE_VIDEO_CHILD_PARENT_HWND.with(|stored_parent| stored_parent.set(0));
        NATIVE_VIDEO_CHILD_BOUNDS.with(|bounds| bounds.set(None));

        // Release the HWND-bound DXGI chain before destroying its window.
        // The immediate context retains bound RTV references, so unbind first.
        THREAD_RENDERER.with(|renderer| {
            let mut renderer = renderer.borrow_mut();
            if let Some(device) = renderer.as_mut() {
                // SAFETY: the RTV was created by this renderer and is bound
                // only on the thread that owns its immediate context.
                unsafe {
                    device.immediate_context.OMSetRenderTargets(
                        None,
                        None::<&windows_062::Win32::Graphics::Direct3D11::ID3D11DepthStencilView>,
                    );
                }
                device.render_target_view = None;
                device.swap_chain = None;
                device.swap_chain_size = None;
                device.swap_chain_hwnd = 0;
            }
        });

        if child_raw == 0 {
            return;
        }
        let child_hwnd = HWND(child_raw as *mut c_void);
        // SAFETY: this is the child HWND created and owned by this module.
        if let Err(error) = unsafe { DestroyWindow(child_hwnd) } {
            tracing::warn!(error = %error, "Could not destroy native video child window");
        } else {
            tracing::info!("Destroyed native video child window");
        }
    });
}

/// Recreate the D3D11 device and its HWND-bound swap chain after device removal.
///
/// The caller is responsible for cooldown policy and for retrying the current
/// decoded frame on the replacement device.
fn recreate_device_after_removal(
    hwnd: HWND,
    surface_width: u32,
    surface_height: u32,
    reason: &windows_062::core::Error,
) -> anyhow::Result<()> {
    tracing::warn!(
        error = %reason,
        width = surface_width,
        height = surface_height,
        "D3D11 device was removed; rebuilding preview device and resources"
    );

    let mut replacement = match D3d11Device::create_hardware()
        .context("could not recreate D3D11 device after device removal")
    {
        Ok(device) => device,
        Err(error) => {
            DEVICE_RECOVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %format!("{error:#}"), "D3D11 device recovery failed");
            return Err(error);
        }
    };
    if let Err(error) = replacement.ensure_swap_chain(hwnd, surface_width, surface_height) {
        DEVICE_RECOVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
        tracing::error!(error = %format!("{error:#}"), "D3D11 swap-chain recovery failed");
        return Err(
            error.context("could not recreate the native video swap chain after device removal")
        );
    }

    THREAD_RENDERER.with(|renderer| {
        *renderer.borrow_mut() = Some(replacement);
    });
    Ok(())
}

/// Upload an NV12 frame to the GPUI thread's D3D11 Y/UV textures.
/// The caller must run on the thread that initialized the native renderer.
pub(crate) fn upload_nv12_frame(
    width: u32,
    height: u32,
    y_stride: usize,
    uv_stride: usize,
    data: &[u8],
    color_matrix: crate::airplay::AvcColorMatrix,
) -> anyhow::Result<()> {
    let initial_result = THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer has not been initialized for a GPUI window"))?;
        let upload_started = Instant::now();
        device.upload_nv12(width, height, y_stride, uv_stride, data, color_matrix)?;
        let upload_time = upload_started.elapsed();
        UPLOADED_FRAMES.fetch_add(1, Ordering::Relaxed);
        device
            .draw_nv12_frame()
            .map(|present_time| (upload_time, present_time))
    });
    let (upload_time, present_time) = match initial_result {
        Ok(timings) => timings,
        Err(original_error) => {
            RENDER_ERRORS.fetch_add(1, Ordering::Relaxed);
            // Treat device removal/reset the same way as the BGRA path. Do not
            // recreate resources for ordinary validation, shader, or resize errors.
            let removed = THREAD_RENDERER.with(|renderer| {
                let renderer = renderer.borrow();
                renderer.as_ref().and_then(|device| {
                    unsafe { device.device.GetDeviceRemovedReason() }
                        .err()
                        .map(|reason| (reason, device.swap_chain_size))
                })
            });
            let Some((reason, Some((surface_width, surface_height)))) = removed else {
                return Err(original_error);
            };
            let now = Instant::now();
            let cooling_down = DEVICE_RECOVERY_RETRY_AFTER
                .with(|retry_after| recovery_cooldown_active(now, retry_after.get()));
            if cooling_down {
                return Err(original_error);
            }
            DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| {
                retry_after.set(Some(now + Duration::from_secs(2)));
            });
            let child_raw = NATIVE_VIDEO_CHILD_HWND.with(Cell::get);
            if child_raw == 0 {
                return Err(original_error);
            }
            // Hide the old surface before replacing its device/swap chain.
            // If recreation fails, the stale last frame must not masquerade as
            // a live preview; a later successful Present reveals the child again.
            unsafe { ShowWindow(HWND(child_raw as *mut c_void), SW_HIDE) };

            recreate_device_after_removal(
                HWND(child_raw as *mut c_void),
                surface_width,
                surface_height,
                &reason,
            )?;
            let retry_result = THREAD_RENDERER
                .with(|renderer| {
                    let mut renderer = renderer.borrow_mut();
                    let device = renderer
                        .as_mut()
                        .ok_or_else(|| anyhow!("replacement D3D11 device is unavailable"))?;
                    let upload_started = Instant::now();
                    device.upload_nv12(width, height, y_stride, uv_stride, data, color_matrix)?;
                    let upload_time = upload_started.elapsed();
                    UPLOADED_FRAMES.fetch_add(1, Ordering::Relaxed);
                    device
                        .draw_nv12_frame()
                        .map(|present_time| (upload_time, present_time))
                })
                .map_err(|error| {
                    DEVICE_RECOVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    error.context("D3D11 NV12 preview retry failed after device recreation")
                })?;
            // Keep the cooldown active if the first frame on the replacement
            // device also fails; otherwise a broken driver can trigger rebuilds
            // on every incoming frame.
            DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| retry_after.set(None));
            DEVICE_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            retry_result
        }
    };
    PRESENTED_FRAMES.fetch_add(1, Ordering::Relaxed);
    let stats_result: anyhow::Result<()> = THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer disappeared after NV12 Present"))?;
        device.stats_frames += 1;
        let upload_ms = upload_time.as_secs_f64() * 1000.0;
        let present_ms = present_time.as_secs_f64() * 1000.0;
        device.stats_upload_total_ms += upload_ms;
        device.stats_upload_max_ms = device.stats_upload_max_ms.max(upload_ms);
        device.stats_present_total_ms += present_ms;
        device.stats_present_max_ms = device.stats_present_max_ms.max(present_ms);
        let elapsed = device.stats_window_started.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let frames = device.stats_frames as f64;
            tracing::info!(
                fps = frames / elapsed.as_secs_f64(),
                upload_avg_ms = device.stats_upload_total_ms / frames,
                upload_max_ms = device.stats_upload_max_ms,
                present_avg_ms = device.stats_present_total_ms / frames,
                present_max_ms = device.stats_present_max_ms,
                frames = device.stats_frames,
                "D3D11 NV12 preview performance"
            );
            device.stats_frames = 0;
            device.stats_upload_total_ms = 0.0;
            device.stats_upload_max_ms = 0.0;
            device.stats_present_total_ms = 0.0;
            device.stats_present_max_ms = 0.0;
            device.stats_window_started = Instant::now();
        }
        Ok(())
    });
    stats_result?;

    let child_raw = NATIVE_VIDEO_CHILD_HWND.with(Cell::get);
    if child_raw != 0 {
        // SAFETY: the native child is owned by this module and is revealed
        // only after its NV12 frame has been successfully presented.
        unsafe { ShowWindow(HWND(child_raw as *mut c_void), SW_SHOW) };
    }
    Ok(())
}

/// Upload one decoded BGRA frame into a shader-readable D3D11 texture.
///
/// Call this on the same GPUI thread that initialized the device. The upload
/// uses a DEFAULT texture and UpdateSubresource; it is a CPU-to-GPU upload,
/// not a zero-copy decoder surface.
pub(crate) fn upload_bgra_frame(
    width: u32,
    height: u32,
    stride: usize,
    data: &[u8],
) -> anyhow::Result<()> {
    let initial_result = THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer has not been initialized for a GPUI window"))?;
        let upload_started = Instant::now();
        device.upload_bgra(width, height, stride, data)?;
        let upload_time = upload_started.elapsed();
        UPLOADED_FRAMES.fetch_add(1, Ordering::Relaxed);
        device
            .draw_video_frame()
            .map(|present_time| (upload_time, present_time))
    });

    let (upload_time, present_time) = match initial_result {
        Ok(timings) => timings,
        Err(original_error) => {
            RENDER_ERRORS.fetch_add(1, Ordering::Relaxed);
            // Rebuild only when the driver reports device removal/reset. Shader,
            // validation, and ordinary resize errors remain visible to the caller.
            let removed = THREAD_RENDERER.with(|renderer| {
                let renderer = renderer.borrow();
                renderer.as_ref().and_then(|device| {
                    unsafe { device.device.GetDeviceRemovedReason() }
                        .err()
                        .map(|reason| (reason, device.swap_chain_size))
                })
            });
            let Some((reason, Some((surface_width, surface_height)))) = removed else {
                return Err(original_error);
            };
            let now = Instant::now();
            let cooling_down = DEVICE_RECOVERY_RETRY_AFTER
                .with(|retry_after| recovery_cooldown_active(now, retry_after.get()));
            if cooling_down {
                return Err(original_error);
            }
            DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| {
                retry_after.set(Some(now + Duration::from_secs(2)));
            });
            let child_raw = NATIVE_VIDEO_CHILD_HWND.with(Cell::get);
            if child_raw == 0 {
                return Err(original_error);
            }
            // Hide the old surface before replacing its device/swap chain.
            // If recreation fails, the stale last frame must not masquerade as
            // a live preview; a later successful Present reveals the child again.
            unsafe { ShowWindow(HWND(child_raw as *mut c_void), SW_HIDE) };

            recreate_device_after_removal(
                HWND(child_raw as *mut c_void),
                surface_width,
                surface_height,
                &reason,
            )?;
            let retry_result = THREAD_RENDERER
                .with(|renderer| {
                    let mut renderer = renderer.borrow_mut();
                    let device = renderer
                        .as_mut()
                        .ok_or_else(|| anyhow!("replacement D3D11 device is unavailable"))?;
                    let upload_started = Instant::now();
                    device.upload_bgra(width, height, stride, data)?;
                    let upload_time = upload_started.elapsed();
                    UPLOADED_FRAMES.fetch_add(1, Ordering::Relaxed);
                    device
                        .draw_video_frame()
                        .map(|present_time| (upload_time, present_time))
                })
                .map_err(|error| {
                    DEVICE_RECOVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    error.context("D3D11 preview retry failed after device recreation")
                })?;
            // Do not clear the cooldown until the replacement has presented
            // a frame successfully; a failed retry must not cause rebuild churn.
            DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| retry_after.set(None));
            DEVICE_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            retry_result
        }
    };

    PRESENTED_FRAMES.fetch_add(1, Ordering::Relaxed);

    let stats_result: anyhow::Result<()> = THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer is unavailable after Present"))?;
        device.stats_frames += 1;
        let upload_ms = upload_time.as_secs_f64() * 1000.0;
        let present_ms = present_time.as_secs_f64() * 1000.0;
        device.stats_upload_total_ms += upload_ms;
        device.stats_upload_max_ms = device.stats_upload_max_ms.max(upload_ms);
        device.stats_present_total_ms += present_ms;
        device.stats_present_max_ms = device.stats_present_max_ms.max(present_ms);
        let elapsed = device.stats_window_started.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let frames = device.stats_frames as f64;
            tracing::info!(
                fps = frames / elapsed.as_secs_f64(),
                upload_avg_ms = device.stats_upload_total_ms / frames,
                upload_max_ms = device.stats_upload_max_ms,
                present_avg_ms = device.stats_present_total_ms / frames,
                present_max_ms = device.stats_present_max_ms,
                frames = device.stats_frames,
                "D3D11 preview performance"
            );
            device.stats_frames = 0;
            device.stats_upload_total_ms = 0.0;
            device.stats_upload_max_ms = 0.0;
            device.stats_present_total_ms = 0.0;
            device.stats_present_max_ms = 0.0;
            device.stats_window_started = Instant::now();
        }
        Ok(())
    });
    stats_result?;

    let child_raw = NATIVE_VIDEO_CHILD_HWND.with(Cell::get);
    if child_raw != 0 {
        // SAFETY: this module owns the child HWND and reveals it only after
        // a successful draw and Present on the same UI thread.
        unsafe { ShowWindow(HWND(child_raw as *mut c_void), SW_SHOW) };
    }
    Ok(())
}

/// Owns D3D11 objects on the thread that created them.
///
/// The Rc marker intentionally makes this type !Send and !Sync. Immediate
/// context calls and resource lifetime remain confined to one thread.
pub(crate) struct D3d11Device {
    device: ID3D11Device,
    immediate_context: ID3D11DeviceContext,
    video_texture: Option<ID3D11Texture2D>,
    _video_shader_view: Option<ID3D11ShaderResourceView>,
    video_texture_size: Option<(u32, u32)>,
    nv12_y_texture: Option<ID3D11Texture2D>,
    nv12_uv_texture: Option<ID3D11Texture2D>,
    _nv12_y_view: Option<ID3D11ShaderResourceView>,
    _nv12_uv_view: Option<ID3D11ShaderResourceView>,
    nv12_texture_size: Option<(u32, u32)>,
    swap_chain: Option<IDXGISwapChain1>,
    swap_chain_hwnd: isize,
    render_target_view: Option<ID3D11RenderTargetView>,
    swap_chain_size: Option<(u32, u32)>,
    vertex_shader: Option<ID3D11VertexShader>,
    pixel_shader: Option<ID3D11PixelShader>,
    nv12_pixel_shader: Option<ID3D11PixelShader>,
    nv12_shader_uses_bt709: Option<bool>,
    nv12_color_matrix_override: Option<bool>,
    sampler: Option<ID3D11SamplerState>,
    stats_window_started: Instant,
    stats_frames: u64,
    stats_upload_total_ms: f64,
    stats_upload_max_ms: f64,
    stats_present_total_ms: f64,
    stats_present_max_ms: f64,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl D3d11Device {
    /// Create a hardware-backed D3D11 device with BGRA interoperability enabled.
    pub(crate) fn create_hardware() -> anyhow::Result<Self> {
        let mut device = None;
        let mut immediate_context = None;

        // SAFETY: output slots are valid for both attempts. Prefer the
        // hardware adapter, but retain a WARP software path for machines,
        // remote sessions, or drivers that cannot create a hardware device.
        let hardware_result = unsafe {
            D3D11CreateDevice(
                None::<&IDXGIAdapter>,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut immediate_context),
            )
        };
        let (driver_name, creation_result) = match hardware_result {
            Ok(()) => ("hardware", Ok(())),
            Err(hardware_error) => {
                tracing::warn!(
                    error = %hardware_error,
                    "Hardware D3D11 device creation failed; retrying with WARP"
                );
                device = None;
                immediate_context = None;
                let warp_result = unsafe {
                    D3D11CreateDevice(
                        None::<&IDXGIAdapter>,
                        D3D_DRIVER_TYPE_WARP,
                        HMODULE::default(),
                        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                        None,
                        D3D11_SDK_VERSION,
                        Some(&mut device),
                        None,
                        Some(&mut immediate_context),
                    )
                };
                if let Err(warp_error) = &warp_result {
                    tracing::error!(
                        hardware_error = %hardware_error,
                        warp_error = %warp_error,
                        "Both hardware and WARP D3D11 device creation failed"
                    );
                }
                ("WARP", warp_result)
            }
        };
        creation_result.context("D3D11CreateDevice failed for both hardware and WARP drivers")?;

        let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice returned no device"))?;
        let immediate_context = immediate_context
            .ok_or_else(|| anyhow!("D3D11CreateDevice returned no immediate context"))?;

        tracing::info!(
            driver = driver_name,
            feature_level = ?unsafe { device.GetFeatureLevel() },
            "D3D11 device created"
        );

        Ok(Self {
            device,
            immediate_context,
            video_texture: None,
            _video_shader_view: None,
            video_texture_size: None,
            nv12_y_texture: None,
            nv12_uv_texture: None,
            _nv12_y_view: None,
            _nv12_uv_view: None,
            nv12_texture_size: None,
            swap_chain: None,
            swap_chain_hwnd: 0,
            render_target_view: None,
            swap_chain_size: None,
            vertex_shader: None,
            pixel_shader: None,
            nv12_pixel_shader: None,
            nv12_shader_uses_bt709: None,
            nv12_color_matrix_override: None,
            sampler: None,
            stats_window_started: Instant::now(),
            stats_frames: 0,
            stats_upload_total_ms: 0.0,
            stats_upload_max_ms: 0.0,
            stats_present_total_ms: 0.0,
            stats_present_max_ms: 0.0,
            _thread_affinity: PhantomData,
        })
    }

    /// Create the HWND-bound DXGI swap chain and its back-buffer render target.
    ///
    /// Ensure the HWND swap chain and its render target match the preview surface.
    fn ensure_swap_chain(&mut self, hwnd: HWND, width: u32, height: u32) -> anyhow::Result<()> {
        if width == 0 || height == 0 || width > 16384 || height > 16384 {
            bail!("invalid DXGI surface dimensions: {width}x{height}");
        }

        let requested_hwnd = hwnd.0 as isize;
        if self.swap_chain.is_some() && self.swap_chain_hwnd != requested_hwnd {
            // A hidden child HWND can be destroyed and recreated when the
            // preview is hidden or its GPUI parent changes. DXGI swap chains
            // remain bound to their original HWND. Unbind the RTV first:
            // the immediate context itself retains a reference to it.
            // SAFETY: the render target belongs to this immediate context.
            unsafe {
                self.immediate_context.OMSetRenderTargets(
                    None,
                    None::<&windows_062::Win32::Graphics::Direct3D11::ID3D11DepthStencilView>,
                );
            }
            self.render_target_view = None;
            self.swap_chain = None;
            self.swap_chain_size = None;
            self.swap_chain_hwnd = 0;
            tracing::info!(
                hwnd = format!("{requested_hwnd:#x}"),
                "Rebinding D3D11 swap chain to recreated native video surface"
            );
        }

        if self.swap_chain.is_none() {
            // Follow the D3D11 device -> DXGI device -> adapter -> factory path.
            let dxgi_device: IDXGIDevice = self
                .device
                .cast()
                .context("could not query IDXGIDevice from the D3D11 device")?;
            // SAFETY: the device is a live D3D11 device owned by this renderer.
            let adapter =
                unsafe { dxgi_device.GetAdapter() }.context("IDXGIDevice::GetAdapter failed")?;
            // SAFETY: adapter is a valid DXGI adapter returned by the device.
            let factory: IDXGIFactory2 = unsafe { adapter.GetParent() }
                .context("IDXGIAdapter::GetParent(IDXGIFactory2) failed")?;

            let desc = DXGI_SWAP_CHAIN_DESC1 {
                Width: width,
                Height: height,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                Stereo: BOOL(0),
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: 2,
                Scaling: DXGI_SCALING_STRETCH,
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL,
                AlphaMode: DXGI_ALPHA_MODE_IGNORE,
                Flags: 0,
            };

            // SAFETY: hwnd is the child window created by this module; desc
            // satisfies flip-model requirements (BGRA8, 2 buffers, 1x MSAA).
            let swap_chain = unsafe {
                factory.CreateSwapChainForHwnd(
                    &self.device,
                    hwnd,
                    &desc,
                    None,
                    None::<&windows_062::Win32::Graphics::Dxgi::IDXGIOutput>,
                )
            }
            .context("IDXGIFactory2::CreateSwapChainForHwnd failed")?;
            self.swap_chain = Some(swap_chain);
            self.swap_chain_hwnd = requested_hwnd;
            self.swap_chain_size = Some((width, height));
            if let Err(error) = self.rebuild_render_target() {
                // Do not leave a half-initialized HWND-bound chain behind.
                // The next sync can retry creation from a clean state.
                self.swap_chain = None;
                self.swap_chain_size = None;
                self.swap_chain_hwnd = 0;
                return Err(error).context("could not initialize the new swap-chain render target");
            }
            tracing::info!(
                width,
                height,
                "D3D11 HWND swap chain created; native surface remains hidden"
            );
        } else {
            if self.swap_chain_size != Some((width, height)) {
                // Unbind the RTV before dropping our reference. D3D11's immediate
                // context otherwise keeps the old back buffer alive and
                // ResizeBuffers can fail with DXGI_ERROR_INVALID_CALL.
                // SAFETY: the render target belongs to this immediate context.
                unsafe {
                    self.immediate_context.OMSetRenderTargets(
                        None,
                        None::<&windows_062::Win32::Graphics::Direct3D11::ID3D11DepthStencilView>,
                    );
                }
                self.render_target_view = None;
                let swap_chain = self
                    .swap_chain
                    .as_ref()
                    .ok_or_else(|| anyhow!("DXGI swap chain unexpectedly absent"))?;
                // SAFETY: swap chain belongs to this renderer and all old RTV refs
                // have been dropped before resizing its buffers.
                unsafe {
                    swap_chain.ResizeBuffers(
                        0,
                        width,
                        height,
                        DXGI_FORMAT_UNKNOWN,
                        DXGI_SWAP_CHAIN_FLAG(0),
                    )
                }
                .context("IDXGISwapChain::ResizeBuffers failed")?;
                // Record the successful buffer resize before RTV creation. If
                // GetBuffer/CreateRenderTargetView fails, the next sync retries
                // RTV creation without issuing ResizeBuffers a second time.
                self.swap_chain_size = Some((width, height));
                tracing::debug!(width, height, "D3D11 swap chain buffers resized");
            }

            // RTV creation is independently retryable after a transient failure.
            if self.render_target_view.is_none() {
                self.rebuild_render_target()
                    .context("could not restore the swap-chain render target")?;
            }
        }

        Ok(())
    }

    /// Reacquire buffer zero and create the RTV after creation or resize.
    fn rebuild_render_target(&mut self) -> anyhow::Result<()> {
        let swap_chain = self
            .swap_chain
            .as_ref()
            .ok_or_else(|| anyhow!("cannot create RTV without a swap chain"))?;
        // SAFETY: buffer zero is the swap chain's current back buffer.
        let back_buffer: ID3D11Texture2D =
            unsafe { swap_chain.GetBuffer(0) }.context("IDXGISwapChain::GetBuffer failed")?;
        let mut render_target = None;
        // SAFETY: back_buffer is a valid render-target-capable swap-chain buffer.
        unsafe {
            self.device
                .CreateRenderTargetView(&back_buffer, None, Some(&mut render_target))
        }
        .context("ID3D11Device::CreateRenderTargetView failed")?;
        self.render_target_view =
            Some(render_target.ok_or_else(|| anyhow!("D3D11 returned no swap-chain RTV"))?);
        Ok(())
    }

    /// Clear and Present once to validate the swap chain without showing it.
    fn present_diagnostic_clear(&self) -> anyhow::Result<()> {
        let target = self
            .render_target_view
            .as_ref()
            .ok_or_else(|| anyhow!("swap-chain render target is not initialized"))?;
        let swap_chain = self
            .swap_chain
            .as_ref()
            .ok_or_else(|| anyhow!("swap chain is not initialized"))?;

        // SAFETY: target belongs to this device; the immediate context is
        // confined to the current GPUI thread.
        unsafe {
            self.immediate_context
                .ClearRenderTargetView(target, &[0.035, 0.045, 0.065, 1.0]);
            swap_chain.Present(1, DXGI_PRESENT(0)).ok()
        }
        .context("IDXGISwapChain::Present failed during renderer bootstrap")?;
        Ok(())
    }

    /// Compile the fullscreen-triangle shaders and create a linear clamp sampler.
    fn ensure_video_pipeline(&mut self) -> anyhow::Result<()> {
        if self.vertex_shader.is_some() && self.pixel_shader.is_some() && self.sampler.is_some() {
            return Ok(());
        }

        const SOURCE: &[u8] = br#"
struct VertexOutput {
    float4 position : SV_Position;
    float2 uv : TEXCOORD0;
};
VertexOutput VSMain(uint vertex_id : SV_VertexID) {
    VertexOutput output;
    float2 position = float2((vertex_id == 2) ? 3.0 : -1.0,
                             (vertex_id == 1) ? 3.0 : -1.0);
    output.position = float4(position, 0.0, 1.0);
    output.uv = float2((position.x + 1.0) * 0.5, (1.0 - position.y) * 0.5);
    return output;
}
Texture2D<float4> video_frame : register(t0);
SamplerState video_sampler : register(s0);
float4 PSMain(VertexOutput input) : SV_Target {
    return video_frame.Sample(video_sampler, input.uv);
}
"#;

        let compile = |entry: &'static std::ffi::CStr,
                       target: &'static std::ffi::CStr|
         -> anyhow::Result<Vec<u8>> {
            let mut bytecode: Option<ID3DBlob> = None;
            // SAFETY: SOURCE and compiler strings remain alive for the call;
            // bytecode is a valid writable COM output slot.
            unsafe {
                D3DCompile(
                    SOURCE.as_ptr().cast(),
                    SOURCE.len(),
                    PCSTR(c"rust-phone-control-video.hlsl".as_ptr().cast()),
                    None,
                    None,
                    PCSTR(entry.as_ptr().cast()),
                    PCSTR(target.as_ptr().cast()),
                    D3DCOMPILE_ENABLE_STRICTNESS,
                    0,
                    &mut bytecode,
                    None,
                )
            }
            .context("D3DCompile failed for the video shader")?;
            let bytecode = bytecode.ok_or_else(|| anyhow!("D3DCompile returned no bytecode"))?;
            // SAFETY: ID3DBlob owns a valid buffer for its reported size.
            let bytes = unsafe {
                slice::from_raw_parts(
                    bytecode.GetBufferPointer().cast::<u8>(),
                    bytecode.GetBufferSize(),
                )
            };
            Ok(bytes.to_vec())
        };

        let vs_code = compile(c"VSMain", c"vs_4_0")?;
        let ps_code = compile(c"PSMain", c"ps_4_0")?;
        let mut vertex_shader = None;
        // SAFETY: shader bytecode was produced by D3DCompile for this device.
        unsafe {
            self.device
                .CreateVertexShader(&vs_code, None, Some(&mut vertex_shader))
        }
        .context("CreateVertexShader failed")?;
        let mut pixel_shader = None;
        // SAFETY: shader bytecode was produced by D3DCompile for this device.
        unsafe {
            self.device
                .CreatePixelShader(&ps_code, None, Some(&mut pixel_shader))
        }
        .context("CreatePixelShader failed")?;

        let sampler_desc = D3D11_SAMPLER_DESC {
            Filter: D3D11_FILTER_MIN_MAG_MIP_LINEAR,
            AddressU: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressV: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressW: D3D11_TEXTURE_ADDRESS_CLAMP,
            MipLODBias: 0.0,
            MaxAnisotropy: 1,
            ComparisonFunc: D3D11_COMPARISON_NEVER,
            BorderColor: [0.0; 4],
            MinLOD: 0.0,
            MaxLOD: f32::MAX,
        };
        let mut sampler = None;
        // SAFETY: sampler_desc is fully initialized for linear clamp sampling.
        unsafe {
            self.device
                .CreateSamplerState(&sampler_desc, Some(&mut sampler))
        }
        .context("CreateSamplerState failed")?;

        self.vertex_shader = vertex_shader;
        self.pixel_shader = pixel_shader;
        self.sampler = sampler;
        tracing::info!("D3D11 fullscreen video shader pipeline created");
        Ok(())
    }

    /// Compile a limited-range BT.601 NV12 conversion shader.
    fn ensure_nv12_pixel_shader(&mut self, width: u32, height: u32) -> anyhow::Result<()> {
        // Prefer SPS VUI colorimetry; retain resolution heuristic only when the stream omits it.
        let use_bt709 = self
            .nv12_color_matrix_override
            .unwrap_or(width >= 1280 || height >= 720);
        if self.nv12_pixel_shader.is_some() && self.nv12_shader_uses_bt709 == Some(use_bt709) {
            return Ok(());
        }
        self.nv12_pixel_shader = None;
        self.nv12_shader_uses_bt709 = None;
        let coefficients = if use_bt709 {
            (1.792741_f32, -0.213249_f32, -0.532909_f32, 2.112402_f32)
        } else {
            (1.596027_f32, -0.391762_f32, -0.812968_f32, 2.017232_f32)
        };
        let source = format!(
            r#"
struct VertexOutput {{
    float4 position : SV_Position;
    float2 uv : TEXCOORD0;
}};
Texture2D<float> luma_plane : register(t0);
Texture2D<float2> chroma_plane : register(t1);
SamplerState video_sampler : register(s0);
float4 PSMain(VertexOutput input) : SV_Target {{
    float y = max(luma_plane.Sample(video_sampler, input.uv).r * 255.0 - 16.0, 0.0);
    float2 chroma = chroma_plane.Sample(video_sampler, input.uv).rg * 255.0 - 128.0;
    float cb = chroma.x;
    float cr = chroma.y;
    float3 rgb = float3(
        (1.164383 * y + {0} * cr) / 255.0,
        (1.164383 * y + {1} * cb + {2} * cr) / 255.0,
        (1.164383 * y + {3} * cb) / 255.0
    );
    return float4(saturate(rgb), 1.0);
}}
"#,
            coefficients.0, coefficients.1, coefficients.2, coefficients.3
        );
        let source = source.as_bytes();
        let mut bytecode: Option<ID3DBlob> = None;
        // SAFETY: shader source and entry-point strings remain alive during compilation.
        unsafe {
            D3DCompile(
                source.as_ptr().cast(),
                source.len(),
                PCSTR(c"rust-phone-control-nv12.hlsl".as_ptr().cast()),
                None,
                None,
                PCSTR(c"PSMain".as_ptr().cast()),
                PCSTR(c"ps_4_0".as_ptr().cast()),
                D3DCOMPILE_ENABLE_STRICTNESS,
                0,
                &mut bytecode,
                None,
            )
        }
        .context("D3DCompile failed for the NV12 pixel shader")?;
        let bytecode =
            bytecode.ok_or_else(|| anyhow!("D3DCompile returned no NV12 shader bytecode"))?;
        // SAFETY: the blob owns a valid byte range for its reported size.
        let code = unsafe {
            slice::from_raw_parts(
                bytecode.GetBufferPointer().cast::<u8>(),
                bytecode.GetBufferSize(),
            )
        };
        let mut shader = None;
        // SAFETY: bytecode was compiled for a D3D11 pixel shader.
        unsafe { self.device.CreatePixelShader(code, None, Some(&mut shader)) }
            .context("CreatePixelShader failed for NV12")?;
        self.nv12_pixel_shader =
            Some(shader.ok_or_else(|| anyhow!("D3D11 returned no NV12 pixel shader"))?);
        self.nv12_shader_uses_bt709 = Some(use_bt709);
        tracing::info!(
            matrix = if use_bt709 { "BT.709" } else { "BT.601" },
            width,
            height,
            "D3D11 NV12 color-conversion shader created"
        );
        Ok(())
    }

    /// Sample the uploaded Y and UV planes and present the converted RGB frame.
    fn draw_nv12_frame(&mut self) -> anyhow::Result<std::time::Duration> {
        self.ensure_video_pipeline()?;
        self.ensure_nv12_pixel_shader(
            self.nv12_texture_size.map(|size| size.0).unwrap_or(0),
            self.nv12_texture_size.map(|size| size.1).unwrap_or(0),
        )?;
        let target = self
            .render_target_view
            .as_ref()
            .ok_or_else(|| anyhow!("swap-chain render target is not initialized"))?;
        let swap_chain = self
            .swap_chain
            .as_ref()
            .ok_or_else(|| anyhow!("swap chain is not initialized"))?;
        let y_view = self
            ._nv12_y_view
            .as_ref()
            .ok_or_else(|| anyhow!("NV12 Y shader view is not initialized"))?;
        let uv_view = self
            ._nv12_uv_view
            .as_ref()
            .ok_or_else(|| anyhow!("NV12 UV shader view is not initialized"))?;
        let (width, height) = self
            .swap_chain_size
            .ok_or_else(|| anyhow!("swap-chain dimensions are not initialized"))?;
        let (frame_width, frame_height) = self
            .nv12_texture_size
            .ok_or_else(|| anyhow!("NV12 texture dimensions are not initialized"))?;
        let [viewport_x, viewport_y, viewport_width, viewport_height] =
            fit_video_viewport(width, height, frame_width, frame_height)
                .ok_or_else(|| anyhow!("cannot fit a zero-sized video frame or preview surface"))?;
        let viewport = [D3D11_VIEWPORT {
            TopLeftX: viewport_x,
            TopLeftY: viewport_y,
            Width: viewport_width,
            Height: viewport_height,
            MinDepth: 0.0,
            MaxDepth: 1.0,
        }];
        let vertex_shader = self.vertex_shader.as_ref().expect("pipeline initialized");
        let pixel_shader = self
            .nv12_pixel_shader
            .as_ref()
            .expect("NV12 shader initialized");
        let sampler = self.sampler.as_ref().expect("pipeline initialized");
        let targets = [Some(target.clone())];
        let resources = [Some(y_view.clone()), Some(uv_view.clone())];
        let samplers = [Some(sampler.clone())];
        let present_started = Instant::now();
        // SAFETY: resources belong to this D3D11 device and its immediate
        // context is confined to the GPUI thread that created the device.
        unsafe {
            self.immediate_context
                .ClearRenderTargetView(target, &[0.0, 0.0, 0.0, 1.0]);
            self.immediate_context.OMSetRenderTargets(
                Some(&targets),
                None::<&windows_062::Win32::Graphics::Direct3D11::ID3D11DepthStencilView>,
            );
            self.immediate_context.RSSetViewports(Some(&viewport));
            self.immediate_context
                .IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            self.immediate_context.VSSetShader(vertex_shader, None);
            self.immediate_context.PSSetShader(pixel_shader, None);
            self.immediate_context
                .PSSetShaderResources(0, Some(&resources));
            self.immediate_context.PSSetSamplers(0, Some(&samplers));
            self.immediate_context.Draw(3, 0);
            self.immediate_context
                .PSSetShaderResources(0, Some(&[None, None]));
            swap_chain.Present(1, DXGI_PRESENT(0)).ok()
        }
        .context("D3D11 NV12 draw or IDXGISwapChain::Present failed")?;
        Ok(present_started.elapsed())
    }

    /// Draw the latest uploaded BGRA frame into the swap-chain back buffer.
    fn draw_video_frame(&mut self) -> anyhow::Result<std::time::Duration> {
        self.ensure_video_pipeline()?;
        let target = self
            .render_target_view
            .as_ref()
            .ok_or_else(|| anyhow!("swap-chain render target is not initialized"))?;
        let swap_chain = self
            .swap_chain
            .as_ref()
            .ok_or_else(|| anyhow!("swap chain is not initialized"))?;
        let shader_view = self
            ._video_shader_view
            .as_ref()
            .ok_or_else(|| anyhow!("video shader-resource view is not initialized"))?;
        let (width, height) = self
            .swap_chain_size
            .ok_or_else(|| anyhow!("swap-chain dimensions are not initialized"))?;
        let (frame_width, frame_height) = self
            .video_texture_size
            .ok_or_else(|| anyhow!("video texture dimensions are not initialized"))?;

        // Fit the source frame inside the preview surface without stretching.
        // The unused area is cleared to black (letterbox or pillarbox).
        let [viewport_x, viewport_y, viewport_width, viewport_height] =
            fit_video_viewport(width, height, frame_width, frame_height)
                .ok_or_else(|| anyhow!("cannot fit a zero-sized video frame or preview surface"))?;
        let viewport = [D3D11_VIEWPORT {
            TopLeftX: viewport_x,
            TopLeftY: viewport_y,
            Width: viewport_width,
            Height: viewport_height,
            MinDepth: 0.0,
            MaxDepth: 1.0,
        }];
        let vertex_shader = self.vertex_shader.as_ref().expect("pipeline initialized");
        let pixel_shader = self.pixel_shader.as_ref().expect("pipeline initialized");
        let sampler = self.sampler.as_ref().expect("pipeline initialized");
        let targets = [Some(target.clone())];
        let resources = [Some(shader_view.clone())];
        let samplers = [Some(sampler.clone())];
        // SAFETY: all resources belong to this D3D11 device and the immediate
        // context is confined to its creating GPUI thread.
        let present_started = Instant::now();
        unsafe {
            self.immediate_context
                .ClearRenderTargetView(target, &[0.0, 0.0, 0.0, 1.0]);
            self.immediate_context.OMSetRenderTargets(
                Some(&targets),
                None::<&windows_062::Win32::Graphics::Direct3D11::ID3D11DepthStencilView>,
            );
            self.immediate_context.RSSetViewports(Some(&viewport));
            self.immediate_context
                .IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            self.immediate_context.VSSetShader(vertex_shader, None);
            self.immediate_context.PSSetShader(pixel_shader, None);
            self.immediate_context
                .PSSetShaderResources(0, Some(&resources));
            self.immediate_context.PSSetSamplers(0, Some(&samplers));
            self.immediate_context.Draw(3, 0);
            self.immediate_context
                .PSSetShaderResources(0, Some(&[None]));
            swap_chain.Present(1, DXGI_PRESENT(0)).ok()
        }
        .context("D3D11 video draw or IDXGISwapChain::Present failed")?;
        Ok(present_started.elapsed())
    }

    /// Create or resize the BGRA texture and upload a frame into it.
    fn upload_bgra(
        &mut self,
        width: u32,
        height: u32,
        stride: usize,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if width == 0 || height == 0 || width > 8192 || height > 8192 {
            bail!("invalid D3D11 video texture dimensions: {width}x{height}");
        }

        let row_bytes = usize::try_from(width)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or_else(|| anyhow!("BGRA row size overflow"))?;
        if stride < row_bytes {
            bail!("BGRA stride {stride} is smaller than row size {row_bytes}");
        }
        // D3D11 reads row_bytes from each row. Padding is needed between
        // rows, but not after the final row in the caller's backing buffer.
        let rows_before_last =
            usize::try_from(height - 1).context("BGRA frame height exceeds the address space")?;
        let required_bytes = stride
            .checked_mul(rows_before_last)
            .and_then(|bytes| bytes.checked_add(row_bytes))
            .ok_or_else(|| anyhow!("BGRA frame size overflow"))?;
        if data.len() < required_bytes {
            bail!(
                "BGRA frame buffer is truncated: {} bytes available, {required_bytes} required",
                data.len()
            );
        }
        let row_pitch = u32::try_from(stride).context("BGRA row pitch exceeds the D3D11 limit")?;
        const MAX_BGRA_UPLOAD_BYTES: usize = 128 * 1024 * 1024;
        let upload_bytes = stride
            .checked_mul(height as usize)
            .ok_or_else(|| anyhow!("BGRA upload size overflow"))?;
        if upload_bytes > MAX_BGRA_UPLOAD_BYTES {
            bail!("BGRA upload exceeds the 128 MiB limit: {upload_bytes} bytes");
        }

        // The immediate context unbinds the previous frame's SRVs after each
        // draw. Release the inactive pixel format so format switches do not
        // retain an entire second set of GPU textures and views.
        self.nv12_y_texture = None;
        self.nv12_uv_texture = None;
        self._nv12_y_view = None;
        self._nv12_uv_view = None;
        self.nv12_texture_size = None;

        if self.video_texture_size != Some((width, height))
            || self.video_texture.is_none()
            || self._video_shader_view.is_none()
        {
            let desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: windows_062::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
            };
            let mut texture = None;
            // SAFETY: desc is fully initialized and the output slot is valid.
            unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut texture)) }
                .context("could not create the D3D11 BGRA video texture")?;
            let texture = texture.ok_or_else(|| anyhow!("D3D11 returned no video texture"))?;

            let mut shader_view = None;
            // SAFETY: texture is a valid shader-resource texture created above.
            unsafe {
                self.device
                    .CreateShaderResourceView(&texture, None, Some(&mut shader_view))
            }
            .context("could not create the D3D11 video shader-resource view")?;

            let shader_view = shader_view
                .ok_or_else(|| anyhow!("D3D11 returned no BGRA shader-resource view"))?;
            self.video_texture = Some(texture);
            self._video_shader_view = Some(shader_view);
            self.video_texture_size = Some((width, height));
            tracing::info!(width, height, "D3D11 video texture allocated");
        }

        let texture = self
            .video_texture
            .as_ref()
            .ok_or_else(|| anyhow!("D3D11 video texture is unexpectedly absent"))?;
        // SAFETY: data contains at least stride * height bytes; row_pitch is
        // validated above; the texture dimensions match the supplied frame.
        unsafe {
            self.immediate_context.UpdateSubresource(
                texture,
                0,
                None,
                data.as_ptr().cast::<c_void>(),
                row_pitch,
                0,
            );
        }
        Ok(())
    }

    /// Upload the Y and interleaved UV planes of an NV12 frame into separate
    /// shader-readable D3D11 textures. Conversion to RGB is intentionally left
    /// to the NV12 pixel shader added by the presentation path.
    #[allow(dead_code)]
    fn upload_nv12(
        &mut self,
        width: u32,
        height: u32,
        y_stride: usize,
        uv_stride: usize,
        data: &[u8],
        color_matrix: crate::airplay::AvcColorMatrix,
    ) -> anyhow::Result<()> {
        self.nv12_color_matrix_override = match color_matrix {
            crate::airplay::AvcColorMatrix::Bt601 => Some(false),
            crate::airplay::AvcColorMatrix::Bt709 => Some(true),
            crate::airplay::AvcColorMatrix::Unspecified => None,
        };
        if width == 0
            || height == 0
            || width % 2 != 0
            || height % 2 != 0
            || width > 8192
            || height > 8192
        {
            bail!("invalid D3D11 NV12 texture dimensions: {width}x{height}");
        }
        if y_stride < width as usize || uv_stride < width as usize {
            bail!(
                "NV12 plane strides are smaller than frame width {width}: Y={y_stride}, UV={uv_stride}"
            );
        }
        let y_bytes = y_stride
            .checked_mul(height as usize)
            .ok_or_else(|| anyhow!("NV12 Y-plane size overflow"))?;
        let uv_rows_before_last = height as usize / 2 - 1;
        let uv_required = uv_stride
            .checked_mul(uv_rows_before_last)
            .and_then(|bytes| bytes.checked_add(width as usize))
            .ok_or_else(|| anyhow!("NV12 UV-plane size overflow"))?;
        let required = y_bytes
            .checked_add(uv_required)
            .ok_or_else(|| anyhow!("NV12 frame size overflow"))?;
        if data.len() < required {
            bail!(
                "NV12 frame buffer is truncated: {} bytes available, {required} required",
                data.len()
            );
        }
        let uv_full_len = uv_stride
            .checked_mul(height as usize / 2)
            .ok_or_else(|| anyhow!("NV12 UV upload size overflow"))?;
        let full_frame_bytes = y_bytes
            .checked_add(uv_full_len)
            .ok_or_else(|| anyhow!("NV12 full upload size overflow"))?;
        const MAX_NV12_UPLOAD_BYTES: usize = 128 * 1024 * 1024;
        if full_frame_bytes > MAX_NV12_UPLOAD_BYTES {
            bail!("NV12 padded upload exceeds the 128 MiB limit: {full_frame_bytes} bytes");
        }
        let y_row_pitch =
            u32::try_from(y_stride).context("NV12 Y row pitch exceeds the D3D11 limit")?;
        let uv_row_pitch =
            u32::try_from(uv_stride).context("NV12 UV row pitch exceeds the D3D11 limit")?;

        // Drop the inactive BGRA resources after its SRV was unbound by the
        // previous successful draw. Keep only the active frame format resident.
        self.video_texture = None;
        self._video_shader_view = None;
        self.video_texture_size = None;

        // Most decoder buffers already include final-row padding. Only make a
        // padded scratch plane when the source omits that final padding.
        let uv_upload = if uv_required == uv_full_len {
            None
        } else {
            let mut padded = vec![0u8; uv_full_len];
            padded[..uv_required].copy_from_slice(&data[y_bytes..y_bytes + uv_required]);
            Some(padded)
        };
        if self.nv12_texture_size != Some((width, height))
            || self.nv12_y_texture.is_none()
            || self.nv12_uv_texture.is_none()
            || self._nv12_y_view.is_none()
            || self._nv12_uv_view.is_none()
        {
            let make_desc = |texture_width, texture_height, format| D3D11_TEXTURE2D_DESC {
                Width: texture_width,
                Height: texture_height,
                MipLevels: 1,
                ArraySize: 1,
                Format: format,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: 0,
            };
            let y_desc = make_desc(width, height, DXGI_FORMAT_R8_UNORM);
            let uv_desc = make_desc(width / 2, height / 2, DXGI_FORMAT_R8G8_UNORM);
            let mut y_texture = None;
            let mut uv_texture = None;
            // SAFETY: descriptors are fully initialized and output slots are valid.
            unsafe {
                self.device
                    .CreateTexture2D(&y_desc, None, Some(&mut y_texture))
                    .context("could not create the D3D11 NV12 Y texture")?;
                self.device
                    .CreateTexture2D(&uv_desc, None, Some(&mut uv_texture))
                    .context("could not create the D3D11 NV12 UV texture")?;
            }
            let y_texture = y_texture.ok_or_else(|| anyhow!("D3D11 returned no NV12 Y texture"))?;
            let uv_texture =
                uv_texture.ok_or_else(|| anyhow!("D3D11 returned no NV12 UV texture"))?;
            let mut y_view = None;
            let mut uv_view = None;
            // SAFETY: both textures were created with D3D11_BIND_SHADER_RESOURCE.
            unsafe {
                self.device
                    .CreateShaderResourceView(&y_texture, None, Some(&mut y_view))
                    .context("could not create the D3D11 NV12 Y shader view")?;
                self.device
                    .CreateShaderResourceView(&uv_texture, None, Some(&mut uv_view))
                    .context("could not create the D3D11 NV12 UV shader view")?;
            }
            let y_view =
                y_view.ok_or_else(|| anyhow!("D3D11 returned no NV12 Y shader-resource view"))?;
            let uv_view =
                uv_view.ok_or_else(|| anyhow!("D3D11 returned no NV12 UV shader-resource view"))?;
            self.nv12_y_texture = Some(y_texture);
            self.nv12_uv_texture = Some(uv_texture);
            self._nv12_y_view = Some(y_view);
            self._nv12_uv_view = Some(uv_view);
            self.nv12_texture_size = Some((width, height));
            tracing::info!(
                width,
                height,
                y_stride,
                uv_stride,
                "D3D11 NV12 plane textures allocated"
            );
        }

        let y_texture = self
            .nv12_y_texture
            .as_ref()
            .ok_or_else(|| anyhow!("NV12 Y texture is unavailable"))?;
        let uv_texture = self
            .nv12_uv_texture
            .as_ref()
            .ok_or_else(|| anyhow!("NV12 UV texture is unavailable"))?;
        // SAFETY: each plane's dimensions and row pitch match its texture;
        // data has been checked through the last visible UV row.
        unsafe {
            self.immediate_context.UpdateSubresource(
                y_texture,
                0,
                None,
                data.as_ptr().cast::<c_void>(),
                y_row_pitch,
                0,
            );
            let uv_source = if let Some(padded) = uv_upload.as_ref() {
                padded.as_ptr()
            } else {
                data.as_ptr().add(y_bytes)
            };
            self.immediate_context.UpdateSubresource(
                uv_texture,
                0,
                None,
                uv_source.cast::<c_void>(),
                uv_row_pitch,
                0,
            );
        }
        Ok(())
    }

    /// Return the Direct3D feature level for diagnostics.
    pub(crate) fn feature_level(&self) -> D3D_FEATURE_LEVEL {
        // SAFETY: GetFeatureLevel reads immutable device capability metadata.
        unsafe { self.device.GetFeatureLevel() }
    }
}

#[cfg(test)]
mod viewport_tests {
    use super::fit_video_viewport;

    fn assert_close(actual: f32, expected: f32) {
        assert!((actual - expected).abs() < 0.01, "{actual} != {expected}");
    }

    #[test]
    fn high_resolution_wheel_deltas_accumulate_until_one_detent() {
        let mut remainder = 0;
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, 30), 0);
        assert_eq!(remainder, 30);
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, 45), 0);
        assert_eq!(remainder, 75);
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, 45), -1);
        assert_eq!(remainder, 0);
    }

    #[test]
    fn wheel_direction_and_partial_reverse_motion_are_preserved() {
        let mut remainder = 0;
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, -60), 0);
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, 30), 0);
        assert_eq!(remainder, -30);
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, -90), 1);
        assert_eq!(remainder, 0);
    }

    #[test]
    fn wheel_delta_can_emit_multiple_steps_without_overflow() {
        let mut remainder = 0;
        assert_eq!(super::accumulate_wheel_delta(&mut remainder, 360), -3);
        assert_eq!(remainder, 0);
    }

    #[test]
    fn recovery_cooldown_is_active_only_before_deadline() {
        let now = std::time::Instant::now();
        let deadline = now + std::time::Duration::from_secs(2);

        assert!(super::recovery_cooldown_active(now, Some(deadline)));
        assert!(!super::recovery_cooldown_active(deadline, Some(deadline)));
        assert!(!super::recovery_cooldown_active(
            deadline + std::time::Duration::from_nanos(1),
            Some(deadline),
        ));
        assert!(!super::recovery_cooldown_active(now, None));
    }

    #[test]
    fn fits_landscape_frame_inside_portrait_preview() {
        let viewport = fit_video_viewport(1080, 1920, 1920, 1080).unwrap();
        assert_close(viewport[0], 0.0);
        assert_close(viewport[1], 656.25);
        assert_close(viewport[2], 1080.0);
        assert_close(viewport[3], 607.5);
    }

    #[test]
    fn fits_portrait_frame_inside_landscape_preview() {
        let viewport = fit_video_viewport(1920, 1080, 1080, 1920).unwrap();
        assert_close(viewport[0], 656.25);
        assert_close(viewport[1], 0.0);
        assert_close(viewport[2], 607.5);
        assert_close(viewport[3], 1080.0);
    }

    #[test]
    fn preserves_matching_aspect_ratio() {
        let viewport = fit_video_viewport(1280, 720, 1920, 1080).unwrap();
        assert_eq!(viewport, [0.0, 0.0, 1280.0, 720.0]);
    }

    #[test]
    fn rejects_zero_dimensions() {
        assert!(fit_video_viewport(0, 720, 1920, 1080).is_none());
        assert!(fit_video_viewport(1280, 720, 0, 1080).is_none());
    }

    #[test]
    fn centers_square_frame_inside_wide_preview() {
        let viewport = fit_video_viewport(1920, 1080, 800, 800).unwrap();
        assert_close(viewport[0], 420.0);
        assert_close(viewport[1], 0.0);
        assert_close(viewport[2], 1080.0);
        assert_close(viewport[3], 1080.0);
    }

    #[test]
    fn viewport_never_exceeds_surface_bounds_for_extreme_aspect_ratios() {
        for (surface_width, surface_height, frame_width, frame_height) in [
            (1920, 1080, 4096, 512),
            (1080, 1920, 512, 4096),
            (1280, 720, 1, u32::MAX),
            (720, 1280, u32::MAX, 1),
        ] {
            let viewport =
                fit_video_viewport(surface_width, surface_height, frame_width, frame_height)
                    .unwrap();
            assert!(
                viewport
                    .iter()
                    .all(|value| value.is_finite() && *value >= 0.0)
            );
            assert!(viewport[0] + viewport[2] <= surface_width as f32 + 0.01);
            assert!(viewport[1] + viewport[3] <= surface_height as f32 + 0.01);
            assert_close(viewport[0] * 2.0 + viewport[2], surface_width as f32);
            assert_close(viewport[1] * 2.0 + viewport[3], surface_height as f32);
        }
    }
}
