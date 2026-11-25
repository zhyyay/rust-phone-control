//! Windows Direct3D 11 video presenter.
//!
//! Device, immediate context, swap chain, shaders, and frame texture stay on the GPUI render thread.

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
            D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL, D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
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
                DXGI_ALPHA_MODE_IGNORE, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_UNKNOWN,
                DXGI_SAMPLE_DESC,
            },
            DXGI_PRESENT, DXGI_SCALING_STRETCH, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_CHAIN_FLAG,
            DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL, DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGIAdapter,
            IDXGIDevice, IDXGIFactory2, IDXGISwapChain1,
        },
    },
    UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, SW_HIDE, SW_SHOW, SWP_NOACTIVATE, SWP_NOOWNERZORDER,
        SWP_NOREDRAW, SWP_NOZORDER, SetWindowPos, ShowWindow, WINDOW_EX_STYLE, WS_CHILD,
        WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
    },
};
use windows_062::core::{BOOL, Interface, PCSTR, PCWSTR};

static PRESENTED_FRAMES: AtomicU64 = AtomicU64::new(0);
static UPLOADED_FRAMES: AtomicU64 = AtomicU64::new(0);
static RENDER_RECOVERY_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

/// Process-wide D3D11 counters; safe to read from the GPUI diagnostics poll.
pub(crate) fn preview_metrics() -> (u64, u64, u64) {
    (
        PRESENTED_FRAMES.load(Ordering::Relaxed),
        UPLOADED_FRAMES.load(Ordering::Relaxed),
        RENDER_RECOVERY_ATTEMPTS.load(Ordering::Relaxed),
    )
}

thread_local! {
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

/// Create and synchronize a hidden native child surface within the GPUI preview rectangle.
///
/// The child uses the built-in STATIC window class, avoiding a custom WndProc or
/// process-global class registration. It remains hidden so the GPUI image fallback
/// stays visible until a D3D11 SwapChain presenter is implemented.
pub(crate) fn sync_native_video_surface(
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> anyhow::Result<()> {
    if width <= 0 || height <= 0 {
        destroy_native_video_surface();
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
        // D3D11 immediate context. It remains hidden until a real decoded frame
        // is drawn by the shader presenter in the next stage.
        THREAD_RENDERER.with(|renderer| {
            let mut renderer = renderer.borrow_mut();
            let device = renderer
                .as_mut()
                .ok_or_else(|| anyhow!("D3D11 renderer is not initialized"))?;
            device.ensure_swap_chain(child_hwnd, width as u32, height as u32)
        })?;

        // Never expose the diagnostic clear color as if it were a phone image.
        unsafe {
            ShowWindow(child_hwnd, SW_HIDE);
        }
        Ok(())
    })
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
        device.upload_bgra(width, height, stride, data)?;
        UPLOADED_FRAMES.fetch_add(1, Ordering::Relaxed);
        device.draw_video_frame()
    });

    let present_time = match initial_result {
        Ok(elapsed) => elapsed,
        Err(original_error) => {
            RENDER_RECOVERY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
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
                .with(|retry_after| retry_after.get().is_some_and(|deadline| now < deadline));
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

            tracing::warn!(
                error = %reason,
                "D3D11 device was removed; rebuilding preview device and resources"
            );
            let mut replacement = D3d11Device::create_hardware()
                .context("could not recreate D3D11 device after device removal")?;
            replacement.ensure_swap_chain(
                HWND(child_raw as *mut c_void),
                surface_width,
                surface_height,
            )?;
            THREAD_RENDERER.with(|renderer| {
                *renderer.borrow_mut() = Some(replacement);
            });
            DEVICE_RECOVERY_RETRY_AFTER.with(|retry_after| retry_after.set(None));

            THREAD_RENDERER
                .with(|renderer| {
                    let mut renderer = renderer.borrow_mut();
                    let device = renderer
                        .as_mut()
                        .ok_or_else(|| anyhow!("replacement D3D11 device is unavailable"))?;
                    device.upload_bgra(width, height, stride, data)?;
                    UPLOADED_FRAMES.fetch_add(1, Ordering::Relaxed);
                    device.draw_video_frame()
                })
                .context("D3D11 preview retry failed after device recreation")?
        }
    };

    PRESENTED_FRAMES.fetch_add(1, Ordering::Relaxed);

    let stats_result: anyhow::Result<()> = THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer is unavailable after Present"))?;
        device.stats_frames += 1;
        let elapsed = device.stats_window_started.elapsed();
        if elapsed >= std::time::Duration::from_secs(1) {
            let fps = device.stats_frames as f64 / elapsed.as_secs_f64();
            tracing::info!(
                fps,
                present_ms = present_time.as_secs_f64() * 1000.0,
                frames = device.stats_frames,
                "D3D11 preview performance"
            );
            device.stats_frames = 0;
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
    swap_chain: Option<IDXGISwapChain1>,
    swap_chain_hwnd: isize,
    render_target_view: Option<ID3D11RenderTargetView>,
    swap_chain_size: Option<(u32, u32)>,
    vertex_shader: Option<ID3D11VertexShader>,
    pixel_shader: Option<ID3D11PixelShader>,
    sampler: Option<ID3D11SamplerState>,
    stats_window_started: Instant,
    stats_frames: u64,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl D3d11Device {
    /// Create a hardware-backed D3D11 device with BGRA interoperability enabled.
    pub(crate) fn create_hardware() -> anyhow::Result<Self> {
        let mut device = None;
        let mut immediate_context = None;

        // SAFETY: output pointers refer to valid, writable Option slots for the
        // duration of the call. The adapter is null to select the default GPU.
        unsafe {
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
        }
        .context("D3D11CreateDevice failed for the default hardware adapter")?;

        let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice returned no device"))?;
        let immediate_context = immediate_context
            .ok_or_else(|| anyhow!("D3D11CreateDevice returned no immediate context"))?;

        tracing::info!(
            feature_level = ?unsafe { device.GetFeatureLevel() },
            "D3D11 hardware device created"
        );

        Ok(Self {
            device,
            immediate_context,
            video_texture: None,
            _video_shader_view: None,
            video_texture_size: None,
            swap_chain: None,
            swap_chain_hwnd: 0,
            render_target_view: None,
            swap_chain_size: None,
            vertex_shader: None,
            pixel_shader: None,
            sampler: None,
            stats_window_started: Instant::now(),
            stats_frames: 0,
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
            // remain bound to their original HWND, so release every back-buffer
            // reference and create a fresh chain for the new child.
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
            self.rebuild_render_target()?;
            tracing::info!(
                width,
                height,
                "D3D11 HWND swap chain created; native surface remains hidden"
            );
        } else if self.swap_chain_size != Some((width, height)) {
            // Release the RTV before ResizeBuffers; DXGI requires all
            // references to old back buffers to be released.
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
            self.swap_chain_size = Some((width, height));
            self.rebuild_render_target()?;
            tracing::debug!(width, height, "D3D11 swap chain resized");
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
        let surface_aspect = width as f32 / height as f32;
        let frame_aspect = frame_width as f32 / frame_height as f32;
        let (viewport_width, viewport_height) = if frame_aspect > surface_aspect {
            (width as f32, width as f32 / frame_aspect)
        } else {
            (height as f32 * frame_aspect, height as f32)
        };
        let viewport = [D3D11_VIEWPORT {
            TopLeftX: (width as f32 - viewport_width) * 0.5,
            TopLeftY: (height as f32 - viewport_height) * 0.5,
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
        let required_bytes = stride
            .checked_mul(height as usize)
            .ok_or_else(|| anyhow!("BGRA frame size overflow"))?;
        if data.len() < required_bytes {
            bail!(
                "BGRA frame buffer is truncated: {} bytes available, {required_bytes} required",
                data.len()
            );
        }
        let row_pitch = u32::try_from(stride).context("BGRA row pitch exceeds the D3D11 limit")?;

        if self.video_texture_size != Some((width, height)) {
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

            self.video_texture = Some(texture);
            self._video_shader_view = shader_view;
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

    /// Return the Direct3D feature level for diagnostics.
    pub(crate) fn feature_level(&self) -> D3D_FEATURE_LEVEL {
        // SAFETY: GetFeatureLevel reads immutable device capability metadata.
        unsafe { self.device.GetFeatureLevel() }
    }
}
