//! Windows Direct3D 11 device and video-texture ownership.
//!
//! The device, immediate context, and uploaded frame texture stay on the GPUI
//! render thread. This module does not create a swap chain or draw over GPUI.

use anyhow::{Context as _, anyhow, bail};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    marker::PhantomData,
    rc::Rc,
};
use windows_062::Win32::{
    Foundation::{HMODULE, HWND},
    Graphics::{
        Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL},
        Direct3D11::{
            D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
            D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11CreateDevice, ID3D11Device,
            ID3D11DeviceContext, ID3D11ShaderResourceView, ID3D11Texture2D,
        },
        Dxgi::{Common::DXGI_FORMAT_B8G8R8A8_UNORM, IDXGIAdapter},
    },
    UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, SW_HIDE, SWP_NOACTIVATE, SWP_NOOWNERZORDER, SWP_NOREDRAW,
        SWP_NOZORDER, SetWindowPos, ShowWindow, WINDOW_EX_STYLE, WS_CHILD, WS_CLIPCHILDREN,
        WS_CLIPSIBLINGS,
    },
};
use windows_062::core::PCWSTR;

thread_local! {
    /// D3D11 immediate contexts remain on the GPUI thread that first initializes them.
    static THREAD_RENDERER: RefCell<Option<D3d11Device>> = const { RefCell::new(None) };
    /// Borrowed GPUI parent HWND; never destroyed or re-parented by this module.
    static GPUI_PARENT_HWND: Cell<isize> = const { Cell::new(0) };
    /// Owned child HWND. It stays hidden until a SwapChain presenter is attached.
    static NATIVE_VIDEO_CHILD_HWND: Cell<isize> = const { Cell::new(0) };
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
            tracing::info!(
                hwnd = format!("{child_raw:#x}"),
                parent = format!("{parent:#x}"),
                "Created hidden native video child window"
            );
        }

        let child_hwnd = HWND(child_raw as *mut c_void);
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
        // Keep the child hidden until SwapChain creation and Present are ready.
        unsafe {
            ShowWindow(child_hwnd, SW_HIDE);
        }
        Ok(())
    })
}

/// Destroy only the native child owned by this module; the GPUI parent is borrowed.
pub(crate) fn destroy_native_video_surface() {
    NATIVE_VIDEO_CHILD_HWND.with(|child_cell| {
        let child_raw = child_cell.replace(0);
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
    THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        let device = renderer
            .as_mut()
            .ok_or_else(|| anyhow!("D3D11 renderer has not been initialized for a GPUI window"))?;
        device.upload_bgra(width, height, stride, data)
    })
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
            _thread_affinity: PhantomData,
        })
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
