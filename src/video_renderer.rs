//! Windows Direct3D 11 device ownership for the native video renderer.
//!
//! This module deliberately creates only the D3D11 device and immediate
//! context. Swap-chain/window integration is a later step after the GPUI
//! native-window lifecycle is verified. Keep this owner on the render thread.

use anyhow::{Context as _, anyhow};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::{cell::RefCell, marker::PhantomData, rc::Rc};
use windows_062::Win32::{
    Foundation::HMODULE,
    Graphics::{
        Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL},
        Direct3D11::{
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11CreateDevice, ID3D11Device,
            ID3D11DeviceContext,
        },
        Dxgi::IDXGIAdapter,
    },
};

thread_local! {
    /// D3D11 immediate contexts remain on the GPUI thread that first initializes them.
    static THREAD_RENDERER: RefCell<Option<D3d11Device>> = const { RefCell::new(None) };
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

    THREAD_RENDERER.with(|renderer| {
        let mut renderer = renderer.borrow_mut();
        if renderer.is_none() {
            *renderer = Some(D3d11Device::create_hardware()?);
            tracing::info!("D3D11 device attached to the GPUI render thread");
        }
        Ok(hwnd)
    })
}

/// Owns the D3D11 device and immediate context on the thread that created it.
///
/// The Rc marker intentionally makes this type !Send and !Sync. D3D11
/// immediate-context calls and renderer resource lifetime stay on one thread.
pub(crate) struct D3d11Device {
    device: ID3D11Device,
    _immediate_context: ID3D11DeviceContext,
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
            _immediate_context: immediate_context,
            _thread_affinity: PhantomData,
        })
    }

    /// Return the Direct3D feature level for diagnostics.
    pub(crate) fn feature_level(&self) -> D3D_FEATURE_LEVEL {
        // SAFETY: GetFeatureLevel reads immutable device capability metadata.
        unsafe { self.device.GetFeatureLevel() }
    }
}
