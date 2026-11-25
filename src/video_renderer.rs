//! Windows Direct3D 11 device ownership for the native video renderer.
//!
//! This module deliberately creates only the D3D11 device and immediate
//! context. Swap-chain/window integration is a later step after the GPUI
//! native-window lifecycle is verified. Keep this owner on the render thread.

use anyhow::{Context as _, anyhow};
use std::{marker::PhantomData, rc::Rc};
use windows_062::{
    Win32::{
        Foundation::HMODULE,
        Graphics::{
            Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL},
            Direct3D11::{
                D3D11CreateDevice, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
                ID3D11Device, ID3D11DeviceContext,
            },
            Dxgi::IDXGIAdapter,
        },
    },
};

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
