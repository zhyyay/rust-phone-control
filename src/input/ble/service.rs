//! Windows HID-over-GATT peripheral services.
//!
//! This implementation targets a Report Host (the iPhone AssistiveTouch path). It exposes
//! HID Report characteristics. Windows reserves Device Information Service
//! (0x180A), so this app must not attempt to publish it. It deliberately does not publish Protocol
//! Mode because Boot Protocol characteristics are not implemented.

use anyhow::{Context, Result, anyhow, bail};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use windows_062::{
    Devices::Bluetooth::{
        BluetoothError,
        GenericAttributeProfile::{
            GattCharacteristicProperties, GattCommunicationStatus, GattLocalCharacteristic,
            GattLocalCharacteristicParameters, GattLocalDescriptorParameters, GattLocalService,
            GattProtectionLevel, GattReadRequestedEventArgs, GattServiceProvider,
            GattServiceProviderAdvertisementStatusChangedEventArgs,
            GattServiceProviderAdvertisingParameters, GattWriteOption, GattWriteRequestedEventArgs,
        },
    },
    Foundation::TypedEventHandler,
    Storage::Streams::{DataReader, DataWriter},
    core::{GUID, IInspectable},
};

use super::descriptor::{
    HID_CONTROL_POINT, HID_INFORMATION, HID_INFORMATION_VALUE, HID_REPORT, HID_REPORT_MAP,
    HID_REPORT_MAP_CHARACTERISTIC, HID_REPORT_REFERENCE,
};
use super::reports::{KeyboardReport, MouseReport};

/// A running, single-active-phone HID peripheral.
pub struct BleHidService {
    providers: Vec<GattServiceProvider>,
    mouse_report: GattLocalCharacteristic,
    keyboard_report: GattLocalCharacteristic,
    suspended: Arc<AtomicBool>,
    mouse_state: Arc<Mutex<Vec<u8>>>,
    keyboard_state: Arc<Mutex<Vec<u8>>>,
    subscription_generation: Arc<AtomicU64>,
}

impl BleHidService {
    /// Creates the HID GATT service and starts advertising.
    pub async fn start() -> Result<Self> {
        let (hid_provider, hid_service) = create_primary_service(0x1812)
            .await
            .context("creating HID GATT service provider")?;

        create_static_characteristic(
            &hid_service,
            HID_INFORMATION,
            &HID_INFORMATION_VALUE,
            GattCharacteristicProperties::Read,
        )
        .await
        .context("creating HID Information characteristic")?;

        create_static_characteristic(
            &hid_service,
            HID_REPORT_MAP_CHARACTERISTIC,
            HID_REPORT_MAP,
            GattCharacteristicProperties::Read,
        )
        .await
        .context("creating HID Report Map characteristic")?;

        let suspended = Arc::new(AtomicBool::new(false));
        let mouse_state = Arc::new(Mutex::new(vec![0; 4]));
        let keyboard_state = Arc::new(Mutex::new(vec![0; 8]));
        let subscription_generation = Arc::new(AtomicU64::new(0));
        let control_point = create_characteristic(
            &hid_service,
            HID_CONTROL_POINT,
            GattCharacteristicProperties::Write
                | GattCharacteristicProperties::WriteWithoutResponse,
        )
        .await
        .context("creating HID Control Point characteristic")?;

        let callback_runtime = tokio::runtime::Handle::current();
        let control_point_suspended = Arc::clone(&suspended);
        let control_point_mouse_state = Arc::clone(&mouse_state);
        let control_point_keyboard_state = Arc::clone(&keyboard_state);
        let control_point_subscription_generation = Arc::clone(&subscription_generation);
        control_point.WriteRequested(&TypedEventHandler::<
            GattLocalCharacteristic,
            GattWriteRequestedEventArgs,
        >::new(move |_sender, args| {
            if let Some(args) = args.cloned() {
                let deferral = args.GetDeferral()?;
                let suspended = Arc::clone(&control_point_suspended);
                let mouse_state = Arc::clone(&control_point_mouse_state);
                let keyboard_state = Arc::clone(&control_point_keyboard_state);
                let subscription_generation = Arc::clone(&control_point_subscription_generation);
                let runtime = callback_runtime.clone();
                runtime.spawn(async move {
                    let result = async {
                        let request = args.GetRequestAsync()?.await?;
                        if request.Offset()? != 0 {
                            if request.Option()? == GattWriteOption::WriteWithResponse {
                                request.RespondWithProtocolError(0x07)?;
                            }
                            return Ok::<(), windows_062::core::Error>(());
                        }

                        let reader = DataReader::FromBuffer(&request.Value()?)?;
                        if reader.UnconsumedBufferLength()? != 1 {
                            if request.Option()? == GattWriteOption::WriteWithResponse {
                                request.RespondWithProtocolError(0x0D)?;
                            }
                            return Ok::<(), windows_062::core::Error>(());
                        }

                        match reader.ReadByte()? {
                            0x00 => {
                                suspended.store(true, Ordering::Release);
                                *mouse_state.lock().unwrap_or_else(|p| p.into_inner()) = vec![0; 4];
                                *keyboard_state.lock().unwrap_or_else(|p| p.into_inner()) =
                                    vec![0; 8];
                                subscription_generation.fetch_add(1, Ordering::AcqRel);
                            }
                            0x01 => {
                                suspended.store(false, Ordering::Release);
                                subscription_generation.fetch_add(1, Ordering::AcqRel);
                            }
                            _ => {
                                if request.Option()? == GattWriteOption::WriteWithResponse {
                                    request.RespondWithProtocolError(0x80)?;
                                }
                                return Ok(());
                            }
                        }

                        if request.Option()? == GattWriteOption::WriteWithResponse {
                            request.Respond()?;
                        }
                        Ok(())
                    }
                    .await;

                    if let Err(error) = result {
                        tracing::warn!("HID Control Point write failed: {error}");
                    }
                    if let Err(error) = deferral.Complete() {
                        tracing::warn!("HID Control Point deferral completion failed: {error}");
                    }
                });
            }
            Ok(())
        }))?;

        let mouse_report =
            create_input_report_characteristic(&hid_service, Arc::clone(&mouse_state))
                .await
                .context("creating mouse input Report characteristic")?;
        add_report_reference(&mouse_report, 1).await?;

        let keyboard_report =
            create_input_report_characteristic(&hid_service, Arc::clone(&keyboard_state))
                .await
                .context("creating keyboard input Report characteristic")?;
        add_report_reference(&keyboard_report, 2).await?;

        // A BLE link can be connected without the HID host subscribing to input reports.
        // Track CCCD subscriptions separately so the probe can distinguish the two states.
        let mouse_subscription_state = Arc::clone(&mouse_state);
        let mouse_subscription_generation = Arc::clone(&subscription_generation);
        mouse_report.SubscribedClientsChanged(&TypedEventHandler::<
            GattLocalCharacteristic,
            IInspectable,
        >::new(move |sender, _args| {
            let sender = sender.ok()?;
            match sender.SubscribedClients() {
                Ok(clients) => {
                    let count = clients.Size().unwrap_or(0);
                    tracing::info!(count, "iPhone mouse HID report subscription count changed");
                    if count == 0 {
                        *mouse_subscription_state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = vec![0; 4];
                        mouse_subscription_generation.fetch_add(1, Ordering::AcqRel);
                    }
                }
                Err(error) => {
                    tracing::warn!("Could not read mouse HID subscribed clients: {error}")
                }
            }
            Ok(())
        }))?;
        let keyboard_subscription_state = Arc::clone(&keyboard_state);
        let keyboard_subscription_generation = Arc::clone(&subscription_generation);
        keyboard_report.SubscribedClientsChanged(&TypedEventHandler::<
            GattLocalCharacteristic,
            IInspectable,
        >::new(move |sender, _args| {
            let sender = sender.ok()?;
            match sender.SubscribedClients() {
                Ok(clients) => {
                    let count = clients.Size().unwrap_or(0);
                    tracing::info!(count, "iPhone keyboard HID report subscription count changed");
                    if count == 0 {
                        *keyboard_subscription_state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = vec![0; 8];
                        keyboard_subscription_generation.fetch_add(1, Ordering::AcqRel);
                    }
                }
                Err(error) => {
                    tracing::warn!("Could not read keyboard HID subscribed clients: {error}")
                }
            }
            Ok(())
        }))?;

        tracing::info!("HID mouse and keyboard report subscription diagnostics are enabled");

        // Windows reserves Device Information Service (0x180A) for the system.
        // Applications receive BluetoothError::DisabledByPolicy when trying to publish it.
        // Publish HID alone during the first radio test: a second GATT provider advertising
        // simultaneously may cause Windows to abort advertising on some adapters. Battery
        // Service can be restored after single-provider advertising is verified.
        let providers = vec![hid_provider];
        for provider in &providers {
            provider.AdvertisementStatusChanged(&TypedEventHandler::<
                GattServiceProvider,
                GattServiceProviderAdvertisementStatusChangedEventArgs,
            >::new(move |_sender, args| {
                if let Some(args) = args.cloned() {
                    tracing::info!(
                        status = ?args.Status(),
                        error = ?args.Error(),
                        "Windows BLE GATT advertising status changed"
                    );
                }
                Ok(())
            }))?;
            let advertising = GattServiceProviderAdvertisingParameters::new()?;
            advertising.SetIsDiscoverable(true)?;
            advertising.SetIsConnectable(true)?;
            if let Err(error) = provider.StartAdvertisingWithParameters(&advertising) {
                for started_provider in &providers {
                    let _ = started_provider.StopAdvertising();
                }
                return Err(error).context("starting Windows BLE GATT advertising");
            }
        }

        tracing::info!(
            "Windows HID-over-GATT advertising request submitted (Report Host, single active controller)"
        );
        Ok(Self {
            providers,
            mouse_report,
            keyboard_report,
            suspended,
            mouse_state,
            keyboard_state,
            subscription_generation,
        })
    }

    /// Sends a four-byte mouse input report to subscribed GATT clients.
    pub async fn send_mouse_report(&self, report: MouseReport) -> Result<()> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let report_bytes = report.as_bytes();
        *self.mouse_state.lock().unwrap_or_else(|p| p.into_inner()) = report_bytes.to_vec();
        let buffer = buffer_from_bytes(&report_bytes)?;
        let results = self
            .mouse_report
            .NotifyValueAsync(&buffer)?
            .await
            .context("sending mouse HID notification")?;

        for index in 0..results.Size()? {
            let result = results.GetAt(index)?;
            let status = result.Status()?;
            if status != GattCommunicationStatus::Success {
                bail!(
                    "mouse HID notification failed for a subscribed client: {status:?}                      (protocol error: {:?})",
                    result.ProtocolError()
                );
            }
        }
        Ok(())
    }

    /// Sends an eight-byte keyboard input report to subscribed GATT clients.
    pub async fn send_keyboard_report(&self, report: KeyboardReport) -> Result<()> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let report_bytes = report.as_bytes();
        *self
            .keyboard_state
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = report_bytes.to_vec();
        let buffer = buffer_from_bytes(&report_bytes)?;
        let results = self
            .keyboard_report
            .NotifyValueAsync(&buffer)?
            .await
            .context("sending keyboard HID notification")?;

        for index in 0..results.Size()? {
            let result = results.GetAt(index)?;
            let status = result.Status()?;
            if status != GattCommunicationStatus::Success {
                bail!(
                    "keyboard HID notification failed for a subscribed client: {status:?}                      (protocol error: {:?})",
                    result.ProtocolError()
                );
            }
        }
        Ok(())
    }

    /// Returns whether the HID host has suspended input reports.
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::Acquire)
    }

    /// Returns a generation that changes whenever input delivery is interrupted.
    pub fn subscription_generation(&self) -> u64 {
        self.subscription_generation.load(Ordering::Acquire)
    }

    /// Stops advertising all published GATT services.
    pub fn stop(&self) -> Result<()> {
        self.suspended.store(true, Ordering::Release);
        *self.mouse_state.lock().unwrap_or_else(|p| p.into_inner()) = vec![0; 4];
        *self.keyboard_state.lock().unwrap_or_else(|p| p.into_inner()) = vec![0; 8];
        self.subscription_generation.fetch_add(1, Ordering::AcqRel);

        let mut first_error = None;
        for provider in &self.providers {
            if let Err(error) = provider.StopAdvertising() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error).context("stopping one or more Windows BLE GATT services");
        }
        Ok(())
    }

    /// Returns the current Windows advertising status for every published service.
    pub fn advertising_status(&self) -> Result<String> {
        self.providers
            .iter()
            .map(|provider| Ok(format!("{:?}", provider.AdvertisementStatus()?)))
            .collect::<Result<Vec<_>>>()
            .map(|statuses| statuses.join(", "))
    }
}

async fn create_primary_service(
    short_uuid: u16,
) -> Result<(GattServiceProvider, GattLocalService)> {
    let uuid = bluetooth_uuid(short_uuid);
    let create_result = GattServiceProvider::CreateAsync(uuid)?
        .await
        .context("creating Windows GATT service provider")?;

    let error = create_result.Error()?;
    if error != BluetoothError::Success {
        bail!("Windows refused GATT service 0x{short_uuid:04X}: {error:?}");
    }

    let provider = create_result.ServiceProvider()?;
    let service = provider.Service()?;
    Ok((provider, service))
}

async fn create_static_characteristic(
    service: &GattLocalService,
    short_uuid: u16,
    value: &[u8],
    properties: GattCharacteristicProperties,
) -> Result<GattLocalCharacteristic> {
    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(properties)?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::EncryptionRequired)?;
    let buffer = buffer_from_bytes(value)?;
    parameters.SetStaticValue(&buffer)?;

    let uuid = bluetooth_uuid(short_uuid);
    let result = service
        .CreateCharacteristicAsync(uuid, &parameters)?
        .await?;
    let error = result.Error()?;
    if error != BluetoothError::Success {
        return Err(anyhow!(
            "creating characteristic 0x{short_uuid:04X} failed: {error:?}"
        ));
    }
    Ok(result.Characteristic()?)
}

async fn create_characteristic(
    service: &GattLocalService,
    short_uuid: u16,
    properties: GattCharacteristicProperties,
) -> Result<GattLocalCharacteristic> {
    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(properties)?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::EncryptionRequired)?;
    parameters.SetWriteProtectionLevel(GattProtectionLevel::EncryptionRequired)?;

    let uuid = bluetooth_uuid(short_uuid);
    let result = service
        .CreateCharacteristicAsync(uuid, &parameters)?
        .await?;
    let error = result.Error()?;
    if error != BluetoothError::Success {
        return Err(anyhow!(
            "creating characteristic 0x{short_uuid:04X} failed: {error:?}"
        ));
    }
    Ok(result.Characteristic()?)
}

async fn create_input_report_characteristic(
    service: &GattLocalService,
    current_report: Arc<Mutex<Vec<u8>>>,
) -> Result<GattLocalCharacteristic> {
    let characteristic = create_characteristic(
        service,
        HID_REPORT,
        GattCharacteristicProperties::Read | GattCharacteristicProperties::Notify,
    )
    .await?;

    let callback_runtime = tokio::runtime::Handle::current();
    characteristic.ReadRequested(&TypedEventHandler::<
        GattLocalCharacteristic,
        GattReadRequestedEventArgs,
    >::new(move |_sender, args| {
        if let Some(args) = args.cloned() {
            let deferral = args.GetDeferral()?;
            let current_report = Arc::clone(&current_report);
            let runtime = callback_runtime.clone();
            runtime.spawn(async move {
                let result = async {
                    let request = args.GetRequestAsync()?.await?;
                    let report = current_report
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone();
                    let writer = DataWriter::new()?;
                    writer.WriteBytes(&report)?;
                    request.RespondWithValue(&writer.DetachBuffer()?)?;
                    Ok::<(), windows_062::core::Error>(())
                }
                .await;

                if let Err(error) = result {
                    tracing::warn!("HID input report read failed: {error}");
                }
                if let Err(error) = deferral.Complete() {
                    tracing::warn!("HID input report deferral completion failed: {error}");
                }
            });
        }
        Ok(())
    }))?;

    Ok(characteristic)
}

async fn add_report_reference(
    characteristic: &GattLocalCharacteristic,
    report_id: u8,
) -> Result<()> {
    let parameters = GattLocalDescriptorParameters::new()?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::EncryptionRequired)?;
    let buffer = buffer_from_bytes(&[report_id, 0x01])?;
    parameters.SetStaticValue(&buffer)?;
    let uuid = bluetooth_uuid(HID_REPORT_REFERENCE);
    let result = characteristic
        .CreateDescriptorAsync(uuid, &parameters)?
        .await?;
    let error = result.Error()?;
    if error != BluetoothError::Success {
        bail!("creating Report Reference descriptor for report {report_id} failed: {error:?}");
    }
    Ok(())
}

fn bluetooth_uuid(short_uuid: u16) -> GUID {
    GUID::from_u128(((short_uuid as u128) << 96) | 0x0000_1000_8000_0080_5F9B_34FB)
}

fn buffer_from_bytes(bytes: &[u8]) -> Result<windows_062::Storage::Streams::IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;
    Ok(writer.DetachBuffer()?)
}
