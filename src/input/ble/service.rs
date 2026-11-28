//! Windows HID-over-GATT peripheral services.
//!
//! This implementation targets a Report Host (the iPhone AssistiveTouch path). It exposes
//! HID Report characteristics. Windows reserves Device Information Service
//! (0x180A), so this app must not attempt to publish it. It deliberately does not publish Protocol
//! Mode because Boot Protocol characteristics are not implemented.

use anyhow::{Context, Result, anyhow, bail};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
use super::reports::{KEYBOARD_REPORT_LEN, MOUSE_REPORT_LEN, KeyboardReport, MouseReport};

/// Observable HID subscription state for the active BLE peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleConnectionState {
    Disconnected,
    PartiallySubscribed,
    Suspended,
    Ready,
}

/// A running, single-active-phone HID peripheral.
pub struct BleHidService {
    providers: Vec<GattServiceProvider>,
    mouse_report: GattLocalCharacteristic,
    keyboard_report: GattLocalCharacteristic,
    suspended: Arc<AtomicBool>,
    stopped: AtomicBool,
    advertising_stopped: AtomicBool,
    mouse_state: Arc<Mutex<Vec<u8>>>,
    keyboard_state: Arc<Mutex<Vec<u8>>>,
    subscription_generation: Arc<AtomicU64>,
    mouse_subscribers: Arc<AtomicUsize>,
    keyboard_subscribers: Arc<AtomicUsize>,
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
        let mouse_state = Arc::new(Mutex::new(vec![0; MOUSE_REPORT_LEN]));
        let keyboard_state = Arc::new(Mutex::new(vec![0; KEYBOARD_REPORT_LEN]));
        let subscription_generation = Arc::new(AtomicU64::new(0));
        let mouse_subscribers = Arc::new(AtomicUsize::new(0));
        let keyboard_subscribers = Arc::new(AtomicUsize::new(0));
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
                                reset_cached_reports(
                                    &mouse_state,
                                    &keyboard_state,
                                    &subscription_generation,
                                );
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
        // Reset cached reports on every CCCD transition so a newly subscribed host never
        // inherits stale held buttons or modifiers from an earlier connection.
        let mouse_subscription_state = Arc::clone(&mouse_state);
        let mouse_subscription_generation = Arc::clone(&subscription_generation);
        let mouse_subscription_count = Arc::clone(&mouse_subscribers);
        mouse_report.SubscribedClientsChanged(&TypedEventHandler::<
            GattLocalCharacteristic,
            IInspectable,
        >::new(move |sender, _args| {
            let sender = sender.ok()?;
            match sender.SubscribedClients() {
                Ok(clients) => {
                    let count = clients.Size().unwrap_or(0);
                    mouse_subscription_count.store(count as usize, Ordering::Release);
                    tracing::info!(count, "iPhone mouse HID report subscription count changed");
                    *mouse_subscription_state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = vec![0; 5];
                    mouse_subscription_generation.fetch_add(1, Ordering::AcqRel);
                }
                Err(error) => {
                    tracing::warn!("Could not read mouse HID subscribed clients: {error}")
                }
            }
            Ok(())
        }))?;
        let keyboard_subscription_state = Arc::clone(&keyboard_state);
        let keyboard_subscription_generation = Arc::clone(&subscription_generation);
        let keyboard_subscription_count = Arc::clone(&keyboard_subscribers);
        keyboard_report.SubscribedClientsChanged(&TypedEventHandler::<
            GattLocalCharacteristic,
            IInspectable,
        >::new(move |sender, _args| {
            let sender = sender.ok()?;
            match sender.SubscribedClients() {
                Ok(clients) => {
                    let count = clients.Size().unwrap_or(0);
                    keyboard_subscription_count.store(count as usize, Ordering::Release);
                    tracing::info!(
                        count,
                        "iPhone keyboard HID report subscription count changed"
                    );
                    *keyboard_subscription_state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()) = vec![0; 8];
                    keyboard_subscription_generation.fetch_add(1, Ordering::AcqRel);
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
            stopped: AtomicBool::new(false),
            advertising_stopped: AtomicBool::new(false),
            mouse_state,
            keyboard_state,
            subscription_generation,
            mouse_subscribers,
            keyboard_subscribers,
        })
    }

    /// Sends a five-byte mouse input report to subscribed GATT clients.
    pub async fn send_mouse_report(&self, report: MouseReport) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            bail!("BLE HID service has stopped");
        }
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
        if self.stopped.load(Ordering::Acquire) {
            bail!("BLE HID service has stopped");
        }
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

    /// Returns whether advertising has been stopped for this service instance.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Reports whether the iPhone subscribed to the mouse and keyboard input reports.
    pub fn connection_state(&self) -> BleConnectionState {
        connection_state_from_flags(
            self.mouse_subscribers.load(Ordering::Acquire) > 0,
            self.keyboard_subscribers.load(Ordering::Acquire) > 0,
            self.suspended.load(Ordering::Acquire),
            self.stopped.load(Ordering::Acquire),
        )
    }

    /// Returns a generation that changes whenever input delivery is interrupted.
    pub fn subscription_generation(&self) -> u64 {
        self.subscription_generation.load(Ordering::Acquire)
    }

    /// Stops advertising all published GATT services.
    pub fn stop(&self) -> Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.suspended.store(true, Ordering::Release);
        reset_cached_reports(
            &self.mouse_state,
            &self.keyboard_state,
            &self.subscription_generation,
        );
        self.mouse_subscribers.store(0, Ordering::Release);
        self.keyboard_subscribers.store(0, Ordering::Release);

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
        self.advertising_stopped.store(true, Ordering::Release);
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

impl Drop for BleHidService {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if self.advertising_stopped.swap(true, Ordering::AcqRel) {
            return;
        }

        for provider in &self.providers {
            if let Err(error) = provider.StopAdvertising() {
                tracing::warn!(
                    error = %error,
                    "BLE HID advertising cleanup retry failed while dropping service"
                );
            }
        }
    }
}

fn reset_cached_reports(
    mouse_state: &Mutex<Vec<u8>>,
    keyboard_state: &Mutex<Vec<u8>>,
    subscription_generation: &AtomicU64,
) {
    *mouse_state.lock().unwrap_or_else(|p| p.into_inner()) = vec![0; MOUSE_REPORT_LEN];
    *keyboard_state.lock().unwrap_or_else(|p| p.into_inner()) = vec![0; 8];
    subscription_generation.fetch_add(1, Ordering::AcqRel);
}

fn connection_state_from_flags(
    mouse_subscribed: bool,
    keyboard_subscribed: bool,
    suspended: bool,
    stopped: bool,
) -> BleConnectionState {
    if stopped || (!mouse_subscribed && !keyboard_subscribed) {
        return BleConnectionState::Disconnected;
    }
    if suspended {
        return BleConnectionState::Suspended;
    }
    match (mouse_subscribed, keyboard_subscribed) {
        (true, true) => BleConnectionState::Ready,
        _ => BleConnectionState::PartiallySubscribed,
    }
}

#[cfg(test)]
mod connection_state_tests {
    use super::{BleConnectionState, connection_state_from_flags};

    #[test]
    fn interruption_clears_both_cached_reports_and_advances_generation() {
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        };

        let mouse = Mutex::new(vec![1, 2, 3, 4]);
        let keyboard = Mutex::new(vec![5, 6, 7, 8, 9, 10, 11, 12]);
        let generation = AtomicU64::new(7);

        super::reset_cached_reports(&mouse, &keyboard, &generation);

        assert_eq!(*mouse.lock().unwrap(), vec![0; 4]);
        assert_eq!(*keyboard.lock().unwrap(), vec![0; 8]);
        assert_eq!(generation.load(Ordering::Acquire), 8);
    }

    #[test]
    fn both_reports_subscribed_means_ready() {
        assert_eq!(
            connection_state_from_flags(true, true, false, false),
            BleConnectionState::Ready
        );
    }

    #[test]
    fn one_report_missing_is_partial() {
        assert_eq!(
            connection_state_from_flags(true, false, false, false),
            BleConnectionState::PartiallySubscribed
        );
        assert_eq!(
            connection_state_from_flags(false, true, false, false),
            BleConnectionState::PartiallySubscribed
        );
    }

    #[test]
    fn no_subscribers_is_disconnected_even_if_suspended() {
        assert_eq!(
            connection_state_from_flags(false, false, true, false),
            BleConnectionState::Disconnected
        );
    }

    #[test]
    fn suspended_subscribed_peer_is_not_reported_ready() {
        assert_eq!(
            connection_state_from_flags(true, true, true, false),
            BleConnectionState::Suspended
        );
    }

    #[test]
    fn stopped_service_is_always_disconnected() {
        assert_eq!(
            connection_state_from_flags(true, true, false, true),
            BleConnectionState::Disconnected
        );
        assert_eq!(
            connection_state_from_flags(true, true, true, true),
            BleConnectionState::Disconnected
        );
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
