//! Windows HID-over-GATT peripheral services.
//!
//! This implementation targets a Report Host (the iPhone AssistiveTouch path). It exposes
//! HID Report characteristics, Battery Service, and Device Information Service. It deliberately
//! does not publish Protocol Mode because Boot Protocol characteristics are not implemented.

use anyhow::{Context, Result, anyhow, bail};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use windows_062::{
    Devices::Bluetooth::{
        BluetoothError,
        GenericAttributeProfile::{
            GattCharacteristic, GattCharacteristicProperties, GattDescriptor,
            GattLocalCharacteristic, GattLocalCharacteristicParameters, GattLocalDescriptorParameters,
            GattLocalService, GattProtectionLevel, GattReadRequestedEventArgs, GattServiceProvider,
            GattServiceProviderAdvertisingParameters, GattWriteOption, GattWriteRequestedEventArgs,
        },
    },
    Foundation::{TypedEventHandler, GUID},
    Storage::Streams::{DataReader, DataWriter},
};

use super::descriptor::{
    HID_CONTROL_POINT, HID_INFORMATION, HID_INFORMATION_VALUE, HID_REPORT,
    HID_REPORT_MAP, HID_REPORT_MAP_CHARACTERISTIC, HID_REPORT_REFERENCE,
};
use super::reports::{KeyboardReport, MouseReport};

const BATTERY_SERVICE_UUID: u16 = 0x180F;
const BATTERY_LEVEL_UUID: u16 = 0x2A19;
const DEVICE_INFORMATION_SERVICE_UUID: u16 = 0x180A;
const PNP_ID_UUID: u16 = 0x2A50;
const BATTERY_LEVEL_PERCENT: u8 = 100;

// USB-IF's reserved test VID, product 1, version 1.0.0. Replace with an assigned VID/PID
// before distributing this application as a product.
const TEST_PNP_ID: [u8; 7] = [0x01, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x01];

/// A running, single-active-phone HID peripheral.
pub struct BleHidService {
    providers: Vec<GattServiceProvider>,
    mouse_report: GattLocalCharacteristic,
    keyboard_report: GattLocalCharacteristic,
    suspended: Arc<AtomicBool>,
}

impl BleHidService {
    /// Creates the HID, Battery, and Device Information GATT services and starts advertising.
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
        let control_point = create_characteristic(
            &hid_service,
            HID_CONTROL_POINT,
            GattCharacteristicProperties::Write
                | GattCharacteristicProperties::WriteWithoutResponse,
        )
        .await
        .context("creating HID Control Point characteristic")?;

        let control_point_suspended = Arc::clone(&suspended);
        control_point.WriteRequested(&TypedEventHandler::<
            GattLocalCharacteristic,
            GattWriteRequestedEventArgs,
        >::new(move |_sender, args| {
            if let Some(args) = args.cloned() {
                let deferral = args.GetDeferral()?;
                let suspended = Arc::clone(&control_point_suspended);
                tokio::spawn(async move {
                    let result = async {
                        let request = args.GetRequestAsync()?.await?;
                        let reader = DataReader::FromBuffer(&request.Value()?)?;
                        if reader.UnconsumedBufferLength()? != 1 {
                            if request.Option()? == GattWriteOption::WriteWithResponse {
                                request.RespondWithProtocolError(0x0D)?;
                            }
                            return Ok::<(), windows_062::core::Error>(());
                        }

                        match reader.ReadByte()? {
                            0x00 => suspended.store(true, Ordering::Release),
                            0x01 => suspended.store(false, Ordering::Release),
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

        let mouse_report = create_input_report_characteristic(&hid_service, 4)
            .await
            .context("creating mouse input Report characteristic")?;
        add_report_reference(&mouse_report, 1).await?;

        let keyboard_report = create_input_report_characteristic(&hid_service, 8)
            .await
            .context("creating keyboard input Report characteristic")?;
        add_report_reference(&keyboard_report, 2).await?;

        // HOGP Report Hosts require both Battery Service and Device Information Service.
        let (battery_provider, battery_service) =
            create_primary_service(BATTERY_SERVICE_UUID)
                .await
                .context("creating Battery Service provider")?;
        create_static_characteristic(
            &battery_service,
            BATTERY_LEVEL_UUID,
            &[BATTERY_LEVEL_PERCENT],
            GattCharacteristicProperties::Read,
        )
        .await
        .context("creating Battery Level characteristic")?;

        let (device_info_provider, device_info_service) =
            create_primary_service(DEVICE_INFORMATION_SERVICE_UUID)
                .await
                .context("creating Device Information Service provider")?;
        create_static_characteristic(
            &device_info_service,
            PNP_ID_UUID,
            &TEST_PNP_ID,
            GattCharacteristicProperties::Read,
        )
        .await
        .context("creating PnP ID characteristic")?;

        let providers = vec![hid_provider, battery_provider, device_info_provider];
        for provider in &providers {
            let advertising = GattServiceProviderAdvertisingParameters::new()?;
            advertising.SetIsDiscoverable(true)?;
            advertising.SetIsConnectable(true)?;
            provider
                .StartAdvertisingWithParameters(&advertising)
                .context("starting Windows BLE GATT advertising")?;
        }

        tracing::info!(
            "Windows HID-over-GATT services are advertising (Report Host, single active controller)"
        );
        Ok(Self {
            providers,
            mouse_report,
            keyboard_report,
            suspended,
        })
    }

    /// Sends a four-byte mouse input report to subscribed GATT clients.
    pub async fn send_mouse_report(&self, report: MouseReport) -> Result<()> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let buffer = buffer_from_bytes(&report.as_bytes())?;
        self.mouse_report
            .NotifyValueAsync(&buffer)?
            .await
            .context("sending mouse HID notification")?;
        Ok(())
    }

    /// Sends an eight-byte keyboard input report to subscribed GATT clients.
    pub async fn send_keyboard_report(&self, report: KeyboardReport) -> Result<()> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let buffer = buffer_from_bytes(&report.as_bytes())?;
        self.keyboard_report
            .NotifyValueAsync(&buffer)?
            .await
            .context("sending keyboard HID notification")?;
        Ok(())
    }

    /// Stops advertising all published GATT services.
    pub fn stop(&self) -> Result<()> {
        for provider in &self.providers {
            provider.StopAdvertising()?;
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

async fn create_primary_service(short_uuid: u16) -> Result<(GattServiceProvider, GattLocalService)> {
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
    report_len: usize,
) -> Result<GattLocalCharacteristic> {
    let characteristic = create_characteristic(
        service,
        HID_REPORT,
        GattCharacteristicProperties::Read | GattCharacteristicProperties::Notify,
    )
    .await?;

    characteristic.ReadRequested(&TypedEventHandler::<
        GattLocalCharacteristic,
        GattReadRequestedEventArgs,
    >::new(move |_sender, args| {
        if let Some(args) = args.cloned() {
            let deferral = args.GetDeferral()?;
            tokio::spawn(async move {
                let result = async {
                    let request = args.GetRequestAsync()?.await?;
                    let writer = DataWriter::new()?;
                    writer.WriteBytes(&vec![0; report_len])?;
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
