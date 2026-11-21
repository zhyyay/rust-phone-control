//! Windows HID-over-GATT peripheral service.
//!
//! Publishes the standard HID service. Mouse and keyboard input reports are dynamic
//! notify characteristics; callers send reports after an iPhone subscribes.

use anyhow::{anyhow, bail, Context, Result};
use windows_062::{
    Devices::Bluetooth::{
        BluetoothError,
        GenericAttributeProfile::{
            GattCharacteristic, GattCharacteristicProperties, GattDescriptor,
            GattLocalCharacteristic, GattLocalCharacteristicParameters,
            GattLocalDescriptorParameters, GattProtectionLevel, GattReadRequestedEventArgs,
            GattServiceProvider, GattServiceProviderAdvertisingParameters, GattServiceUuids,
            GattWriteOption, GattWriteRequestedEventArgs,
        },
    },
    Foundation::TypedEventHandler,
    Storage::Streams::{DataReader, DataWriter},
};

use super::descriptor::{
    HID_CONTROL_POINT, HID_INFORMATION, HID_INFORMATION_VALUE, HID_PROTOCOL_MODE,
    HID_REPORT_MAP, HID_REPORT_MAP_CHARACTERISTIC, HID_REPORT_REFERENCE,
};
use super::reports::{KeyboardReport, MouseReport};

/// A running, single-active-phone HID peripheral.
pub struct BleHidService {
    provider: GattServiceProvider,
    mouse_report: GattLocalCharacteristic,
    keyboard_report: GattLocalCharacteristic,
}

impl BleHidService {
    /// Creates the HID GATT database and starts connectable BLE advertising.
    pub async fn start() -> Result<Self> {
        let service_uuid = GattServiceUuids::HumanInterfaceDevice()?;
        let create_result = GattServiceProvider::CreateAsync(service_uuid)?
            .await
            .context("creating Windows HID GATT service provider")?;

        let error = create_result.Error()?;
        if error != BluetoothError::Success {
            bail!("Windows refused HID GATT service creation: {error:?}");
        }

        let provider = create_result.ServiceProvider()?;
        let service = provider.Service()?;

        create_static_characteristic(
            &service,
            HID_INFORMATION,
            &HID_INFORMATION_VALUE,
            GattCharacteristicProperties::Read,
        )
        .await
        .context("creating HID Information characteristic")?;

        create_static_characteristic(
            &service,
            HID_REPORT_MAP_CHARACTERISTIC,
            HID_REPORT_MAP,
            GattCharacteristicProperties::Read,
        )
        .await
        .context("creating HID Report Map characteristic")?;

        let control_point = create_characteristic(
            &service,
            HID_CONTROL_POINT,
            GattCharacteristicProperties::Write | GattCharacteristicProperties::WriteWithoutResponse,
        )
        .await
        .context("creating HID Control Point characteristic")?;
        control_point.WriteRequested(
            &TypedEventHandler::<GattLocalCharacteristic, GattWriteRequestedEventArgs>::new(
                |_sender, args| {
                    if let Some(args) = args.cloned() {
                        let deferral = args.GetDeferral()?;
                        tokio::spawn(async move {
                            let result = async {
                                let request = args.GetRequestAsync()?.await?;
                                if request.Option()? == GattWriteOption::WriteWithResponse {
                                    request.Respond()?;
                                }
                                Ok::<(), windows_062::core::Error>(())
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
                },
            ),
        )?;

        let protocol_mode = create_characteristic(
            &service,
            HID_PROTOCOL_MODE,
            GattCharacteristicProperties::Read
                | GattCharacteristicProperties::Write
                | GattCharacteristicProperties::WriteWithoutResponse,
        )
        .await
        .context("creating HID Protocol Mode characteristic")?;
        protocol_mode.WriteRequested(
            &TypedEventHandler::<GattLocalCharacteristic, GattWriteRequestedEventArgs>::new(
                |_sender, args| {
                    if let Some(args) = args.cloned() {
                        let deferral = args.GetDeferral()?;
                        tokio::spawn(async move {
                            let result = async {
                                let request = args.GetRequestAsync()?.await?;
                                let reader = DataReader::FromBuffer(&request.Value()?)?;
                                let requested_mode = reader.ReadByte()?;
                                if requested_mode == 1 {
                                    if request.Option()? == GattWriteOption::WriteWithResponse {
                                        request.Respond()?;
                                    }
                                } else {
                                    request.RespondWithProtocolError(0x03)?;
                                }
                                Ok::<(), windows_062::core::Error>(())
                            }
                            .await;
                            if let Err(error) = result {
                                tracing::warn!("HID Protocol Mode write failed: {error}");
                            }
                            if let Err(error) = deferral.Complete() {
                                tracing::warn!("HID Protocol Mode deferral completion failed: {error}");
                            }
                        });
                    }
                    Ok(())
                },
            ),
        )?;

        let mouse_report = create_input_report_characteristic(&service, 4)
            .await
            .context("creating mouse input Report characteristic")?;
        add_report_reference(&mouse_report, 1).await?;

        let keyboard_report = create_input_report_characteristic(&service, 8)
            .await
            .context("creating keyboard input Report characteristic")?;
        add_report_reference(&keyboard_report, 2).await?;

        let advertising = GattServiceProviderAdvertisingParameters::new()?;
        advertising.SetIsDiscoverable(true)?;
        advertising.SetIsConnectable(true)?;
        provider
            .StartAdvertisingWithParameters(&advertising)
            .context("starting Windows BLE HID advertising")?;

        tracing::info!("Windows HID GATT service is advertising (single active controller)");
        Ok(Self {
            provider,
            mouse_report,
            keyboard_report,
        })
    }

    /// Sends a four-byte mouse input report to subscribed GATT clients.
    pub async fn send_mouse_report(&self, report: MouseReport) -> Result<()> {
        let buffer = buffer_from_bytes(&report.as_bytes())?;
        self.mouse_report
            .NotifyValueAsync(&buffer)?
            .await
            .context("sending mouse HID notification")?;
        Ok(())
    }

    /// Sends an eight-byte keyboard input report to subscribed GATT clients.
    pub async fn send_keyboard_report(&self, report: KeyboardReport) -> Result<()> {
        let buffer = buffer_from_bytes(&report.as_bytes())?;
        self.keyboard_report
            .NotifyValueAsync(&buffer)?
            .await
            .context("sending keyboard HID notification")?;
        Ok(())
    }

    /// Stops advertising. Windows owns the underlying connection lifecycle.
    pub fn stop(&self) -> Result<()> {
        self.provider.StopAdvertising()?;
        Ok(())
    }

    /// Returns the current Windows advertising status for diagnostics.
    pub fn advertising_status(&self) -> Result<String> {
        Ok(format!("{:?}", self.provider.AdvertisementStatus()?))
    }
}

async fn create_static_characteristic(
    service: &windows_062::Devices::Bluetooth::GenericAttributeProfile::GattLocalService,
    short_uuid: u16,
    value: &[u8],
    properties: GattCharacteristicProperties,
) -> Result<GattLocalCharacteristic> {
    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(properties)?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    let buffer = buffer_from_bytes(value)?;
    parameters.SetStaticValue(&buffer)?;

    let uuid = GattCharacteristic::ConvertShortIdToUuid(short_uuid)?;
    let result = service.CreateCharacteristicAsync(uuid, &parameters)?.await?;
    let error = result.Error()?;
    if error != BluetoothError::Success {
        return Err(anyhow!("creating characteristic 0x{short_uuid:04X} failed: {error:?}"));
    }
    Ok(result.Characteristic()?)
}

async fn create_characteristic(
    service: &windows_062::Devices::Bluetooth::GenericAttributeProfile::GattLocalService,
    short_uuid: u16,
    properties: GattCharacteristicProperties,
) -> Result<GattLocalCharacteristic> {
    let parameters = GattLocalCharacteristicParameters::new()?;
    parameters.SetCharacteristicProperties(properties)?;
    parameters.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    parameters.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;

    let uuid = GattCharacteristic::ConvertShortIdToUuid(short_uuid)?;
    let result = service.CreateCharacteristicAsync(uuid, &parameters)?.await?;
    let error = result.Error()?;
    if error != BluetoothError::Success {
        return Err(anyhow!("creating characteristic 0x{short_uuid:04X} failed: {error:?}"));
    }
    Ok(result.Characteristic()?)
}

async fn create_input_report_characteristic(
    service: &windows_062::Devices::Bluetooth::GenericAttributeProfile::GattLocalService,
    report_len: usize,
) -> Result<GattLocalCharacteristic> {
    let characteristic = create_characteristic(
        service,
        super::descriptor::HID_REPORT,
        GattCharacteristicProperties::Read | GattCharacteristicProperties::Notify,
    )
    .await?;

    characteristic.ReadRequested(
        &TypedEventHandler::<GattLocalCharacteristic, GattReadRequestedEventArgs>::new(
            move |_sender, args| {
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
            },
        ),
    )?;

    Ok(characteristic)
}

async fn add_report_reference(characteristic: &GattLocalCharacteristic, report_id: u8) -> Result<()> {
    let parameters = GattLocalDescriptorParameters::new()?;
    let buffer = buffer_from_bytes(&[report_id, 0x01])?;
    parameters.SetStaticValue(&buffer)?;
    let uuid = GattDescriptor::ConvertShortIdToUuid(HID_REPORT_REFERENCE)?;
    let result = characteristic.CreateDescriptorAsync(uuid, &parameters)?.await?;
    let error = result.Error()?;
    if error != BluetoothError::Success {
        bail!("creating Report Reference descriptor for report {report_id} failed: {error:?}");
    }
    Ok(())
}

fn buffer_from_bytes(bytes: &[u8]) -> Result<windows_062::Storage::Streams::IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;
    Ok(writer.DetachBuffer()?)
}
