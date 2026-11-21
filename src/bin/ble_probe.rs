#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use rust_phone_control::input::ble::{service::BleHidService, windows::probe_hid_peripheral};

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Checking Windows BLE HID peripheral capability...");
    let capability = probe_hid_peripheral().await?;
    println!("Adapter: {:?}", capability.adapter_id);
    println!("Status: {:?}", capability.status);

    if !matches!(
        capability.status,
        rust_phone_control::input::ble::BleCapabilityStatus::Supported
    ) {
        anyhow::bail!("The adapter is not ready to host a BLE HID peripheral.");
    }

    println!("Creating HID GATT service and starting BLE advertising...");
    let service = BleHidService::start().await?;
    let advertising_status = service.advertising_status()?;
    println!("HID GATT advertising status: {advertising_status}");
    if advertising_status.contains("(3)") {
        eprintln!(
            "WARNING: Windows aborted GATT advertising. Check the status-change event log above for the BluetoothError."
        );
    }
    println!("Keep this window open while pairing your iPhone. Press Ctrl+C to stop.");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Stopping BLE HID advertising...");
            service.stop()?;
        }
        _ = std::future::pending::<()>() => {}
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ble-probe is available only on Windows.");
}
