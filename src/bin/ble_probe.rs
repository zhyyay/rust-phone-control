#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use rust_phone_control::input::ble::{service::BleHidService, windows::probe_hid_peripheral};

    println!("Checking Windows BLE HID peripheral capability...");
    let capability = probe_hid_peripheral().await?;
    println!("Adapter: {:?}", capability.adapter_name);
    println!("Status: {:?}", capability.status);

    if !matches!(
        capability.status,
        rust_phone_control::input::ble::BleCapabilityStatus::Supported
    ) {
        anyhow::bail!("The adapter is not ready to host a BLE HID peripheral.");
    }

    println!("Creating HID GATT service and starting BLE advertising...");
    let service = BleHidService::start().await?;
    println!(
        "HID GATT service is active. Advertising status: {}",
        service.advertising_status()?
    );
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
