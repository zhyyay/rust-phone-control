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
    // Windows may report a transient Aborted status immediately after StartAdvertising,
    // then transition to Started asynchronously. Wait briefly for the settled state.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let advertising_status = loop {
        let status = service.advertising_status()?;
        if status.contains("(2)") || tokio::time::Instant::now() >= deadline {
            break status;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

    println!("HID GATT advertising status: {advertising_status}");
    if !advertising_status.contains("(2)") {
        eprintln!(
            "WARNING: Windows did not report Started within 2 seconds. Check the status-change event log above."
        );
    } else {
        println!("Windows BLE GATT advertising is started.");
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
