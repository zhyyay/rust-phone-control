#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use rust_phone_control::input::{
        ble::{
            reports::{KeyboardReport, MouseReport},
            service::BleHidService,
            windows::probe_hid_peripheral,
        },
        event::{KeyModifiers, MouseButtons},
    };

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
    println!("Keep this window open while your iPhone is connected.");
    println!("Watch for mouse and keyboard report subscription count logs.");
    println!("When BOTH counts show 1, open an editable text field on iPhone, focus it,");
    println!("then press Enter here to send a small mouse move and the letter 'a'.");
    println!("Do not press Enter until both report subscriptions are logged.");
    println!("Press Ctrl+C to stop without sending a test.");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Stopping BLE HID advertising...");
            service.stop()?;
        }
        line = async {
            use tokio::io::AsyncBufReadExt;
            let mut input = tokio::io::BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            input.read_line(&mut line).await?;
            Ok::<String, std::io::Error>(line)
        } => {
            let _line = line?;
            println!("Sending mouse movement test (24, 0)...");
            service.send_mouse_report(MouseReport::new(MouseButtons::NONE, 24, 0, 0)).await?;
            service.send_mouse_report(MouseReport::release()).await?;
            println!("Mouse report notifications submitted.");

            println!("Sending keyboard test: lowercase 'a'...");
            service.send_keyboard_report(KeyboardReport::new(
                KeyModifiers::NONE,
                [0x04, 0, 0, 0, 0, 0],
            )).await?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            service.send_keyboard_report(KeyboardReport::release()).await?;
            println!("Keyboard report notifications submitted.");
            println!("Test complete. Press Ctrl+C to stop.");
            tokio::signal::ctrl_c().await?;
            service.stop()?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ble-probe is available only on Windows.");
}
