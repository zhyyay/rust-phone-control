#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use rust_phone_control::input::ble::{
        BleCapabilityStatus, BleInputController, windows::probe_hid_peripheral,
    };
    use rust_phone_control::input::event::MouseButtons;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Checking Windows BLE HID peripheral capability...");
    let capability = probe_hid_peripheral().await?;
    println!("Adapter: {:?}", capability.adapter_id);
    println!("Status: {:?}", capability.status);

    if !matches!(capability.status, BleCapabilityStatus::Supported) {
        anyhow::bail!("The adapter is not ready to host a BLE HID peripheral.");
    }

    println!("Creating HID GATT service and starting BLE advertising...");
    let controller = BleInputController::start().await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let advertising_status = loop {
        let status = controller.advertising_status()?;
        if status.contains("(2)") || tokio::time::Instant::now() >= deadline {
            break status;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

    println!("HID GATT advertising status: {advertising_status}");
    if !advertising_status.contains("(2)") {
        eprintln!("WARNING: Windows did not report Started within 2 seconds.");
    } else {
        println!("Windows BLE GATT advertising is started.");
    }

    println!("Keep this window open while your iPhone is connected.");
    println!("Wait until BOTH mouse and keyboard subscription counts show 1.");
    println!("On iPhone, open Notes and focus an empty note text field.");
    println!("Then press Enter here once to test mouse move, left click, scroll, and text.");
    println!("The test types: BLE OK");
    println!("Press Ctrl+C to stop without sending a test.");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Stopping BLE HID advertising...");
            controller.stop()?;
        }
        line = async {
            use tokio::io::AsyncBufReadExt;
            let mut input = tokio::io::BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            input.read_line(&mut line).await?;
            Ok::<String, std::io::Error>(line)
        } => {
            let _line = line?;
            println!("Testing obvious diagonal mouse movement (127, 127)...");
            controller.move_mouse(127, 127).await?;
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            println!("Testing reverse mouse movement (-127, -127)...");
            controller.move_mouse(-127, -127).await?;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            println!("Testing left mouse click...");
            controller.click(MouseButtons::LEFT).await?;
            println!("Testing vertical scroll...");
            controller.scroll(1).await?;
            println!("Typing ASCII test text...");
            controller.type_text("BLE OK").await?;
            controller.release_all().await?;
            println!("Input test reports submitted. Check the iPhone, then press Ctrl+C.");
            tokio::signal::ctrl_c().await?;
            controller.stop()?;
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ble-probe is available only on Windows.");
}
