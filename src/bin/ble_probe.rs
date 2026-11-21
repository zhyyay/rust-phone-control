#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use rust_phone_control::input::ble::windows::probe_hid_peripheral;

    println!("Checking Windows BLE HID peripheral capability...");
    let capability = probe_hid_peripheral().await?;
    println!("Adapter: {:?}", capability.adapter_name);
    println!("Status: {:?}", capability.status);
    println!("\nThis diagnostic does not advertise a service or pair a phone.");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ble-probe is available only on Windows.");
}
