use anyhow::{Context, Result};
use rust_phone_control::IctrlClient;

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
    println!("Checking iCTRL at {url}");
    let client = IctrlClient::new(&url)?;
    let probe = client.probe().await.context("iCTRL discovery failed")?;
    println!("\n/status:");
    println!("{}", serde_json::to_string_pretty(&probe.status)?);
    println!("\n/schema: received {} bytes", probe.schema.to_string().len());
    println!("\n/skill: received {} bytes", probe.skill.len());
    println!("\niCTRL discovery successful. No pairing or control request was sent.");
    Ok(())
}
