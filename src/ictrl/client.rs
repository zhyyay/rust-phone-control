use anyhow::{Context, Result};
use reqwest::{Client, Url};
use serde_json::Value;
use std::time::Duration;

/// Read-only discovery client for public iCTRL endpoints.
/// Authenticated RPC requires X25519 pairing and sealed HMAC-SHA256 requests.
#[derive(Clone)]
pub struct IctrlClient { http: Client, base_url: Url }

#[derive(Debug, Clone)]
pub struct IctrlProbe {
    pub base_url: String,
    pub status: Value,
    pub schema: Value,
    pub skill: String,
}

impl IctrlClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let mut url = Url::parse(base_url).context("invalid iCTRL URL")?;
        if !matches!(url.scheme(), "http" | "https") {
            anyhow::bail!("iCTRL URL must use http or https");
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("rust-phone-control/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build HTTP client")?;
        Ok(Self { http, base_url: url })
    }

    async fn get_json(&self, endpoint: &str) -> Result<Value> {
        self.http.get(self.base_url.join(endpoint)?)
            .send().await.with_context(|| format!("request iCTRL {endpoint}"))?
            .error_for_status().with_context(|| format!("iCTRL {endpoint} returned an error"))?
            .json::<Value>().await.with_context(|| format!("decode iCTRL {endpoint} JSON"))
    }

    pub async fn probe(&self) -> Result<IctrlProbe> {
        let status = self.get_json("status").await?;
        let schema = self.get_json("schema").await?;
        let skill = self.http.get(self.base_url.join("skill")?)
            .send().await.context("request iCTRL skill")?
            .error_for_status().context("iCTRL skill endpoint returned an error")?
            .text().await.context("read iCTRL skill text")?;
        Ok(IctrlProbe { base_url: self.base_url.to_string(), status, schema, skill })
    }
}
