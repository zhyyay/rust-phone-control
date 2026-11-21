//! DNS-SD / mDNS publication for the local AirPlay endpoint.

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};

use super::config;

pub struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    pub fn start() -> Result<Self> {
        let daemon = ServiceDaemon::new().context("create mDNS service daemon")?;
        let device_id = config::device_id();
        // Feature flags are intentionally zero: this endpoint does not claim
        // mirroring, FairPlay, or pairing support until those are implemented.
        let properties = [
            ("deviceid", device_id.as_str()),
            ("features", config::FEATURES),
            ("model", config::MODEL),
            ("srcvers", config::SOURCE_VERSION),
            ("flags", "0x0"),
        ];
        let service = ServiceInfo::new(
            config::SERVICE_TYPE,
            config::SERVICE_NAME,
            config::HOST_NAME,
            (),
            config::TCP_PORT,
            &properties[..],
        )
        .context("build AirPlay mDNS service record")?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        daemon
            .register(service)
            .context("register AirPlay mDNS service")?;

        tracing::info!(
            service = %fullname,
            port = config::TCP_PORT,
            device_id = %device_id,
            "AirPlay discovery endpoint published (capabilities not yet enabled)"
        );
        Ok(Self { daemon, fullname })
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        if let Err(error) = self.daemon.unregister(&self.fullname) {
            tracing::warn!(error = %error, "Could not unregister AirPlay mDNS service");
        }
        if let Err(error) = self.daemon.shutdown() {
            tracing::warn!(error = %error, "Could not shut down mDNS daemon");
        }
    }
}
