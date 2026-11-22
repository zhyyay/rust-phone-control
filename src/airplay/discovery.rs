//! DNS-SD / mDNS publication for the local AirPlay endpoint.

use anyhow::{Context, Result};
use mdns_sd::{DaemonEvent, ServiceDaemon, ServiceInfo};
use std::thread::{self, JoinHandle};

use super::config;

pub struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
    monitor_thread: Option<JoinHandle<()>>,
}

impl Advertisement {
    pub fn start() -> Result<Self> {
        let daemon = ServiceDaemon::new().context("create mDNS service daemon")?;

        // mdns-sd creates its multicast sockets on the daemon thread. Socket
        // binding and multicast-interface errors are reported asynchronously
        // through monitor(), so keep this receiver alive and surface failures.
        let events = daemon.monitor().context("monitor mDNS service daemon")?;
        let monitor_thread = thread::Builder::new()
            .name("airplay-mdns-monitor".to_owned())
            .spawn(move || {
                while let Ok(event) = events.recv() {
                    match event {
                        DaemonEvent::Error(error) => {
                            tracing::error!(error = %error, "mDNS daemon reported an error");
                        }
                        DaemonEvent::Announce(service, interface) => {
                            tracing::info!(
                                service = %service,
                                interface = %interface,
                                "mDNS service announcement sent"
                            );
                        }
                        DaemonEvent::Respond(interface) => {
                            tracing::debug!(
                                interface = %interface,
                                "mDNS query response sent"
                            );
                        }
                        other => {
                            tracing::debug!(event = ?other, "mDNS daemon event");
                        }
                    }
                }
                tracing::debug!("mDNS daemon monitor stopped");
            })
            .context("spawn mDNS event monitor thread")?;

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
            .context("queue AirPlay mDNS service registration")?;

        tracing::info!(
            service = %fullname,
            port = config::TCP_PORT,
            device_id = %device_id,
            "AirPlay mDNS service registration queued; waiting for daemon announcement"
        );
        Ok(Self {
            daemon,
            fullname,
            monitor_thread: Some(monitor_thread),
        })
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
        if let Some(monitor_thread) = self.monitor_thread.take() {
            if monitor_thread.join().is_err() {
                tracing::warn!("mDNS event monitor thread panicked");
            }
        }
    }
}
