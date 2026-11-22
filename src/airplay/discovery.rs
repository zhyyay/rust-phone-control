//! DNS-SD / mDNS publication for the local AirPlay endpoint.
//!
//! iOS screen-mirroring discovery commonly browses both the AirPlay service
//! and the legacy RAOP service. Publish both records with the same stable
//! device identity and control endpoint. The RAOP record is a discovery hint;
//! this project does not advertise audio codecs or encryption modes it cannot
//! currently serve.

use anyhow::{Context, Result};
use mdns_sd::{DaemonEvent, IfKind, ServiceDaemon, ServiceInfo};
use std::thread::{self, JoinHandle};

use super::config;

pub struct Advertisement {
    daemon: ServiceDaemon,
    fullnames: Vec<String>,
    monitor_thread: Option<JoinHandle<()>>,
}

impl Advertisement {
    pub fn start() -> Result<Self> {
        let daemon = ServiceDaemon::new().context("create mDNS service daemon")?;
        // Do not publish discovery records on loopback or the known Clash
        // Meta virtual adapter. Keep normal physical interfaces enabled so
        // both Wi-Fi and Ethernet deployments remain discoverable.
        daemon
            .disable_interface(IfKind::LoopbackV4)
            .context("disable IPv4 loopback for AirPlay discovery")?;
        daemon
            .disable_interface(IfKind::LoopbackV6)
            .context("disable IPv6 loopback for AirPlay discovery")?;
        daemon
            .disable_interface(IfKind::Name("Meta".to_owned()))
            .context("disable Meta virtual adapter for AirPlay discovery")?;

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
                            tracing::info!(
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
        let (public_key, pairing_identifier) = super::pair_setup::discovery_identity()
            .map_err(anyhow::Error::msg)
            .context("load persistent AirPlay discovery identity")?;
        let airplay_properties = [
            ("deviceid", device_id.as_str()),
            ("features", config::FEATURES),
            ("model", config::MODEL),
            ("srcvers", config::SOURCE_VERSION),
            ("flags", config::STATUS_FLAGS),
            ("pk", public_key.as_str()),
            ("pi", pairing_identifier.as_str()),
            ("vv", "2"),
        ];
        let airplay_service = ServiceInfo::new(
            config::SERVICE_TYPE,
            config::SERVICE_NAME,
            config::HOST_NAME,
            (),
            config::TCP_PORT,
            &airplay_properties[..],
        )
        .context("build AirPlay mDNS service record")?
        .enable_addr_auto();

        let raop_instance = format!("{}@{}", device_id.replace(':', ""), config::SERVICE_NAME);
        // RAOP is advertised because iOS versions commonly use it as part of
        // the Screen Mirroring discovery path. Keep the TXT record minimal:
        // no codec or encryption support is claimed by this receiver yet.
        let raop_properties = [
            ("txtvers", "1"),
            ("am", config::MODEL),
            ("vs", config::SOURCE_VERSION),
            ("sf", config::STATUS_FLAGS),
            ("ft", config::FEATURES),
            ("pk", public_key.as_str()),
            ("vv", "2"),
        ];
        let raop_service = ServiceInfo::new(
            config::RAOP_SERVICE_TYPE,
            &raop_instance,
            config::HOST_NAME,
            (),
            config::TCP_PORT,
            &raop_properties[..],
        )
        .context("build RAOP discovery service record")?
        .enable_addr_auto();

        let airplay_fullname = airplay_service.get_fullname().to_owned();
        let raop_fullname = raop_service.get_fullname().to_owned();

        daemon
            .register(airplay_service)
            .context("queue AirPlay mDNS service registration")?;
        if let Err(error) = daemon.register(raop_service) {
            let _ = daemon.unregister(&airplay_fullname);
            let _ = daemon.shutdown();
            let _ = monitor_thread.join();
            return Err(error).context("queue RAOP mDNS service registration");
        }

        tracing::info!(
            airplay_service = %airplay_fullname,
            raop_service = %raop_fullname,
            port = config::TCP_PORT,
            device_id = %device_id,
            features = config::FEATURES,
            "AirPlay and RAOP mDNS service registrations queued"
        );

        Ok(Self {
            daemon,
            fullnames: vec![airplay_fullname, raop_fullname],
            monitor_thread: Some(monitor_thread),
        })
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        for fullname in &self.fullnames {
            if let Err(error) = self.daemon.unregister(fullname) {
                tracing::warn!(
                    service = %fullname,
                    error = %error,
                    "Could not unregister AirPlay discovery service"
                );
            }
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
