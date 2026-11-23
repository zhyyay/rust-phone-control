//! Windows DNS-SD publication for the local AirPlay endpoint.
//!
//! Windows owns the mDNS sockets and answers multicast and QU-unicast queries.
//! The application only registers the AirPlay and RAOP service descriptions;
//! it does not bind UDP 5353 itself.

use anyhow::{Context, Result, anyhow, bail};
use std::{
    ffi::c_void,
    ptr,
    sync::mpsc,
};
use windows_062::{
    core::PWSTR,
    Win32::Foundation::{BOOL, DNS_REQUEST_PENDING},
    Win32::NetworkManagement::Dns::{
        DnsServiceDeRegister, DnsServiceFreeInstance, DnsServiceRegister,
        DNS_SERVICE_INSTANCE, DNS_SERVICE_REGISTER_REQUEST,
    },
};

use super::config;

const DNS_SERVICE_REQUEST_VERSION: u32 = 1;

struct Completion {
    status: u32,
    instance: usize,
}

unsafe extern "system" fn registration_complete(
    status: u32,
    context: *const c_void,
    instance: *const DNS_SERVICE_INSTANCE,
) {
    if context.is_null() {
        return;
    }

    // The boxed sender is transferred to this one-shot Windows callback.
    let sender = unsafe {
        Box::from_raw(context.cast_mut().cast::<mpsc::Sender<Completion>>())
    };
    let _ = sender.send(Completion {
        status,
        instance: instance as usize,
    });
}

fn submit_request(
    request: &DNS_SERVICE_REGISTER_REQUEST,
    deregister: bool,
) -> Result<usize> {
    let (sender, receiver) = mpsc::channel();
    let context = Box::into_raw(Box::new(sender)).cast::<c_void>();
    let mut request = *request;
    request.pQueryContext = context;

    // DNS-SD registration and deregistration complete asynchronously. Keep
    // the callback context alive until Windows invokes the completion callback.
    let status = unsafe {
        if deregister {
            DnsServiceDeRegister(&request, None)
        } else {
            DnsServiceRegister(&request, None)
        }
    };

    if status != DNS_REQUEST_PENDING as u32 {
        // No callback will be issued when the request was rejected immediately.
        unsafe {
            drop(Box::from_raw(context.cast::<mpsc::Sender<Completion>>()));
        }
        bail!(
            "Windows DNS-SD {} request failed immediately: 0x{status:08X}",
            if deregister { "deregistration" } else { "registration" }
        );
    }

    let completion = receiver
        .recv()
        .context("Windows DNS-SD completion callback channel closed")?;
    if completion.status != 0 {
        if completion.instance != 0 {
            unsafe {
                DnsServiceFreeInstance(
                    completion.instance as *const DNS_SERVICE_INSTANCE,
                );
            }
        }
        bail!(
            "Windows DNS-SD {} completed with status 0x{:08X}",
            if deregister { "deregistration" } else { "registration" },
            completion.status
        );
    }
    if completion.instance == 0 {
        bail!("Windows DNS-SD completed without returning a service instance");
    }

    Ok(completion.instance)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct ServiceData {
    instance_name: Vec<u16>,
    host_name: Vec<u16>,
    key_strings: Vec<Vec<u16>>,
    value_strings: Vec<Vec<u16>>,
    keys: Vec<PWSTR>,
    values: Vec<PWSTR>,
    instance: DNS_SERVICE_INSTANCE,
}

impl ServiceData {
    fn new(
        instance_name: &str,
        properties: &[(&str, &str)],
    ) -> Self {
        let mut instance_name = wide(instance_name);
        let host = std::env::var("COMPUTERNAME")
            .unwrap_or_else(|_| "rust-phone-control".to_owned());
        let mut host_name = wide(&format!("{host}.local"));
        let key_strings = properties
            .iter()
            .map(|(key, _)| wide(key))
            .collect::<Vec<_>>();
        let value_strings = properties
            .iter()
            .map(|(_, value)| wide(value))
            .collect::<Vec<_>>();
        let keys = key_strings
            .iter()
            .map(|value| PWSTR(value.as_ptr() as *mut u16))
            .collect::<Vec<_>>();
        let values = value_strings
            .iter()
            .map(|value| PWSTR(value.as_ptr() as *mut u16))
            .collect::<Vec<_>>();

        let instance = DNS_SERVICE_INSTANCE {
            pszInstanceName: PWSTR(instance_name.as_mut_ptr()),
            pszHostName: PWSTR(host_name.as_mut_ptr()),
            ip4Address: ptr::null_mut(),
            ip6Address: ptr::null_mut(),
            wPort: config::TCP_PORT,
            wPriority: 0,
            wWeight: 0,
            dwPropertyCount: keys.len() as u32,
            keys: if keys.is_empty() {
                ptr::null_mut()
            } else {
                keys.as_ptr() as *mut PWSTR
            },
            values: if values.is_empty() {
                ptr::null_mut()
            } else {
                values.as_ptr() as *mut PWSTR
            },
            dwInterfaceIndex: 0,
        };

        Self {
            instance_name,
            host_name,
            key_strings,
            value_strings,
            keys,
            values,
            instance,
        }
    }
}

struct RegisteredService {
    fullname: String,
    instance: usize,
    interface_index: u32,
}

impl RegisteredService {
    fn register(
        fullname: String,
        properties: &[(&str, &str)],
        interface_index: u32,
    ) -> Result<Self> {
        let mut data = ServiceData::new(&fullname, properties);
        let mut request = DNS_SERVICE_REGISTER_REQUEST {
            Version: DNS_SERVICE_REQUEST_VERSION,
            InterfaceIndex: interface_index,
            pServiceInstance: &mut data.instance,
            pRegisterCompletionCallback: Some(registration_complete),
            pQueryContext: ptr::null_mut(),
            unicastEnabled: BOOL(0),
            ..Default::default()
        };

        let instance = submit_request(&request, false)
            .with_context(|| format!("register Windows mDNS service {fullname}"))?;

        // The callback returns a Windows-owned copy, so the temporary UTF-16
        // strings and pointer arrays can now be released.
        let _ = (
            &data.instance_name,
            &data.host_name,
            &data.key_strings,
            &data.value_strings,
            &data.keys,
            &data.values,
        );
        request.pServiceInstance = ptr::null_mut();

        tracing::info!(
            service = %fullname,
            interface_index,
            port = config::TCP_PORT,
            "Windows DNS-SD service registration completed"
        );

        Ok(Self {
            fullname,
            instance,
            interface_index,
        })
    }

    fn unregister(self) -> Result<()> {
        let mut request = DNS_SERVICE_REGISTER_REQUEST {
            Version: DNS_SERVICE_REQUEST_VERSION,
            InterfaceIndex: self.interface_index,
            pServiceInstance: self.instance as *mut DNS_SERVICE_INSTANCE,
            pRegisterCompletionCallback: Some(registration_complete),
            pQueryContext: ptr::null_mut(),
            unicastEnabled: BOOL(0),
            ..Default::default()
        };

        let completion_instance = submit_request(&request, true)
            .with_context(|| format!("unregister Windows mDNS service {}", self.fullname))?;

        unsafe {
            DnsServiceFreeInstance(completion_instance as *const DNS_SERVICE_INSTANCE);
        }
        request.pServiceInstance = ptr::null_mut();
        tracing::info!(
            service = %self.fullname,
            interface_index = self.interface_index,
            "Windows DNS-SD service unregistered"
        );
        Ok(())
    }
}

pub struct Advertisement {
    registrations: Vec<RegisteredService>,
}

impl Advertisement {
    pub fn start() -> Result<Self> {
        let device_id = config::device_id();
        let (public_key, pairing_identifier) = super::pair_setup::discovery_identity()
            .map_err(anyhow::Error::msg)
            .context("load persistent AirPlay discovery identity")?;

        let interface_index = config::wifi_interface_index().unwrap_or_else(|| {
            tracing::warn!(
                "No active Wi-Fi adapter was found; Windows DNS-SD will publish on all interfaces"
            );
            0
        });

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
        let airplay_fullname = format!(
            "{}.{}",
            config::SERVICE_NAME,
            config::SERVICE_TYPE.trim_end_matches('.')
        );

        let raop_instance = format!(
            "{}@{}",
            device_id.replace(':', ""),
            config::SERVICE_NAME
        );
        let raop_fullname = format!(
            "{}.{}",
            raop_instance,
            config::RAOP_SERVICE_TYPE.trim_end_matches('.')
        );
        let raop_properties = [
            ("txtvers", "1"),
            ("am", config::MODEL),
            ("vs", config::SOURCE_VERSION),
            ("sf", config::STATUS_FLAGS),
            ("ft", config::FEATURES),
            ("pk", public_key.as_str()),
            ("vv", "2"),
        ];

        let mut registrations = Vec::with_capacity(2);
        registrations.push(RegisteredService::register(
            airplay_fullname,
            &airplay_properties,
            interface_index,
        )?);

        match RegisteredService::register(
            raop_fullname,
            &raop_properties,
            interface_index,
        ) {
            Ok(registration) => registrations.push(registration),
            Err(error) => {
                for registration in registrations.drain(..).rev() {
                    if let Err(cleanup_error) = registration.unregister() {
                        tracing::error!(
                            error = %cleanup_error,
                            "Could not roll back partial Windows DNS-SD registration"
                        );
                    }
                }
                return Err(error);
            }
        }

        tracing::info!(
            airplay_service = %registrations[0].fullname,
            raop_service = %registrations[1].fullname,
            interface_index,
            port = config::TCP_PORT,
            device_id = %device_id,
            "AirPlay and RAOP services registered through Windows DNS-SD"
        );

        Ok(Self { registrations })
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..).rev() {
            if let Err(error) = registration.unregister() {
                tracing::error!(
                    error = %format!("{error:#}"),
                    "Could not unregister Windows DNS-SD service"
                );
            }
        }
    }
}
