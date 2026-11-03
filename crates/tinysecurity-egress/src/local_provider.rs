//! Same-machine local provider endpoint classification for `LocalOnly` privacy mode.
use std::net::{Ipv4Addr, Ipv6Addr};
use tinysecurity_bus::ProviderEndpointLocality2;
use url::Host;

/// Classify a host literal for a local provider endpoint without performing DNS.
///
/// Only loopback and unspecified IP literals plus `localhost` names are considered
/// on-device. RFC 1918, link-local, IPv6 ULA and other LAN addresses remain external:
/// `LocalOnly` means that user data does not leave this machine, not merely this LAN.
/// Invalid or unrecognized hosts fail closed as external.
#[must_use]
pub fn classify_provider_endpoint(host: &str) -> ProviderEndpointLocality2 {
    let Ok(host) = Host::parse(host) else {
        return ProviderEndpointLocality2::External;
    };
    let on_device = match host {
        Host::Ipv4(address) => local_v4(address),
        Host::Ipv6(address) => local_v6(address),
        Host::Domain(name) => {
            let name = name.strip_suffix('.').unwrap_or(&name);
            name.eq_ignore_ascii_case("localhost")
                || name.to_ascii_lowercase().ends_with(".localhost")
        }
    };
    if on_device {
        ProviderEndpointLocality2::OnDevice
    } else {
        ProviderEndpointLocality2::External
    }
}

fn local_v4(address: Ipv4Addr) -> bool {
    address.is_loopback() || address.is_unspecified()
}

fn local_v6(address: Ipv6Addr) -> bool {
    address.to_ipv4_mapped().map_or_else(
        || address.is_loopback() || address.is_unspecified(),
        local_v4,
    )
}

#[cfg(test)]
#[path = "local_provider_tests.rs"]
mod tests;
