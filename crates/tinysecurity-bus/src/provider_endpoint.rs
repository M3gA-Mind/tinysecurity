//! Host endpoint locality classification for `LocalOnly` privacy mode (contract 1.32).
use serde::{Deserialize, Serialize};

/// Maximum size of a parsed URL host supplied for provider locality classification.
pub const MAX_PROVIDER_HOST_BYTES: usize = 255;

/// The parsed host component of a configured provider endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEndpointRequest2 {
    /// Host only, as returned by the URL parser; excludes scheme, port, path, query and fragment.
    pub host: String,
}

impl ProviderEndpointRequest2 {
    /// Validate the bounded host input before classifying it.
    ///
    /// # Errors
    /// Returns `InvalidArguments` for an empty, oversized, whitespace-containing or
    /// control-character-containing host.
    pub fn validate(&self) -> crate::Result<()> {
        if self.host.is_empty()
            || self.host.len() > MAX_PROVIDER_HOST_BYTES
            || self
                .host
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}

/// Whether a provider host is reserved for the same machine or may be elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProviderEndpointLocality2 {
    /// A loopback or localhost name that identifies this machine itself.
    OnDevice,
    /// Any other host, including private or link-local network addresses.
    External,
}

/// Result of classifying one configured provider host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEndpointResponse2 {
    /// Locality used by the host's `LocalOnly` decision.
    pub locality: ProviderEndpointLocality2,
}

#[cfg(test)]
#[path = "provider_endpoint_tests.rs"]
mod tests;
