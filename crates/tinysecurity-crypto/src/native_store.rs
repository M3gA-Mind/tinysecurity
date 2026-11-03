//! Native secret backends behind the accepted `SecretStore` port.
//!
//! Construction is lazy for OS stores; availability is established only by an
//! operation. Errors are content-free and never carry names or values.
use crate::{Error, Result};
use sha2::Digest;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tinystoragedrivers::secrets::{EncryptedFileSecrets, KeyringSecrets, SecretStore};

/// Trusted backend selection supplied during initialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Keychain, Credential Manager or the platform default credential store.
    Os,
    /// Linux kernel keyring.
    LinuxKernel,
    /// Linux Secret Service; available only with the explicit feature.
    SecretService,
    /// Protected encrypted file store with a module-owned key file.
    EncryptedFile(PathBuf),
}

/// Open a backend under a credential service namespace.
///
/// # Errors
/// Returns `KeyringUnavailable` for an unsupported selection on this build or
/// platform, or when the encrypted file store cannot be admitted.
pub fn open(service: &str, backend: Backend) -> Result<Arc<dyn SecretStore>> {
    match backend {
        Backend::Os => Ok(Arc::new(KeyringSecrets::new(service))),
        #[cfg(target_os = "linux")]
        Backend::LinuxKernel => Ok(Arc::new(KeyringSecrets::linux_kernel(service))),
        #[cfg(all(target_os = "linux", feature = "keyring-secret-service"))]
        Backend::SecretService => Ok(Arc::new(KeyringSecrets::secret_service(service))),
        Backend::EncryptedFile(dir) => {
            if !dir.is_absolute() || service.is_empty() {
                return Err(Error::InvalidInput);
            }
            // Distinct services never share a store or key file: each owns a
            // subdirectory named by a digest of the service, not by caller text.
            let digest = sha2::Sha256::digest(service.as_bytes());
            let name: String = digest.iter().take(16).fold(String::new(), |mut out, b| {
                use std::fmt::Write;
                let _ = write!(out, "{b:02x}");
                out
            });
            let dir = dir.join(format!("svc-{name}"));
            create_private_dir(&dir)?;
            EncryptedFileSecrets::with_key_file(&dir)
                .map(|store| Arc::new(store) as Arc<dyn SecretStore>)
                .map_err(|_| Error::KeyringUnavailable)
        }
        #[allow(unreachable_patterns)]
        _ => Err(Error::KeyringUnavailable),
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|_| Error::KeyringUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::KeyringUnavailable)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_store_tests.rs"]
mod tests;
