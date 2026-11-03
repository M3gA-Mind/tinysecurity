//! Bounded master resolution for a single boot owner.
//!
//! Generic get/set ports provide neither cross-provider CAS nor durable deletion
//! authority. Callers must keep one boot owner per target; legacy sources are
//! retained even after exact readback. An in-process reservation rejects overlap
//! without holding a lock across driver I/O. Once mutation starts, cancellation,
//! panic, backend failure or failed readback permanently latches this resolver
//! unavailable. Generic ports cannot prove a canceled mutation has stopped.
//! Replacing the resolver is not recovery authority: the owner must establish
//! that all old backend mutations are quiescent before restarting resolution.
use crate::{Error, Result, secretstore::project_error};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tinystoragedrivers::secrets::{SecretStore, Zeroizing, crypto};

/// Historical service namespace used by native stores.
pub const SERVICE: &str = "openhuman";
/// Immutable purpose: these masters must never be conflated.
#[derive(Clone, PartialEq, Eq)]
pub enum MasterSlot {
    /// File-encryption master, account `app:master_key`.
    App,
    /// Configuration encryption master, account `user:secretstore.master_key`.
    User(String),
    /// Registered protected-file master, named `.secret_key`.
    File,
}
impl std::fmt::Debug for MasterSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSlot([redacted])")
    }
}
impl MasterSlot {
    fn name(&self) -> String {
        match self {
            Self::App => "app:master_key".into(),
            Self::User(user) => format!("{user}:secretstore.master_key"),
            Self::File => ".secret_key".into(),
        }
    }
}
/// A trusted immutable binding between a legacy reader and its historical slot.
/// This generic store binding grants no native file access or mutation authority.
pub struct LegacySource {
    reader: Arc<dyn SecretStore>,
    slot: MasterSlot,
}
impl std::fmt::Debug for LegacySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacySource([redacted])")
    }
}
impl LegacySource {
    /// Bind a known store to the exact slot to read, without performing I/O.
    /// Applicability and slot validity are checked by resolver construction.
    #[must_use]
    pub fn at_slot(reader: Arc<dyn SecretStore>, slot: MasterSlot) -> Self {
        Self { reader, slot }
    }
}
fn validated_name(slot: &MasterSlot) -> Result<String> {
    if matches!(slot, MasterSlot::User(user) if user.is_empty() || user.contains(':')) {
        return Err(Error::InvalidInput);
    }
    let name = slot.name();
    tinystoragedrivers::secrets::validate_name(&name).map_err(|_| Error::InvalidInput)?;
    Ok(name)
}
/// Trusted injected entropy source; production delegates to the driver.
pub trait MasterMint: Send + Sync {
    /// Generate a new native master only after all registered sources are absent.
    /// # Errors
    /// Returns a content-free entropy failure.
    fn mint(&self) -> Result<Zeroizing<[u8; 32]>>;
}
/// Driver-backed operating-system entropy.
#[derive(Debug)]
pub struct DriverMint;
impl MasterMint for DriverMint {
    fn mint(&self) -> Result<Zeroizing<[u8; 32]>> {
        crypto::generate_key().map_err(|_| Error::Entropy)
    }
}
/// Native master bytes with a redacted diagnostic representation.
pub struct MasterKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([redacted])")
    }
}
impl MasterKey {
    /// Borrow the unchanged native bytes for owner encryption.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Ordered immutable store inventory established by trusted construction.
pub struct MasterResolver {
    target: Arc<dyn SecretStore>,
    legacy: Vec<LegacySource>,
    name: String,
    mint: Arc<dyn MasterMint>,
    reserved: AtomicBool,
}
impl std::fmt::Debug for MasterResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterResolver([redacted])")
    }
}
impl MasterResolver {
    /// Bind one target and at most three applicable known legacy stores.
    /// No store enumeration or ambient credential discovery occurs.
    /// # Errors
    /// Rejects an invalid slot or an inventory exceeding the immutable bound.
    pub fn new(
        target: Arc<dyn SecretStore>,
        legacy: Vec<Arc<dyn SecretStore>>,
        slot: &MasterSlot,
        mint: Arc<dyn MasterMint>,
    ) -> Result<Self> {
        Self::new_with_sources(
            target,
            legacy
                .into_iter()
                .map(|reader| LegacySource::at_slot(reader, slot.clone()))
                .collect(),
            slot,
            mint,
        )
    }
    /// Bind an ordered inventory of at most three source readers and slots.
    /// Exact slots are allowed; only File/User bindings may cross slots, for
    /// configuration masters. File denotes a generic named store entry here.
    /// No filesystem capability or cross-provider CAS is provided.
    /// # Errors
    /// Rejects invalid identities, excessive inventory and cross-purpose bindings
    /// before any target or source I/O.
    pub fn new_with_sources(
        target: Arc<dyn SecretStore>,
        legacy: Vec<LegacySource>,
        slot: &MasterSlot,
        mint: Arc<dyn MasterMint>,
    ) -> Result<Self> {
        if legacy.len() > 3 {
            return Err(Error::InvalidInput);
        }
        let name = validated_name(slot)?;
        for source in &legacy {
            validated_name(&source.slot)?;
            if source.slot != *slot
                && !matches!(
                    (slot, &source.slot),
                    (MasterSlot::User(_), MasterSlot::File)
                        | (MasterSlot::File, MasterSlot::User(_))
                )
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            target,
            legacy,
            name,
            mint,
            reserved: AtomicBool::new(false),
        })
    }
    /// Resolve existing bytes before minting or mutating any store.
    /// # Errors
    /// Unresolved, malformed, ambiguous or inaccessible state fails closed.
    /// Overlap returns unavailable; no async I/O runs under a state lock.
    /// Mutation uncertainty remains unavailable until independently reconciled;
    /// constructing a new resolver does not establish backend quiescence.
    pub async fn resolve(&self) -> Result<MasterKey> {
        let mut reservation = self.reserve()?;
        if let Some(bytes) = self
            .target
            .get(&self.name)
            .await
            .map_err(|e| project_error(&e))?
        {
            return parse(&bytes);
        }
        let mut selected: Option<(MasterKey, Zeroizing<Vec<u8>>)> = None;
        for source in &self.legacy {
            if let Some(bytes) = source
                .reader
                .get(&source.slot.name())
                .await
                .map_err(|e| project_error(&e))?
            {
                let key = parse(&bytes)?;
                if let Some((previous, _)) = &selected {
                    if previous.bytes() != key.bytes() {
                        return Err(Error::SecretInvalid);
                    }
                } else {
                    selected = Some((key, bytes));
                }
            }
        }
        let (key, encoded) = if let Some(existing) = selected {
            existing
        } else {
            let key = self.mint.mint()?;
            let encoded = crypto::key_to_hex(&key);
            (MasterKey(key), Zeroizing::new(encoded.as_bytes().to_vec()))
        };
        // Set futures can detach backend work when dropped. Fence before polling.
        reservation.uncertain = true;
        self.target
            .set(&self.name, &encoded)
            .await
            .map_err(|e| project_error(&e))?;
        let readback = self
            .target
            .get(&self.name)
            .await
            .map_err(|e| project_error(&e))?
            .ok_or(Error::KeyringUnavailable)?;
        if *readback != *encoded {
            return Err(Error::SecretInvalid);
        }
        reservation.uncertain = false;
        Ok(key)
    }

    /// Resolve only an already stored master without creating or changing entries.
    ///
    /// The target is checked first. If it is absent, all registered historical
    /// sources are read and must agree. Confirmed absence returns `Ok(None)`;
    /// denied, unavailable, malformed, or ambiguous state remains an error.
    ///
    /// # Errors
    /// Returns a content-free error if any required read fails, any stored key
    /// is malformed, legacy sources disagree, or another resolution is active.
    pub async fn resolve_existing(&self) -> Result<Option<MasterKey>> {
        let _reservation = self.reserve()?;
        if let Some(bytes) = self
            .target
            .get(&self.name)
            .await
            .map_err(|error| project_error(&error))?
        {
            return parse(&bytes).map(Some);
        }

        let mut selected: Option<MasterKey> = None;
        for source in &self.legacy {
            if let Some(bytes) = source
                .reader
                .get(&source.slot.name())
                .await
                .map_err(|error| project_error(&error))?
            {
                let key = parse(&bytes)?;
                if selected
                    .as_ref()
                    .is_some_and(|previous| previous.bytes() != key.bytes())
                {
                    return Err(Error::SecretInvalid);
                }
                selected.get_or_insert(key);
            }
        }
        Ok(selected)
    }

    fn reserve(&self) -> Result<Reservation<'_>> {
        self.reserved
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::KeyringUnavailable)?;
        Ok(Reservation {
            reserved: &self.reserved,
            uncertain: false,
        })
    }
}
struct Reservation<'a> {
    reserved: &'a AtomicBool,
    uncertain: bool,
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.uncertain {
            self.reserved.store(false, Ordering::Release);
        }
    }
}
fn parse(bytes: &[u8]) -> Result<MasterKey> {
    if bytes.len() > 128 {
        return Err(Error::SecretInvalid);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::SecretInvalid)?;
    crypto::key_from_hex(text)
        .map(MasterKey)
        .map_err(|_| Error::SecretInvalid)
}
#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
