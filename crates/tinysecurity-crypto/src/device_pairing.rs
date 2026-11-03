//! Module-owned paired-device identity, proof and tunnel lifecycle.
//!
//! Design, API boundaries and operational constraints are documented in the
//! [module README](https://github.com/tinyhumansai/tinysecurity/blob/main/crates/tinysecurity-crypto/src/device_pairing/README.md).

use crate::{
    Error, Result,
    device::{KeyPair, PublicKey, Role, Tunnel},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tinysecurity_bus::{DevicePairingConfig2, DevicePairingContextResponse2, DevicePairingSource2};
use zeroize::{Zeroize, Zeroizing};

/// Trusted epoch and monotonic time, never a request field.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// Epoch milliseconds.
    pub wall: u64,
    /// Monotonic milliseconds.
    pub monotonic: u64,
}

struct Identity {
    secret: Zeroizing<[u8; 32]>,
    key: KeyPair,
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity([REDACTED])")
    }
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Record {
    id: String,
    scope: String,
    user: String,
    device_key: String,
    channel: String,
    // Each renewal candidate is serialized through snapshot(), which enforces max_state_bytes;
    // channel ids are independently capped at 128 bytes by valid_channel().
    #[serde(default)]
    channels: BTreeSet<String>,
    nonce: String,
    #[serde(default)]
    identity_id: String,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
struct Revocation {
    scope: String,
    user: String,
    channel: String,
    #[serde(default)]
    pairing_id: String,
}
struct Binding {
    scope: String,
    user: String,
    channel: String,
    pairing_token: Option<String>,
    nonce: String,
    generation: u64,
}
impl From<&DevicePairingContextResponse2> for Binding {
    fn from(c: &DevicePairingContextResponse2) -> Self {
        Self {
            scope: c.scope_id.clone(),
            user: c.user_binding.clone(),
            channel: c.channel_id.clone(),
            pairing_token: c.pairing_token.clone(),
            nonce: c.connection_nonce.clone(),
            generation: c.generation,
        }
    }
}
impl PartialEq for Binding {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope
            && self.user == other.user
            && self.channel == other.channel
            && self.pairing_token == other.pairing_token
            && self.nonce == other.nonce
            && self.generation == other.generation
    }
}
impl Eq for Binding {}
struct Handshake {
    device_key: String,
    tunnel: Option<Arc<Mutex<Tunnel>>>,
}
struct Pending {
    binding: Binding,
    expected_key: Option<String>,
    pairing_id: Option<String>,
    identity_id: String,
    expires_wall: u64,
    expires_mono: u64,
    handshake: Option<Handshake>,
    confirming: bool,
}
struct PendingRequest {
    binding: Binding,
    expected_key: Option<String>,
    pairing_id: Option<String>,
    identity_id: String,
    ttl: u32,
    context_expiry: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Snapshot {
    version: u8,
    identities: BTreeMap<String, [u8; 32]>,
    #[serde(default)]
    scope_identities: BTreeMap<String, String>,
    pairings: Vec<Record>,
    #[serde(default)]
    revocations: Vec<Revocation>,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        self.identities.values_mut().for_each(Zeroize::zeroize);
    }
}

/// Legacy encrypted host value after internal native decryption, ready for one atomic import.
pub struct LegacyDeviceIdentity {
    /// Existing paired-device channel id.
    pub channel_id: String,
    /// Existing public device key from trusted host metadata.
    pub device_public_key: String,
    /// Private core identity, consumed and zeroized by the native owner.
    pub core_private_key: Zeroizing<[u8; 32]>,
    /// Explicit old metadata state; revoked identities are never imported.
    pub revoked: bool,
}
impl std::fmt::Debug for LegacyDeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacyDeviceIdentity([REDACTED])")
    }
}

/// Public metadata produced by an idempotent legacy import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedDevicePairing {
    /// Existing host/backend channel.
    pub channel_id: String,
    /// Stable module identity used by later revoke and reconnect operations.
    pub pairing_id: String,
    /// Existing public device identity.
    pub device_public_key: String,
    /// Preserved old core identity for the unchanged wire handshake.
    pub core_public_key: String,
}

#[derive(Default)]
struct LegacyImportBatch {
    seen_channels: BTreeSet<String>,
    identities: BTreeMap<String, Identity>,
    records: BTreeMap<String, Record>,
    imported: Vec<ImportedDevicePairing>,
}
impl LegacyImportBatch {
    fn stage(
        &mut self,
        owner: &DevicePairingOwner,
        binding: &Binding,
        row: LegacyDeviceIdentity,
    ) -> Result<()> {
        if row.revoked
            || !valid_channel(&row.channel_id)
            || !self.seen_channels.insert(row.channel_id.clone())
            || owner
                .revocations
                .iter()
                .any(|revocation| revocation.channel == row.channel_id)
        {
            return Err(Error::DeviceDenied);
        }
        PublicKey::decode(&row.device_public_key)?;
        let secret = row.core_private_key;
        let key = KeyPair::from_secret(Zeroizing::new(*secret))?;
        let core_public_key = key.public_key().encode();
        if let Some(existing) = owner.records.values().find(|record| {
            record.scope == binding.scope
                && record.user == binding.user
                && record.device_key == row.device_public_key
                && owner
                    .identities
                    .get(&record.identity_id)
                    .is_some_and(|identity| identity.key.public_key().encode() == core_public_key)
        }) {
            if existing.scope != binding.scope
                || existing.user != binding.user
                || existing.device_key != row.device_public_key
                || !existing.channels.contains(&row.channel_id)
                    && existing.channel != row.channel_id
            {
                return Err(Error::DeviceDenied);
            }
            if owner
                .records
                .values()
                .any(|record| record.id != existing.id && record.channels.contains(&row.channel_id))
            {
                return Err(Error::DeviceDenied);
            }
            self.imported.push(ImportedDevicePairing {
                channel_id: row.channel_id,
                pairing_id: existing.id.clone(),
                device_public_key: existing.device_key.clone(),
                core_public_key,
            });
            return Ok(());
        }
        if owner
            .records
            .values()
            .any(|record| record.channels.contains(&row.channel_id))
        {
            return Err(Error::DeviceDenied);
        }
        let id = random_id()?;
        let identity_id = format!("legacy:{id}");
        let record = Record {
            id: id.clone(),
            scope: binding.scope.clone(),
            user: binding.user.clone(),
            device_key: row.device_public_key.clone(),
            channel: row.channel_id.clone(),
            channels: [row.channel_id.clone()].into(),
            nonce: "legacy-imported".into(),
            identity_id: identity_id.clone(),
        };
        if self
            .identities
            .insert(identity_id, Identity { secret, key })
            .is_some()
            || self.records.insert(id.clone(), record).is_some()
        {
            return Err(Error::DeviceDenied);
        }
        self.imported.push(ImportedDevicePairing {
            channel_id: row.channel_id,
            pairing_id: id,
            device_public_key: row.device_public_key,
            core_public_key,
        });
        Ok(())
    }
}

/// Public metadata recovered for a known channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredDevicePairing {
    /// Stable module identity used by later revoke and reconnect operations.
    pub pairing_id: String,
    /// Existing public device identity.
    pub device_public_key: String,
    /// Core identity the existing device expects on the wire.
    pub core_public_key: String,
}
/// Confirmation prepared for durable encrypted storage before a tunnel is published.
pub struct PreparedConfirmation {
    receipt: String,
    session_id: String,
    record: Record,
    tunnel: Arc<Mutex<Tunnel>>,
    session_expires: (u64, u64),
    state: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for PreparedConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedConfirmation([REDACTED])")
    }
}
impl PreparedConfirmation {
    /// Private state bytes for the native cipher owner only; encrypt before persistence.
    #[must_use]
    pub fn state_to_encrypt(&self) -> &[u8] {
        &self.state
    }
    /// Verified public device key.
    #[must_use]
    pub fn device_public_key(&self) -> &str {
        &self.record.device_key
    }
}

/// Public metadata returned only after durable confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingResult {
    /// Stable module-minted identity.
    pub pairing_id: String,
    /// Transient module-minted frame capability; changes on every successful reconnect.
    pub session_id: String,
    /// Verified device wire public key.
    pub device_public_key: String,
    /// Registered device scope.
    pub scope_id: String,
    /// Active backend channel.
    pub channel_id: String,
    /// Absolute session expiry.
    pub expires_at_ms: u64,
}

/// Native owner for stable identities, one-time receipts and bounded tunnel sessions.
pub struct DevicePairingOwner {
    config: DevicePairingConfig2,
    generation: u64,
    identities: BTreeMap<String, Identity>,
    scope_identities: BTreeMap<String, String>,
    records: BTreeMap<String, Record>,
    revocations: BTreeSet<Revocation>,
    sessions: BTreeMap<String, String>,
    tunnels: BTreeMap<String, Arc<Mutex<Tunnel>>>,
    session_expiries: BTreeMap<String, (u64, u64)>,
    pending: BTreeMap<String, Pending>,
    last: Time,
    faulted: bool,
}
impl std::fmt::Debug for DevicePairingOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DevicePairingOwner([REDACTED])")
    }
}
impl DevicePairingOwner {
    /// Initialize from module-owned identities loaded by the native cipher owner.
    /// # Errors
    /// Rejects invalid bounds, scopes, keys or generation.
    pub fn new(
        config: DevicePairingConfig2,
        generation: u64,
        now: Time,
        secrets: BTreeMap<String, Zeroizing<[u8; 32]>>,
    ) -> Result<Self> {
        validate_config(&config, generation)?;
        if secrets.len() != config.scopes.len()
            || config
                .scopes
                .iter()
                .any(|s| !secrets.contains_key(&s.scope_id))
        {
            return Err(Error::DeviceDenied);
        }
        let mut identities = BTreeMap::new();
        let mut scope_identities = BTreeMap::new();
        for (scope, secret) in secrets {
            let key = KeyPair::from_secret(Zeroizing::new(*secret))?;
            let identity_id = scope_identity_id(&scope);
            if identities
                .insert(identity_id.clone(), Identity { secret, key })
                .is_some()
            {
                return Err(Error::DeviceDenied);
            }
            scope_identities.insert(scope, identity_id);
        }
        Ok(Self {
            config,
            generation,
            identities,
            scope_identities,
            records: BTreeMap::new(),
            revocations: BTreeSet::new(),
            sessions: BTreeMap::new(),
            tunnels: BTreeMap::new(),
            session_expiries: BTreeMap::new(),
            pending: BTreeMap::new(),
            last: now,
            faulted: false,
        })
    }

    /// Restore stable private identities and durable pairings from an authenticated module snapshot.
    /// The caller must first decrypt the snapshot with the configured Secret2 master capability.
    /// # Errors
    /// Rejects corrupt state, unknown scopes, invalid identities or incompatible bounds.
    pub fn restore(
        config: DevicePairingConfig2,
        generation: u64,
        now: Time,
        plaintext: &[u8],
    ) -> Result<Self> {
        let mut snapshot: Snapshot =
            serde_json::from_slice(plaintext).map_err(|_| Error::DeviceDenied)?;
        if snapshot.version != 1 && snapshot.version != 2 {
            return Err(Error::DeviceDenied);
        }
        let old_scope_layout = snapshot.version == 1;
        let mut secrets = std::mem::take(&mut snapshot.identities)
            .into_iter()
            .map(|(identity_id, secret)| (identity_id, Zeroizing::new(secret)))
            .collect::<BTreeMap<_, _>>();
        let scope_identities = if old_scope_layout {
            let mut migrated = BTreeMap::new();
            for scope in &config.scopes {
                let secret = secrets.remove(&scope.scope_id).ok_or(Error::DeviceDenied)?;
                let identity_id = scope_identity_id(&scope.scope_id);
                secrets.insert(identity_id.clone(), secret);
                migrated.insert(scope.scope_id.clone(), identity_id);
            }
            migrated
        } else {
            std::mem::take(&mut snapshot.scope_identities)
        };
        if scope_identities.len() != config.scopes.len()
            || config.scopes.iter().any(|scope| {
                scope_identities
                    .get(&scope.scope_id)
                    .is_none_or(|identity_id| !secrets.contains_key(identity_id))
            })
        {
            return Err(Error::DeviceDenied);
        }
        validate_config(&config, generation)?;
        let mut owner = Self {
            config,
            generation,
            identities: BTreeMap::new(),
            scope_identities: scope_identities.clone(),
            records: BTreeMap::new(),
            revocations: BTreeSet::new(),
            sessions: BTreeMap::new(),
            tunnels: BTreeMap::new(),
            session_expiries: BTreeMap::new(),
            pending: BTreeMap::new(),
            last: now,
            faulted: false,
        };
        for (identity_id, secret) in secrets {
            let key = KeyPair::from_secret(Zeroizing::new(*secret))?;
            owner
                .identities
                .insert(identity_id, Identity { secret, key });
        }
        Self::restore_records(
            &mut owner,
            std::mem::take(&mut snapshot.pairings),
            old_scope_layout,
        )?;
        Self::restore_revocations(&mut owner, std::mem::take(&mut snapshot.revocations))?;
        if owner.records.values().any(|record| {
            record.channels.iter().any(|channel| {
                owner
                    .revocations
                    .iter()
                    .any(|revocation| revocation.channel == *channel)
            })
        }) {
            return Err(Error::DeviceDenied);
        }
        if occupied_pairing_count(&owner.records, &owner.revocations)
            > owner.config.max_pairings as usize
        {
            return Err(Error::DeviceDenied);
        }
        Ok(owner)
    }

    fn restore_records(
        owner: &mut Self,
        records: Vec<Record>,
        old_scope_layout: bool,
    ) -> Result<()> {
        for record in records {
            let mut record = record;
            if record.channels.is_empty() {
                record.channels.insert(record.channel.clone());
            }
            if record.identity_id.is_empty() && old_scope_layout {
                record.identity_id = scope_identity_id(&record.scope);
            }
            if !owner.scope_identities.contains_key(&record.scope)
                || !owner.identities.contains_key(&record.identity_id)
                || record.id.len() != 32
                || !record.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || PublicKey::decode(&record.device_key).is_err()
                || record.user.is_empty()
                || !valid_channel(&record.channel)
                || record
                    .channels
                    .iter()
                    .any(|channel| !valid_channel(channel))
                || !record.channels.contains(&record.channel)
                || record.nonce.is_empty()
                || owner.records.values().any(|existing| {
                    existing
                        .channels
                        .iter()
                        .any(|channel| record.channels.contains(channel))
                })
                || owner.records.insert(record.id.clone(), record).is_some()
            {
                return Err(Error::DeviceDenied);
            }
        }
        Ok(())
    }

    fn restore_revocations(owner: &mut Self, revocations: Vec<Revocation>) -> Result<()> {
        let mut candidate = owner.revocations.clone();
        for revocation in revocations {
            if !owner.scope_identities.contains_key(&revocation.scope)
                || revocation.user.is_empty()
                || !valid_channel(&revocation.channel)
                || candidate
                    .iter()
                    .any(|existing| existing.channel == revocation.channel)
                || owner
                    .records
                    .values()
                    .any(|record| record.channels.contains(&revocation.channel))
            {
                return Err(Error::DeviceDenied);
            }
            candidate.insert(revocation);
        }
        if occupied_pairing_count(&owner.records, &candidate) > owner.config.max_pairings as usize {
            return Err(Error::DeviceDenied);
        }
        owner.revocations = candidate;
        Ok(())
    }

    /// Return the stable core public key for a configured scope.
    /// # Errors
    /// Denies unknown scopes, clock rollback and faulted authority.
    pub fn public_key(&mut self, scope: &str, now: Time) -> Result<String> {
        self.check_time(now)?;
        let identity_id = self
            .scope_identities
            .get(scope)
            .ok_or(Error::DeviceDenied)?;
        self.identities
            .get(identity_id)
            .map(|i| i.key.public_key().encode())
            .ok_or(Error::DeviceDenied)
    }

    /// Return the exact core public key assigned to one enrolled pairing.
    /// # Errors
    /// Denies an unknown pairing, unavailable clock or faulted owner.
    pub fn core_public_key_for_pairing(&mut self, id: &str, now: Time) -> Result<String> {
        self.check_time(now)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        self.identities
            .get(&record.identity_id)
            .map(|identity| identity.key.public_key().encode())
            .ok_or(Error::DeviceDenied)
    }

    /// Serialize the current identity and pairing registry for immediate internal encryption.
    /// The returned zeroizing buffer must never be passed to a host callback.
    /// # Errors
    /// Rejects faulted state or a snapshot exceeding the configured size limit.
    pub fn snapshot_state(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.snapshot(&self.records)
    }

    /// Import a validated whole batch of old channel-specific static identities.
    /// The supplied private bytes are already confined to the module and are
    /// consumed into zeroizing native key owners before any state is published.
    /// # Errors
    /// Rejects invalid source/context, revoked or duplicate rows, conflicts,
    /// invalid keys, capacity overflow or an oversized resulting snapshot.
    pub fn import_legacy_identities(
        &mut self,
        context: &DevicePairingContextResponse2,
        rows: Vec<LegacyDeviceIdentity>,
        now: Time,
    ) -> Result<Vec<ImportedDevicePairing>> {
        self.check_time(now)?;
        let binding = self.user_controller_context(context, now)?;
        if rows.len() > self.config.max_pairings as usize {
            return Err(Error::DeviceDenied);
        }
        let mut batch = LegacyImportBatch {
            imported: Vec::with_capacity(rows.len()),
            ..LegacyImportBatch::default()
        };
        for row in rows {
            batch.stage(self, &binding, row)?;
        }
        if occupied_pairing_count(&self.records, &self.revocations)
            .saturating_add(batch.records.len())
            .saturating_add(
                self.pending
                    .values()
                    .filter(|pending| pending.pairing_id.is_none())
                    .count(),
            )
            > self.config.max_pairings as usize
        {
            return Err(Error::DeviceDenied);
        }
        let mut candidate_identities = self
            .identities
            .iter()
            .map(|(id, identity)| (id.clone(), *identity.secret))
            .collect::<BTreeMap<_, _>>();
        candidate_identities.extend(
            batch
                .identities
                .iter()
                .map(|(id, identity)| (id.clone(), *identity.secret)),
        );
        let mut candidate_records = self.records.clone();
        candidate_records.extend(batch.records.clone());
        let candidate = Snapshot {
            version: 2,
            identities: candidate_identities,
            scope_identities: self.scope_identities.clone(),
            pairings: candidate_records.values().cloned().collect(),
            revocations: self.revocations.iter().cloned().collect(),
        };
        let candidate_bytes =
            Zeroizing::new(serde_json::to_vec(&candidate).map_err(|_| Error::DeviceDenied)?);
        if candidate_bytes.len() > self.config.max_state_bytes as usize {
            return Err(Error::DeviceDenied);
        }
        self.ensure_revocation_capacity(candidate_bytes.len(), &candidate_records)?;
        drop(candidate);
        for (id, identity) in batch.identities {
            self.identities.insert(id, identity);
        }
        self.records.extend(batch.records);
        Ok(batch.imported)
    }

    /// Merge the latest authenticated persistence snapshot during Recover without discarding live tunnels.
    /// This repairs the in-memory owner after a CAS committed but its response was lost.
    /// # Errors
    /// Rejects corrupt, foreign, conflicting or incompatible durable state.
    pub fn merge_recovered_durable_state(
        &mut self,
        plaintext: &[u8],
        context: &DevicePairingContextResponse2,
        now: Time,
    ) -> Result<()> {
        self.check_time(now)?;
        let binding = self.recovery_user_controller_context(context, &context.channel_id, now)?;
        let durable = Self::restore(self.config.clone(), self.generation, now, plaintext)?;
        if durable.scope_identities != self.scope_identities {
            return Err(Error::DeviceDenied);
        }
        for (identity_id, identity) in &durable.identities {
            if let Some(current) = self.identities.get(identity_id)
                && current.key.public_key() != identity.key.public_key()
            {
                return Err(Error::DeviceDenied);
            }
        }
        for record in durable.records.values() {
            if record.scope != binding.scope || record.user != binding.user {
                return Err(Error::DeviceDenied);
            }
            if durable
                .revocations
                .iter()
                .chain(self.revocations.iter())
                .any(|revocation| record.channels.contains(&revocation.channel))
            {
                return Err(Error::DeviceDenied);
            }
            if let Some(current) = self.records.get(&record.id) {
                if current != record {
                    return Err(Error::DeviceDenied);
                }
            } else if self.records.values().any(|current| {
                current
                    .channels
                    .iter()
                    .any(|channel| record.channels.contains(channel))
            }) {
                return Err(Error::DeviceDenied);
            }
        }
        if self.records.values().any(|record| {
            durable
                .revocations
                .iter()
                .any(|revocation| record.channels.contains(&revocation.channel))
        }) {
            return Err(Error::DeviceDenied);
        }
        let mut identities = self
            .identities
            .iter()
            .map(|(id, identity)| (id.clone(), *identity.secret))
            .collect::<BTreeMap<_, _>>();
        for (id, identity) in &durable.identities {
            identities.entry(id.clone()).or_insert(*identity.secret);
        }
        let mut records = self.records.clone();
        records.extend(durable.records.clone());
        let mut revocations = self.revocations.clone();
        revocations.extend(durable.revocations.iter().cloned());
        let candidate = Snapshot {
            version: 2,
            identities,
            scope_identities: self.scope_identities.clone(),
            pairings: records.values().cloned().collect(),
            revocations: revocations.iter().cloned().collect(),
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&candidate).map_err(|_| Error::DeviceDenied)?);
        if bytes.len() > self.config.max_state_bytes as usize
            || occupied_pairing_count(&records, &revocations) > self.config.max_pairings as usize
        {
            return Err(Error::DeviceDenied);
        }
        drop(candidate);
        for (id, identity) in durable.identities {
            self.identities.entry(id).or_insert(identity);
        }
        self.records.extend(durable.records);
        self.revocations = revocations;
        Ok(())
    }

    /// Recover public pairing metadata for one callback-authorized channel.
    /// # Errors
    /// Rejects missing, ambiguous, revoked or foreign pairings.
    pub fn recover_channel(
        &mut self,
        channel_id: &str,
        context: &DevicePairingContextResponse2,
        now: Time,
    ) -> Result<RecoveredDevicePairing> {
        self.check_time(now)?;
        let binding = self.recovery_user_controller_context(context, channel_id, now)?;
        let mut matches = self.records.values().filter(|record| {
            record.scope == binding.scope
                && record.user == binding.user
                && record.channel == channel_id
        });
        let record = matches.next().ok_or(Error::DeviceDenied)?;
        if matches.next().is_some() {
            return Err(Error::DeviceDenied);
        }
        let core_public_key = self
            .identities
            .get(&record.identity_id)
            .ok_or(Error::DeviceDenied)?
            .key
            .public_key()
            .encode();
        Ok(RecoveredDevicePairing {
            pairing_id: record.id.clone(),
            device_public_key: record.device_key.clone(),
            core_public_key,
        })
    }

    /// Begin initial enrollment from the authenticated user-controller source.
    /// # Errors
    /// Rejects invalid source, scope, context, expiry or capacity.
    pub fn begin(
        &mut self,
        context: &DevicePairingContextResponse2,
        ttl_ms: u32,
        now: Time,
    ) -> Result<(String, String, u64)> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::AuthenticatedUserController)?;
        if !valid_channel(&binding.channel) {
            return Err(Error::DeviceDenied);
        }
        if self
            .revocations
            .iter()
            .any(|revocation| revocation.channel == binding.channel)
        {
            return Err(Error::DeviceDenied);
        }
        if self
            .records
            .values()
            .any(|record| record.channels.contains(&binding.channel))
        {
            return Err(Error::DeviceDenied);
        }
        if !self.scope_identities.contains_key(&binding.scope)
            || binding.channel.is_empty()
            || binding.nonce.is_empty()
            || occupied_pairing_count(&self.records, &self.revocations)
                + self
                    .pending
                    .values()
                    .filter(|pending| pending.pairing_id.is_none())
                    .count()
                >= self.config.max_pairings as usize
        {
            return Err(Error::DeviceDenied);
        }
        let identity_id = self
            .scope_identities
            .get(&binding.scope)
            .cloned()
            .ok_or(Error::DeviceDenied)?;
        self.new_pending(
            PendingRequest {
                binding,
                expected_key: None,
                pairing_id: None,
                identity_id,
                ttl: ttl_ms,
                context_expiry: context.expires_at_ms,
            },
            now,
        )
    }

    /// Begin same-key renewal under a fresh backend reconnect attestation.
    /// # Errors
    /// Rejects wrong user/scope/source or stale pairing.
    pub fn renew(
        &mut self,
        id: &str,
        context: &DevicePairingContextResponse2,
        ttl_ms: u32,
        now: Time,
    ) -> Result<(String, String, u64)> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::BackendReconnect)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        if record.scope != binding.scope || record.user != binding.user {
            return Err(Error::DeviceDenied);
        }
        if self.channel_claimed(&binding, id) {
            return Err(Error::DeviceDenied);
        }
        if self
            .revocations
            .iter()
            .any(|revocation| revocation.channel == binding.channel)
        {
            return Err(Error::DeviceDenied);
        }
        let expected_key = record.device_key.clone();
        let identity_id = record.identity_id.clone();
        let pairing_id = record.id.clone();
        self.new_pending(
            PendingRequest {
                binding,
                expected_key: Some(expected_key),
                pairing_id: Some(pairing_id),
                identity_id,
                ttl: ttl_ms,
                context_expiry: context.expires_at_ms,
            },
            now,
        )
    }

    /// Open the unchanged v3 handshake and return its unchanged v4 acknowledgement.
    /// # Errors
    /// Rejects expired, replayed, substituted or unauthenticated handshakes.
    pub fn handshake(
        &mut self,
        receipt: &str,
        context: &DevicePairingContextResponse2,
        frame: &[u8],
        now: Time,
    ) -> Result<Vec<u8>> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::RegisteredSocket)?;
        let pending = self.pending.get_mut(receipt).ok_or(Error::DeviceDenied)?;
        validate_pending(pending, &binding, now)?;
        if pending.handshake.is_some() {
            return Err(Error::DeviceDenied);
        }
        let identity_id = pending.identity_id.clone();
        let identity = self
            .identities
            .get(&identity_id)
            .ok_or(Error::DeviceDenied)?;
        let (client_handshake_ephemeral, plaintext) = identity.key.open_handshake(frame)?;
        let payload = parse_handshake_payload(&plaintext, &client_handshake_ephemeral)?;
        let peer_static = PublicKey::decode(&payload.device_pubkey)?;
        let client_session_ephemeral = PublicKey::decode(&payload.client_ephemeral_pubkey)?;
        if pending
            .expected_key
            .as_deref()
            .is_some_and(|expected| expected != payload.device_pubkey)
        {
            return Err(Error::DeviceDenied);
        }
        let server_ephemeral = KeyPair::generate()?;
        let server_public = server_ephemeral.public_key();
        let keys = identity.key.session_keys(
            peer_static,
            &server_ephemeral,
            client_session_ephemeral,
            client_session_ephemeral,
            server_public,
        )?;
        let tunnel = Arc::new(Mutex::new(Tunnel::new(Role::Server, keys)));
        let ack = serde_json::to_vec(&serde_json::json!({"kind":"handshake_ack", "server_ephemeral_pubkey":server_public.encode()})).map_err(|_| Error::DeviceDenied)?;
        let ack = identity.key.seal_ack(client_session_ephemeral, &ack)?;
        pending.handshake = Some(Handshake {
            device_key: payload.device_pubkey,
            tunnel: Some(tunnel),
        });
        Ok(ack)
    }

    /// Verify first static-DH-authenticated frame and prepare a durable transaction.
    /// # Errors
    /// Rejects missing or replayed proof, mismatched context, wrong renewal key or expiry.
    pub fn prepare_confirmation(
        &mut self,
        receipt: &str,
        context: &DevicePairingContextResponse2,
        frame: &[u8],
        now: Time,
    ) -> Result<PreparedConfirmation> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::RegisteredSocket)?;
        let pairing_id = self
            .pending
            .get(receipt)
            .ok_or(Error::DeviceDenied)?
            .pairing_id
            .clone();
        if self.records.values().any(|existing| {
            Some(existing.id.as_str()) != pairing_id.as_deref()
                && existing.channels.contains(&binding.channel)
        }) || self
            .revocations
            .iter()
            .any(|revocation| revocation.channel == binding.channel)
        {
            return Err(Error::DeviceDenied);
        }
        let mut channels = pairing_id
            .as_deref()
            .and_then(|id| self.records.get(id))
            .map_or_else(BTreeSet::new, |old| old.channels.clone());
        channels.insert(binding.channel.clone());
        let record = {
            let pending = self.pending.get_mut(receipt).ok_or(Error::DeviceDenied)?;
            validate_pending(pending, &binding, now)?;
            if pending.confirming {
                return Err(Error::DeviceDenied);
            }
            let handshake = pending.handshake.as_mut().ok_or(Error::DeviceDenied)?;
            handshake
                .tunnel
                .as_ref()
                .ok_or(Error::DeviceDenied)?
                .lock()
                .map_err(|_| Error::DeviceDenied)?
                .open(frame)?;
            Record {
                id: pending.pairing_id.clone().map_or_else(random_id, Ok)?,
                scope: binding.scope.clone(),
                user: binding.user.clone(),
                device_key: handshake.device_key.clone(),
                channel: binding.channel.clone(),
                channels: channels.clone(),
                nonce: binding.nonce.clone(),
                identity_id: pending.identity_id.clone(),
            }
        };
        let session_expires =
            session_expiry(now, self.config.max_session_ttl_ms, context.expires_at_ms)?;
        let mut records = self.records.clone();
        records.insert(record.id.clone(), record.clone());
        let state = self.snapshot(&records)?;
        self.ensure_revocation_capacity(state.len(), &records)?;
        let session_id = random_id()?;
        let pending = self.pending.get_mut(receipt).ok_or(Error::DeviceDenied)?;
        pending.confirming = true;
        let tunnel = pending
            .handshake
            .as_mut()
            .and_then(|handshake| handshake.tunnel.take())
            .ok_or(Error::DeviceDenied)?;
        Ok(PreparedConfirmation {
            receipt: receipt.into(),
            session_id,
            record,
            tunnel,
            session_expires,
            state,
        })
    }

    /// Commit after ciphertext CAS storage succeeds; only then does the handle become usable.
    /// # Errors
    /// Rejects expired, stale-generation, substituted or absent confirmation state.
    pub fn commit_confirmation(
        &mut self,
        prepared: PreparedConfirmation,
        now: Time,
    ) -> Result<PairingResult> {
        self.check_time(now)?;
        let pending = self
            .pending
            .get(&prepared.receipt)
            .ok_or(Error::DeviceDenied)?;
        if !pending.confirming
            || now.wall >= pending.expires_wall
            || now.monotonic >= pending.expires_mono
            || pending.binding.generation != self.generation
            || pending
                .pairing_id
                .as_ref()
                .is_some_and(|id| id != &prepared.record.id)
        {
            return Err(Error::DeviceDenied);
        }
        self.pending.remove(&prepared.receipt);
        self.sessions
            .retain(|_, pairing_id| pairing_id != &prepared.record.id);
        self.tunnels
            .retain(|session_id, _| self.sessions.contains_key(session_id));
        self.session_expiries
            .retain(|session_id, _| self.sessions.contains_key(session_id));
        let session_id = prepared.session_id;
        self.sessions
            .insert(session_id.clone(), prepared.record.id.clone());
        self.tunnels.insert(session_id.clone(), prepared.tunnel);
        self.session_expiries
            .insert(session_id.clone(), prepared.session_expires);
        self.records
            .insert(prepared.record.id.clone(), prepared.record.clone());
        Ok(to_result(
            &prepared.record,
            session_id,
            prepared.session_expires.0,
        ))
    }

    /// Cancel a failed persistence transaction and consume its receipt.
    pub fn abort_confirmation(&mut self, receipt: &str) {
        self.pending.remove(receipt);
    }

    /// Retire only a socket session while preserving the durable pairing record.
    /// # Errors
    /// Rejects a closure from another scope, channel, nonce or source.
    pub fn end_session(
        &mut self,
        session_id: &str,
        context: &DevicePairingContextResponse2,
        now: Time,
    ) -> Result<()> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::SocketClosed)?;
        let id = self.sessions.get(session_id).ok_or(Error::DeviceDenied)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        if record.scope != binding.scope
            || record.user != binding.user
            || record.channel != binding.channel
            || record.nonce != binding.nonce
        {
            return Err(Error::DeviceDenied);
        }
        self.sessions.remove(session_id);
        self.tunnels.remove(session_id);
        self.session_expiries.remove(session_id);
        Ok(())
    }

    /// Refresh a live session from a fresh attestation of its same authenticated socket.
    /// This retains the existing tunnel keys and counters and does not alter durable pairing.
    /// # Errors
    /// Rejects an expired/closed handle or a foreign, stale, or unauthenticated socket.
    pub fn refresh_session(
        &mut self,
        session_id: &str,
        context: &DevicePairingContextResponse2,
        now: Time,
    ) -> Result<(u64, u64)> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::RegisteredSocket)?;
        let id = self.sessions.get(session_id).ok_or(Error::DeviceDenied)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        let (current_wall, current_mono) = *self
            .session_expiries
            .get(session_id)
            .ok_or(Error::DeviceDenied)?;
        if record.scope != binding.scope
            || record.user != binding.user
            || record.channel != binding.channel
            || record.nonce != binding.nonce
            || now.wall >= current_wall
            || now.monotonic >= current_mono
        {
            return Err(Error::DeviceDenied);
        }
        let expires = session_expiry(now, self.config.max_session_ttl_ms, context.expires_at_ms)?;
        self.session_expiries.insert(session_id.into(), expires);
        Ok(expires)
    }

    /// Return all transient handles belonging to one durable pairing before revocation.
    #[must_use]
    pub fn sessions_for_pairing(&self, pairing_id: &str) -> Vec<String> {
        self.sessions
            .iter()
            .filter_map(|(session, pairing)| (pairing == pairing_id).then_some(session.clone()))
            .collect()
    }

    /// Return current transient handles that a pending renewal will replace.
    #[must_use]
    pub fn sessions_for_pending(&self, receipt: &str) -> Vec<String> {
        self.pending
            .get(receipt)
            .and_then(|pending| pending.pairing_id.as_deref())
            .map(|pairing_id| self.sessions_for_pairing(pairing_id))
            .unwrap_or_default()
    }

    /// Return pending receipts tied to one pairing before revocation.
    #[must_use]
    pub fn pending_for_pairing(&self, pairing_id: &str) -> Vec<String> {
        self.pending
            .iter()
            .filter_map(|(receipt, pending)| {
                (pending.pairing_id.as_deref() == Some(pairing_id)).then_some(receipt.clone())
            })
            .collect()
    }

    /// Retire a newly committed but not yet published transient session.
    /// Durable enrollment remains intact.
    pub fn retire_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        self.tunnels.remove(session_id);
        self.session_expiries.remove(session_id);
    }

    /// Obtain the module-internal shared tunnel for registration in the existing `DeviceFrame2`
    /// capability registry. The returned handle is never exposed through the bus.
    /// # Errors
    /// Rejects unknown, expired, or retired session capabilities.
    pub fn session_tunnel(
        &self,
        session_id: &str,
        now: Time,
    ) -> Result<(String, Arc<Mutex<Tunnel>>, u64, u64)> {
        if self.faulted || now.wall < self.last.wall || now.monotonic < self.last.monotonic {
            return Err(Error::DeviceDenied);
        }
        let pairing_id = self.sessions.get(session_id).ok_or(Error::DeviceDenied)?;
        let record = self.records.get(pairing_id).ok_or(Error::DeviceDenied)?;
        let (expires_wall, expires_monotonic) = *self
            .session_expiries
            .get(session_id)
            .ok_or(Error::DeviceDenied)?;
        if now.wall >= expires_wall || now.monotonic >= expires_monotonic {
            return Err(Error::DeviceDenied);
        }
        Ok((
            record.scope.clone(),
            Arc::clone(self.tunnels.get(session_id).ok_or(Error::DeviceDenied)?),
            expires_wall,
            expires_monotonic,
        ))
    }

    /// Remove one pairing and every live tunnel, returning the state to persist before success.
    /// # Errors
    /// Rejects an unauthenticated or cross-scope controller.
    pub fn revoke(
        &mut self,
        id: &str,
        context: &DevicePairingContextResponse2,
        now: Time,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_time(now)?;
        let binding = self.context(context, DevicePairingSource2::AuthenticatedUserController)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        if record.scope != binding.scope || record.user != binding.user {
            return Err(Error::DeviceDenied);
        }
        let tombstones = record
            .channels
            .iter()
            .map(|channel| Revocation {
                scope: record.scope.clone(),
                user: record.user.clone(),
                channel: channel.clone(),
                pairing_id: record.id.clone(),
            })
            .collect::<Vec<_>>();
        self.snapshot_after_revoking(&self.records, id)?;
        if occupied_pairing_count(&self.records, &self.revocations).saturating_sub(1) + 1
            > self.config.max_pairings as usize
        {
            return Err(Error::DeviceDenied);
        }
        let removed = self
            .sessions
            .iter()
            .filter_map(|(session, pairing)| (pairing == id).then_some(session.clone()))
            .collect::<Vec<_>>();
        self.pending
            .retain(|_, pending| pending.pairing_id.as_deref() != Some(id));
        for session in removed {
            self.sessions.remove(&session);
            self.tunnels.remove(&session);
            self.session_expiries.remove(&session);
        }
        let record = self.records.remove(id).ok_or(Error::DeviceDenied)?;
        self.revocations.extend(tombstones);
        self.remove_unreferenced_identity(&record.identity_id);
        self.snapshot(&self.records)
    }

    /// Seal one frame through a live tunnel capability.
    /// # Errors
    /// Rejects unknown, wrong-scope, expired or retired sessions.
    pub fn seal(
        &mut self,
        session_id: &str,
        scope: &str,
        bytes: &[u8],
        now: Time,
    ) -> Result<Vec<u8>> {
        self.check_time(now)?;
        let id = self.sessions.get(session_id).ok_or(Error::DeviceDenied)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        let (expires_wall, expires_monotonic) = *self
            .session_expiries
            .get(session_id)
            .ok_or(Error::DeviceDenied)?;
        if record.scope != scope || now.wall >= expires_wall || now.monotonic >= expires_monotonic {
            return Err(Error::DeviceDenied);
        }
        self.tunnels
            .get(session_id)
            .ok_or(Error::DeviceDenied)?
            .lock()
            .map_err(|_| Error::DeviceDenied)?
            .seal(bytes)
    }

    /// Open one authenticated frame through a live tunnel capability.
    /// # Errors
    /// Rejects unknown, wrong-scope, expired, replayed or retired sessions.
    pub fn open(
        &mut self,
        session_id: &str,
        scope: &str,
        frame: &[u8],
        now: Time,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_time(now)?;
        let id = self.sessions.get(session_id).ok_or(Error::DeviceDenied)?;
        let record = self.records.get(id).ok_or(Error::DeviceDenied)?;
        let (expires_wall, expires_monotonic) = *self
            .session_expiries
            .get(session_id)
            .ok_or(Error::DeviceDenied)?;
        if record.scope != scope || now.wall >= expires_wall || now.monotonic >= expires_monotonic {
            return Err(Error::DeviceDenied);
        }
        self.tunnels
            .get(session_id)
            .ok_or(Error::DeviceDenied)?
            .lock()
            .map_err(|_| Error::DeviceDenied)?
            .open(frame)
    }

    /// Wipe every private identity, pairing, pending receipt and tunnel at shutdown/reinit.
    pub fn close(&mut self) {
        self.faulted = true;
        self.identities.clear();
        self.scope_identities.clear();
        self.records.clear();
        self.revocations.clear();
        self.sessions.clear();
        self.tunnels.clear();
        self.session_expiries.clear();
        self.pending.clear();
    }

    /// Whether this owner has been permanently closed after an authority fault.
    #[must_use]
    pub fn is_faulted(&self) -> bool {
        self.faulted
    }

    /// Permanently fault after an indeterminate persistence failure.
    pub fn fail_persistence(&mut self) {
        self.close();
    }

    fn context(
        &self,
        c: &DevicePairingContextResponse2,
        source: DevicePairingSource2,
    ) -> Result<Binding> {
        if c.source != source
            || c.generation != self.generation
            || c.scope_id.is_empty()
            || c.user_binding.is_empty()
            || (source != DevicePairingSource2::AuthenticatedUserController
                && !valid_channel(&c.channel_id))
            || (source != DevicePairingSource2::AuthenticatedUserController
                && c.connection_nonce.is_empty())
            || (source == DevicePairingSource2::RegisteredSocket
                && !c.pairing_token.as_deref().is_some_and(valid_pairing_token))
            || c.pairing_token
                .as_deref()
                .is_some_and(|token| !valid_pairing_token(token))
            || c.expires_at_ms <= self.last.wall
            || !self.scope_identities.contains_key(&c.scope_id)
        {
            return Err(Error::DeviceDenied);
        }
        Ok(Binding::from(c))
    }
    fn user_controller_context(
        &self,
        context: &DevicePairingContextResponse2,
        now: Time,
    ) -> Result<Binding> {
        if context.source != DevicePairingSource2::AuthenticatedUserController
            || context.generation != self.generation
            || context.scope_id.is_empty()
            || context.user_binding.is_empty()
            || (!context.channel_id.is_empty() && !valid_channel(&context.channel_id))
            || (!context.channel_id.is_empty()
                && !context
                    .pairing_token
                    .as_deref()
                    .is_some_and(valid_pairing_token))
            || context
                .pairing_token
                .as_deref()
                .is_some_and(|token| !valid_pairing_token(token))
            || context.expires_at_ms <= now.wall
            || !self.scope_identities.contains_key(&context.scope_id)
        {
            return Err(Error::DeviceDenied);
        }
        Ok(Binding::from(context))
    }
    fn recovery_user_controller_context(
        &self,
        context: &DevicePairingContextResponse2,
        channel_id: &str,
        now: Time,
    ) -> Result<Binding> {
        if context.source != DevicePairingSource2::AuthenticatedUserController
            || context.generation != self.generation
            || context.scope_id.is_empty()
            || context.user_binding.is_empty()
            || !valid_channel(channel_id)
            || context.channel_id != channel_id
            || context.pairing_token.is_some()
            || !context.connection_nonce.is_empty()
            || context.expires_at_ms <= now.wall
            || !self.scope_identities.contains_key(&context.scope_id)
        {
            return Err(Error::DeviceDenied);
        }
        Ok(Binding::from(context))
    }
    fn new_pending(&mut self, request: PendingRequest, now: Time) -> Result<(String, String, u64)> {
        if self.pending.len() >= self.config.max_pending as usize
            || request.ttl == 0
            || request.ttl > self.config.max_pending_ttl_ms
        {
            return Err(Error::DeviceDenied);
        }
        let expires_wall = now
            .wall
            .checked_add(u64::from(request.ttl))
            .ok_or(Error::DeviceDenied)?
            .min(request.context_expiry);
        let expires_mono = now
            .monotonic
            .checked_add(u64::from(request.ttl))
            .ok_or(Error::DeviceDenied)?;
        if expires_wall <= now.wall {
            return Err(Error::DeviceDenied);
        }
        let receipt = random_id()?;
        if self.pending.contains_key(&receipt) {
            return Err(Error::DeviceDenied);
        }
        let public = self
            .identities
            .get(&request.identity_id)
            .ok_or(Error::DeviceDenied)?
            .key
            .public_key()
            .encode();
        self.pending.insert(
            receipt.clone(),
            Pending {
                binding: request.binding,
                expected_key: request.expected_key,
                pairing_id: request.pairing_id,
                identity_id: request.identity_id,
                expires_wall,
                expires_mono,
                handshake: None,
                confirming: false,
            },
        );
        Ok((receipt, public, expires_wall))
    }
    fn validate_time(&mut self, now: Time) -> Result<()> {
        if self.faulted || now.wall < self.last.wall || now.monotonic < self.last.monotonic {
            self.close();
            return Err(Error::DeviceDenied);
        }
        self.last = now;
        Ok(())
    }
    /// Prune expired pending receipts and return their ids to the host adapter.
    ///
    /// The adapter uses these ids to retire receipt-bound confidential aliases
    /// when the native owner expires the corresponding enrollment.
    ///
    /// # Errors
    /// Rejects a faulted owner or a clock that moved backwards.
    pub fn prune_expired_pending(&mut self, now: Time) -> Result<Vec<String>> {
        self.validate_time(now)?;
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                now.wall >= pending.expires_wall || now.monotonic >= pending.expires_mono
            })
            .map(|(receipt, _)| receipt.clone())
            .collect();
        for receipt in &expired {
            self.pending.remove(receipt);
        }
        Ok(expired)
    }
    fn check_time(&mut self, now: Time) -> Result<()> {
        self.validate_time(now)?;
        self.pending
            .retain(|_, p| now.wall < p.expires_wall && now.monotonic < p.expires_mono);
        Ok(())
    }
    fn snapshot(&self, records: &BTreeMap<String, Record>) -> Result<Zeroizing<Vec<u8>>> {
        self.snapshot_with_revocations(records, &self.revocations)
    }

    fn ensure_revocation_capacity(
        &self,
        active_snapshot_bytes: usize,
        records: &BTreeMap<String, Record>,
    ) -> Result<()> {
        let reserved = records.values().try_fold(0usize, |total, record| {
            let tombstones = record
                .channels
                .iter()
                .map(|channel| Revocation {
                    scope: record.scope.clone(),
                    user: record.user.clone(),
                    channel: channel.clone(),
                    pairing_id: record.id.clone(),
                })
                .collect::<Vec<_>>();
            let tombstone_bytes = serde_json::to_vec(&tombstones)
                .map_err(|_| Error::DeviceDenied)?
                .len()
                .saturating_sub(2)
                .saturating_add(tombstones.len());
            let record_bytes = serde_json::to_vec(record)
                .map_err(|_| Error::DeviceDenied)?
                .len();
            Ok::<_, Error>(total.saturating_add(tombstone_bytes.saturating_sub(record_bytes)))
        })?;
        if active_snapshot_bytes.saturating_add(reserved) > self.config.max_state_bytes as usize {
            return Err(Error::DeviceDenied);
        }
        Ok(())
    }

    fn snapshot_after_revoking(
        &self,
        records: &BTreeMap<String, Record>,
        pairing_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut remaining_records = records.clone();
        let record = remaining_records
            .remove(pairing_id)
            .ok_or(Error::DeviceDenied)?;
        let mut revocations = self.revocations.clone();
        revocations.extend(record.channels.iter().map(|channel| Revocation {
            scope: record.scope.clone(),
            user: record.user.clone(),
            channel: channel.clone(),
            pairing_id: record.id.clone(),
        }));
        self.snapshot_with_revocations(&remaining_records, &revocations)
    }

    fn snapshot_with_revocations(
        &self,
        records: &BTreeMap<String, Record>,
        revocations: &BTreeSet<Revocation>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.faulted {
            return Err(Error::DeviceDenied);
        }
        let snapshot = Snapshot {
            version: 2,
            identities: self
                .identities
                .iter()
                .map(|(id, i)| (id.clone(), *i.secret))
                .collect(),
            scope_identities: self.scope_identities.clone(),
            pairings: records.values().cloned().collect(),
            revocations: revocations.iter().cloned().collect(),
        };
        if occupied_pairing_count(records, revocations) > self.config.max_pairings as usize {
            return Err(Error::DeviceDenied);
        }
        let bytes = serde_json::to_vec(&snapshot).map_err(|_| Error::DeviceDenied)?;
        if bytes.len() > self.config.max_state_bytes as usize {
            return Err(Error::DeviceDenied);
        }
        Ok(Zeroizing::new(bytes))
    }

    fn channel_claimed(&self, binding: &Binding, except_id: &str) -> bool {
        self.records
            .values()
            .any(|record| record.id != except_id && record.channels.contains(&binding.channel))
            || self
                .revocations
                .iter()
                .any(|revocation| revocation.channel == binding.channel)
    }

    fn remove_unreferenced_identity(&mut self, identity_id: &str) {
        let is_scope_identity = self.scope_identities.values().any(|id| id == identity_id);
        let is_referenced = self
            .records
            .values()
            .any(|record| record.identity_id == identity_id);
        if !is_scope_identity && !is_referenced {
            self.identities.remove(identity_id);
        }
    }
}

fn validate_config(c: &DevicePairingConfig2, generation: u64) -> Result<()> {
    if generation == 0
        || c.scopes.is_empty()
        || c.scopes.len() > 128
        || !(1..=4096).contains(&c.max_pairings)
        || !(1..=128).contains(&c.max_pending)
        || !(1..=300_000).contains(&c.max_pending_ttl_ms)
        || !(1..=604_800_000).contains(&c.max_session_ttl_ms)
        || !(1..=1_048_576).contains(&c.max_state_bytes)
        || !(1..=30_000).contains(&c.callback_timeout_ms)
    {
        return Err(Error::DeviceDenied);
    }
    let mut ids = BTreeSet::new();
    for s in &c.scopes {
        if s.scope_id.len() != 32
            || !s.scope_id.bytes().all(|b| b.is_ascii_hexdigit())
            || s.secret_registration_id.len() != 32
            || s.persistence_backend_id.is_empty()
            || s.persistence_backend_id.len() > 128
            || s.persistence_backend_id.chars().any(char::is_control)
            || !ids.insert(s.scope_id.as_str())
        {
            return Err(Error::DeviceDenied);
        }
        match (
            s.legacy_device_backend_id.as_deref(),
            s.legacy_source_registration_id.as_deref(),
        ) {
            (None, None) => {}
            (Some(backend), Some(registration))
                if !backend.is_empty()
                    && registration.len() == 32
                    && registration.bytes().all(|byte| byte.is_ascii_hexdigit()) => {}
            _ => return Err(Error::DeviceDenied),
        }
    }
    Ok(())
}

fn scope_identity_id(scope: &str) -> String {
    format!("scope:{scope}")
}

fn valid_channel(channel: &str) -> bool {
    !channel.is_empty()
        && channel.len() <= 128
        && channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
}
fn valid_pairing_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 512 && token.bytes().all(|byte| byte.is_ascii_graphic())
}
fn validate_pending(p: &Pending, b: &Binding, now: Time) -> Result<()> {
    if p.binding != *b || now.wall >= p.expires_wall || now.monotonic >= p.expires_mono {
        Err(Error::DeviceDenied)
    } else {
        Ok(())
    }
}
fn session_expiry(now: Time, max_ttl_ms: u32, host_expiry: u64) -> Result<(u64, u64)> {
    let ttl = u64::from(max_ttl_ms).min(host_expiry.saturating_sub(now.wall));
    if ttl == 0 {
        return Err(Error::DeviceDenied);
    }
    Ok((
        now.wall.checked_add(ttl).ok_or(Error::DeviceDenied)?,
        now.monotonic.checked_add(ttl).ok_or(Error::DeviceDenied)?,
    ))
}
fn to_result(r: &Record, session_id: String, expires_at_ms: u64) -> PairingResult {
    PairingResult {
        pairing_id: r.id.clone(),
        session_id,
        device_public_key: r.device_key.clone(),
        scope_id: r.scope.clone(),
        channel_id: r.channel.clone(),
        expires_at_ms,
    }
}
fn occupied_pairing_count(
    records: &BTreeMap<String, Record>,
    revocations: &BTreeSet<Revocation>,
) -> usize {
    let mut retired_ids = BTreeSet::new();
    let mut legacy_tombstones = 0usize;
    for revocation in revocations {
        if revocation.pairing_id.is_empty() {
            legacy_tombstones += 1;
        } else {
            retired_ids.insert(revocation.pairing_id.as_str());
        }
    }
    records.len() + retired_ids.len() + legacy_tombstones
}

fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
    let mut id = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut id, "{b:02x}").map_err(|_| Error::Entropy)?;
    }
    Ok(id)
}
#[derive(serde::Deserialize)]
struct HandshakePayload {
    device_pubkey: String,
    client_ephemeral_pubkey: String,
}

fn parse_handshake_payload(bytes: &[u8], frame_ephemeral: &PublicKey) -> Result<HandshakePayload> {
    if let Ok(payload) = serde_json::from_slice(bytes) {
        return Ok(payload);
    }
    // Older clients send the device static key as the entire plaintext. The
    // sealed frame already carries the client ephemeral key in this format.
    let device_pubkey = std::str::from_utf8(bytes)
        .map_err(|_| Error::DeviceDenied)?
        .trim();
    PublicKey::decode(device_pubkey)?;
    Ok(HandshakePayload {
        device_pubkey: device_pubkey.to_owned(),
        client_ephemeral_pubkey: frame_ephemeral.encode(),
    })
}

#[cfg(test)]
#[path = "device_pairing_tests.rs"]
mod tests;
