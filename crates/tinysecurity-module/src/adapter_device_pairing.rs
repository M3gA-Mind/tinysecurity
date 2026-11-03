//! Host-attested pairing lifecycle over the existing `DeviceFrame2` registry.

use super::Arc;
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    sync::{Mutex, RwLock},
};
use tinysecurity::crypto::{
    device_handles::{PairedTunnelRegistration, Registry},
    device_pairing::{DevicePairingOwner, LegacyDeviceIdentity, Time},
    native_handles::cipher::DevicePairingStateCipher,
};
use tinysecurity_bus::{
    DevicePairingConfig2, DevicePairingContextRequest2, DevicePairingContextResponse2,
    DevicePairingLegacyFormat2, DevicePairingLegacyLoadRequest2, DevicePairingLegacyLoadResponse2,
    DevicePairingOperation2, DevicePairingPersistenceOperation2, DevicePairingPersistenceRequest2,
    DevicePairingPersistenceResponse2, DevicePairingPurpose2, DevicePairingRequest2,
    DevicePairingResponse2, DevicePairingRuntimeScope2, MasterPurpose2, MasterSlotKind2,
    SecretRegistration2, callback_names2,
};
use zeroize::{Zeroize, Zeroizing};

fn denied() -> tinybus::Error {
    tinybus::Error::failed("device pairing authority denied")
}
const MAX_LEGACY_IMPORT_HANDLES: usize = 4096;
fn consume_legacy_import_handle(
    consumed: &mut BTreeSet<(String, String)>,
    scope_id: &str,
    handle: &str,
    limit: usize,
) -> tinybus::Result<()> {
    if scope_id.len() != 32
        || !scope_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || handle.is_empty()
        || handle.len() > 256
        || handle.chars().any(char::is_control)
        || consumed.len() >= limit
        || !consumed.insert((scope_id.to_owned(), handle.to_owned()))
    {
        return Err(denied());
    }
    Ok(())
}
fn validate_logout_context(
    context: &DevicePairingContextResponse2,
    generation: u64,
    now: Time,
) -> tinybus::Result<()> {
    if context.source != tinysecurity_bus::DevicePairingSource2::AuthenticatedUserLogout
        || context.generation != generation
        || context.expires_at_ms <= now.wall
    {
        return Err(denied());
    }
    Ok(())
}
fn validate_unlock_context(
    context: &DevicePairingContextResponse2,
    generation: u64,
    now: Time,
) -> tinybus::Result<()> {
    if context.source != tinysecurity_bus::DevicePairingSource2::AuthenticatedUserController
        || context.generation != generation
        || context.expires_at_ms <= now.wall
    {
        return Err(denied());
    }
    Ok(())
}
fn unlock_scope_lookup<T>(
    context: &DevicePairingContextResponse2,
    generation: u64,
    now: Time,
    lookup: impl FnOnce() -> tinybus::Result<T>,
) -> tinybus::Result<T> {
    validate_unlock_context(context, generation, now)?;
    lookup()
}
fn valid_persistence_backend_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
}
fn lookup_scope(
    catalog: &RwLock<BTreeMap<String, tinysecurity_bus::DevicePairingScope2>>,
    scope_id: &str,
) -> tinybus::Result<tinysecurity_bus::DevicePairingScope2> {
    catalog
        .read()
        .map_err(|_| denied())?
        .get(scope_id)
        .cloned()
        .ok_or_else(denied)
}
fn consume_legacy_import(
    consumed: &Mutex<BTreeSet<(String, String)>>,
    scope_id: &str,
    handle: &str,
) -> tinybus::Result<()> {
    let mut consumed = consumed.lock().map_err(|_| denied())?;
    consume_legacy_import_handle(&mut consumed, scope_id, handle, MAX_LEGACY_IMPORT_HANDLES)
}
fn one_scope_config(
    config: &DevicePairingConfig2,
    catalog: &RwLock<BTreeMap<String, tinysecurity_bus::DevicePairingScope2>>,
    scope_id: &str,
) -> tinybus::Result<DevicePairingConfig2> {
    let mut config = config.clone();
    config.scopes = vec![lookup_scope(catalog, scope_id)?];
    Ok(config)
}
fn validate_runtime_approval_snapshot(
    approval: &tinysecurity_bus::ApprovalScope2,
    generation: u64,
) -> tinybus::Result<()> {
    if approval.generation != generation || !approval.require_approval || approval.auto_approve_all
    {
        return Err(denied());
    }
    Ok(())
}
fn validate_secret_scope_binding(
    approval: &tinysecurity_bus::ApprovalScope2,
    selected: &tinysecurity_bus::ApprovalScope2,
    verified: &tinysecurity_bus::ApprovalScope2,
) -> tinybus::Result<()> {
    if selected != approval || verified != approval {
        return Err(denied());
    }
    Ok(())
}
fn validate_runtime_defaults(defaults: &DevicePairingRuntimeScope2) -> tinybus::Result<()> {
    if !valid_persistence_backend_id(&defaults.persistence_backend_id)
        || defaults.allowed_origins.is_empty()
        || defaults.allowed_origins.len() > 8
        || defaults
            .legacy_device_backend_id
            .as_ref()
            .is_some_and(|id| id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || defaults
            .allowed_origins
            .iter()
            .enumerate()
            .any(|(index, origin)| defaults.allowed_origins[..index].contains(origin))
    {
        return Err(denied());
    }
    Ok(())
}
fn derive_runtime_scope(
    approval: &tinysecurity_bus::ApprovalScope2,
    secret: &SecretRegistration2,
    defaults: &DevicePairingRuntimeScope2,
) -> tinybus::Result<(
    tinysecurity_bus::DevicePairingScope2,
    tinysecurity_bus::Origin,
)> {
    if approval.scope_id.len() != 32
        || !approval
            .scope_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || approval.generation == 0
        || !approval.require_approval
        || approval.auto_approve_all
        || secret.approval_scope_id != approval.scope_id
        || secret.purpose != MasterPurpose2::ConfigUserMaster
        || secret.target.slot != MasterSlotKind2::User
        || secret.registration_id.len() != 32
        || !secret
            .registration_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !defaults.allowed_origins.contains(&secret.origin)
        || !valid_persistence_backend_id(&defaults.persistence_backend_id)
        || defaults
            .legacy_device_backend_id
            .as_ref()
            .is_some_and(|id| id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(denied());
    }
    let scope = tinysecurity_bus::DevicePairingScope2 {
        scope_id: approval.scope_id.clone(),
        secret_registration_id: secret.registration_id.clone(),
        persistence_backend_id: defaults.persistence_backend_id.clone(),
        legacy_device_backend_id: defaults.legacy_device_backend_id.clone(),
        legacy_source_registration_id: defaults
            .legacy_device_backend_id
            .as_ref()
            .map(|_| secret.registration_id.clone()),
    };
    Ok((scope, secret.origin.clone()))
}
#[allow(clippy::too_many_arguments)] // Both registries are updated under the caller's lock pair.
fn admit_runtime_scope(
    scope: tinysecurity_bus::DevicePairingScope2,
    approval: tinysecurity_bus::ApprovalScope2,
    origin: tinysecurity_bus::Origin,
    registry: &Registry,
    generation: u64,
    now: tinysecurity::crypto::device_handles::Time,
    epochs: &mut BTreeMap<String, u64>,
    catalog: &mut BTreeMap<String, tinysecurity_bus::DevicePairingScope2>,
) -> tinybus::Result<tinysecurity_bus::DevicePairingScopeReceipt2> {
    if scope.scope_id != approval.scope_id
        || approval.generation != generation
        || scope.secret_registration_id.len() != 32
        || !scope
            .secret_registration_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !valid_persistence_backend_id(&scope.persistence_backend_id)
        || scope.legacy_device_backend_id.is_some() != scope.legacy_source_registration_id.is_some()
        || scope
            .legacy_source_registration_id
            .as_deref()
            .is_some_and(|id| id != scope.secret_registration_id)
    {
        return Err(denied());
    }
    if let Some(existing) = catalog.get(&scope.scope_id) {
        if existing != &scope || !epochs.contains_key(&scope.scope_id) {
            return Err(denied());
        }
        registry
            .register_scope(approval, origin, generation, now)
            .map_err(|_| denied())?;
        return Ok(tinysecurity_bus::DevicePairingScopeReceipt2 {
            scope_id: scope.scope_id,
            active: true,
        });
    }
    if catalog.len() >= 128 || epochs.contains_key(&scope.scope_id) {
        return Err(denied());
    }
    // Native admission is the only fallible mutation. The two host-owned maps
    // are already locked by the caller and insertion cannot fail afterward.
    registry
        .register_scope(approval, origin, generation, now)
        .map_err(|_| denied())?;
    let scope_id = scope.scope_id.clone();
    catalog.insert(scope_id.clone(), scope);
    epochs.insert(scope_id.clone(), 0);
    Ok(tinysecurity_bus::DevicePairingScopeReceipt2 {
        scope_id,
        active: true,
    })
}
fn check_persistence_fault(
    owner: &mut DevicePairingOwner,
    faulted: &AtomicBool,
) -> tinybus::Result<()> {
    if faulted.load(Ordering::Acquire) {
        owner.fail_persistence();
        Err(denied())
    } else {
        Ok(())
    }
}

fn begin_with_master_alias(
    owner: &mut DevicePairingOwner,
    pending_master_aliases: &mut BTreeMap<String, String>,
    context: &DevicePairingContextResponse2,
    ttl_ms: u32,
    alias: &str,
    now: Time,
) -> tinybus::Result<(String, String, u64)> {
    let expired = owner.prune_expired_pending(now).map_err(|_| denied())?;
    for receipt in expired {
        pending_master_aliases.remove(&receipt);
    }
    let (receipt, public, expiry) = owner.begin(context, ttl_ms, now).map_err(|_| denied())?;
    pending_master_aliases.insert(receipt.clone(), alias.to_owned());
    Ok((receipt, public, expiry))
}

fn time(clock: &dyn tinysecurity::approval::Clock) -> tinybus::Result<Time> {
    Ok(Time {
        wall: clock.wall_ms().ok_or_else(denied)?,
        monotonic: clock.monotonic_ms(),
    })
}
fn registry_clock_sample(
    clock: &dyn tinysecurity::approval::Clock,
) -> Option<tinysecurity::crypto::device_handles::Time> {
    Some(tinysecurity::crypto::device_handles::Time {
        wall: clock.wall_ms()?,
        monotonic: clock.monotonic_ms(),
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StateEnvelope {
    version: u8,
    scope_id: String,
    backend_id: String,
    secret_registration_id: String,
    state: String,
}
impl Drop for StateEnvelope {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}
fn encode_snapshot(
    snapshot: &[u8],
    scope: &tinysecurity_bus::DevicePairingScope2,
) -> tinybus::Result<Zeroizing<String>> {
    let envelope = StateEnvelope {
        version: 1,
        scope_id: scope.scope_id.clone(),
        backend_id: scope.persistence_backend_id.clone(),
        secret_registration_id: scope.secret_registration_id.clone(),
        state: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, snapshot),
    };
    serde_json::to_string(&envelope)
        .map(Zeroizing::new)
        .map_err(|_| denied())
}
fn decode_state(
    cipher: &DevicePairingStateCipher,
    ciphertext: &[u8],
    scope: &tinysecurity_bus::DevicePairingScope2,
) -> tinybus::Result<Zeroizing<Vec<u8>>> {
    decode_state_with(ciphertext, scope, |text| {
        cipher.decrypt(text).map_err(|_| denied())
    })
}
fn decode_state_with(
    ciphertext: &[u8],
    scope: &tinysecurity_bus::DevicePairingScope2,
    decrypt: impl FnOnce(&str) -> tinybus::Result<Zeroizing<String>>,
) -> tinybus::Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(ciphertext).map_err(|_| denied())?;
    if !text.starts_with("enc2:") {
        return Err(denied());
    }
    let plaintext = decrypt(text).map_err(|_| denied())?;
    let envelope: StateEnvelope = serde_json::from_str(&plaintext).map_err(|_| denied())?;
    if envelope.version != 1
        || envelope.scope_id != scope.scope_id
        || envelope.backend_id != scope.persistence_backend_id
        || envelope.secret_registration_id != scope.secret_registration_id
    {
        return Err(denied());
    }
    let state = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.state)
        .map_err(|_| denied())?;
    Ok(Zeroizing::new(state))
}
fn finish_refresh<T>(
    result: tinybus::Result<T>,
    owner: &mut DevicePairingOwner,
    registry: &Registry,
    scope_id: &str,
    session_id: &str,
) -> tinybus::Result<T> {
    if let Ok(value) = result {
        Ok(value)
    } else {
        if owner.is_faulted() {
            registry
                .retire_paired_scope(scope_id)
                .map_err(|_| denied())?;
        } else {
            owner.retire_session(session_id);
            registry
                .retire_paired_tunnel(session_id)
                .map_err(|_| denied())?;
        }
        Err(denied())
    }
}

struct HostCallbacks {
    connection: tinybus::Connection,
    peer: tinybus::BusName,
    config: DevicePairingConfig2,
    scope_catalog: Arc<RwLock<BTreeMap<String, tinysecurity_bus::DevicePairingScope2>>>,
    consumed_legacy_imports: Mutex<BTreeSet<(String, String)>>,
}
impl HostCallbacks {
    fn scope(&self, scope_id: &str) -> tinybus::Result<tinysecurity_bus::DevicePairingScope2> {
        lookup_scope(&self.scope_catalog, scope_id)
    }
    async fn resolve(
        &self,
        host_event_id: &str,
        purpose: DevicePairingPurpose2,
        requested_channel_id: Option<&str>,
    ) -> tinybus::Result<DevicePairingContextResponse2> {
        if host_event_id.is_empty() || host_event_id.len() > 128 {
            return Err(denied());
        }
        let request = DevicePairingContextRequest2 {
            host_event_id: host_event_id.into(),
            purpose,
            requested_channel_id: requested_channel_id.map(str::to_string),
        };
        self.connection
            .proxy(
                self.peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::DEVICE_PAIRING_HOST,
            )
            .map_err(|_| denied())?
            .with_timeout(std::time::Duration::from_millis(u64::from(
                self.config.callback_timeout_ms,
            )))
            .call_confidential(callback_names2::RESOLVE_PAIRING_EVENT, (&request,))
            .await
            .map_err(|_| denied())
    }
    async fn persist(
        &self,
        scope_id: &str,
        operation: DevicePairingPersistenceOperation2,
    ) -> tinybus::Result<DevicePairingPersistenceResponse2> {
        let scope = self.scope(scope_id)?;
        let request = DevicePairingPersistenceRequest2 {
            backend_id: scope.persistence_backend_id.clone(),
            scope_id: scope.scope_id.clone(),
            secret_registration_id: scope.secret_registration_id.clone(),
            operation,
        };
        let response = self
            .connection
            .proxy(
                self.peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::DEVICE_PAIRING_HOST,
            )
            .map_err(|_| denied())?
            .with_timeout(std::time::Duration::from_millis(u64::from(
                self.config.callback_timeout_ms,
            )))
            .call_confidential::<DevicePairingPersistenceResponse2>(
                callback_names2::PERSIST_DEVICE_PAIRING,
                (&request,),
            )
            .await
            .map_err(|_| denied())?;
        if response.backend_id != request.backend_id
            || response.scope_id != request.scope_id
            || response.secret_registration_id != request.secret_registration_id
            || response.revision.is_empty()
            || response.revision.len() > 256
        {
            return Err(denied());
        }
        Ok(response)
    }
    async fn load_legacy(
        &self,
        scope_id: &str,
        handle: &str,
        context: &DevicePairingContextResponse2,
    ) -> tinybus::Result<DevicePairingLegacyLoadResponse2> {
        let scope = self.scope(scope_id)?;
        let backend_id = scope
            .legacy_device_backend_id
            .as_deref()
            .ok_or_else(denied)?;
        let source_registration_id = scope
            .legacy_source_registration_id
            .as_deref()
            .ok_or_else(denied)?;
        if handle.is_empty() || handle.len() > 256 {
            return Err(denied());
        }
        consume_legacy_import(&self.consumed_legacy_imports, scope_id, handle)?;
        let request = DevicePairingLegacyLoadRequest2 {
            handle: handle.into(),
        };
        let response = self
            .connection
            .proxy(
                self.peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::DEVICE_PAIRING_HOST,
            )
            .map_err(|_| denied())?
            .with_timeout(std::time::Duration::from_millis(u64::from(
                self.config.callback_timeout_ms,
            )))
            .call_confidential::<DevicePairingLegacyLoadResponse2>(
                callback_names2::LOAD_LEGACY_DEVICE_IDENTITIES,
                (&request,),
            )
            .await
            .map_err(|_| denied())?;
        if response.scope_id != scope_id
            || response.user_binding != context.user_binding
            || response.generation != context.generation
            || response.backend_id != backend_id
            || response.source_registration_id != source_registration_id
            || response.records.len() > self.config.max_pairings as usize
        {
            return Err(denied());
        }
        let mut total = 0usize;
        for row in &response.records {
            total = total
                .checked_add(row.channel_id.len())
                .and_then(|value| value.checked_add(row.device_public_key.len()))
                .and_then(|value| value.checked_add(row.ciphertext.len()))
                .ok_or_else(denied)?;
            if row.ciphertext.len() > 4096 || total > self.config.max_state_bytes as usize {
                return Err(denied());
            }
        }
        Ok(response)
    }
}

async fn store_state(
    callbacks: &HostCallbacks,
    scope: &tinysecurity_bus::DevicePairingScope2,
    owner: &DevicePairingOwner,
    cipher: &DevicePairingStateCipher,
    revision: &str,
    generation: u64,
) -> tinybus::Result<String> {
    let snapshot = owner.snapshot_state().map_err(|_| denied())?;
    store_snapshot(callbacks, scope, cipher, &snapshot, revision, generation).await
}

fn empty_response() -> DevicePairingResponse2 {
    DevicePairingResponse2 {
        receipt: None,
        pairing_id: None,
        session_id: None,
        core_public_key: None,
        device_public_key: None,
        frame: Vec::new(),
        expires_at_ms: 0,
    }
}
fn response_with_key(public_key: String) -> DevicePairingResponse2 {
    DevicePairingResponse2 {
        core_public_key: Some(public_key),
        ..empty_response()
    }
}
async fn store_snapshot(
    callbacks: &HostCallbacks,
    scope: &tinysecurity_bus::DevicePairingScope2,
    cipher: &DevicePairingStateCipher,
    snapshot: &[u8],
    revision: &str,
    generation: u64,
) -> tinybus::Result<String> {
    if !cipher.is_bound_to(
        &scope.secret_registration_id,
        &scope.scope_id,
        &scope.persistence_backend_id,
        generation,
    ) {
        return Err(denied());
    }
    let plaintext = encode_snapshot(snapshot, scope)?;
    let ciphertext = cipher.encrypt(&plaintext).map_err(|_| denied())?;
    let expected_ciphertext = ciphertext.as_bytes().to_vec();
    let response = callbacks
        .persist(
            &scope.scope_id,
            DevicePairingPersistenceOperation2::Store {
                expected_revision: revision.into(),
                ciphertext: expected_ciphertext.clone(),
            },
        )
        .await?;
    if response.revision == revision
        || response.ciphertext.as_deref() != Some(expected_ciphertext.as_slice())
    {
        return Err(denied());
    }
    Ok(response.revision)
}

struct LoadedScope {
    owner: DevicePairingOwner,
    cipher: DevicePairingStateCipher,
    revision: String,
    pending_master_aliases: BTreeMap<String, String>,
    epoch: u64,
    generation: u64,
    persistence_faulted: Arc<AtomicBool>,
}

async fn lock_and_validate_scope<T>(
    scope: &tokio::sync::Mutex<T>,
    validate: impl FnOnce(&mut T) -> tinybus::Result<()>,
) -> tinybus::Result<tokio::sync::MutexGuard<'_, T>> {
    let mut scope = scope.lock().await;
    validate(&mut scope)?;
    Ok(scope)
}

#[derive(Clone)]
struct PersistenceContext {
    faulted: Arc<AtomicBool>,
    registry: Arc<Registry>,
    scope_id: String,
}
struct PersistenceFence {
    context: PersistenceContext,
    completed: bool,
}
impl PersistenceFence {
    fn new(context: PersistenceContext) -> Self {
        Self {
            context,
            completed: false,
        }
    }
    fn complete(mut self) {
        self.completed = true;
    }
}
impl Drop for PersistenceFence {
    fn drop(&mut self) {
        if !self.completed {
            self.context.faulted.store(true, Ordering::Release);
            let _ = self
                .context
                .registry
                .retire_paired_scope(&self.context.scope_id);
        }
    }
}
// Retain the fence after the CAS response until all authority checks and publication finish.
struct Persisted<T> {
    value: T,
    fence: PersistenceFence,
}
impl<T> Persisted<T> {
    fn complete(self) -> T {
        self.fence.complete();
        self.value
    }

    fn fail(self, owner: &mut DevicePairingOwner) {
        owner.fail_persistence();
        drop(self);
    }
}
impl<T> std::fmt::Debug for Persisted<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Persisted([REDACTED])")
    }
}
async fn persist_fenced<T>(
    context: PersistenceContext,
    persist: impl std::future::Future<Output = tinybus::Result<T>>,
) -> tinybus::Result<Persisted<T>> {
    let fence = PersistenceFence::new(context);
    let value = persist.await?;
    Ok(Persisted { value, fence })
}
async fn import_legacy_and_persist<F, Fut>(
    owner: &mut DevicePairingOwner,
    persistence: PersistenceContext,
    context: &DevicePairingContextResponse2,
    identities: Vec<LegacyDeviceIdentity>,
    now: Time,
    persist: F,
) -> tinybus::Result<(
    Vec<tinysecurity::crypto::device_pairing::ImportedDevicePairing>,
    Persisted<String>,
)>
where
    F: FnOnce(Zeroizing<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = tinybus::Result<String>>,
{
    let imported = owner
        .import_legacy_identities(context, identities, now)
        .map_err(|_| denied())?;
    let fence = PersistenceFence::new(persistence);
    let Ok(snapshot) = owner.snapshot_state() else {
        owner.fail_persistence();
        return Err(denied());
    };
    let revision = persist(snapshot).await?;
    Ok((
        imported,
        Persisted {
            value: revision,
            fence,
        },
    ))
}
async fn revoke_and_persist<F, Fut>(
    owner: &mut DevicePairingOwner,
    persistence: PersistenceContext,
    pairing_id: &str,
    context: &DevicePairingContextResponse2,
    now: Time,
    before_persist: impl FnOnce() -> tinybus::Result<()>,
    persist: F,
) -> tinybus::Result<Persisted<String>>
where
    F: FnOnce(Zeroizing<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = tinybus::Result<String>>,
{
    let snapshot = owner
        .revoke(pairing_id, context, now)
        .map_err(|_| denied())?;
    let fence = PersistenceFence::new(persistence);
    before_persist()?;
    let revision = persist(snapshot).await?;
    Ok(Persisted {
        value: revision,
        fence,
    })
}

fn fail_revoke_owner_on_error(owner: &mut DevicePairingOwner, persistence_faulted: &AtomicBool) {
    if persistence_faulted.load(Ordering::Acquire) {
        owner.fail_persistence();
    }
}

struct ScopeRegistry {
    epochs: BTreeMap<String, u64>,
    loaded: BTreeMap<String, Arc<tokio::sync::Mutex<LoadedScope>>>,
}
type LoadedScopes = Mutex<ScopeRegistry>;
static PAIRING: OnceLock<Option<Arc<PairingState>>> = OnceLock::new();

/// Process-lifetime owner. The outer map's scope entries are initialized only by Unlock.
pub(super) struct PairingState {
    config: DevicePairingConfig2,
    callbacks: HostCallbacks,
    secret: Arc<super::secret::SecretState>,
    registry: Arc<Registry>,
    clock: Arc<dyn tinysecurity::approval::Clock>,
    generation: AtomicU64,
    scopes: LoadedScopes,
    scope_catalog: Arc<RwLock<BTreeMap<String, tinysecurity_bus::DevicePairingScope2>>>,
}
impl std::fmt::Debug for PairingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingState([REDACTED])")
    }
}

impl PairingState {
    fn validate_scope_epoch(
        &self,
        scopes: &ScopeRegistry,
        scope_id: &str,
        epoch: u64,
        generation: u64,
        context: &DevicePairingContextResponse2,
    ) -> tinybus::Result<()> {
        if scopes.epochs.get(scope_id) != Some(&epoch)
            || context.scope_id != scope_id
            || context.generation != generation
            || self.generation.load(Ordering::Acquire) != generation
            || context.expires_at_ms <= time(self.clock.as_ref())?.wall
        {
            return Err(denied());
        }
        Ok(())
    }
    fn validate_live_scope(
        &self,
        loaded: &mut LoadedScope,
        context: &DevicePairingContextResponse2,
    ) -> tinybus::Result<()> {
        check_persistence_fault(&mut loaded.owner, &loaded.persistence_faulted)?;
        let scopes = self.scopes.lock().map_err(|_| denied())?;
        self.validate_scope_epoch(
            &scopes,
            &context.scope_id,
            loaded.epoch,
            loaded.generation,
            context,
        )
    }
    /// Bind one live approval scope to pairing using init-fixed authority defaults.
    pub(super) fn register_scope(
        &self,
        request: &tinysecurity_bus::RegisterDevicePairingScopeRequest2,
        approvals: &tinysecurity::approval::Engine,
    ) -> tinybus::Result<tinysecurity_bus::DevicePairingScopeReceipt2> {
        let approval = approvals
            .scope_snapshot(&request.approval_scope_id)
            .map_err(|_| denied())?;
        let generation = self.generation.load(Ordering::Acquire);
        validate_runtime_approval_snapshot(&approval, generation)?;
        let defaults = self.config.runtime_scope.as_ref().ok_or_else(denied)?;
        let (secret_registration, secret_scope) =
            self.secret.config_master_for_scope(&approval.scope_id)?;
        let verified_secret_scope = self
            .secret
            .cipher_scope(&secret_registration.registration_id)?;
        validate_secret_scope_binding(&approval, &secret_scope, &verified_secret_scope)?;
        let (scope, origin) = derive_runtime_scope(&approval, &secret_registration, defaults)?;
        let now = time(self.clock.as_ref())?;
        let mut scopes = self.scopes.lock().map_err(|_| denied())?;
        let mut catalog = self.scope_catalog.write().map_err(|_| denied())?;
        admit_runtime_scope(
            scope,
            approval,
            origin,
            &self.registry,
            generation,
            tinysecurity::crypto::device_handles::Time {
                wall: now.wall,
                monotonic: now.monotonic,
            },
            &mut scopes.epochs,
            &mut catalog,
        )
    }
    async fn unlock_scope(
        &self,
        context: &DevicePairingContextResponse2,
        epoch: u64,
    ) -> tinybus::Result<LoadedScope> {
        let scope = self.callbacks.scope(&context.scope_id)?;
        let generation = self.generation.load(Ordering::Acquire);
        if context.source != tinysecurity_bus::DevicePairingSource2::AuthenticatedUserController
            || context.generation != generation
            || context.expires_at_ms <= time(self.clock.as_ref())?.wall
        {
            return Err(denied());
        }
        let alias = context.secret_master_handle.as_deref().ok_or_else(denied)?;
        self.secret.validate_cipher_master(
            &scope.secret_registration_id,
            alias,
            generation,
            context.expires_at_ms,
        )?;
        let cipher = self.secret.pairing_state_cipher(
            &scope.secret_registration_id,
            alias,
            generation,
            &scope.scope_id,
            &scope.persistence_backend_id,
        )?;
        let loaded = self
            .callbacks
            .persist(&scope.scope_id, DevicePairingPersistenceOperation2::Load)
            .await?;
        self.secret.validate_cipher_master(
            &scope.secret_registration_id,
            alias,
            generation,
            context.expires_at_ms,
        )?;
        if loaded.ciphertext.as_ref().is_some_and(|value| {
            value.len() > (self.config.max_state_bytes as usize).saturating_mul(3) + 256
        }) {
            return Err(denied());
        }
        let one_scope = one_scope_config(&self.config, &self.scope_catalog, &scope.scope_id)?;
        let owner = if let Some(ciphertext) = loaded.ciphertext.as_deref() {
            let state = decode_state(&cipher, ciphertext, &scope)?;
            DevicePairingOwner::restore(one_scope, generation, time(self.clock.as_ref())?, &state)
                .map_err(|_| denied())?
        } else {
            let mut secret = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut *secret).map_err(|_| denied())?;
            let owner = DevicePairingOwner::new(
                one_scope,
                generation,
                time(self.clock.as_ref())?,
                [(scope.scope_id.clone(), secret)].into(),
            )
            .map_err(|_| denied())?;
            let revision = store_state(
                &self.callbacks,
                &scope,
                &owner,
                &cipher,
                &loaded.revision,
                generation,
            )
            .await?;
            return Ok(LoadedScope {
                owner,
                cipher,
                revision,
                pending_master_aliases: BTreeMap::new(),
                epoch,
                generation,
                persistence_faulted: Arc::new(AtomicBool::new(false)),
            });
        };
        Ok(LoadedScope {
            owner,
            cipher,
            revision: loaded.revision,
            pending_master_aliases: BTreeMap::new(),
            epoch,
            generation,
            persistence_faulted: Arc::new(AtomicBool::new(false)),
        })
    }
    async fn load_scope(
        &self,
        context: &DevicePairingContextResponse2,
    ) -> tinybus::Result<Arc<tokio::sync::Mutex<LoadedScope>>> {
        let (epoch, existing) = unlock_scope_lookup(
            context,
            self.generation.load(Ordering::Acquire),
            time(self.clock.as_ref())?,
            || {
                let scopes = self.scopes.lock().map_err(|_| denied())?;
                let epoch = *scopes.epochs.get(&context.scope_id).ok_or_else(denied)?;
                Ok((epoch, scopes.loaded.get(&context.scope_id).cloned()))
            },
        )?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let loaded = Arc::new(tokio::sync::Mutex::new(
            self.unlock_scope(context, epoch).await?,
        ));
        let mut scopes = self.scopes.lock().map_err(|_| denied())?;
        if scopes.epochs.get(&context.scope_id) != Some(&epoch)
            || context.generation != self.generation.load(Ordering::Acquire)
            || context.expires_at_ms <= time(self.clock.as_ref())?.wall
        {
            return Err(denied());
        }
        Ok(Arc::clone(
            scopes
                .loaded
                .entry(context.scope_id.clone())
                .or_insert(loaded),
        ))
    }
    fn loaded_scope(
        &self,
        scope_id: &str,
    ) -> tinybus::Result<Arc<tokio::sync::Mutex<LoadedScope>>> {
        self.scopes
            .lock()
            .map_err(|_| denied())?
            .loaded
            .get(scope_id)
            .cloned()
            .ok_or_else(denied)
    }
    #[allow(clippy::too_many_lines)] // Keeps the serialized lifecycle transitions auditable together.
    async fn execute(
        &self,
        request: DevicePairingRequest2,
    ) -> tinybus::Result<DevicePairingResponse2> {
        if request.call_id.is_empty()
            || request.call_id.len() > 128
            || request.call_id.chars().any(char::is_control)
        {
            return Err(denied());
        }
        match request.operation {
            DevicePairingOperation2::Unlock { host_event_id } => {
                let context = self
                    .callbacks
                    .resolve(&host_event_id, DevicePairingPurpose2::UserController, None)
                    .await?;
                let alias = context.secret_master_handle.as_deref().ok_or_else(denied)?;
                let scope = self.callbacks.scope(&context.scope_id)?;
                let generation = self.generation.load(Ordering::Acquire);
                self.secret.validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    generation,
                    context.expires_at_ms,
                )?;
                let loaded = self.load_scope(&context).await?;
                let mut loaded = lock_and_validate_scope(loaded.as_ref(), |loaded| {
                    self.validate_live_scope(loaded, &context)?;
                    self.secret.validate_cipher_master(
                        &scope.secret_registration_id,
                        alias,
                        generation,
                        context.expires_at_ms,
                    )
                })
                .await?;
                let public = loaded
                    .owner
                    .public_key(&context.scope_id, time(self.clock.as_ref())?)
                    .map_err(|_| denied())?;
                Ok(response_with_key(public))
            }
            DevicePairingOperation2::Lock { host_event_id } => {
                let context = self
                    .callbacks
                    .resolve(&host_event_id, DevicePairingPurpose2::UserLogout, None)
                    .await?;
                let loaded = {
                    let mut scopes = self.scopes.lock().map_err(|_| denied())?;
                    validate_logout_context(
                        &context,
                        self.generation.load(Ordering::Acquire),
                        time(self.clock.as_ref())?,
                    )?;
                    let epoch = scopes
                        .epochs
                        .get_mut(&context.scope_id)
                        .ok_or_else(denied)?;
                    *epoch = epoch.checked_add(1).ok_or_else(denied)?;
                    scopes.loaded.remove(&context.scope_id)
                };
                self.registry
                    .retire_paired_scope(&context.scope_id)
                    .map_err(|_| denied())?;
                if let Some(loaded) = loaded {
                    let mut loaded = loaded.lock().await;
                    loaded.owner.close();
                    loaded.pending_master_aliases.clear();
                }
                Ok(empty_response())
            }
            DevicePairingOperation2::Begin { host_event_id } => {
                let context = self
                    .callbacks
                    .resolve(&host_event_id, DevicePairingPurpose2::UserController, None)
                    .await?;
                let scope = self.callbacks.scope(&context.scope_id)?;
                let alias = context.secret_master_handle.as_deref().ok_or_else(denied)?;
                let generation = self.generation.load(Ordering::Acquire);
                self.secret.validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    generation,
                    context.expires_at_ms,
                )?;
                let loaded = self.loaded_scope(&context.scope_id)?;
                let mut loaded = loaded.lock().await;
                self.validate_live_scope(&mut loaded, &context)?;
                self.secret.validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    generation,
                    context.expires_at_ms,
                )?;
                let LoadedScope {
                    owner,
                    pending_master_aliases,
                    ..
                } = &mut *loaded;
                let (receipt, public, expiry) = begin_with_master_alias(
                    owner,
                    pending_master_aliases,
                    &context,
                    self.config.max_pending_ttl_ms,
                    alias,
                    time(self.clock.as_ref())?,
                )?;
                Ok(DevicePairingResponse2 {
                    receipt: Some(receipt),
                    core_public_key: Some(public),
                    expires_at_ms: expiry,
                    ..empty_response()
                })
            }
            DevicePairingOperation2::ImportLegacy { host_event_id } => {
                let context = self
                    .callbacks
                    .resolve(&host_event_id, DevicePairingPurpose2::LegacyImport, None)
                    .await?;
                let scope = self.callbacks.scope(&context.scope_id)?.clone();
                let alias = context.secret_master_handle.as_deref().ok_or_else(denied)?;
                let handle = context.legacy_import_handle.as_deref().ok_or_else(denied)?;
                let generation = self.generation.load(Ordering::Acquire);
                if context.source
                    != tinysecurity_bus::DevicePairingSource2::AuthenticatedUserController
                    || context.generation != generation
                {
                    return Err(denied());
                }
                self.secret.validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    generation,
                    context.expires_at_ms,
                )?;
                let rows = self
                    .callbacks
                    .load_legacy(&scope.scope_id, handle, &context)
                    .await?;
                self.secret.validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    generation,
                    context.expires_at_ms,
                )?;
                self.validate_context_live(&context)?;
                let loaded = self.loaded_scope(&scope.scope_id)?;
                let mut loaded = loaded.lock().await;
                self.validate_live_scope(&mut loaded, &context)?;
                self.secret.validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    generation,
                    context.expires_at_ms,
                )?;
                if !loaded.cipher.is_bound_to(
                    &scope.secret_registration_id,
                    &scope.scope_id,
                    &scope.persistence_backend_id,
                    generation,
                ) {
                    return Err(denied());
                }
                let mut identities = Vec::with_capacity(rows.records.len());
                for row in rows.records {
                    let value = std::str::from_utf8(&row.ciphertext).map_err(|_| denied())?;
                    let valid_prefix = match row.format {
                        DevicePairingLegacyFormat2::Enc2 => value.starts_with("enc2:"),
                        DevicePairingLegacyFormat2::Enc => value.starts_with("enc:"),
                    };
                    if !valid_prefix || row.ciphertext.len() > 16_384 {
                        return Err(denied());
                    }
                    let private = match row.format {
                        DevicePairingLegacyFormat2::Enc2 => loaded.cipher.decrypt(value),
                        DevicePairingLegacyFormat2::Enc => loaded.cipher.decrypt_legacy(value),
                    }
                    .map_err(|_| denied())?;
                    let bytes = Zeroizing::new(
                        base64::Engine::decode(
                            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                            private.as_bytes(),
                        )
                        .map_err(|_| denied())?,
                    );
                    let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| denied())?;
                    identities.push(LegacyDeviceIdentity {
                        channel_id: row.channel_id,
                        device_public_key: row.device_public_key,
                        core_private_key: Zeroizing::new(secret),
                        revoked: row.revoked,
                    });
                }
                let LoadedScope {
                    owner,
                    cipher,
                    revision: expected_revision,
                    persistence_faulted,
                    ..
                } = &mut *loaded;
                let callbacks = &self.callbacks;
                let store_scope = scope.clone();
                let (imported, revision) = match import_legacy_and_persist(
                    owner,
                    PersistenceContext {
                        faulted: Arc::clone(persistence_faulted),
                        registry: Arc::clone(&self.registry),
                        scope_id: scope.scope_id.clone(),
                    },
                    &context,
                    identities,
                    time(self.clock.as_ref())?,
                    move |snapshot| async move {
                        store_snapshot(
                            callbacks,
                            &store_scope,
                            cipher,
                            &snapshot,
                            expected_revision,
                            generation,
                        )
                        .await
                    },
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => {
                        if loaded.persistence_faulted.load(Ordering::Acquire) {
                            loaded.owner.fail_persistence();
                        }
                        return Err(error);
                    }
                };
                if self
                    .secret
                    .validate_cipher_master(
                        &scope.secret_registration_id,
                        alias,
                        generation,
                        context.expires_at_ms,
                    )
                    .is_err()
                {
                    revision.fail(&mut loaded.owner);
                    loaded.pending_master_aliases.clear();
                    return Err(denied());
                }
                if let Err(error) = self.validate_live_scope(&mut loaded, &context) {
                    revision.fail(&mut loaded.owner);
                    loaded.pending_master_aliases.clear();
                    return Err(error);
                }
                loaded.revision = revision.complete();
                // The bus result intentionally contains no private material. Existing
                // host channel metadata already owns the public pairing presentation.
                let _ = imported;
                Ok(empty_response())
            }
            DevicePairingOperation2::Recover {
                channel_id,
                host_event_id,
            } => self.recover(channel_id, host_event_id).await,
            DevicePairingOperation2::Renew {
                pairing_id,
                host_event_id,
            } => {
                let context = self
                    .callbacks
                    .resolve(&host_event_id, DevicePairingPurpose2::Reconnect, None)
                    .await?;
                let loaded = self.loaded_scope(&context.scope_id)?;
                let mut loaded = loaded.lock().await;
                self.validate_live_scope(&mut loaded, &context)?;
                let (receipt, public, expiry) = loaded
                    .owner
                    .renew(
                        &pairing_id,
                        &context,
                        self.config.max_pending_ttl_ms,
                        time(self.clock.as_ref())?,
                    )
                    .map_err(|_| denied())?;
                Ok(DevicePairingResponse2 {
                    receipt: Some(receipt),
                    core_public_key: Some(public),
                    expires_at_ms: expiry,
                    ..empty_response()
                })
            }
            DevicePairingOperation2::Handshake {
                receipt,
                host_event_id,
                frame,
            } => {
                if frame.len() > tinysecurity::crypto::device::MAX_MESSAGE_BYTES + 64 {
                    return Err(denied());
                }
                let context = self
                    .callbacks
                    .resolve(&host_event_id, DevicePairingPurpose2::SocketEvent, None)
                    .await?;
                let loaded = self.loaded_scope(&context.scope_id)?;
                let mut loaded = lock_and_validate_scope(loaded.as_ref(), |loaded| {
                    self.validate_live_scope(loaded, &context)
                })
                .await?;
                let frame = loaded
                    .owner
                    .handshake(&receipt, &context, &frame, time(self.clock.as_ref())?)
                    .map_err(|_| denied())?;
                Ok(DevicePairingResponse2 {
                    frame,
                    ..empty_response()
                })
            }
            DevicePairingOperation2::Confirm {
                receipt,
                host_event_id,
                frame,
            } => self.confirm(receipt, host_event_id, frame).await,
            DevicePairingOperation2::RefreshSession {
                session_id,
                host_event_id,
            } => self.refresh(session_id, host_event_id).await,
            DevicePairingOperation2::EndSession {
                session_id,
                host_event_id,
            } => self.end_session(session_id, host_event_id).await,
            DevicePairingOperation2::Revoke {
                pairing_id,
                host_event_id,
            } => self.revoke(pairing_id, host_event_id).await,
        }
    }
    fn validate_context_live(
        &self,
        context: &DevicePairingContextResponse2,
    ) -> tinybus::Result<()> {
        let scopes = self.scopes.lock().map_err(|_| denied())?;
        let epoch = *scopes.epochs.get(&context.scope_id).ok_or_else(denied)?;
        self.validate_scope_epoch(
            &scopes,
            &context.scope_id,
            epoch,
            context.generation,
            context,
        )
    }
    async fn recover(
        &self,
        channel_id: String,
        host_event_id: String,
    ) -> tinybus::Result<DevicePairingResponse2> {
        if channel_id.is_empty() || channel_id.len() > 256 {
            return Err(denied());
        }
        let context = self
            .callbacks
            .resolve(
                &host_event_id,
                DevicePairingPurpose2::UserController,
                Some(&channel_id),
            )
            .await?;
        if context.source != tinysecurity_bus::DevicePairingSource2::AuthenticatedUserController
            || context.channel_id != channel_id
            || context.generation != self.generation.load(Ordering::Acquire)
        {
            return Err(denied());
        }
        let scope = self.callbacks.scope(&context.scope_id)?.clone();
        let loaded = self.loaded_scope(&scope.scope_id)?;
        let mut loaded = loaded.lock().await;
        self.validate_live_scope(&mut loaded, &context)?;
        let durable = self
            .callbacks
            .persist(&scope.scope_id, DevicePairingPersistenceOperation2::Load)
            .await?;
        if durable.ciphertext.as_ref().is_none_or(|ciphertext| {
            ciphertext.len() > (self.config.max_state_bytes as usize).saturating_mul(3) + 256
        }) {
            return Err(denied());
        }
        self.validate_live_scope(&mut loaded, &context)?;
        let plaintext = decode_state(
            &loaded.cipher,
            durable.ciphertext.as_deref().ok_or_else(denied)?,
            &scope,
        )?;
        loaded
            .owner
            .merge_recovered_durable_state(&plaintext, &context, time(self.clock.as_ref())?)
            .map_err(|_| denied())?;
        // The merge is now committed to the in-memory owner. Keep the CAS token
        // in sync even when channel recovery or final context validation fails.
        loaded.revision = durable.revision;
        // Keep the current CAS token: Recover only rehydrates an already committed
        // revision and does not write or reset the live tunnel registry.
        let recovered = loaded
            .owner
            .recover_channel(&channel_id, &context, time(self.clock.as_ref())?)
            .map_err(|_| denied())?;
        self.validate_live_scope(&mut loaded, &context)?;
        Ok(DevicePairingResponse2 {
            pairing_id: Some(recovered.pairing_id),
            device_public_key: Some(recovered.device_public_key),
            core_public_key: Some(recovered.core_public_key),
            ..empty_response()
        })
    }
    async fn confirm(
        &self,
        receipt: String,
        host_event_id: String,
        frame: Vec<u8>,
    ) -> tinybus::Result<DevicePairingResponse2> {
        if frame.len() > tinysecurity::crypto::device::MAX_MESSAGE_BYTES + 64 {
            return Err(denied());
        }
        let context = self
            .callbacks
            .resolve(&host_event_id, DevicePairingPurpose2::SocketEvent, None)
            .await?;
        let scope = self.callbacks.scope(&context.scope_id)?.clone();
        let loaded = self.loaded_scope(&scope.scope_id)?;
        let mut loaded = loaded.lock().await;
        self.validate_live_scope(&mut loaded, &context)?;
        if let Some(alias) = loaded.pending_master_aliases.get(&receipt) {
            self.secret.validate_cipher_master(
                &scope.secret_registration_id,
                alias,
                loaded.generation,
                context.expires_at_ms,
            )?;
        }
        let previous_sessions = loaded.owner.sessions_for_pending(&receipt);
        let now = time(self.clock.as_ref())?;
        let prepared = loaded
            .owner
            .prepare_confirmation(&receipt, &context, &frame, now)
            .map_err(|_| denied())?;
        let revision = match persist_fenced(
            PersistenceContext {
                faulted: Arc::clone(&loaded.persistence_faulted),
                registry: Arc::clone(&self.registry),
                scope_id: scope.scope_id.clone(),
            },
            store_snapshot(
                &self.callbacks,
                &scope,
                &loaded.cipher,
                prepared.state_to_encrypt(),
                &loaded.revision,
                loaded.generation,
            ),
        )
        .await
        {
            Ok(revision) => revision,
            Err(error) => {
                loaded.owner.abort_confirmation(&receipt);
                loaded.owner.fail_persistence();
                loaded.pending_master_aliases.clear();
                return Err(error);
            }
        };
        if let Some(alias) = loaded.pending_master_aliases.get(&receipt)
            && self
                .secret
                .validate_cipher_master(
                    &scope.secret_registration_id,
                    alias,
                    loaded.generation,
                    context.expires_at_ms,
                )
                .is_err()
        {
            revision.fail(&mut loaded.owner);
            loaded.pending_master_aliases.clear();
            return Err(denied());
        }
        if let Err(error) = self.validate_live_scope(&mut loaded, &context) {
            revision.fail(&mut loaded.owner);
            loaded.pending_master_aliases.clear();
            return Err(error);
        }
        loaded.revision.clone_from(&revision.value);
        loaded.pending_master_aliases.remove(&receipt);
        for previous in previous_sessions {
            if self.registry.retire_paired_tunnel(&previous).is_err() {
                loaded.owner.fail_persistence();
                return Err(denied());
            }
        }
        let result = loaded
            .owner
            .commit_confirmation(prepared, time(self.clock.as_ref())?)
            .map_err(|_| denied())?;
        let generation = loaded.generation;
        let response = self.publish_confirmed_session(&mut loaded, generation, &context, result)?;
        revision.complete();
        Ok(response)
    }

    fn publish_confirmed_session(
        &self,
        loaded: &mut LoadedScope,
        generation: u64,
        context: &DevicePairingContextResponse2,
        result: tinysecurity::crypto::device_pairing::PairingResult,
    ) -> tinybus::Result<DevicePairingResponse2> {
        let now = time(self.clock.as_ref())?;
        let (scope_id, tunnel, expires_wall, expires_monotonic) = loaded
            .owner
            .session_tunnel(&result.session_id, now)
            .map_err(|_| denied())?;
        let scopes = self.scopes.lock().map_err(|_| denied())?;
        self.validate_scope_epoch(&scopes, &scope_id, loaded.epoch, generation, context)?;
        if self
            .registry
            .register_paired_tunnel_with_clock(
                PairedTunnelRegistration {
                    scope_id: &scope_id,
                    handle: &result.session_id,
                    tunnel,
                    generation,
                    expires_wall,
                    expires_monotonic,
                    now: tinysecurity::crypto::device_handles::Time {
                        wall: now.wall,
                        monotonic: now.monotonic,
                    },
                },
                || registry_clock_sample(self.clock.as_ref()),
            )
            .is_err()
        {
            loaded.owner.retire_session(&result.session_id);
            return Err(denied());
        }
        drop(scopes);
        Ok(DevicePairingResponse2 {
            pairing_id: Some(result.pairing_id),
            session_id: Some(result.session_id),
            device_public_key: Some(result.device_public_key),
            expires_at_ms: result.expires_at_ms,
            ..empty_response()
        })
    }
    async fn refresh(
        &self,
        session_id: String,
        host_event_id: String,
    ) -> tinybus::Result<DevicePairingResponse2> {
        let context = self
            .callbacks
            .resolve(&host_event_id, DevicePairingPurpose2::SocketEvent, None)
            .await?;
        let loaded = self.loaded_scope(&context.scope_id)?;
        let mut loaded = loaded.lock().await;
        self.validate_live_scope(&mut loaded, &context)?;
        let expiry = finish_refresh(
            loaded
                .owner
                .refresh_session(&session_id, &context, time(self.clock.as_ref())?)
                .map_err(|_| denied()),
            &mut loaded.owner,
            &self.registry,
            &context.scope_id,
            &session_id,
        )?;
        if self
            .registry
            .refresh_paired_tunnel_with_clock(
                &context.scope_id,
                &session_id,
                loaded.generation,
                expiry.0,
                expiry.1,
                || registry_clock_sample(self.clock.as_ref()),
            )
            .is_err()
        {
            loaded.owner.retire_session(&session_id);
            self.registry
                .retire_paired_tunnel(&session_id)
                .map_err(|_| denied())?;
            return Err(denied());
        }
        Ok(DevicePairingResponse2 {
            session_id: Some(session_id),
            expires_at_ms: expiry.0,
            ..empty_response()
        })
    }
    async fn end_session(
        &self,
        session_id: String,
        host_event_id: String,
    ) -> tinybus::Result<DevicePairingResponse2> {
        let context = self
            .callbacks
            .resolve(&host_event_id, DevicePairingPurpose2::SocketClosed, None)
            .await?;
        let loaded = self.loaded_scope(&context.scope_id)?;
        let mut loaded = loaded.lock().await;
        self.validate_live_scope(&mut loaded, &context)?;
        loaded
            .owner
            .end_session(&session_id, &context, time(self.clock.as_ref())?)
            .map_err(|_| denied())?;
        self.registry
            .retire_paired_tunnel(&session_id)
            .map_err(|_| denied())?;
        Ok(empty_response())
    }
    async fn revoke(
        &self,
        pairing_id: String,
        host_event_id: String,
    ) -> tinybus::Result<DevicePairingResponse2> {
        let context = self
            .callbacks
            .resolve(&host_event_id, DevicePairingPurpose2::UserController, None)
            .await?;
        let scope = self.callbacks.scope(&context.scope_id)?.clone();
        let loaded = self.loaded_scope(&scope.scope_id)?;
        let mut loaded = loaded.lock().await;
        self.validate_live_scope(&mut loaded, &context)?;
        let sessions = loaded.owner.sessions_for_pairing(&pairing_id);
        let pending = loaded.owner.pending_for_pairing(&pairing_id);
        let LoadedScope {
            owner,
            cipher,
            revision: expected_revision,
            persistence_faulted,
            pending_master_aliases,
            ..
        } = &mut *loaded;
        let callbacks = &self.callbacks;
        let registry = &self.registry;
        let generation = self.generation.load(Ordering::Acquire);
        let revision = match revoke_and_persist(
            owner,
            PersistenceContext {
                faulted: Arc::clone(persistence_faulted),
                registry: Arc::clone(&self.registry),
                scope_id: scope.scope_id.clone(),
            },
            &pairing_id,
            &context,
            time(self.clock.as_ref())?,
            || {
                for receipt in pending {
                    pending_master_aliases.remove(&receipt);
                }
                for session in sessions {
                    registry
                        .retire_paired_tunnel(&session)
                        .map_err(|_| denied())?;
                }
                Ok(())
            },
            move |snapshot| async move {
                store_snapshot(
                    callbacks,
                    &scope,
                    cipher,
                    &snapshot,
                    expected_revision,
                    generation,
                )
                .await
            },
        )
        .await
        {
            Ok(revision) => revision,
            Err(error) => {
                fail_revoke_owner_on_error(owner, persistence_faulted.as_ref());
                return Err(error);
            }
        };
        self.validate_live_scope(&mut loaded, &context)?;
        loaded.revision = revision.complete();
        Ok(DevicePairingResponse2 {
            pairing_id: Some(pairing_id),
            ..empty_response()
        })
    }
    async fn reinitialize(&self, generation: u64) -> tinybus::Result<()> {
        if generation == self.generation.load(Ordering::Acquire) {
            return Ok(());
        }
        let scopes = {
            let mut registry = self.scopes.lock().map_err(|_| denied())?;
            let mut next = Vec::with_capacity(registry.epochs.len());
            for epoch in registry.epochs.values() {
                next.push(epoch.checked_add(1).ok_or_else(denied)?);
            }
            for (epoch, next) in registry.epochs.values_mut().zip(next) {
                *epoch = next;
            }
            self.generation.store(generation, Ordering::Release);
            std::mem::take(&mut registry.loaded)
        };
        for scope in scopes.into_values() {
            let mut scope = scope.lock().await;
            scope.owner.close();
            scope.pending_master_aliases.clear();
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)] // Init-time policy validation and registry construction stay together.
pub(super) fn configured(
    config: Option<DevicePairingConfig2>,
    connection: &tinybus::Connection,
    peer: Option<&str>,
    secret: Option<&Arc<super::secret::SecretState>>,
    registry: Option<&Arc<Registry>>,
    clock: Arc<dyn tinysecurity::approval::Clock>,
    generation: u64,
) -> tinybus::Result<Option<Arc<PairingState>>> {
    if let Some(active) = PAIRING.get() {
        return match active {
            Some(active) if config.as_ref().is_none_or(|value| value == &active.config) => {
                Ok(Some(active.clone()))
            }
            None if config.is_none() => Ok(None),
            _ => Err(denied()),
        };
    }
    config
        .map(|config| {
            if generation == 0
                || (config.scopes.is_empty() && config.runtime_scope.is_none())
                || config.scopes.len() > 128
                || !(1..=4096).contains(&config.max_pairings)
                || !(1..=128).contains(&config.max_pending)
                || !(1..=300_000).contains(&config.max_pending_ttl_ms)
                || !(1..=604_800_000).contains(&config.max_session_ttl_ms)
                || !(1..=1_048_576).contains(&config.max_state_bytes)
                || !(1..=30_000).contains(&config.callback_timeout_ms)
            {
                return Err(denied());
            }
            if let Some(runtime) = &config.runtime_scope {
                validate_runtime_defaults(runtime)?;
            }
            let peer = peer.ok_or_else(denied)?.parse::<tinybus::BusName>()?;
            if !peer.is_unique() {
                return Err(denied());
            }
            let secret = secret.ok_or_else(denied)?.clone();
            let registry = registry.ok_or_else(denied)?.clone();
            let device_scopes = registry.configuration().map_err(|_| denied())?;
            let mut scope_ids = std::collections::BTreeSet::new();
            for scope in &config.scopes {
                let legacy_configured = scope.legacy_device_backend_id.is_some()
                    && scope.legacy_source_registration_id.is_some();
                if scope.scope_id.len() != 32
                    || !scope.scope_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || scope.secret_registration_id.len() != 32
                    || !scope
                        .secret_registration_id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || !valid_persistence_backend_id(&scope.persistence_backend_id)
                    || scope.legacy_device_backend_id.is_some()
                        != scope.legacy_source_registration_id.is_some()
                    || scope.legacy_device_backend_id.as_ref().is_some_and(|id| {
                        id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    || scope
                        .legacy_source_registration_id
                        .as_ref()
                        .is_some_and(|id| {
                            id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                    || (legacy_configured
                        && scope.legacy_source_registration_id.as_deref()
                            != Some(scope.secret_registration_id.as_str()))
                    || !scope_ids.insert(scope.scope_id.as_str())
                    || !device_scopes
                        .scopes
                        .iter()
                        .any(|value| value.scope_id == scope.scope_id)
                    || secret.cipher_scope(&scope.secret_registration_id)?.scope_id
                        != scope.scope_id
                {
                    return Err(denied());
                }
            }
            let epochs = config
                .scopes
                .iter()
                .map(|scope| (scope.scope_id.clone(), 0))
                .collect();
            let scope_catalog = Arc::new(RwLock::new(
                config
                    .scopes
                    .iter()
                    .map(|scope| (scope.scope_id.clone(), scope.clone()))
                    .collect(),
            ));
            Ok(Arc::new(PairingState {
                callbacks: HostCallbacks {
                    connection: connection.clone(),
                    peer,
                    config: config.clone(),
                    scope_catalog: Arc::clone(&scope_catalog),
                    consumed_legacy_imports: Mutex::new(BTreeSet::new()),
                },
                config,
                secret,
                registry,
                clock,
                generation: AtomicU64::new(generation),
                scopes: Mutex::new(ScopeRegistry {
                    epochs,
                    loaded: BTreeMap::new(),
                }),
                scope_catalog,
            }))
        })
        .transpose()
}

pub(super) fn activate(state: Option<Arc<PairingState>>) -> tinybus::Result<()> {
    PAIRING.set(state).map_err(|_| denied())
}
pub(super) async fn transition(
    state: Option<&Arc<PairingState>>,
    generation: u64,
) -> tinybus::Result<()> {
    if let Some(state) = state {
        state.reinitialize(generation).await?;
    }
    Ok(())
}

pub(super) async fn invoke(
    request: DevicePairingRequest2,
) -> tinybus::Result<DevicePairingResponse2> {
    let state = PAIRING.get().and_then(Option::as_ref).ok_or_else(denied)?;
    state.execute(request).await
}

/// Register one dynamically admitted scope against canonical approval state.
pub(super) fn register_scope(
    request: &tinysecurity_bus::RegisterDevicePairingScopeRequest2,
    approvals: &tinysecurity::approval::Engine,
) -> tinybus::Result<tinysecurity_bus::DevicePairingScopeReceipt2> {
    PAIRING
        .get()
        .and_then(Option::as_ref)
        .ok_or_else(denied)?
        .register_scope(request, approvals)
}

#[cfg(test)]
#[path = "adapter_device_pairing_tests.rs"]
mod tests;
