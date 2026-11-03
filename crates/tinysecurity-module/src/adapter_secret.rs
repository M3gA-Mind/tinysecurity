//! Human-only confidential master facade. Persistent resolver uncertainty is
//! never reset by reinitialization, generation changes or SDK tree retention.
use super::{PolicyService, approval_failure};
use crate::secret_callbacks::{CallbackStore, GuardedMint, LiveGrant, ResolveContext, StoreBroker};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock},
};
use tinysecurity::crypto::{
    keyring::{LegacySource, MasterResolver, MasterSlot},
    native_handles as handles,
};
use tinysecurity_bus::{
    ApprovalActionRequest2, ApprovalConfig2, ApprovalRow2, ApprovalScope2, AuditConfig2,
    AuditCorrelation2, CallerContext, Check, EvaluateApprovalRequest2, EvaluateRequest,
    EvaluateSecretRequest2, ExecuteSecretRequest2, MasterPurpose2, MasterSlotKind2, Origin,
    RegisterSecretScopeRequest2, SecretConfig2, SecretOperation2, SecretRegistration2,
    SecretRequest2, SecretResponse2, SecretScopeReceipt2, ToolCall,
};
use zeroize::{Zeroize, Zeroizing};
static SECRET: OnceLock<Option<Arc<SecretState>>> = OnceLock::new();
fn denied() -> tinybus::Error {
    tinybus::Error::failed("secret authority denied")
}
fn native_denied() -> tinysecurity::crypto::Error {
    tinysecurity::crypto::Error::NativeDenied
}
struct Clock(Arc<dyn tinysecurity::approval::Clock>);
impl handles::NativeClock for Clock {
    fn now(&self) -> tinysecurity::crypto::Result<handles::Time> {
        Ok(handles::Time {
            wall: self.0.wall_ms().ok_or_else(native_denied)?,
            monotonic: self.0.monotonic_ms(),
        })
    }
}
fn opaque() -> tinybus::Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| denied())?;
    let mut out = String::with_capacity(64);
    for byte in bytes.iter() {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    Ok(out)
}
struct Registered {
    descriptor: SecretRegistration2,
    scope: RwLock<ApprovalScope2>,
    broker: Arc<StoreBroker>,
    resolver: MasterResolver,
}
struct Pending {
    request: SecretRequest2,
    audit: AuditCorrelation2,
    work: handles::Reservation,
    row: Option<ApprovalRow2>,
}
struct Alias {
    handle: handles::MasterHandle,
    registration: String,
    purpose: handles::Purpose,
    generation: u64,
}
struct DenyCipherDelivery;
impl handles::cipher::NativeCipherConsumer for DenyCipherDelivery {
    fn deliver<'a>(
        &'a self,
        _delivery: &'a handles::cipher::CipherDelivery,
    ) -> handles::Verification<'a, handles::cipher::DeliveryAcknowledgement> {
        Box::pin(async { Err(native_denied()) })
    }
}
/// Strong process owner deliberately outlives all service trees; closed owners
/// stay closed and uncertain resolvers cannot be replaced through init.
pub(super) struct SecretState {
    config: SecretConfig2,
    peer: String,
    registry: handles::Registry,
    registered: BTreeMap<String, Arc<Registered>>,
    dynamic: Mutex<BTreeMap<String, Arc<Registered>>>,
    connection: tinybus::Connection,
    pending: Mutex<BTreeMap<(String, String), Pending>>,
    aliases: Mutex<BTreeMap<String, Alias>>,
    clock: Arc<dyn handles::NativeClock>,
}
fn purpose(value: MasterPurpose2) -> handles::Purpose {
    match value {
        MasterPurpose2::ConfigUserMaster => handles::Purpose::ConfigUserMaster,
        MasterPurpose2::AppEncryptionMaster => handles::Purpose::AppEncryptionMaster,
    }
}
fn slot(value: MasterSlotKind2, user: &str) -> (MasterSlot, String) {
    match value {
        MasterSlotKind2::App => (MasterSlot::App, "app:master_key".into()),
        MasterSlotKind2::User => (
            MasterSlot::User(user.into()),
            format!("{user}:secretstore.master_key"),
        ),
        MasterSlotKind2::File => (MasterSlot::File, ".secret_key".into()),
    }
}
fn id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn unique_config_master_for_scope<'a>(
    registrations: impl Iterator<Item = &'a SecretRegistration2>,
    scope_id: &str,
) -> tinybus::Result<&'a SecretRegistration2> {
    let mut matches = registrations.filter(|registration| {
        registration.approval_scope_id == scope_id
            && registration.purpose == MasterPurpose2::ConfigUserMaster
    });
    let registration = matches.next().ok_or_else(denied)?;
    if matches.next().is_some() {
        return Err(denied());
    }
    Ok(registration)
}
fn ensure_scope_id_matches(scope_id: &str, canonical: &ApprovalScope2) -> tinybus::Result<()> {
    if canonical.scope_id != scope_id {
        return Err(denied());
    }
    Ok(())
}
#[derive(Default)]
struct Inventory {
    registrations: BTreeSet<String>,
    scopes: BTreeSet<String>,
    targets: BTreeSet<(String, MasterSlotKind2, String)>,
}
impl Inventory {
    fn admit(
        &mut self,
        descriptor: &SecretRegistration2,
        scope: &ApprovalScope2,
        generation: u64,
    ) -> tinybus::Result<()> {
        if !id(&descriptor.registration_id)
            || !self
                .registrations
                .insert(descriptor.registration_id.clone())
            || !self.scopes.insert(descriptor.approval_scope_id.clone())
            || scope.generation != generation
            || descriptor.legacy.len() > 3
            || descriptor.origin == Origin::Cron
        {
            return Err(denied());
        }
        let app = descriptor.purpose == MasterPurpose2::AppEncryptionMaster;
        if app != (descriptor.target.slot == MasterSlotKind2::App) {
            return Err(denied());
        }
        let mut inventory = BTreeSet::new();
        for binding in std::iter::once(&descriptor.target).chain(&descriptor.legacy) {
            if !id(&binding.backend_id)
                || !inventory.insert((&binding.backend_id, binding.slot))
                || app != (binding.slot == MasterSlotKind2::App)
            {
                return Err(denied());
            }
        }
        // Disallow two logical resolvers for one actual descriptor+subject slot.
        if !self.targets.insert((
            descriptor.target.backend_id.clone(),
            descriptor.target.slot,
            if descriptor.target.slot == MasterSlotKind2::User {
                scope.subject.user.clone()
            } else {
                String::new()
            },
        )) {
            return Err(denied());
        }
        Ok(())
    }
}
impl SecretState {
    fn new(
        config: SecretConfig2,
        connection: &tinybus::Connection,
        peer: &str,
        approvals: &ApprovalConfig2,
        engine: &tinysecurity::approval::Engine,
        generation: u64,
        clock: Arc<dyn tinysecurity::approval::Clock>,
    ) -> tinybus::Result<Self> {
        if config.registrations.is_empty()
            || config.registrations.len() > 128
            || !(1..=30000).contains(&config.callback_timeout_ms)
        {
            return Err(denied());
        }
        let mut inventory = Inventory::default();
        let mut native = Vec::new();
        let mut registered = BTreeMap::new();
        for descriptor in &config.registrations {
            let scope = approvals
                .scopes
                .iter()
                .find(|scope| scope.scope_id == descriptor.approval_scope_id)
                .ok_or_else(denied)?;
            inventory.admit(descriptor, scope, generation)?;
            native.push(handles::Registration {
                id: descriptor.registration_id.clone(),
                subject: scope.subject.clone(),
                durable_subject: engine
                    .durable_scope(&scope.scope_id)
                    .map_err(approval_failure)?,
                policy_ref: engine
                    .durable_policy_ref(&scope.scope_id)
                    .map_err(approval_failure)?,
                purposes: vec![purpose(descriptor.purpose)],
            });
            let broker = Arc::new(StoreBroker::new(
                connection.clone(),
                peer,
                config.callback_timeout_ms,
            )?);
            let (target_slot, target_name) = slot(descriptor.target.slot, &scope.subject.user);
            let target = Arc::new(CallbackStore::new(
                broker.clone(),
                descriptor.target.clone(),
                target_name,
                false,
            ));
            let legacy = descriptor
                .legacy
                .iter()
                .map(|binding| {
                    let (source_slot, name) = slot(binding.slot, &scope.subject.user);
                    LegacySource::at_slot(
                        Arc::new(CallbackStore::new(
                            broker.clone(),
                            binding.clone(),
                            name,
                            true,
                        )),
                        source_slot,
                    )
                })
                .collect();
            let resolver = MasterResolver::new_with_sources(
                target,
                legacy,
                &target_slot,
                Arc::new(GuardedMint(broker.clone())),
            )
            .map_err(|_| denied())?;
            registered.insert(
                descriptor.registration_id.clone(),
                Arc::new(Registered {
                    descriptor: descriptor.clone(),
                    scope: RwLock::new(scope.clone()),
                    broker,
                    resolver,
                }),
            );
        }
        let clock: Arc<dyn handles::NativeClock> = Arc::new(Clock(clock));
        let limits = handles::Limits {
            max_handles: config.limits.max_handles,
            max_in_flight: config.limits.max_in_flight,
            operations_per_minute: config.limits.operations_per_minute,
            max_ttl_ms: config.limits.max_ttl_ms,
            ..Default::default()
        };
        let registry = handles::Registry::new(native, peer, generation, limits, clock.clone())
            .map_err(|_| denied())?;
        Ok(Self {
            config,
            peer: peer.into(),
            registry,
            registered,
            dynamic: Mutex::new(BTreeMap::new()),
            connection: connection.clone(),
            pending: Mutex::new(BTreeMap::new()),
            aliases: Mutex::new(BTreeMap::new()),
            clock,
        })
    }
    pub(super) fn cipher_registry(&self) -> handles::Registry {
        self.registry.clone()
    }
    pub(super) fn cipher_scope(&self, registration: &str) -> tinybus::Result<ApprovalScope2> {
        let reg = self.registration_id(registration)?;
        if reg.descriptor.purpose != MasterPurpose2::ConfigUserMaster {
            return Err(denied());
        }
        Ok(reg.scope.read().map_err(|_| denied())?.clone())
    }
    /// Find the unique live `ConfigUserMaster` binding for one canonical approval scope.
    /// The caller supplies no registration alias; ambiguity fails closed.
    pub(super) fn config_master_for_scope(
        &self,
        scope_id: &str,
    ) -> tinybus::Result<(SecretRegistration2, ApprovalScope2)> {
        let dynamic = self.dynamic.lock().map_err(|_| denied())?;
        let descriptors = self
            .registered
            .values()
            .chain(dynamic.values())
            .map(|registration| &registration.descriptor);
        let descriptor = unique_config_master_for_scope(descriptors, scope_id)?.clone();
        drop(dynamic);
        let registration = self.registration_id(&descriptor.registration_id)?;
        let canonical = registration.scope.read().map_err(|_| denied())?.clone();
        ensure_scope_id_matches(scope_id, &canonical)?;
        Ok((descriptor, canonical))
    }
    pub(super) fn prepare_cipher(
        &self,
        owner: &handles::cipher::CipherOwner,
        request: &mut tinysecurity_bus::SecretCipherRequest2,
        generation: u64,
    ) -> tinybus::Result<handles::cipher::CipherPending> {
        self.prune()?;
        let aliases = self.aliases.lock().map_err(|_| denied())?;
        let alias = aliases.get(&request.master_handle).ok_or_else(denied)?;
        if alias.registration != request.registration_id
            || alias.generation != generation
            || alias.purpose != handles::Purpose::ConfigUserMaster
        {
            return Err(denied());
        }
        owner
            .prepare(handles::cipher::CipherRequest {
                registration: &request.registration_id,
                authenticated_peer: &self.peer,
                generation,
                call_id: &request.call_id,
                master: &alias.handle,
                kind: super::cipher::kind(request.operation),
                input: Zeroizing::new(std::mem::take(&mut request.input)),
                ttl_ms: request.ttl_ms,
            })
            .map_err(|_| denied())
    }
    pub(super) fn pairing_state_cipher(
        &self,
        registration: &str,
        alias_id: &str,
        generation: u64,
        scope_id: &str,
        backend_id: &str,
    ) -> tinybus::Result<handles::cipher::DevicePairingStateCipher> {
        let scope = self.cipher_scope(registration)?;
        if scope.scope_id != scope_id {
            return Err(denied());
        }
        let aliases = self.aliases.lock().map_err(|_| denied())?;
        let alias = aliases.get(alias_id).ok_or_else(denied)?;
        if alias.registration != registration
            || alias.generation != generation
            || alias.purpose != handles::Purpose::ConfigUserMaster
        {
            return Err(denied());
        }
        let owner = handles::cipher::CipherOwner::new(
            self.registry.clone(),
            handles::cipher::CipherConfig {
                consumer: format!("device-pairing-state-{scope_id}"),
                enabled: true,
            },
            Arc::new(DenyCipherDelivery),
        )
        .map_err(|_| denied())?;
        let pending = owner
            .prepare(handles::cipher::CipherRequest {
                registration,
                authenticated_peer: &self.peer,
                generation,
                call_id: "device-pairing-state-unlock",
                master: &alias.handle,
                kind: handles::cipher::CipherKind::Encrypt,
                input: Zeroizing::new(b"device-pairing-state".to_vec()),
                ttl_ms: self.config.limits.max_ttl_ms,
            })
            .map_err(|_| denied())?;
        owner
            .retain_device_pairing_state(pending, scope_id, backend_id)
            .map_err(|_| denied())
    }
    pub(super) fn validate_cipher_master(
        &self,
        registration: &str,
        alias: &str,
        generation: u64,
        deadline: u64,
    ) -> tinybus::Result<()> {
        let now = self.clock.now().map_err(|_| {
            self.close();
            denied()
        })?;
        if now.wall >= deadline {
            return Err(denied());
        }
        let aliases = self.aliases.lock().map_err(|_| denied())?;
        let alias = aliases.get(alias).ok_or_else(denied)?;
        self.registry
            .validate_handle(
                &alias.handle,
                registration,
                handles::Purpose::ConfigUserMaster,
                &self.peer,
                generation,
            )
            .map_err(|_| denied())
    }
    fn registration_id(&self, id: &str) -> tinybus::Result<Arc<Registered>> {
        if let Some(reg) = self.registered.get(id) {
            // Static registrations remain owned by the immutable init snapshot.
            return Ok(reg.clone());
        }
        self.dynamic
            .lock()
            .map_err(|_| denied())?
            .get(id)
            .cloned()
            .ok_or_else(denied)
    }
    fn registration(&self, request: &SecretRequest2) -> tinybus::Result<Arc<Registered>> {
        let reg = self.registration_id(&request.registration_id)?;
        if request.call_id.is_empty()
            || request.call_id.len() > 128
            || request.call_id.chars().any(char::is_control)
            || request.ttl_ms == 0
            || request.ttl_ms > self.config.limits.max_ttl_ms
            || !matches!(
                (reg.descriptor.purpose, request.operation),
                (
                    MasterPurpose2::ConfigUserMaster,
                    SecretOperation2::ResolveConfigMaster
                ) | (
                    MasterPurpose2::AppEncryptionMaster,
                    SecretOperation2::ResolveAppMaster
                )
            )
        {
            return Err(denied());
        }
        Ok(reg)
    }
    pub(super) fn register_scope(
        &self,
        request: RegisterSecretScopeRequest2,
        engine: &tinysecurity::approval::Engine,
    ) -> tinybus::Result<SecretScopeReceipt2> {
        let descriptor = request.registration;
        let scope = engine
            .scope_snapshot(&descriptor.approval_scope_id)
            .map_err(approval_failure)?;
        let registration_id = descriptor.registration_id.clone();
        if let Some(existing) = self.registered.get(&registration_id) {
            return if existing.descriptor == descriptor {
                Ok(SecretScopeReceipt2 {
                    registration_id,
                    active: true,
                })
            } else {
                Err(denied())
            };
        }

        let mut dynamic = self.dynamic.lock().map_err(|_| denied())?;
        if let Some(existing) = dynamic.get(&registration_id) {
            return if existing.descriptor == descriptor {
                Ok(SecretScopeReceipt2 {
                    registration_id,
                    active: true,
                })
            } else {
                Err(denied())
            };
        }
        let mut inventory = Inventory::default();
        for existing in self.registered.values().chain(dynamic.values()) {
            let mut live_scope = existing.scope.read().map_err(|_| denied())?.clone();
            live_scope.generation = scope.generation;
            inventory.admit(&existing.descriptor, &live_scope, scope.generation)?;
        }
        inventory.admit(&descriptor, &scope, scope.generation)?;

        let native = handles::Registration {
            id: registration_id.clone(),
            subject: scope.subject.clone(),
            durable_subject: engine
                .durable_scope(&scope.scope_id)
                .map_err(approval_failure)?,
            policy_ref: engine
                .durable_policy_ref(&scope.scope_id)
                .map_err(approval_failure)?,
            purposes: vec![purpose(descriptor.purpose)],
        };
        let broker = Arc::new(StoreBroker::new(
            self.connection.clone(),
            &self.peer,
            self.config.callback_timeout_ms,
        )?);
        let (target_slot, target_name) = slot(descriptor.target.slot, &scope.subject.user);
        let target = Arc::new(CallbackStore::new(
            broker.clone(),
            descriptor.target.clone(),
            target_name,
            false,
        ));
        let legacy = descriptor
            .legacy
            .iter()
            .map(|binding| {
                let (source_slot, name) = slot(binding.slot, &scope.subject.user);
                LegacySource::at_slot(
                    Arc::new(CallbackStore::new(
                        broker.clone(),
                        binding.clone(),
                        name,
                        true,
                    )),
                    source_slot,
                )
            })
            .collect();
        let resolver = MasterResolver::new_with_sources(
            target,
            legacy,
            &target_slot,
            Arc::new(GuardedMint(broker.clone())),
        )
        .map_err(|_| denied())?;

        self.registry
            .register_scope(native, scope.generation)
            .map_err(|_| denied())?;
        dynamic.insert(
            registration_id.clone(),
            Arc::new(Registered {
                descriptor,
                scope: RwLock::new(scope),
                broker,
                resolver,
            }),
        );
        Ok(SecretScopeReceipt2 {
            registration_id,
            active: true,
        })
    }
    pub(super) fn retire_approval_scope(&self, scope_id: &str) -> tinybus::Result<()> {
        let mut dynamic = self.dynamic.lock().map_err(|_| denied())?;
        let ids = self
            .registered
            .iter()
            .filter(|(_, registration)| registration.descriptor.approval_scope_id == scope_id)
            .map(|(id, _)| id.clone())
            .chain(
                dynamic
                    .iter()
                    .filter(|(_, registration)| {
                        registration.descriptor.approval_scope_id == scope_id
                    })
                    .map(|(id, _)| id.clone()),
            )
            .collect::<Vec<_>>();
        for id in &ids {
            self.registry.revoke_scope(id).map_err(|_| denied())?;
        }
        let dynamic_ids = dynamic
            .iter()
            .filter(|(_, registration)| registration.descriptor.approval_scope_id == scope_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        dynamic.retain(|id, _| !dynamic_ids.contains(id));
        self.pending
            .lock()
            .map_err(|_| denied())?
            .retain(|(id, _), _| !ids.contains(id));
        self.aliases
            .lock()
            .map_err(|_| denied())?
            .retain(|_, alias| !ids.contains(&alias.registration));
        Ok(())
    }
    pub(super) fn refresh_approval_scope(
        &self,
        scope_id: &str,
        engine: &tinysecurity::approval::Engine,
    ) -> tinybus::Result<()> {
        let scope = engine.scope_snapshot(scope_id).map_err(approval_failure)?;
        for registered in self
            .registered
            .values()
            .filter(|registered| registered.descriptor.approval_scope_id == scope_id)
        {
            let mut current = registered.scope.write().map_err(|_| denied())?;
            if current.subject != scope.subject {
                return Err(denied());
            }
            self.registry
                .replace_scope(
                    &handles::Registration {
                        id: registered.descriptor.registration_id.clone(),
                        subject: scope.subject.clone(),
                        durable_subject: engine
                            .durable_scope(scope_id)
                            .map_err(approval_failure)?,
                        policy_ref: engine
                            .durable_policy_ref(scope_id)
                            .map_err(approval_failure)?,
                        purposes: vec![purpose(registered.descriptor.purpose)],
                    },
                    scope.generation,
                )
                .map_err(|_| denied())?;
            *current = scope.clone();
        }
        self.pending
            .lock()
            .map_err(|_| denied())?
            .retain(|(registration, _), _| {
                self.registered
                    .get(registration)
                    .is_some_and(|entry| entry.descriptor.approval_scope_id != scope_id)
            });
        Ok(())
    }
    fn prune(&self) -> tinybus::Result<()> {
        let now = self.clock.now().map_err(|_| {
            self.close();
            denied()
        })?;
        self.pending
            .lock()
            .map_err(|_| denied())?
            .retain(|_, pending| {
                pending.work.binding().expires_at_ms() > now.wall && pending.work.validate().is_ok()
            });
        self.aliases
            .lock()
            .map_err(|_| denied())?
            .retain(|_, alias| {
                self.registry
                    .validate_handle(
                        &alias.handle,
                        &alias.registration,
                        alias.purpose,
                        &self.peer,
                        alias.generation,
                    )
                    .is_ok()
            });
        Ok(())
    }
    fn close(&self) {
        self.registry.close();
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
        if let Ok(mut aliases) = self.aliases.lock() {
            aliases.clear();
        }
        if let Ok(mut dynamic) = self.dynamic.lock() {
            dynamic.clear();
        }
        super::cipher::close_pending();
    }
}
fn call(reg: &Registered, scope: &ApprovalScope2, binding: &handles::Binding) -> EvaluateRequest {
    EvaluateRequest {
        caller: CallerContext {
            agent: scope.subject.agent.clone(),
            call_id: binding.safe_call_id(),
            tier: scope.ceiling.clone(),
            origin: reg.descriptor.origin.clone(),
            ..Default::default()
        },
        call: ToolCall {
            tool: "native_secret_grant".into(),
            arguments_json: binding.safe_arguments(),
            checks: vec![Check::Unknown {
                description: "native-master-authority".into(),
            }],
        },
    }
}
pub(super) struct Initialization<'a> {
    pub(super) connection: &'a tinybus::Connection,
    pub(super) peer: Option<&'a str>,
    pub(super) approvals: Option<&'a ApprovalConfig2>,
    pub(super) engine: Option<&'a Arc<tinysecurity::approval::Engine>>,
    pub(super) audit: Option<&'a AuditConfig2>,
    pub(super) generation: u64,
    pub(super) clock: Arc<dyn tinysecurity::approval::Clock>,
}
pub(super) fn configured(
    config: Option<SecretConfig2>,
    init: Initialization<'_>,
) -> tinybus::Result<Option<Arc<SecretState>>> {
    if let Some(active) = SECRET.get() {
        return match active {
            Some(active)
                if config
                    .as_ref()
                    .is_none_or(|config| config == &active.config) =>
            {
                Ok(Some(active.clone()))
            }
            None if config.is_none() => Ok(None),
            _ => Err(denied()),
        };
    }
    config
        .map(|config| {
            if !init.audit.is_some_and(|audit| audit.required) {
                return Err(denied());
            }
            SecretState::new(
                config,
                init.connection,
                init.peer.ok_or_else(denied)?,
                init.approvals.ok_or_else(denied)?,
                init.engine.ok_or_else(denied)?.as_ref(),
                init.generation,
                init.clock,
            )
            .map(Arc::new)
        })
        .transpose()
}
struct Lifetime(Arc<SecretState>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.close();
    }
}
pub(super) struct PreparedGeneration<'a> {
    native: handles::PreparedGeneration<'a>,
    pending: MutexGuard<'a, BTreeMap<(String, String), Pending>>,
    aliases: MutexGuard<'a, BTreeMap<String, Alias>>,
}
impl PreparedGeneration<'_> {
    pub(super) fn commit(self) {
        let Self {
            native,
            mut pending,
            mut aliases,
        } = self;
        // Reservations reacquire the native state lock when dropped.
        native.commit();
        pending.clear();
        aliases.clear();
    }
}
pub(super) fn prepare_generation(
    state: Option<&Arc<SecretState>>,
    generation: u64,
) -> tinybus::Result<Option<PreparedGeneration<'_>>> {
    state
        .map(|state| {
            // Match prune and admission: facade inventories precede the native lock.
            let pending = state.pending.lock().map_err(|_| denied())?;
            let aliases = state.aliases.lock().map_err(|_| denied())?;
            let native = state
                .registry
                .prepare_generation(generation)
                .map_err(|_| denied())?;
            Ok(PreparedGeneration {
                native,
                pending,
                aliases,
            })
        })
        .transpose()
}
pub(super) fn activate(state: Option<Arc<SecretState>>) -> tinybus::Result<()> {
    SECRET.set(state.clone()).map_err(|_| denied())?;
    if let Some(state) = state {
        let guard = Lifetime(state);
        tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
    }
    Ok(())
}
struct Verifier<'a> {
    engine: &'a tinysecurity::approval::Engine,
    reg: &'a Registered,
    scope: &'a ApprovalScope2,
    request_id: String,
    audit: AuditCorrelation2,
}
impl handles::HumanGrantVerifier for Verifier<'_> {
    fn consume<'a>(
        &'a self,
        binding: &'a handles::Binding,
    ) -> handles::Verification<'a, handles::HumanGrantReceipt> {
        Box::pin(async move {
            let (row, ack) = self
                .engine
                .consume_native_grant(ApprovalActionRequest2 {
                    scope_id: self.scope.scope_id.clone(),
                    request_id: self.request_id.clone(),
                    request: call(self.reg, self.scope, binding),
                    audit: self.audit.clone(),
                })
                .await
                .map_err(|_| native_denied())?;
            let scope = ack.expected_scope().clone();
            handles::HumanGrantReceipt::from_verified_native_consumption(
                binding,
                row,
                ack.into_receipt(),
                scope,
            )
        })
    }
}
// Wipe unpublished aliases; owned master remains bounded/expired by its registry.
struct Output(Option<SecretResponse2>);
impl Drop for Output {
    fn drop(&mut self) {
        if let Some(SecretResponse2::MasterHandle { handle, .. }) = &mut self.0 {
            handle.zeroize();
        }
    }
}
impl PolicyService {
    pub(super) async fn secret_approval(
        &self,
        request: EvaluateSecretRequest2,
    ) -> tinybus::Result<ApprovalRow2> {
        let state = self.secret.as_ref().ok_or_else(denied)?;
        state.prune()?;
        let reg = state.registration(&request.request)?;
        let reg_scope = reg.scope.read().map_err(|_| denied())?.clone();
        let engine = self.approvals.as_ref().ok_or_else(denied)?;
        let generation = self.read()?.info().generation;
        let key = (
            request.request.registration_id.clone(),
            request.request.call_id.clone(),
        );
        let (approval, expires) = {
            let mut pending = state.pending.lock().map_err(|_| denied())?;
            if let Some(existing) = pending.get(&key) {
                if existing.request != request.request || existing.audit != request.audit {
                    return Err(denied());
                }
                // A canceled/in-progress begin cannot mint another challenge for its durable row.
                return existing.row.clone().ok_or_else(denied);
            }
            let work = state
                .registry
                .reserve(handles::Request {
                    registration: &request.request.registration_id,
                    authenticated_peer: &state.peer,
                    purpose: purpose(reg.descriptor.purpose),
                    kind: handles::OperationKind::NativeMasterGrant,
                    call_id: &request.request.call_id,
                    input: Zeroizing::new(
                        serde_json::to_vec(&request.request).map_err(|_| denied())?,
                    ),
                    ttl_ms: request.request.ttl_ms,
                    generation,
                })
                .map_err(|_| denied())?;
            let approval = call(&reg, &reg_scope, work.binding());
            let expires = work.binding().expires_at_ms();
            pending.insert(
                key.clone(),
                Pending {
                    request: request.request,
                    audit: request.audit.clone(),
                    work,
                    row: None,
                },
            );
            (approval, expires)
        };
        let row = engine
            .begin_native_grant(
                EvaluateApprovalRequest2 {
                    scope_id: reg_scope.scope_id.clone(),
                    request: approval,
                    ttl_ms: None,
                    summary: "native master authority".into(),
                    audit: request.audit,
                },
                expires,
            )
            .await
            .map_err(approval_failure)?;
        if self.read()?.info().generation != generation {
            return Err(denied());
        }
        state.prune()?;
        let mut pending = state.pending.lock().map_err(|_| denied())?;
        let record = pending.get_mut(&key).ok_or_else(denied)?;
        record.row = Some(row.clone());
        Ok(row)
    }
    pub(super) async fn secret_execute(
        &self,
        request: ExecuteSecretRequest2,
    ) -> tinybus::Result<SecretResponse2> {
        let state = self.secret.as_ref().ok_or_else(denied)?;
        state.prune()?;
        let reg = state.registration(&request.request)?;
        let reg_scope = reg.scope.read().map_err(|_| denied())?.clone();
        let generation = self.read()?.info().generation;
        let key = (
            request.request.registration_id.clone(),
            request.request.call_id.clone(),
        );
        let work = {
            let mut pending = state.pending.lock().map_err(|_| denied())?;
            let record = pending.get(&key).ok_or_else(denied)?;
            if record.request != request.request
                || record
                    .row
                    .as_ref()
                    .is_none_or(|row| row.request_id != request.request_id)
            {
                return Err(denied());
            }
            pending.remove(&key).ok_or_else(denied)?.work
        };
        let grant = state
            .registry
            .authorize_human(
                work,
                &Verifier {
                    engine: self.approvals.as_ref().ok_or_else(denied)?,
                    reg: &reg,
                    scope: &reg_scope,
                    request_id: request.request_id,
                    audit: request.audit,
                },
            )
            .await
            .map_err(|_| denied())?;
        let live = Arc::new(LiveGrant::new(state.registry.clone(), grant));
        let lease = reg
            .broker
            .lease(ResolveContext::new(
                request.request.registration_id.clone(),
                generation,
                opaque()?,
                live.clone(),
            ))
            .map_err(|_| denied())?;
        live.validate().map_err(|_| denied())?;
        let key = reg.resolver.resolve().await.map_err(|_| denied())?;
        live.validate().map_err(|_| denied())?;
        drop(lease);
        let handle = state
            .registry
            .retain_master(live.take().map_err(|_| denied())?, key)
            .map_err(|_| denied())?;
        state
            .registry
            .validate_handle(
                &handle,
                &request.request.registration_id,
                purpose(reg.descriptor.purpose),
                &state.peer,
                generation,
            )
            .map_err(|_| denied())?;
        if self.read()?.info().generation != generation {
            return Err(denied());
        }
        let alias = opaque()?;
        let mut output = Output(Some(SecretResponse2::MasterHandle {
            handle: alias.clone(),
            purpose: reg.descriptor.purpose,
            generation,
        }));
        let mut aliases = state.aliases.lock().map_err(|_| denied())?;
        if aliases.len() >= state.config.limits.max_handles as usize || aliases.contains_key(&alias)
        {
            return Err(denied());
        }
        // A prepared generation transition also holds this alias lock. Recheck
        // after acquiring it so an old execution cannot repopulate the new inventory.
        state
            .registry
            .validate_handle(
                &handle,
                &request.request.registration_id,
                purpose(reg.descriptor.purpose),
                &state.peer,
                generation,
            )
            .map_err(|_| denied())?;
        aliases.insert(
            alias,
            Alias {
                handle,
                registration: request.request.registration_id,
                purpose: purpose(reg.descriptor.purpose),
                generation,
            },
        );
        output.0.take().ok_or_else(denied)
    }
}
#[cfg(test)]
#[path = "adapter_secret_tests.rs"]
mod tests;
