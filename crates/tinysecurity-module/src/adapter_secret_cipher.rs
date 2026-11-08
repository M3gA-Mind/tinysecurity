//! Fixed routine authority over real acquired masters. Native output is staged in
//! bounded physical slots; unknown callback work permanently occupies its slot.
//!
//! Two kinds of cipher share this machinery. The static cipher comes from init
//! config and audits under the init subject. A runtime cipher belongs to one
//! secret registration (`RegisterSecretScope2` with a cipher, contract 2.1): it
//! has its own consumer, slots, audit subject and stream, and every call selects
//! its state by the request's registration, so one tenant can never reach another's.
use super::{PolicyService, secret::SecretState};
use crate::callbacks::AuditClient;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tinysecurity::crypto::native_handles::{
    self as handles,
    cipher::{
        CipherConfig, CipherDelivery, CipherKind, CipherOwner, CipherPending, CipherResult,
        DeliveryAcknowledgement, NativeCipherConsumer,
    },
};
use tinysecurity_bus::{
    AuditCorrelation2, AuditEvent2, AuditHealth2, AuditKind2, AuditSinkRequest2,
    AuditSinkResponse2, EvaluateSecretCipherRequest2, ExecuteSecretCipherRequest2,
    SecretCipherConfig2, SecretCipherDeliveryIdentity2, SecretCipherDeliveryRequest2,
    SecretCipherDeliveryResponse2, SecretCipherKind2, SecretCipherPending2, SecretCipherRequest2,
    SecretCipherResponse2, SecretScopeCipher2, SubjectScope, callback_names2,
};
use zeroize::Zeroize;

static CIPHER: OnceLock<Option<Arc<CipherState>>> = OnceLock::new();
/// Runtime ciphers, keyed by the secret registration that owns each one.
static RUNTIME: OnceLock<Mutex<BTreeMap<String, Arc<CipherState>>>> = OnceLock::new();
/// Consumer identities, each bound to one registration and its physical slots for
/// the process lifetime: a slot left uncertain is never handed out again, not even
/// to a later cipher of the same registration.
static CONSUMERS: OnceLock<Mutex<BTreeMap<String, ConsumerBinding>>> = OnceLock::new();
/// The one pending inventory of every cipher, so generation activation can hold it.
static PENDING: OnceLock<Mutex<BTreeMap<String, Pending>>> = OnceLock::new();
/// Fingerprint of the master each live cipher registration uses. Two live
/// registrations may not share one master, or one could open the other's
/// ciphertext. Entries are released when their registration is retired.
static MASTERS: OnceLock<Mutex<BTreeMap<[u8; 32], String>>> = OnceLock::new();
type Slots = Arc<Mutex<Vec<Option<String>>>>;
struct ConsumerBinding {
    registration: String,
    slots: Slots,
}
fn runtime() -> &'static Mutex<BTreeMap<String, Arc<CipherState>>> {
    RUNTIME.get_or_init(Mutex::default)
}
fn consumers() -> &'static Mutex<BTreeMap<String, ConsumerBinding>> {
    CONSUMERS.get_or_init(Mutex::default)
}
fn pending() -> &'static Mutex<BTreeMap<String, Pending>> {
    PENDING.get_or_init(Mutex::default)
}
fn masters() -> &'static Mutex<BTreeMap<[u8; 32], String>> {
    MASTERS.get_or_init(Mutex::default)
}
fn duplicate_master() -> tinybus::Error {
    tinybus::Error::failed("secret master already bound to another live registration")
}
/// Refuse a master another live registration already holds. Nothing is bound.
fn check_master(registration: &str, fingerprint: [u8; 32]) -> tinybus::Result<()> {
    let masters = masters().lock().map_err(|_| denied())?;
    match masters.get(&fingerprint) {
        Some(owner) if owner != registration => Err(duplicate_master()),
        _ => Ok(()),
    }
}
/// Bind `fingerprint` to `registration`, refusing a master another live
/// registration already holds. A registration keeps every fingerprint it has bound:
/// a rotated key leaves its old handles valid, so the old fingerprint stays held
/// until the registration is retired.
fn bind_master(registration: &str, fingerprint: [u8; 32]) -> tinybus::Result<()> {
    let mut masters = masters().lock().map_err(|_| denied())?;
    match masters.get(&fingerprint) {
        Some(owner) if owner == registration => Ok(()),
        Some(_) => Err(duplicate_master()),
        None => {
            masters.insert(fingerprint, registration.into());
            Ok(())
        }
    }
}
fn denied() -> tinybus::Error {
    tinybus::Error::failed("secret authority denied")
}
fn native_denied() -> tinysecurity::crypto::Error {
    tinysecurity::crypto::Error::NativeDenied
}
pub(super) fn kind(kind: SecretCipherKind2) -> CipherKind {
    match kind {
        SecretCipherKind2::Encrypt => CipherKind::Encrypt,
        SecretCipherKind2::Decrypt => CipherKind::Decrypt,
        SecretCipherKind2::DecryptAndMigrate => CipherKind::DecryptAndMigrate,
    }
}
fn opaque_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
struct Input(SecretCipherRequest2);
impl Drop for Input {
    fn drop(&mut self) {
        self.0.input.zeroize();
    }
}
struct Output(SecretCipherDeliveryRequest2);
impl Drop for Output {
    fn drop(&mut self) {
        self.0.plaintext.zeroize();
        if let Some(value) = &mut self.0.replacement {
            value.zeroize();
        }
    }
}
fn metadata(request: &SecretCipherRequest2) -> SecretCipherRequest2 {
    SecretCipherRequest2 {
        registration_id: request.registration_id.clone(),
        master_handle: request.master_handle.clone(),
        call_id: request.call_id.clone(),
        operation: request.operation,
        input: Vec::new(),
        ttl_ms: request.ttl_ms,
    }
}
pub(super) struct Pending {
    /// The cipher that admitted this work; only its own registration executes it.
    state: Arc<CipherState>,
    request: SecretCipherRequest2,
    work: CipherPending,
    intent: RoutineAcknowledgement,
}
/// Actual required audit response, bound privately to immutable native operation.
/// No serde constructor or invocation receipt can create this authority.
struct RoutineAcknowledgement {
    response: AuditSinkResponse2,
    operation: String,
    phase: &'static str,
    generation: u64,
}
impl RoutineAcknowledgement {
    fn verify(&self, operation: &str, phase: &'static str, generation: u64) -> tinybus::Result<()> {
        if self.operation != operation
            || self.phase != phase
            || self.generation != generation
            || self.response.events.len() != 1
        {
            return Err(denied());
        }
        Ok(())
    }
}
struct Context {
    request: SecretCipherRequest2,
    operation: String,
    generation: u64,
    deadline: u64,
    slot: u16,
    delivery_audit: AuditCorrelation2,
    staged: Mutex<Option<SecretCipherDeliveryIdentity2>>,
    /// Set just before the consumer is called: from then on the slot is fenced.
    attempted: AtomicBool,
}
struct Broker {
    connection: tinybus::Connection,
    peer: tinybus::BusName,
    config: SecretCipherConfig2,
    secret: Arc<SecretState>,
    /// The client of this cipher's own audit subject and stream.
    audit: Arc<AuditClient>,
    /// The init client, whose redaction registry follows policy reinit.
    registry_source: Arc<AuditClient>,
    subject: SubjectScope,
    audit_binding: Mutex<(SubjectScope, String)>,
    slots: Slots,
    contexts: Mutex<BTreeMap<String, Arc<Context>>>,
}
impl Broker {
    fn validate(&self, context: &Context) -> tinybus::Result<()> {
        self.secret.validate_cipher_master(
            &context.request.registration_id,
            &context.request.master_handle,
            context.generation,
            context.deadline,
        )?;
        if self
            .slots
            .lock()
            .map_err(|_| denied())?
            .get(usize::from(context.slot))
            .and_then(Option::as_ref)
            != Some(&context.operation)
        {
            return Err(denied());
        }
        Ok(())
    }
    fn lease(self: &Arc<Self>, context: Context) -> tinybus::Result<Lease> {
        let mut slots = self.slots.lock().map_err(|_| denied())?;
        let slot = slots.iter().position(Option::is_none).ok_or_else(denied)?;
        let mut context = context;
        context.slot = u16::try_from(slot).map_err(|_| denied())?;
        let context = Arc::new(context);
        let mut contexts = self.contexts.lock().map_err(|_| denied())?;
        if contexts.contains_key(&context.operation) {
            return Err(denied());
        }
        slots[slot] = Some(context.operation.clone());
        contexts.insert(context.operation.clone(), context.clone());
        Ok(Lease {
            broker: self.clone(),
            context,
            succeeded: false,
        })
    }
    async fn audit(
        &self,
        operation: &str,
        output: Option<&str>,
        phase: &'static str,
        generation: u64,
        correlation: AuditCorrelation2,
    ) -> tinybus::Result<RoutineAcknowledgement> {
        if !self.audit.required() || correlation.generation != generation {
            return Err(denied());
        }
        let (durable_subject, policy_ref) =
            self.audit_binding.lock().map_err(|_| denied())?.clone();
        let batch = AuditSinkRequest2 {
            scope: self.audit.scope().clone(),
            stream_id: self.audit.stream_id().into(),
            expected_tail: correlation.expected_tail,
            events: vec![AuditEvent2 {
                sequence: correlation
                    .expected_tail
                    .checked_add(1)
                    .ok_or_else(denied)?,
                event_id: correlation.event_id,
                generation,
                kind: AuditKind2::NativeRoutine,
                attribution: "native-config-cipher".into(),
                arguments_json: serde_json::to_string(&serde_json::json!({
                    "operation": operation, "output": output, "phase": phase,
                    "subject": durable_subject, "policy": policy_ref,
                    "purpose": "config_user_master", "consumer": "fixed-native"
                }))
                .map_err(|_| denied())?,
                rule_ids: vec![],
            }],
        };
        let evidence = self
            .audit
            .append_native_with_registry(batch, self.registry_source.registry())
            .await;
        if !evidence.permitted || !evidence.committed || evidence.health != AuditHealth2::Healthy {
            return Err(denied());
        }
        Ok(RoutineAcknowledgement {
            response: evidence.receipt.ok_or_else(denied)?,
            operation: operation.into(),
            phase,
            generation,
        })
    }
}
struct Lease {
    broker: Arc<Broker>,
    context: Arc<Context>,
    succeeded: bool,
}
impl Lease {
    /// Free the slot of a request refused before any delivery was attempted. The
    /// consumer never saw it, so nothing about it is uncertain.
    fn release_unattempted(&self) {
        if self.context.attempted.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut slots) = self.broker.slots.lock()
            && slots
                .get(usize::from(self.context.slot))
                .and_then(Option::as_ref)
                == Some(&self.context.operation)
        {
            slots[usize::from(self.context.slot)] = None;
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut contexts) = self.broker.contexts.lock() {
            contexts.remove(&self.context.operation);
        }
        // A canceled/failed sender cannot prove receiver quiescence. Keep its
        // physical slot occupied for the process lifetime, including reinit.
        if self.succeeded
            && let Ok(mut slots) = self.broker.slots.lock()
            && slots
                .get(usize::from(self.context.slot))
                .and_then(Option::as_ref)
                == Some(&self.context.operation)
        {
            slots[usize::from(self.context.slot)] = None;
        }
    }
}
impl NativeCipherConsumer for Broker {
    fn deliver<'a>(
        &'a self,
        delivery: &'a CipherDelivery,
    ) -> handles::Verification<'a, DeliveryAcknowledgement> {
        Box::pin(async move {
            let operation = delivery.safe_call_id();
            let context = self
                .contexts
                .lock()
                .map_err(|_| native_denied())?
                .get(&operation)
                .cloned()
                .ok_or_else(native_denied)?;
            self.validate(&context).map_err(|_| native_denied())?;
            if delivery.registration() != self.config.registration_id
                || delivery.subject() != &self.subject
                || delivery.call_id() != context.request.call_id
                || delivery.kind() != kind(context.request.operation)
                || delivery.expires_at_ms() != context.deadline
            {
                return Err(native_denied());
            }
            let identity = SecretCipherDeliveryIdentity2 {
                consumer_id: self.config.consumer_id.clone(),
                registration_id: self.config.registration_id.clone(),
                operation_id: operation.clone(),
                output_id: delivery.safe_output_id(),
                generation: context.generation,
                operation: context.request.operation,
                slot: context.slot,
                expires_at_ms: context.deadline,
            };
            let output = Output(SecretCipherDeliveryRequest2 {
                identity: identity.clone(),
                plaintext: delivery.plaintext().as_bytes().to_vec(),
                replacement: delivery
                    .migration_replacement()
                    .map(|s| s.as_bytes().to_vec()),
            });
            let proxy = self
                .connection
                .proxy(
                    self.peer.as_str(),
                    callback_names2::OBJECT_PATH,
                    callback_names2::SECRET_CIPHER_CONSUMER,
                )
                .map_err(|_| native_denied())?
                .with_timeout(std::time::Duration::from_millis(u64::from(
                    self.config.timeout_ms,
                )));
            context.attempted.store(true, Ordering::SeqCst);
            let response = proxy
                .call_confidential::<SecretCipherDeliveryResponse2>(
                    callback_names2::DELIVER,
                    (&output.0,),
                )
                .await;
            self.validate(&context).map_err(|_| native_denied())?;
            let response = response.map_err(|_| native_denied())?;
            if !response.staged || response.identity != identity {
                return Err(native_denied());
            }
            let audit = self
                .audit(
                    &operation,
                    Some(&identity.output_id),
                    "output-stage",
                    context.generation,
                    context.delivery_audit.clone(),
                )
                .await;
            self.validate(&context).map_err(|_| native_denied())?;
            audit
                .map_err(|_| native_denied())?
                .verify(&operation, "output-stage", context.generation)
                .map_err(|_| native_denied())?;
            *context.staged.lock().map_err(|_| native_denied())? = Some(identity);
            Ok(delivery.acknowledge())
        })
    }
}
pub(super) struct CipherState {
    config: SecretCipherConfig2,
    /// The runtime request this cipher was registered with; `None` for the static one.
    requested: Option<SecretScopeCipher2>,
    owner: CipherOwner,
    broker: Arc<Broker>,
}
impl CipherState {
    #[cfg(test)]
    pub(super) fn audit_policy_ref(&self) -> tinybus::Result<String> {
        Ok(self
            .broker
            .audit_binding
            .lock()
            .map_err(|_| denied())?
            .1
            .clone())
    }
}
pub(super) fn configured(
    config: Option<SecretCipherConfig2>,
    connection: &tinybus::Connection,
    peer: Option<&str>,
    secret: Option<&Arc<SecretState>>,
    engine: Option<&Arc<tinysecurity::approval::Engine>>,
    audit: Option<&Arc<AuditClient>>,
) -> tinybus::Result<Option<Arc<CipherState>>> {
    if let Some(active) = CIPHER.get() {
        return match active {
            Some(active) if config.as_ref().is_none_or(|c| c == &active.config) => {
                Ok(Some(active.clone()))
            }
            None if config.is_none() => Ok(None),
            _ => Err(denied()),
        };
    }
    config
        .map(|config| create(config, connection, peer, secret, engine, audit))
        .transpose()
}
fn valid_config(config: &SecretCipherConfig2) -> bool {
    opaque_id(&config.registration_id)
        && opaque_id(&config.consumer_id)
        && (1..=128).contains(&config.slots)
        && (1..=30000).contains(&config.timeout_ms)
}
/// Everything one cipher is built from, already checked by its caller.
struct Parts<'a> {
    config: SecretCipherConfig2,
    requested: Option<SecretScopeCipher2>,
    connection: &'a tinybus::Connection,
    peer: tinybus::BusName,
    secret: Arc<SecretState>,
    scope: tinysecurity_bus::ApprovalScope2,
    engine: &'a tinysecurity::approval::Engine,
    audit: Arc<AuditClient>,
    registry_source: Arc<AuditClient>,
    slots: Slots,
}
fn build(parts: Parts<'_>) -> tinybus::Result<Arc<CipherState>> {
    let broker = Arc::new(Broker {
        connection: parts.connection.clone(),
        peer: parts.peer,
        config: parts.config.clone(),
        secret: parts.secret.clone(),
        audit: parts.audit,
        registry_source: parts.registry_source,
        subject: parts.scope.subject.clone(),
        audit_binding: Mutex::new((
            parts
                .engine
                .durable_scope(&parts.scope.scope_id)
                .map_err(|_| denied())?,
            parts
                .engine
                .durable_policy_ref(&parts.scope.scope_id)
                .map_err(|_| denied())?,
        )),
        slots: parts.slots,
        contexts: Mutex::new(BTreeMap::new()),
    });
    let owner = CipherOwner::new(
        parts.secret.cipher_registry(),
        CipherConfig {
            consumer: parts.config.consumer_id.clone(),
            enabled: parts.config.enabled,
        },
        broker.clone(),
    )
    .map_err(|_| denied())?;
    Ok(Arc::new(CipherState {
        config: parts.config,
        requested: parts.requested,
        owner,
        broker,
    }))
}
fn unique_peer(peer: Option<&str>) -> tinybus::Result<tinybus::BusName> {
    let peer = peer.ok_or_else(denied)?.parse::<tinybus::BusName>()?;
    if !peer.is_unique() {
        return Err(denied());
    }
    Ok(peer)
}
pub(super) fn create(
    config: SecretCipherConfig2,
    connection: &tinybus::Connection,
    peer: Option<&str>,
    secret: Option<&Arc<SecretState>>,
    engine: Option<&Arc<tinysecurity::approval::Engine>>,
    audit: Option<&Arc<AuditClient>>,
) -> tinybus::Result<Arc<CipherState>> {
    if !valid_config(&config) {
        return Err(denied());
    }
    let secret = secret.ok_or_else(denied)?.clone();
    let scope = secret.cipher_scope(&config.registration_id)?;
    let engine = engine.ok_or_else(denied)?;
    let audit = audit.ok_or_else(denied)?.clone();
    // Init-only: the static cipher audits under the init subject and stream.
    if !audit.required() || audit.scope() != &scope.subject {
        return Err(denied());
    }
    let peer = unique_peer(peer)?;
    let slots = Arc::new(Mutex::new(vec![None; usize::from(config.slots)]));
    build(Parts {
        config,
        requested: None,
        connection,
        peer,
        secret,
        scope,
        engine,
        audit: audit.clone(),
        registry_source: audit,
        slots,
    })
}
/// Inputs of one runtime cipher request, checked before the secret registers.
pub(super) struct RuntimeRequest<'a> {
    pub(super) registration_id: &'a str,
    pub(super) approval_scope_id: &'a str,
    pub(super) cipher: &'a SecretScopeCipher2,
    pub(super) engine: &'a tinysecurity::approval::Engine,
    pub(super) audit: Option<&'a Arc<AuditClient>>,
    pub(super) static_cipher: Option<&'a CipherState>,
}
impl RuntimeRequest<'_> {
    fn config(&self) -> SecretCipherConfig2 {
        SecretCipherConfig2 {
            registration_id: self.registration_id.into(),
            consumer_id: self.cipher.consumer_id.clone(),
            enabled: self.cipher.enabled,
            slots: self.cipher.slots,
            timeout_ms: self.cipher.timeout_ms,
        }
    }
    /// Refuse a request that could not become a working, isolated cipher, before
    /// anything registers: shape, consumer ownership and the one stream per subject.
    pub(super) fn check(&self) -> tinybus::Result<AuditClient> {
        let config = self.config();
        let audit = self.audit.ok_or_else(denied)?;
        if !valid_config(&config)
            || !opaque_id(&self.cipher.audit_stream_id)
            || !audit.required()
            || runtime()
                .lock()
                .map_err(|_| denied())?
                .contains_key(self.registration_id)
        {
            return Err(denied());
        }
        if let Some(fixed) = self.static_cipher
            && (fixed.config.consumer_id == config.consumer_id
                || fixed.config.registration_id == config.registration_id)
        {
            return Err(denied());
        }
        if let Some(bound) = consumers()
            .lock()
            .map_err(|_| denied())?
            .get(&config.consumer_id)
            && (bound.registration != self.registration_id
                || bound.slots.lock().map_err(|_| denied())?.len() != usize::from(config.slots))
        {
            return Err(denied());
        }
        let scope = self
            .engine
            .scope_snapshot(self.approval_scope_id)
            .map_err(|_| denied())?;
        // A runtime approval scope already owns a stream: its cipher must use it.
        // An init scope shares the init stream, which only the init subject may use.
        match self
            .engine
            .scope_audit_stream(self.approval_scope_id)
            .map_err(|_| denied())?
        {
            Some(stream) if stream == self.cipher.audit_stream_id => {}
            None if &scope.subject == audit.scope() => {}
            _ => return Err(denied()),
        }
        audit.for_subject(&scope.subject, &self.cipher.audit_stream_id)
    }
}
/// Create and publish the cipher of one freshly registered runtime secret scope.
pub(super) fn register(
    request: &RuntimeRequest<'_>,
    secret: &Arc<SecretState>,
) -> tinybus::Result<()> {
    let audit = Arc::new(request.check()?);
    let registry_source = request.audit.ok_or_else(denied)?.clone();
    let config = request.config();
    let scope = secret.cipher_scope(request.registration_id)?;
    let peer = unique_peer(Some(secret.peer()))?;
    let mut consumers = consumers().lock().map_err(|_| denied())?;
    let slots = consumers.get(&config.consumer_id).map_or_else(
        || Arc::new(Mutex::new(vec![None; usize::from(config.slots)])),
        |bound| bound.slots.clone(),
    );
    let state = build(Parts {
        config: config.clone(),
        requested: Some(request.cipher.clone()),
        connection: secret.connection(),
        peer,
        secret: secret.clone(),
        scope,
        engine: request.engine,
        audit,
        registry_source,
        slots: slots.clone(),
    })?;
    let mut active = runtime().lock().map_err(|_| denied())?;
    if active.contains_key(request.registration_id) {
        return Err(denied());
    }
    consumers.insert(
        config.consumer_id,
        ConsumerBinding {
            registration: request.registration_id.into(),
            slots,
        },
    );
    active.insert(request.registration_id.into(), state);
    Ok(())
}
/// Whether any runtime cipher is live, so a neutral boot still reports the authority.
pub(super) fn runtime_active() -> bool {
    runtime().lock().is_ok_and(|active| !active.is_empty())
}
/// Whether a repeated registration asks for exactly the cipher it already has.
pub(super) fn matches_runtime(
    registration: &str,
    cipher: Option<&SecretScopeCipher2>,
) -> tinybus::Result<bool> {
    let active = runtime().lock().map_err(|_| denied())?;
    Ok(active
        .get(registration)
        .and_then(|state| state.requested.as_ref())
        == cipher)
}
/// Drop the ciphers and pending work of retired registrations. Their consumers
/// stay bound, so uncertain slots stay occupied for the process lifetime.
pub(super) fn retire(registrations: &[String]) {
    if let Ok(mut active) = runtime().lock() {
        active.retain(|id, _| !registrations.contains(id));
    }
    if let Ok(mut masters) = masters().lock() {
        masters.retain(|_, owner| !registrations.contains(owner));
    }
    if let Ok(mut inventory) = pending().lock() {
        inventory.retain(|_, work| !registrations.contains(&work.request.registration_id));
    }
}

pub(super) fn activate(state: Option<Arc<CipherState>>) -> tinybus::Result<()> {
    if let Some(state) = &state {
        // Reserve the static consumer so no runtime registration can claim it.
        let mut consumers = consumers().lock().map_err(|_| denied())?;
        if consumers.contains_key(&state.config.consumer_id) {
            return Err(denied());
        }
        consumers.insert(
            state.config.consumer_id.clone(),
            ConsumerBinding {
                registration: state.config.registration_id.clone(),
                slots: state.broker.slots.clone(),
            },
        );
    }
    CIPHER.set(state).map_err(|_| denied())
}
pub(super) fn close_pending() {
    if let Ok(mut pending) = pending().lock() {
        pending.clear();
    }
    if let Ok(mut masters) = masters().lock() {
        masters.clear();
    }
    if let Ok(mut active) = runtime().lock() {
        active.clear();
    }
    // Physical uncertainty is deliberately not cleared by close or generation.
}
pub(super) fn refresh_approval_scope(
    scope_id: &str,
    secret: &SecretState,
    engine: &tinysecurity::approval::Engine,
    cipher: Option<&CipherState>,
) -> tinybus::Result<()> {
    let Some(state) = cipher else {
        return Ok(());
    };
    let scope = secret.cipher_scope(&state.config.registration_id)?;
    if scope.scope_id != scope_id {
        return Ok(());
    }
    let binding = (
        engine.durable_scope(scope_id).map_err(|_| denied())?,
        engine.durable_policy_ref(scope_id).map_err(|_| denied())?,
    );
    *state.broker.audit_binding.lock().map_err(|_| denied())? = binding;
    Ok(())
}
type Inventory<'a> = MutexGuard<'a, BTreeMap<String, Pending>>;
pub(super) fn prepare_generation() -> tinybus::Result<Inventory<'static>> {
    pending().lock().map_err(|_| denied())
}
impl PolicyService {
    /// The cipher of `registration`: the static one, or that registration's own.
    fn cipher_for(&self, registration: &str) -> tinybus::Result<Arc<CipherState>> {
        if let Some(state) = &self.secret_cipher
            && state.config.registration_id == registration
        {
            return Ok(state.clone());
        }
        runtime()
            .lock()
            .map_err(|_| denied())?
            .get(registration)
            .cloned()
            .ok_or_else(denied)
    }
    pub(super) async fn cipher_evaluate(
        &self,
        request: EvaluateSecretCipherRequest2,
    ) -> tinybus::Result<SecretCipherPending2> {
        let mut input = Input(request.request);
        let state = self.cipher_for(&input.0.registration_id)?;
        pending()
            .lock()
            .map_err(|_| denied())?
            .retain(|_, pending| pending.state.owner.validate_pending(&pending.work).is_ok());
        let generation = self.read()?.info().generation;
        // The master's fingerprint must be unique among live registrations before
        // any ciphertext is produced or opened under it.
        let fingerprint = state.broker.secret.master_fingerprint(
            &state.owner,
            &input.0.registration_id,
            &input.0.master_handle,
            generation,
        )?;
        check_master(&input.0.registration_id, fingerprint)?;
        let metadata = metadata(&input.0);
        let work = state
            .broker
            .secret
            .prepare_cipher(&state.owner, &mut input.0, generation)?;
        let operation = work.binding().map_err(|_| denied())?.safe_call_id();
        let expires_at_ms = work.binding().map_err(|_| denied())?.expires_at_ms();
        state.owner.validate_pending(&work).map_err(|_| denied())?;
        let intent = state
            .broker
            .audit(&operation, None, "intent", generation, request.audit)
            .await;
        state.owner.validate_pending(&work).map_err(|_| denied())?;
        let intent = intent?;
        intent.verify(&operation, "intent", generation)?;
        let pending_id = tinysecurity::audit::opaque_id().map_err(|_| denied())?;
        let mut inventory = pending().lock().map_err(|_| denied())?;
        inventory.retain(|_, p| p.state.owner.validate_pending(&p.work).is_ok());
        // Acquiring this lock serializes final admission with generation activation.
        state.owner.validate_pending(&work).map_err(|_| denied())?;
        // A retired registration loses its cipher; never admit work for it.
        if !self
            .cipher_for(&metadata.registration_id)
            .is_ok_and(|current| Arc::ptr_eq(&current, &state))
        {
            return Err(denied());
        }
        // Bind only when this request is admitted, so a refused request binds nothing.
        // The binding is atomic with the check, so two registrations cannot both win.
        bind_master(&metadata.registration_id, fingerprint)?;
        if inventory
            .insert(
                pending_id.clone(),
                Pending {
                    state: state.clone(),
                    request: metadata,
                    work,
                    intent,
                },
            )
            .is_some()
        {
            return Err(denied());
        }
        Ok(SecretCipherPending2 {
            pending_id,
            expires_at_ms,
        })
    }
    pub(super) async fn cipher_execute(
        &self,
        request: ExecuteSecretCipherRequest2,
    ) -> tinybus::Result<SecretCipherResponse2> {
        let input = Input(request.request);
        let state = self.cipher_for(&input.0.registration_id)?;
        let generation = self.read()?.info().generation;
        let pending = {
            let mut inventory = pending().lock().map_err(|_| denied())?;
            // Check ownership before removal: another registration's request
            // can neither execute nor discard this pending.
            let owned = inventory.get(&request.pending_id).is_some_and(|pending| {
                Arc::ptr_eq(&pending.state, &state)
                    && pending.request.registration_id == input.0.registration_id
            });
            if !owned {
                return Err(denied());
            }
            inventory.remove(&request.pending_id).ok_or_else(denied)?
        };
        if pending.request != metadata(&input.0) || !pending.work.matches_input(&input.0.input) {
            return Err(denied());
        }
        // The original private pending owns cipher input; wipe this duplicate
        // before retaining admission across any audit or delivery await.
        drop(input);
        state
            .owner
            .validate_pending(&pending.work)
            .map_err(|_| denied())?;
        let binding = pending.work.binding().map_err(|_| denied())?;
        let operation = binding.safe_call_id();
        pending.intent.verify(&operation, "intent", generation)?;
        let mut lease = state.broker.lease(Context {
            request: pending.request,
            operation: operation.clone(),
            generation,
            deadline: binding.expires_at_ms(),
            slot: 0,
            delivery_audit: request.delivery_audit.clone(),
            staged: Mutex::new(None),
            attempted: AtomicBool::new(false),
        })?;
        let execution = state
            .broker
            .audit(&operation, None, "execution", generation, request.audit)
            .await;
        state
            .owner
            .validate_pending(&pending.work)
            .map_err(|_| denied())?;
        execution?.verify(&operation, "execution", generation)?;
        let Ok(completed) = state.owner.execute_guarded(pending.work).await else {
            // Refused before delivery (for example, ciphertext that does not
            // authenticate): the slot is free again. Refused after delivery stays fenced.
            lease.release_unattempted();
            return Err(denied());
        };
        completed.validate().map_err(|_| denied())?;
        let staged = lease.context.staged.lock().map_err(|_| denied())?.clone();
        if staged.is_none() {
            let output = state
                .broker
                .audit(
                    &operation,
                    Some(completed.safe_output_id()),
                    "output-stage",
                    generation,
                    request.delivery_audit,
                )
                .await;
            completed.validate().map_err(|_| denied())?;
            output?.verify(&operation, "output-stage", generation)?;
        }
        let publication = state
            .broker
            .audit(
                &operation,
                Some(completed.safe_output_id()),
                "publication",
                generation,
                request.completion_audit,
            )
            .await;
        completed.validate().map_err(|_| denied())?;
        publication?.verify(&operation, "publication", generation)?;
        state.broker.validate(&lease.context)?;
        let result = match completed.publish().map_err(|_| denied())? {
            CipherResult::Ciphertext(ciphertext) => {
                SecretCipherResponse2::Ciphertext { ciphertext }
            }
            CipherResult::Delivered {
                migrated,
                replacement_ciphertext,
            } => SecretCipherResponse2::Delivered {
                identity: staged.ok_or_else(denied)?,
                migrated,
                replacement_ciphertext,
            },
        };
        lease.succeeded = true;
        Ok(result)
    }
}
