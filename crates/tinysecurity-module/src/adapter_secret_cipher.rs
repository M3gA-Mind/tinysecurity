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
    owner: CipherOwner,
    broker: Arc<Broker>,
    pending: Mutex<BTreeMap<String, Pending>>,
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
pub(super) fn create(
    config: SecretCipherConfig2,
    connection: &tinybus::Connection,
    peer: Option<&str>,
    secret: Option<&Arc<SecretState>>,
    engine: Option<&Arc<tinysecurity::approval::Engine>>,
    audit: Option<&Arc<AuditClient>>,
) -> tinybus::Result<Arc<CipherState>> {
    if !opaque_id(&config.registration_id)
        || !opaque_id(&config.consumer_id)
        || !(1..=128).contains(&config.slots)
        || !(1..=30000).contains(&config.timeout_ms)
    {
        return Err(denied());
    }
    let secret = secret.ok_or_else(denied)?.clone();
    let scope = secret.cipher_scope(&config.registration_id)?;
    let engine = engine.ok_or_else(denied)?;
    let audit = audit.ok_or_else(denied)?.clone();
    if !audit.required() || audit.scope() != &scope.subject {
        return Err(denied());
    }
    let peer = peer.ok_or_else(denied)?.parse::<tinybus::BusName>()?;
    if !peer.is_unique() {
        return Err(denied());
    }
    let broker = Arc::new(Broker {
        connection: connection.clone(),
        peer,
        config: config.clone(),
        secret: secret.clone(),
        audit,
        subject: scope.subject.clone(),
        audit_binding: Mutex::new((
            engine
                .durable_scope(&scope.scope_id)
                .map_err(|_| denied())?,
            engine
                .durable_policy_ref(&scope.scope_id)
                .map_err(|_| denied())?,
        )),
        slots: Mutex::new(vec![None; usize::from(config.slots)]),
        contexts: Mutex::new(BTreeMap::new()),
    });
    let owner = CipherOwner::new(
        secret.cipher_registry(),
        CipherConfig {
            consumer: config.consumer_id.clone(),
            enabled: config.enabled,
        },
        broker.clone(),
    )
    .map_err(|_| denied())?;
    Ok(Arc::new(CipherState {
        config,
        owner,
        broker,
        pending: Mutex::new(BTreeMap::new()),
    }))
}

pub(super) fn activate(state: Option<Arc<CipherState>>) -> tinybus::Result<()> {
    CIPHER.set(state).map_err(|_| denied())
}
pub(super) fn close_pending() {
    if let Some(Some(state)) = CIPHER.get()
        && let Ok(mut pending) = state.pending.lock()
    {
        pending.clear();
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
pub(super) fn prepare_generation() -> tinybus::Result<Option<Inventory<'static>>> {
    CIPHER
        .get()
        .and_then(Option::as_ref)
        .map(|state| state.pending.lock().map_err(|_| denied()))
        .transpose()
}
impl PolicyService {
    pub(super) async fn cipher_evaluate(
        &self,
        request: EvaluateSecretCipherRequest2,
    ) -> tinybus::Result<SecretCipherPending2> {
        let mut input = Input(request.request);
        let state = self.secret_cipher.as_ref().ok_or_else(denied)?;
        state
            .pending
            .lock()
            .map_err(|_| denied())?
            .retain(|_, pending| state.owner.validate_pending(&pending.work).is_ok());
        if input.0.registration_id != state.config.registration_id {
            return Err(denied());
        }
        let generation = self.read()?.info().generation;
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
        let mut inventory = state.pending.lock().map_err(|_| denied())?;
        inventory.retain(|_, p| state.owner.validate_pending(&p.work).is_ok());
        // Acquiring this lock serializes final admission with generation activation.
        state.owner.validate_pending(&work).map_err(|_| denied())?;
        if inventory
            .insert(
                pending_id.clone(),
                Pending {
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
        let state = self.secret_cipher.as_ref().ok_or_else(denied)?;
        let generation = self.read()?.info().generation;
        let pending = state
            .pending
            .lock()
            .map_err(|_| denied())?
            .remove(&request.pending_id)
            .ok_or_else(denied)?;
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
        let completed = state
            .owner
            .execute_guarded(pending.work)
            .await
            .map_err(|_| denied())?;
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
