//! Internal typed native retention. Trusted verifier ports supply authority;
//! serialized claims, initialization registrations and receipt shapes do not.
pub use crate::device_handles::Time;
use crate::{
    Error, Result,
    keyring::MasterKey,
    password::PasswordKey,
    work_budget::{BudgetError, RateCounter, WorkBudget},
};
use aws_lc_rs::{constant_time, hmac};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
};
use tinysecurity_bus::{
    ApprovalChoice2, ApprovalLifecycle2, ApprovalRow2, AuditSinkResponse2, SubjectScope,
};
use zeroize::{Zeroize, Zeroizing};

/// Maximum lifetime scope identities retained by one native secret registry.
pub const MAX_NATIVE_SCOPES: usize = 65_536;

/// Native purposes are distinct from device static and ephemeral keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// User configuration encryption.
    ConfigUserMaster,
    /// App encrypted-map storage.
    AppEncryptionMaster,
    /// Caller-owned password encryption.
    PasswordEncryption,
}
/// Exact internal retention operation, never a bus-deserialized authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// Retain an owner-loaded native master after human key authority.
    NativeMasterGrant,
    /// Retain an already-derived caller-owned password key.
    RetainPassword,
    /// Retain exact caller-owned plaintext without returning it.
    RetainPlaintext,
    /// Exact owner-created config cipher work, never external routine receipt authority.
    ConfigCipher,
    /// Exact native App file-store work; requires distinct consumed Human Once consent.
    AppStore,
}
/// Immutable trusted owner registration. No field grants live authority.
#[derive(Clone, PartialEq, Eq)]
pub struct Registration {
    /// Trusted native registration identity.
    pub id: String,
    /// Actual original authenticated subject.
    pub subject: SubjectScope,
    /// Approval engine's already-mapped durable subject.
    pub durable_subject: SubjectScope,
    /// Immutable approval policy reference.
    pub policy_ref: String,
    /// Registered purpose ceiling.
    pub purposes: Vec<Purpose>,
}
/// Finite retention and admission ceilings.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// At most 4096 retained entries.
    pub max_handles: u32,
    /// At most 32 admitted operations; no wait queue.
    pub max_in_flight: u32,
    /// Per-registration rate ceiling, at most 4096 per minute.
    pub operations_per_minute: u32,
    /// At most 300000 milliseconds.
    pub max_ttl_ms: u32,
    /// Per-input logical-length bound, at most one MiB; backing capacity is charged separately.
    pub max_input_bytes: usize,
    /// Aggregate retained backing-capacity bound, at most sixteen MiB.
    pub max_retained_bytes: usize,
    /// Aggregate pending input backing capacity and fixed challenge bytes, at most sixteen MiB.
    pub max_pending_bytes: usize,
    /// Combined pending, retained and generation-key bytes, at most thirty-two MiB.
    pub max_resident_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_handles: 128,
            max_in_flight: 4,
            operations_per_minute: 120,
            max_ttl_ms: 30_000,
            max_input_bytes: 1_048_576,
            max_retained_bytes: 4_194_304,
            max_pending_bytes: 4_194_304,
            max_resident_bytes: 8_388_608,
        }
    }
}
/// Trusted clock port, independent of invocation input.
pub trait NativeClock: Send + Sync {
    /// Obtain both clocks; failure permanently closes authority.
    /// # Errors
    /// Returns a content-free native clock failure.
    fn now(&self) -> Result<Time>;
}
/// Trusted internal request. Transport callers cannot create native provenance.
pub struct Request<'a> {
    /// Immutable registration selected by the authenticated native handler.
    pub registration: &'a str,
    /// Actual captured authenticated peer, never a request's claimed sender.
    pub authenticated_peer: &'a str,
    /// Purpose selected by the registered handler.
    pub purpose: Purpose,
    /// Exact operation selected by that handler.
    pub kind: OperationKind,
    /// Original authenticated call identity.
    pub call_id: &'a str,
    /// Exact memory-only input binding; never hashed publicly or serialized.
    pub input: Zeroizing<Vec<u8>>,
    /// May only shorten the configured lifetime.
    pub ttl_ms: u32,
    /// Captured current generation.
    pub generation: u64,
}
struct ConfidentialBytes(Zeroizing<Vec<u8>>);
impl std::ops::Deref for ConfidentialBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ConfidentialBytes {
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl Drop for ConfidentialBytes {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        tests::observe_wiped(&self.0);
    }
}
struct Scope {
    registration: Registration,
    epoch: u64,
    rate: RateCounter,
    active: bool,
}
struct State {
    scopes: BTreeMap<String, Scope>,
    entries: BTreeMap<[u8; 32], Entry>,
    generation: u64,
    peer: String,
    time: Time,
    closed: bool,
    authorization_key: ConfidentialBytes,
    budget: WorkBudget,
    retained_bytes: usize,
    pending_bytes: usize,
    limits: Limits,
    app_uncertain: bool,
}
enum Material {
    Master(MasterKey),
    Password(PasswordKey),
    Plaintext(ConfidentialBytes),
}
impl Material {
    fn size(&self) -> usize {
        match self {
            Self::Master(key) => key.bytes().len(),
            Self::Password(key) => {
                let _ = std::mem::size_of_val(key);
                32
            }
            Self::Plaintext(bytes) => bytes.capacity(),
        }
    }
}
struct Entry {
    registration: String,
    purpose: Purpose,
    kind: OperationKind,
    generation: u64,
    epoch: u64,
    expires: Time,
    material: Material,
}
/// Registry lifetime owner. Clones cannot revive closed or superseded authority.
#[derive(Clone)]
pub struct Registry {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn NativeClock>,
    physical_gate: Arc<Mutex<()>>,
}
/// Exact private authorization binding. Only safe keyed correlation is public.
pub struct Binding {
    registration: String,
    subject: SubjectScope,
    durable_subject: SubjectScope,
    policy_ref: String,
    peer: String,
    generation: u64,
    epoch: u64,
    purpose: Purpose,
    kind: OperationKind,
    call_id: String,
    expires: Time,
    input: ConfidentialBytes,
    challenge: ConfidentialBytes,
    commitment: [u8; 32],
    cipher: Option<cipher::CipherBinding>,
}
impl Binding {
    /// Owner-sampled absolute wall deadline, for exact durable native approval.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires.wall
    }
    /// Nonreversible keyed correlation for durable safe argument wrappers.
    #[must_use]
    pub fn safe_arguments(&self) -> String {
        format!(
            "{{\"native_authorization_v1\":\"{}\"}}",
            hex(&self.commitment)
        )
    }
    /// Safe execution correlation containing only the keyed commitment.
    #[must_use]
    pub fn safe_call_id(&self) -> String {
        format!("native-{}", hex(&self.commitment))
    }
    /// Captured native registration.
    #[must_use]
    pub fn registration(&self) -> &str {
        &self.registration
    }
    /// Captured original subject, for the trusted verifier port.
    #[must_use]
    pub fn subject(&self) -> &SubjectScope {
        &self.subject
    }
    /// Captured exact native purpose.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Original call correlation, available only to the trusted port.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Private fresh challenge for the actual pending owner to consume once.
    #[must_use]
    pub fn private_challenge(&self) -> &[u8] {
        &self.challenge
    }
}
/// An admitted owner of bounded work; Drop releases capacity without refunding rate.
pub struct Reservation {
    registry: Registry,
    binding: Binding,
    extra_bytes: usize,
}
impl Reservation {
    /// Check the original reservation before returning a cached pending review.
    /// No new challenge, deadline or authority is created.
    /// # Errors
    /// Denies expiry, revocation, generation changes, closed state and clock faults.
    pub fn validate(&self) -> Result<()> {
        self.registry.validate(self)
    }
    /// Borrow the exact original private binding; no new challenge or deadline is minted.
    #[must_use]
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let charged = self
            .binding
            .input
            .capacity()
            .saturating_add(32)
            .saturating_add(self.extra_bytes);
        // Confidential backing allocations must physically disappear before
        // capacity becomes available to another admitted operation.
        let empty = || ConfidentialBytes(Zeroizing::new(Vec::new()));
        drop(std::mem::replace(&mut self.binding.input, empty()));
        drop(std::mem::replace(&mut self.binding.challenge, empty()));
        if let Ok(mut state) = self.registry.state.lock() {
            state.budget.release();
            state.pending_bytes = state.pending_bytes.saturating_sub(charged);
        }
    }
}
struct Echo {
    commitment: [u8; 32],
    challenge: ConfidentialBytes,
}
impl Echo {
    fn new(binding: &Binding) -> Self {
        Self {
            commitment: binding.commitment,
            challenge: ConfidentialBytes(Zeroizing::new(binding.challenge.to_vec())),
        }
    }
    fn verify(&self, binding: &Binding) -> Result<()> {
        constant_time::verify_slices_are_equal(&self.commitment, &binding.commitment)
            .map_err(|_| Error::NativeDenied)?;
        constant_time::verify_slices_are_equal(&self.challenge, &binding.challenge)
            .map_err(|_| Error::NativeDenied)
    }
}
/// Trusted port acknowledgement of COMPLETED durable Human Once consumption.
/// Shape checks alone cannot prove backend provenance. The creator must first
/// finish actual `VerifyHuman`, decision/reservation CAS and required audit.
pub struct HumanGrantReceipt {
    echo: Echo,
    row: ApprovalRow2,
    audit: AuditSinkResponse2,
    expected_audit_scope: SubjectScope,
}
impl HumanGrantReceipt {
    /// Acknowledge a completed exact Engine.consume operation, never a prepared
    /// row or caller-declared decision. Only the trusted engine integrator calls this.
    /// # Errors
    /// Rejects malformed, substituted, reusable, judge or missing audit evidence.
    pub fn from_durable_consumption(
        binding: &Binding,
        row: ApprovalRow2,
        audit: AuditSinkResponse2,
    ) -> Result<Self> {
        Self::from_verified_native_consumption(binding, row, audit, binding.durable_subject.clone())
    }
    /// Bind completed trusted consumption to the actual sanitized audit scope.
    /// The verifier obtains scope independently from the registered subject and
    /// actual verified required-sink acknowledgement, never a caller-selected scope.
    /// # Errors
    /// Rejects mismatched receipts and every ordinary grant mismatch.
    pub fn from_verified_native_consumption(
        binding: &Binding,
        row: ApprovalRow2,
        audit: AuditSinkResponse2,
        expected_audit_scope: SubjectScope,
    ) -> Result<Self> {
        let receipt = Self {
            echo: Echo::new(binding),
            row,
            audit,
            expected_audit_scope,
        };
        receipt.verify(binding)?;
        Ok(receipt)
    }
    fn verify(&self, binding: &Binding) -> Result<()> {
        self.echo.verify(binding)?;
        let row = &self.row;
        if binding.kind != OperationKind::NativeMasterGrant
            || row.state != ApprovalLifecycle2::Reserved
            || row.choice != Some(ApprovalChoice2::Once)
            || row.judge.is_some()
            || row.outcome.is_some()
            || !opaque(&row.request_id, 32)
            || !opaque(&row.nonce, 32)
            || !row.reservation_id.as_deref().is_some_and(|v| opaque(v, 32))
            || !row
                .decision_ticket_sha256
                .as_deref()
                .is_some_and(|v| opaque(v, 64))
            || row.version == 0
            || row.binding.binding_version != 1
            || row.binding.scope != binding.durable_subject
            || row.binding.policy_ref != binding.policy_ref
            || row.binding.generation != binding.generation
            || row.audit.generation != binding.generation
            || row.binding.caller.call_id != binding.safe_call_id()
            || row.tool_name != "native_secret_grant"
            || row.args_redacted != binding.safe_arguments()
            || row.expires_at_ms != binding.expires.wall
            || row.expires_at_ms <= row.created_at_ms
            || !row.attribution.as_deref().is_some_and(text)
            || !opaque(&self.audit.stream_id, 32)
            || self.audit.scope != self.expected_audit_scope
            || self.audit.events.len() != 1
        {
            return Err(Error::NativeDenied);
        }
        let sequence = row
            .audit
            .expected_tail
            .checked_add(1)
            .ok_or(Error::NativeDenied)?;
        if self.audit.events[0].event_id != row.audit.event_id
            || !opaque(&row.audit.event_id, 32)
            || self.audit.events[0].sequence != sequence
            || self.audit.new_tail != sequence
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
}
/// Trusted acknowledgement of actual private pending-operation consumption.
/// This authorizes caller-owned material only, never native key provisioning.
pub struct RoutineReceipt {
    echo: Echo,
    pending: String,
    consumer: String,
}
impl RoutineReceipt {
    /// Called only after the trusted private pending owner has consumed the exact
    /// fresh challenge, authenticated handler call, input and output binding.
    /// Nonempty strings alone are not evidence; the port is a trusted integration.
    /// # Errors
    /// Rejects native-grant operations and malformed owner correlations.
    pub fn from_consumed_pending(binding: &Binding, pending: &str, consumer: &str) -> Result<Self> {
        if matches!(
            binding.kind,
            OperationKind::NativeMasterGrant
                | OperationKind::ConfigCipher
                | OperationKind::AppStore
        ) || !text(pending)
            || !text(consumer)
        {
            return Err(Error::NativeDenied);
        }
        Ok(Self {
            echo: Echo::new(binding),
            pending: pending.into(),
            consumer: consumer.into(),
        })
    }
    fn verify(&self, binding: &Binding) -> Result<()> {
        if matches!(
            binding.kind,
            OperationKind::NativeMasterGrant
                | OperationKind::ConfigCipher
                | OperationKind::AppStore
        ) || !text(&self.pending)
            || !text(&self.consumer)
        {
            return Err(Error::NativeDenied);
        }
        self.echo.verify(binding)
    }
}
/// A bounded trusted verifier future, owned by the caller across cancellation.
pub type Verification<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
/// Trusted implementation-owner port; never implemented from model validity claims.
pub trait HumanGrantVerifier: Send + Sync {
    /// Complete exact durable Human Once consumption, authenticated human verification,
    /// reservation CAS and required audit for this binding before acknowledging.
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, HumanGrantReceipt>;
}
/// Trusted native pending owner port, distinct from a human credential grant.
pub trait NativeRoutineVerifier: Send + Sync {
    /// Consume exact live private operation/challenge authorization once.
    /// Routine acknowledgement cannot mint, read or renew native credential authority.
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt>;
}
/// Unforgeable internal native-grant publication token, consumed by publication.
pub struct HumanGrant(Reservation);
/// Unforgeable internal routine publication token, consumed by publication.
pub struct AuthorizedRoutine(Reservation);
/// Marker for an opaque native master handle.
#[derive(Debug)]
pub struct MasterMaterial;
/// Marker for an opaque caller-owned password handle.
#[derive(Debug)]
pub struct PasswordMaterial;
/// Marker for an opaque retained plaintext handle.
#[derive(Debug)]
pub struct PlaintextMaterial;
/// Opaque process-local capability; has no serialization or material-read API.
pub struct OpaqueHandle<T> {
    bytes: ConfidentialBytes,
    kind: OperationKind,
    marker: PhantomData<T>,
}
/// Native master capability.
pub type MasterHandle = OpaqueHandle<MasterMaterial>;
/// Password capability.
pub type PasswordHandle = OpaqueHandle<PasswordMaterial>;
/// Plaintext capability.
pub type PlaintextHandle = OpaqueHandle<PlaintextMaterial>;
macro_rules! redacted {
    ($($name:ty),+ $(,)?) => { $(impl std::fmt::Debug for $name {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("NativeAuthority([REDACTED])") }
    })+ };
}
redacted!(
    Registry,
    Binding,
    Reservation,
    HumanGrant,
    AuthorizedRoutine,
    HumanGrantReceipt,
    RoutineReceipt,
    Registration,
    Request<'_>
);
impl<T> std::fmt::Debug for OpaqueHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpaqueHandle([REDACTED])")
    }
}
/// Internal bounded native App encrypted-file consumer.
pub mod app_store;
/// Bounded internal config-master cipher consumers.
pub mod cipher;

impl Registry {
    /// Capture trusted immutable registrations and actual SDK peer; no live grant is issued.
    /// # Errors
    /// Rejects invalid descriptors, bounds, clocks and unavailable entropy.
    pub fn new(
        registrations: Vec<Registration>,
        peer: &str,
        generation: u64,
        limits: Limits,
        clock: Arc<dyn NativeClock>,
    ) -> Result<Self> {
        // An empty list is a neutral registry: scopes arrive through `register_scope`.
        if registrations.len() > MAX_NATIVE_SCOPES
            || !peer.starts_with(':')
            || !text(peer)
            || generation == 0
            || !(1..=4096).contains(&limits.max_handles)
            || !(1..=32).contains(&limits.max_in_flight)
            || !(1..=4096).contains(&limits.operations_per_minute)
            || !(1..=300_000).contains(&limits.max_ttl_ms)
            || !(1..=1_048_576).contains(&limits.max_input_bytes)
            || !(1..=16_777_216).contains(&limits.max_retained_bytes)
            || !(32..=16_777_216).contains(&limits.max_pending_bytes)
            || !(64..=33_554_432).contains(&limits.max_resident_bytes)
        {
            return Err(Error::NativeDenied);
        }
        let now = clock.now().map_err(|_| Error::NativeClock)?;
        let mut scopes = BTreeMap::new();
        for registration in registrations {
            if !valid_registration(&registration) || scopes.contains_key(&registration.id) {
                return Err(Error::NativeDenied);
            }
            scopes.insert(
                registration.id.clone(),
                Scope {
                    registration,
                    epoch: 1,
                    rate: RateCounter::new(now.monotonic),
                    active: true,
                },
            );
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                scopes,
                entries: BTreeMap::new(),
                generation,
                peer: peer.into(),
                time: now,
                closed: false,
                authorization_key: random_bytes()?,
                budget: WorkBudget::default(),
                retained_bytes: 0,
                pending_bytes: 0,
                limits,
                app_uncertain: false,
            })),
            clock,
            physical_gate: Arc::new(Mutex::new(())),
        })
    }
    /// Add one immutable trusted subject scope without replacing the live
    /// registry or changing the authority of existing subjects.
    ///
    /// An exact repeat is idempotent. Reusing an identity with different
    /// subject, policy, or purpose data is refused. The host must establish the
    /// corresponding approval scope before registering this native authority.
    ///
    /// # Errors
    /// Rejects invalid or conflicting registrations, a stale expected
    /// generation, closed state, clock failure, and capacity beyond the fixed
    /// fixed scope ceiling.
    pub fn register_scope(&self, registration: Registration, generation: u64) -> Result<()> {
        let (mut state, now) = self.checked_lock()?;
        if state.generation != generation || !valid_registration(&registration) {
            return Err(Error::NativeDenied);
        }
        if let Some(existing) = state.scopes.get(&registration.id) {
            return if existing.active && existing.registration == registration {
                Ok(())
            } else {
                Err(Error::NativeDenied)
            };
        }
        if state.scopes.len() >= MAX_NATIVE_SCOPES {
            return Err(Error::NativeCapacity);
        }
        state.scopes.insert(
            registration.id.clone(),
            Scope {
                registration,
                epoch: 1,
                rate: RateCounter::new(now.monotonic),
                active: true,
            },
        );
        Ok(())
    }
    /// Replace only the policy reference of one live trusted scope.
    /// Subject identities and native purposes are immutable. The epoch changes
    /// before the new policy becomes visible, invalidating reservations and
    /// retained handles created under the prior policy.
    ///
    /// # Errors
    /// Rejects invalid registrations, stale generation, identity changes,
    /// unknown scopes, closed state, clock failure, or epoch exhaustion.
    pub fn replace_scope(&self, registration: &Registration, generation: u64) -> Result<()> {
        let (mut state, now) = self.checked_lock()?;
        if state.generation != generation || !valid_registration(registration) {
            return Err(Error::NativeDenied);
        }
        let scope = state
            .scopes
            .get_mut(&registration.id)
            .ok_or(Error::NativeDenied)?;
        if scope.registration.subject != registration.subject
            || scope.registration.durable_subject != registration.durable_subject
            || scope.registration.purposes != registration.purposes
        {
            return Err(Error::NativeDenied);
        }
        if scope.active && &scope.registration == registration {
            return Ok(());
        }
        let epoch = scope.epoch.checked_add(1).ok_or(Error::NativeDenied)?;
        scope.registration.clone_from(registration);
        scope.epoch = epoch;
        scope.rate = RateCounter::new(now.monotonic);
        scope.active = true;
        state
            .entries
            .retain(|_, entry| entry.registration != registration.id);
        state.recount();
        Ok(())
    }
    fn lock(&self) -> Result<StateGuard<'_>> {
        let gate = self.physical_gate.lock().map_err(|_| Error::NativeDenied)?;
        let state = self.state.lock().map_err(|_| Error::NativeDenied)?;
        Ok(StateGuard { state, _gate: gate })
    }
    fn sample(&self, state: &mut State) -> Result<Time> {
        let Ok(now) = self.clock.now() else {
            state.close();
            return Err(Error::NativeClock);
        };
        state.check(now)?;
        Ok(now)
    }
    fn checked_lock(&self) -> Result<(StateGuard<'_>, Time)> {
        let mut state = self.lock()?;
        let now = self.sample(&mut state)?;
        Ok((state, now))
    }

    /// Reserve bounded exact private input before any callback or native work.
    /// # Errors
    /// Denies substituted peer/purpose, stale generation, rollback, invalid lifetime or exhausted bounds.
    pub fn reserve(&self, request: Request<'_>) -> Result<Reservation> {
        self.reserve_internal(request, None, false, None)
    }
    fn reserve_internal(
        &self,
        mut request: Request<'_>,
        cipher: Option<cipher::CipherBinding>,
        app: bool,
        mut backing: Option<&mut app_store::BackingAdmission>,
    ) -> Result<Reservation> {
        let input = ConfidentialBytes(std::mem::take(&mut request.input));
        let (mut state, now) = self.checked_lock()?;
        let expires = request_deadline(&state, &request, &input, cipher.as_ref(), app, now)?;
        let ordinary_bytes = input
            .capacity()
            .checked_add(32)
            .ok_or(Error::NativeCapacity)?;
        let extra_bytes = if let Some(backing) = &backing {
            if !app || !Arc::ptr_eq(&self.state, &backing.registry.state) {
                return Err(Error::NativeDenied);
            }
            backing
                .bytes
                .checked_sub(ordinary_bytes)
                .ok_or(Error::NativeCapacity)?
        } else {
            0
        };
        let pending = if backing.is_some() {
            state.pending_bytes
        } else {
            state
                .pending_bytes
                .checked_add(ordinary_bytes)
                .ok_or(Error::NativeCapacity)?
        };
        if pending > state.limits.max_pending_bytes
            || pending
                .checked_add(state.retained_bytes)
                .and_then(|v| v.checked_add(32))
                .is_none_or(|v| v > state.limits.max_resident_bytes)
        {
            return Err(Error::NativeCapacity);
        }
        if request.kind == OperationKind::RetainPassword && input.len() > 4112 {
            return Err(Error::Limit);
        }
        let scope = state
            .scopes
            .get(request.registration)
            .ok_or(Error::NativeDenied)?;
        if !scope.active || !scope.registration.purposes.contains(&request.purpose) {
            return Err(Error::NativeDenied);
        }
        let mut binding = Binding {
            registration: request.registration.into(),
            subject: scope.registration.subject.clone(),
            durable_subject: scope.registration.durable_subject.clone(),
            policy_ref: scope.registration.policy_ref.clone(),
            peer: state.peer.clone(),
            generation: state.generation,
            epoch: scope.epoch,
            purpose: request.purpose,
            kind: request.kind,
            call_id: request.call_id.into(),
            expires,
            input,
            challenge: random_bytes()?,
            commitment: [0; 32],
            cipher,
        };
        binding.commitment = commitment(&state.authorization_key, &binding);
        let limits = state.limits;
        let State { scopes, budget, .. } = &mut *state;
        if backing.is_none() {
            budget
                .reserve(
                    &mut scopes
                        .get_mut(request.registration)
                        .ok_or(Error::NativeDenied)?
                        .rate,
                    now.monotonic,
                    limits.max_in_flight,
                    limits.operations_per_minute,
                )
                .map_err(|e| match e {
                    BudgetError::Capacity => Error::NativeCapacity,
                    BudgetError::Rate => Error::NativeRate,
                })?;
        }
        if let Some(backing) = backing.as_mut() {
            backing.active = false;
        }
        state.pending_bytes = pending;
        Ok(Reservation {
            registry: self.clone(),
            binding,
            extra_bytes,
        })
    }
    fn validate(&self, work: &Reservation) -> Result<()> {
        let (state, now) = self.checked_lock()?;
        state.live(self, work, now)
    }
    /// Consume a trusted completed human receipt without holding a lock across its future.
    /// # Errors
    /// Rejects routine operations, malformed or substituted receipts, and post-callback revocation.
    pub async fn authorize_human(
        &self,
        work: Reservation,
        verifier: &dyn HumanGrantVerifier,
    ) -> Result<HumanGrant> {
        self.validate(&work)?;
        if work.binding.kind != OperationKind::NativeMasterGrant {
            return Err(Error::NativeDenied);
        }
        let receipt = verifier.consume(&work.binding).await?;
        receipt.verify(&work.binding)?;
        self.validate(&work)?;
        Ok(HumanGrant(work))
    }
    /// Consume a trusted private pending receipt; this never issues native master authority.
    /// # Errors
    /// Rejects native grants, substituted receipts and post-callback invalidation.
    pub async fn authorize_routine(
        &self,
        work: Reservation,
        verifier: &dyn NativeRoutineVerifier,
    ) -> Result<AuthorizedRoutine> {
        self.validate(&work)?;
        if matches!(
            work.binding.kind,
            OperationKind::NativeMasterGrant
                | OperationKind::ConfigCipher
                | OperationKind::AppStore
        ) {
            return Err(Error::NativeDenied);
        }
        let receipt = verifier.consume(&work.binding).await?;
        receipt.verify(&work.binding)?;
        self.validate(&work)?;
        Ok(AuthorizedRoutine(work))
    }
    /// Check live human authority before each subsequent backend await and publication.
    /// No lock remains held after this call; callers must recheck after every await.
    /// # Errors
    /// Denies wrong registry, expiry, revocation, generation and clock faults.
    pub fn validate_grant(&self, grant: &HumanGrant) -> Result<()> {
        self.validate(&grant.0)
    }
    /// Retain an owner-loaded native master after exact human authority; never reads or mints it here.
    /// # Errors
    /// Denies expired/revoked tokens, wrong operation and exhausted capacity.
    pub fn retain_master(&self, grant: HumanGrant, key: MasterKey) -> Result<MasterHandle> {
        self.insert(
            grant.0,
            Material::Master(key),
            OperationKind::NativeMasterGrant,
        )
    }
    /// Retain an already-derived caller-owned password key; no derivation worker is started.
    /// # Errors
    /// Denies wrong purpose, expired/revoked tokens and exhausted capacity.
    pub fn retain_password(
        &self,
        auth: AuthorizedRoutine,
        key: PasswordKey,
    ) -> Result<PasswordHandle> {
        self.insert(
            auth.0,
            Material::Password(key),
            OperationKind::RetainPassword,
        )
    }
    /// Retain exact bound plaintext without exposing a plaintext-read member.
    /// # Errors
    /// Rejects substituted input, wrong operation and expired/revoked or exhausted authority.
    pub fn retain_plaintext(
        &self,
        auth: AuthorizedRoutine,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<PlaintextHandle> {
        let bytes = ConfidentialBytes(bytes);
        if constant_time::verify_slices_are_equal(&bytes, &auth.0.binding.input).is_err() {
            return Err(Error::NativeDenied);
        }
        self.insert(
            auth.0,
            Material::Plaintext(bytes),
            OperationKind::RetainPlaintext,
        )
    }
    fn insert<T>(
        &self,
        work: Reservation,
        material: Material,
        kind: OperationKind,
    ) -> Result<OpaqueHandle<T>> {
        let (mut state, now) = self.checked_lock()?;
        state.live(self, &work, now)?;
        if work.binding.kind != kind {
            return Err(Error::NativeDenied);
        }
        let size = material.size();
        let retained = state
            .retained_bytes
            .checked_add(size)
            .ok_or(Error::NativeCapacity)?;
        if state.entries.len() >= state.limits.max_handles as usize
            || retained > state.limits.max_retained_bytes
            || retained
                .checked_add(state.pending_bytes)
                .and_then(|v| v.checked_add(32))
                .is_none_or(|v| v > state.limits.max_resident_bytes)
        {
            return Err(Error::NativeCapacity);
        }
        let bytes = random_bytes()?;
        let identity = handle_identity(&state.authorization_key, &bytes);
        if state.entries.contains_key(&identity) {
            return Err(Error::NativeDenied);
        }
        state.entries.insert(
            identity,
            Entry {
                registration: work.binding.registration.clone(),
                purpose: work.binding.purpose,
                kind,
                generation: work.binding.generation,
                epoch: work.binding.epoch,
                expires: work.binding.expires,
                material,
            },
        );
        state.retained_bytes = retained;
        let handle = OpaqueHandle {
            bytes,
            kind,
            marker: PhantomData,
        };
        drop(state);
        drop(work);
        Ok(handle)
    }
    /// Validate opaque capability identity only; never returns or borrows retained material.
    /// # Errors
    /// Rejects wrong registry/peer/subject/purpose, expiry, rollback and stale generation.
    pub fn validate_handle<T>(
        &self,
        handle: &OpaqueHandle<T>,
        registration: &str,
        purpose: Purpose,
        authenticated_peer: &str,
        generation: u64,
    ) -> Result<()> {
        let (state, _) = self.checked_lock()?;
        let identity = handle_identity(&state.authorization_key, &handle.bytes);
        let entry = state.entries.get(&identity).ok_or(Error::NativeDenied)?;
        if authenticated_peer != state.peer
            || generation != state.generation
            || entry.generation != generation
            || entry.registration != registration
            || entry.purpose != purpose
            || entry.kind != handle.kind
            || state
                .scopes
                .get(registration)
                .is_none_or(|scope| !scope.active || scope.epoch != entry.epoch)
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    /// Revoke all subject entries and fence admitted work, without altering another subject.
    /// # Errors
    /// Rejects unknown/closed registrations and epoch exhaustion.
    pub fn revoke_scope(&self, registration: &str) -> Result<()> {
        let (mut state, _) = self.checked_lock()?;
        let scope = state
            .scopes
            .get_mut(registration)
            .ok_or(Error::NativeDenied)?;
        if !scope.active {
            return Err(Error::NativeDenied);
        }
        scope.epoch = scope.epoch.checked_add(1).ok_or(Error::NativeDenied)?;
        scope.active = false;
        state
            .entries
            .retain(|_, entry| entry.registration != registration);
        state.recount();
        Ok(())
    }
    /// Prepare a generation rotation while excluding concurrent authority changes.
    /// Clock faults retain their permanent close behavior; valid preparations dropped
    /// before publication preserve the current generation and private entries.
    /// # Errors
    /// Rejects stale generation, closed state, clock or entropy failure.
    pub fn prepare_generation(&self, generation: u64) -> Result<PreparedGeneration<'_>> {
        let (state, _) = self.checked_lock()?;
        if generation <= state.generation {
            return Err(Error::NativeDenied);
        }
        let key = random_bytes()?;
        Ok(PreparedGeneration {
            state,
            generation,
            key,
        })
    }
    /// Advance generation, rotate its private authorization key and wipe retained entries.
    /// # Errors
    /// Rejects non-increasing generation, closed state, clock or entropy failure.
    pub fn advance_generation(&self, generation: u64) -> Result<()> {
        self.prepare_generation(generation)?.commit();
        Ok(())
    }
    /// Permanently close even when another owner retains this registry or a pending future.
    pub fn close(&self) {
        let _gate = match self.physical_gate.lock() {
            Ok(gate) => gate,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.close();
    }
}
// State checks can expire or permanently close authority. They share the
// physical phase gate even when called from ordinary handle validation.
struct StateGuard<'a> {
    state: MutexGuard<'a, State>,
    _gate: MutexGuard<'a, ()>,
}
impl std::ops::Deref for StateGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.state
    }
}
impl std::ops::DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.state
    }
}
/// A locked generation rotation whose final activation cannot fail.
pub struct PreparedGeneration<'a> {
    state: StateGuard<'a>,
    generation: u64,
    key: ConfidentialBytes,
}
impl std::fmt::Debug for PreparedGeneration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedGeneration([REDACTED])")
    }
}
impl PreparedGeneration<'_> {
    /// Rotate authority and release the native lock before old reservations are dropped.
    pub fn commit(mut self) {
        self.state.entries.clear();
        self.state.retained_bytes = 0;
        self.state.authorization_key = self.key;
        self.state.generation = self.generation;
    }
}
impl State {
    fn close(&mut self) {
        self.closed = true;
        self.entries.clear();
        self.retained_bytes = 0;
        self.authorization_key.as_mut_slice().zeroize();
    }
    fn check(&mut self, now: Time) -> Result<()> {
        if now.wall < self.time.wall || now.monotonic < self.time.monotonic {
            self.close();
            return Err(Error::NativeClock);
        }
        self.time = now;
        if self.closed {
            return Err(Error::NativeDenied);
        }
        self.entries.retain(|_, entry| {
            now.wall < entry.expires.wall && now.monotonic < entry.expires.monotonic
        });
        self.recount();
        Ok(())
    }
    fn recount(&mut self) {
        self.retained_bytes = self
            .entries
            .values()
            .map(|entry| entry.material.size())
            .sum();
    }
    fn live(&self, registry: &Registry, work: &Reservation, now: Time) -> Result<()> {
        if !Arc::ptr_eq(&registry.state, &work.registry.state)
            || work.binding.generation != self.generation
            || now.wall >= work.binding.expires.wall
            || now.monotonic >= work.binding.expires.monotonic
            || self
                .scopes
                .get(&work.binding.registration)
                .is_none_or(|scope| scope.epoch != work.binding.epoch)
            || constant_time::verify_slices_are_equal(
                &commitment(&self.authorization_key, &work.binding),
                &work.binding.commitment,
            )
            .is_err()
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
}
fn request_deadline(
    state: &State,
    request: &Request<'_>,
    input: &ConfidentialBytes,
    cipher: Option<&cipher::CipherBinding>,
    app: bool,
    now: Time,
) -> Result<Time> {
    if request.authenticated_peer != state.peer
        || request.generation != state.generation
        || !text(request.call_id)
        || request.ttl_ms == 0
        || request.ttl_ms > state.limits.max_ttl_ms
        || input.len()
            > cipher.map_or(state.limits.max_input_bytes, |binding| {
                binding.input_limit(state.limits.max_input_bytes, input)
            })
        || (request.kind == OperationKind::AppStore) != app
        || (app && request.purpose != Purpose::AppEncryptionMaster)
        || (request.kind == OperationKind::ConfigCipher) != cipher.is_some()
        || (request.kind == OperationKind::NativeMasterGrant
            && request.purpose == Purpose::PasswordEncryption)
        || (request.kind == OperationKind::RetainPassword
            && request.purpose != Purpose::PasswordEncryption)
    {
        return Err(Error::NativeDenied);
    }
    let mut expires = Time {
        wall: now
            .wall
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(Error::NativeDenied)?,
        monotonic: now
            .monotonic
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(Error::NativeDenied)?,
    };
    if let Some(cipher) = cipher {
        cipher.cap_deadline(&mut expires, now)?;
    }
    Ok(expires)
}
fn random_bytes() -> Result<ConfidentialBytes> {
    let mut bytes = Zeroizing::new(vec![0; 32]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|_| Error::Entropy)?;
    Ok(ConfidentialBytes(bytes))
}
fn field(context: &mut hmac::Context, bytes: &[u8]) {
    context.update(&(bytes.len() as u64).to_be_bytes());
    context.update(bytes);
}
fn commitment(key: &[u8], binding: &Binding) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut context = hmac::Context::with_key(&key);
    context.update(b"tinysecurity/native-authorization/v1\0");
    for bytes in [
        binding.registration.as_bytes(),
        binding.peer.as_bytes(),
        binding.subject.user.as_bytes(),
        binding.subject.workspace.as_bytes(),
        binding.subject.agent.as_bytes(),
        binding.durable_subject.user.as_bytes(),
        binding.durable_subject.workspace.as_bytes(),
        binding.durable_subject.agent.as_bytes(),
        binding.policy_ref.as_bytes(),
        binding.call_id.as_bytes(),
        &binding.challenge,
        &binding.input,
    ] {
        field(&mut context, bytes);
    }
    for number in [
        binding.generation,
        binding.epoch,
        binding.purpose as u64,
        binding.kind as u64,
        binding.expires.wall,
        binding.expires.monotonic,
    ] {
        context.update(&number.to_be_bytes());
    }
    if let Some(cipher) = &binding.cipher {
        context.update(b"tinysecurity/config-cipher/v1\0");
        cipher.commit(&mut context);
    }
    let tag = context.sign();
    let mut result = [0; 32];
    result.copy_from_slice(tag.as_ref());
    result
}
fn handle_identity(key: &[u8], bytes: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut context = hmac::Context::with_key(&key);
    context.update(b"tinysecurity/native-handle/v1\0");
    field(&mut context, bytes);
    let tag = context.sign();
    let mut result = [0; 32];
    result.copy_from_slice(tag.as_ref());
    result
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn valid_registration(registration: &Registration) -> bool {
    text(&registration.id)
        && text(&registration.policy_ref)
        && !registration.purposes.is_empty()
        && registration.purposes.len() <= 3
        && registration.purposes.iter().collect::<BTreeSet<_>>().len()
            == registration.purposes.len()
        && [&registration.subject, &registration.durable_subject]
            .iter()
            .all(|subject| {
                [&subject.user, &subject.workspace, &subject.agent]
                    .iter()
                    .all(|v| text(v))
            })
}
fn opaque(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
#[cfg(test)]
#[path = "native_handles_tests.rs"]
mod tests;
