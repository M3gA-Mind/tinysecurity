//! Callback-driven state transitions without locks held across external awaits.
use crate::binding;
use crate::{Error, Result};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicU64, Ordering},
};
use tinysecurity_bus::{
    ApprovalActionRequest2, ApprovalCasRequest2, ApprovalCasResponse2, ApprovalChoice2,
    ApprovalConfig2, ApprovalDeliveryRequest2, ApprovalDeliveryResponse2, ApprovalGrants2,
    ApprovalHistoryImport2, ApprovalLifecycle2, ApprovalLoadRequest2, ApprovalLoadResponse2,
    ApprovalPurgeSessionRequest2, ApprovalRecordRequest2, ApprovalRow2, ApprovalScope2,
    ApprovalScopeOutcome2, ApprovalScopeReceipt2, AuditCorrelation2, CallerContext, Check,
    DecideRequest2, EvaluateApprovalRequest2, EvaluateRequest, HUMAN_ONLY_TOOLS2,
    HumanDecisionReceipt2, MAX_APPROVAL_SCOPES2, Origin, PreauthorizeFlowRequest2,
    RecordExecutionRequest2, RedactMode, RegisterApprovalScopeRequest2,
    RetireApprovalScopeRequest2, SubjectScope, ToolCall, VerifyHumanRequest2,
};
use tinysecurity_redact::Redactor;
/// Trusted acknowledgement binding an exact row to the untouched actual sink receipt.
/// The adapter captures and validates sanitized scope through the audit owner.
#[derive(Clone)]
pub struct NativeAuditAcknowledgement {
    row: ApprovalRow2,
    expected_scope: SubjectScope,
    receipt: tinysecurity_bus::AuditSinkResponse2,
}
impl std::fmt::Debug for NativeAuditAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeAuditAcknowledgement([REDACTED])")
    }
}
impl NativeAuditAcknowledgement {
    /// Acknowledge actual required persistence through a trusted port.
    /// The creator validates authenticated sink, captured stream and original subject.
    /// # Errors
    /// Rejects mismatched fields without rewriting the receipt.
    pub fn from_verified_sink(
        row: ApprovalRow2,
        expected_scope: SubjectScope,
        receipt: tinysecurity_bus::AuditSinkResponse2,
    ) -> Result<Self> {
        let tail = row
            .audit
            .expected_tail
            .checked_add(1)
            .ok_or(Error::Invalid)?;
        if receipt.scope != expected_scope
            || !binding::hex(&receipt.stream_id, 32)
            || receipt.new_tail != tail
            || receipt.events.len() != 1
            || receipt.events[0].sequence != tail
            || receipt.events[0].event_id != row.audit.event_id
        {
            return Err(Error::Denied);
        }
        Ok(Self {
            row,
            expected_scope,
            receipt,
        })
    }
    /// Captured sanitized audit scope, distinct from the approval subject digest.
    #[must_use]
    pub fn expected_scope(&self) -> &SubjectScope {
        &self.expected_scope
    }
    /// Return the actual sink response unchanged; never manufactures durability.
    #[must_use]
    pub fn into_receipt(self) -> tinysecurity_bus::AuditSinkResponse2 {
        self.receipt
    }
}
/// Move-only App I/O consumption proof, never reconstructed from serialized rows.
/// This proves exact native Human Once consent and required audit acknowledgement.
/// It does not prove that a file or master is currently live: the trusted crypto
/// owner must verify its independently keyed operation/material/resource binding.
/// No public constructor, serialization or clone can recreate this authority.
pub struct NativeAppIoGrant {
    scope_id: String,
    original: EvaluateRequest,
    acknowledgement: NativeAuditAcknowledgement,
}
impl std::fmt::Debug for NativeAppIoGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeAppIoGrant([REDACTED])")
    }
}
impl NativeAppIoGrant {
    /// Verify and consume against the trusted owner's independently computed wrapper.
    /// The owner must also check live master epoch, resource, cancellation and both
    /// clocks; supplying this proof's old fields does not establish current authority.
    /// Returns the immutable consumed row and the actual sink acknowledgement unchanged.
    /// # Errors
    /// Denies changed scope, original action/context/commitment, generation or deadline.
    pub fn into_verified_consumption(
        self,
        scope_id: &str,
        request: &EvaluateRequest,
        generation: u64,
        expires_at_ms: u64,
    ) -> Result<(ApprovalRow2, NativeAuditAcknowledgement)> {
        let row = &self.acknowledgement.row;
        if self.scope_id != scope_id
            || &self.original != request
            || row.binding.generation != generation
            || row.expires_at_ms != expires_at_ms
        {
            return Err(Error::Denied);
        }
        Ok((row.clone(), self.acknowledgement))
    }
}
/// Trusted authenticated host storage, prompt and audit ports.
#[async_trait::async_trait]
pub trait Ports: Send + Sync + std::fmt::Debug {
    /// Load the exact captured durable subject.
    /// # Errors
    /// Fails closed on unavailable, malformed or unrelated responses.
    async fn load(&self, request: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2>;
    /// Durable CAS with idempotent mutation receipt ledger, even after later versions.
    /// # Errors
    /// Timeout is indeterminate; conflicting mutation reuse must reject.
    async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2>;
    /// Remove undecided rows for one exact session in one exact subject.
    /// # Errors
    /// Rejects an unavailable store or a response that does not echo the request.
    async fn purge_session(
        &self,
        _request: ApprovalPurgeSessionRequest2,
    ) -> Result<tinysecurity_bus::ApprovalPurgeSessionResponse2> {
        Err(Error::Denied)
    }
    /// Deliver a verified per-user prompt; never a decision.
    /// # Errors
    /// Rejects unavailable or unverified human channels.
    async fn prompt(&self, request: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2>;
    /// Verify exact ticket using a private authenticated-human host ledger.
    /// # Errors
    /// Rejects ticketless, forged, wrong-owner or mismatched review authority.
    async fn human(&self, request: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2>;
    /// Confirm the whole exact sanitized audit phase.
    /// # Errors
    /// Rejects failed or unrelated persistence receipts.
    async fn audit(&self, row: ApprovalRow2) -> Result<()>;
    /// Return the actual verified required-sink receipt for this exact durable phase.
    /// Implementations must validate authenticated sink, scope, stream, event and tail.
    /// The default denies native authority; a successful generic audit is insufficient.
    /// # Errors
    /// Rejects absent, uncommitted or unrelated receipts.
    async fn native_audit(&self, _row: ApprovalRow2) -> Result<NativeAuditAcknowledgement> {
        Err(Error::Denied)
    }
    /// Admit a runtime subject to the store and audit ports before it becomes usable.
    /// The default refuses, so a port that cannot serve a new subject fails closed.
    /// # Errors
    /// Rejects subjects the ports cannot serve with an authenticated, bounded stream.
    async fn admit_scope(&self, _scope: &ApprovalScope2, _audit_stream_id: &str) -> Result<()> {
        Err(Error::Denied)
    }
    /// Forget a retired subject. The default has nothing to forget.
    /// # Errors
    /// Fails closed when the ports cannot release the subject.
    async fn release_scope(&self, _scope: &ApprovalScope2) -> Result<()> {
        Ok(())
    }
}
/// Epoch and monotonic clocks injected together for deterministic expiration.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Epoch milliseconds; None is a failed wall clock.
    fn wall_ms(&self) -> Option<u64>;
    /// Monotonic milliseconds from the clock's creation.
    fn monotonic_ms(&self) -> u64;
}
/// Process-local clock with a durable epoch and monotonic elapsed time.
#[derive(Debug)]
pub struct SystemClock(std::time::Instant);
impl Default for SystemClock {
    fn default() -> Self {
        Self(std::time::Instant::now())
    }
}
impl Clock for SystemClock {
    fn wall_ms(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    }
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}
/// Live registrations by identity, with a subject index so admission stays linear.
#[derive(Default)]
struct ScopeTable {
    by_id: std::collections::BTreeMap<String, Arc<ScopeEntry>>,
    subjects: std::collections::BTreeSet<(String, String, String)>,
}
impl ScopeTable {
    fn key(scope: &ApprovalScope2) -> (String, String, String) {
        let subject = &scope.subject;
        (
            subject.user.clone(),
            subject.workspace.clone(),
            subject.agent.clone(),
        )
    }
    fn holds_subject(&self, scope: &ApprovalScope2) -> bool {
        self.subjects.contains(&Self::key(scope))
    }
    fn insert(&mut self, entry: ScopeEntry) -> bool {
        let key = Self::key(&entry.scope);
        let fresh = self.subjects.insert(key);
        self.by_id
            .insert(entry.scope.scope_id.clone(), Arc::new(entry));
        fresh
    }
    /// Put back an entry removed by a retirement the ports could not complete.
    fn reinstate(&mut self, entry: Arc<ScopeEntry>) {
        self.subjects.insert(Self::key(&entry.scope));
        self.by_id.insert(entry.scope.scope_id.clone(), entry);
    }
    fn remove(&mut self, id: &str) -> Option<Arc<ScopeEntry>> {
        let removed = self.by_id.remove(id)?;
        self.subjects.remove(&Self::key(&removed.scope));
        Some(removed)
    }
}
/// One live registration with its host-configured automatic approvals.
struct ScopeEntry {
    scope: ApprovalScope2,
    tools: std::collections::BTreeSet<String>,
    flows: std::collections::BTreeSet<(String, String)>,
    /// Runtime scopes own an audit stream; init scopes share the base stream.
    audit_stream_id: Option<String>,
}
impl ScopeEntry {
    fn init(scope: ApprovalScope2) -> Self {
        Self {
            scope,
            tools: std::collections::BTreeSet::new(),
            flows: std::collections::BTreeSet::new(),
            audit_stream_id: None,
        }
    }
    fn runtime(request: RegisterApprovalScopeRequest2) -> Self {
        let ApprovalGrants2 { tools, flows } = request.grants;
        Self {
            scope: request.scope,
            tools: tools.into_iter().collect(),
            flows: flows.into_iter().map(|g| (g.flow_id, g.tool)).collect(),
            audit_stream_id: Some(request.audit_stream_id),
        }
    }
    /// Host-configured grants only convert a required approval; denials and
    /// automatic scopes were decided before, and reviewed reuse never reaches here.
    /// An unlabelled origin is approved by a whole-tool grant alone. `durable_flow`
    /// says a live durable flow-trust row covers this exact tool and flow.
    fn grant_for(
        &self,
        request: &EvaluateApprovalRequest2,
        rule: tinysecurity_auto::rules::Rule,
        durable_flow: bool,
        durable_tool: bool,
    ) -> Option<&'static str> {
        if self.scope.require_approval && !durable_tool && !durable_flow {
            return None;
        }
        match rule {
            tinysecurity_auto::rules::Rule::Approval => self
                .grant(
                    &request.request.call.tool,
                    request.request.caller.flow.as_deref(),
                )
                .or_else(|| durable_tool.then_some("auto:tool-grant"))
                .or_else(|| durable_flow.then_some("auto:flow-grant")),
            tinysecurity_auto::rules::Rule::GrantOnly => self
                .tool_grant(&request.request.call.tool)
                .or_else(|| durable_tool.then_some("auto:tool-grant")),
            _ => None,
        }
    }
    /// Whole-tool grant of the scope; human-only and native tools never match.
    fn tool_grant(&self, tool: &str) -> Option<&'static str> {
        (!HUMAN_ONLY_TOOLS2.contains(&tool)
            && !binding::is_native(tool)
            && self.tools.contains(tool))
        .then_some("auto:tool-grant")
    }
    /// Which host-configured grant, if any, approves this exact tool and flow.
    /// Human-only tools never match, even if a grant names them.
    fn grant(&self, tool: &str, flow: Option<&str>) -> Option<&'static str> {
        if HUMAN_ONLY_TOOLS2.contains(&tool) || binding::is_native(tool) {
            return None;
        }
        if self.tools.contains(tool) {
            return Some("auto:tool-grant");
        }
        flow.filter(|flow| self.flows.contains(&((*flow).to_owned(), tool.to_owned())))
            .map(|_| "auto:flow-grant")
    }
    /// Equal registration apart from the generation, which the engine owns.
    fn same_posture(&self, other: &Self) -> bool {
        let mut scope = other.scope.clone();
        scope.generation = self.scope.generation;
        self.scope == scope && self.tools == other.tools && self.flows == other.flows
    }
}
struct NativeIntent {
    original: ApprovalRow2,
    decision: Option<ApprovalRow2>,
    consumed: Option<ApprovalRow2>,
}
/// Immutable subject engine. Host-instance ownership prevents orphan execution.
pub struct Engine {
    scopes: RwLock<ScopeTable>,
    /// Held across the ports' awaits so registration and retirement of subjects
    /// never interleave; replacement is atomic under the table lock alone.
    lifecycle: tokio::sync::Mutex<()>,
    /// Serializes flow-trust grants and revocations so one pair has one live row.
    flow_trust_lock: tokio::sync::Mutex<()>,
    /// Serializes whole-tool trust grants and revocations so one tool has one live row.
    tool_trust_lock: tokio::sync::Mutex<()>,
    ports: Arc<dyn Ports>,
    clock: Arc<dyn Clock>,
    redactor: RwLock<Redactor>,
    automatic: RwLock<Option<Arc<tinysecurity_auto::Engine>>>,
    previous_automatic: RwLock<Option<Arc<tinysecurity_auto::Engine>>>,
    instance: String,
    generation: AtomicU64,
    time: Mutex<(u64, u64, u64, bool)>,
    creations: Mutex<std::collections::BTreeMap<String, ApprovalRow2>>,
    // Only this trusted engine instance can establish native-row provenance.
    // No serialized label or approval-row snapshot reconstructs it after restart.
    native_intents: Mutex<std::collections::BTreeMap<String, NativeIntent>>,
}
impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Engine([REDACTED])")
    }
}
impl Engine {
    /// Capture trusted setup; invalid scopes and timeouts never become capabilities.
    /// # Errors
    /// Rejects unavailable entropy, invalid or duplicate registrations.
    pub fn new(
        config: ApprovalConfig2,
        ports: Arc<dyn Ports>,
        clock: Arc<dyn Clock>,
        redactor: Redactor,
    ) -> Result<Self> {
        if !(1..=30000).contains(&config.timeout_ms)
            || config.scopes.is_empty()
            || config.scopes.len() > 128
        {
            return Err(Error::Invalid);
        }
        let generation = config.scopes[0].generation;
        if config.scopes.iter().any(|s| s.generation != generation) {
            return Err(Error::Invalid);
        }
        let mut entries = ScopeTable::default();
        for scope in config.scopes {
            Self::validate_scope(&scope)?;
            // One identity and one subject per registration: the audit and store
            // ports key by subject, and retiring one scope must not orphan another.
            if entries.by_id.contains_key(&scope.scope_id) || entries.holds_subject(&scope) {
                return Err(Error::Invalid);
            }
            entries.insert(ScopeEntry::init(scope));
        }
        let wall = clock.wall_ms().ok_or(Error::Unavailable)?;
        let time = (wall, clock.monotonic_ms(), wall, false);
        Ok(Self {
            scopes: RwLock::new(entries),
            lifecycle: tokio::sync::Mutex::new(()),
            flow_trust_lock: tokio::sync::Mutex::new(()),
            tool_trust_lock: tokio::sync::Mutex::new(()),
            ports,
            clock,
            redactor: RwLock::new(redactor),
            automatic: RwLock::new(None),
            previous_automatic: RwLock::new(None),
            instance: binding::opaque()?,
            generation: AtomicU64::new(generation),
            time: Mutex::new(time),
            creations: Mutex::new(std::collections::BTreeMap::new()),
            native_intents: Mutex::new(std::collections::BTreeMap::new()),
        })
    }
    /// Replace the fully validated native scorer through trusted SDK setup only.
    /// No invocation can create or replace this capability.
    /// # Errors
    /// Fails closed when the internal configuration lock is poisoned.
    pub fn replace_automatic(&self, engine: Option<Arc<tinysecurity_auto::Engine>>) -> Result<()> {
        let mut active = self.automatic.write().map_err(|_| Error::Unavailable)?;
        let mut previous = self
            .previous_automatic
            .write()
            .map_err(|_| Error::Unavailable)?;
        if engine.is_some() {
            previous.clone_from(&engine);
        }
        *active = engine;
        Ok(())
    }
    /// Clone the active scorer without retaining a lock across an await.
    /// # Errors
    /// Fails closed when the internal configuration lock is poisoned.
    pub fn automatic(&self) -> Result<Option<Arc<tinysecurity_auto::Engine>>> {
        self.automatic
            .read()
            .map(|engine| engine.clone())
            .map_err(|_| Error::Unavailable)
    }
    /// Retain the shared reservation ledger while a scorer is temporarily disabled.
    /// # Errors
    /// Fails closed when the internal history lock is poisoned.
    pub fn previous_automatic(&self) -> Result<Option<Arc<tinysecurity_auto::Engine>>> {
        self.previous_automatic
            .read()
            .map(|engine| engine.clone())
            .map_err(|_| Error::Unavailable)
    }
    /// Persist a real pending request before prompting or returning its identity.
    /// # Errors
    /// Rejects mismatches, unavailable callbacks and expired clocks.
    pub async fn begin(&self, request: EvaluateApprovalRequest2) -> Result<ApprovalRow2> {
        if binding::is_native(&request.request.call.tool) {
            return Err(Error::Denied);
        }
        self.begin_inner(request, None).await
    }
    /// Begin exact native master authority through a trusted owner handler only.
    /// The request must contain only the registry keyed safe wrapper and fixed tool.
    /// `expires_at_ms` is the original reservation deadline, never a refreshed TTL.
    /// Resume is limited to this live Engine instance; restart/reinit loses provenance.
    /// # Errors
    /// Denies generic/prepared rows, hard-denied origins, stale or over-ceiling deadlines.
    pub async fn begin_native_grant(
        &self,
        request: EvaluateApprovalRequest2,
        expires_at_ms: u64,
    ) -> Result<ApprovalRow2> {
        Self::native_request(&request.request, "native_secret_grant")?;
        if request.ttl_ms.is_some() {
            return Err(Error::Denied);
        }
        self.begin_inner(request, Some(expires_at_ms)).await
    }
    /// Begin one App I/O operation through a trusted native owner only.
    /// The owner supplies its independently computed keyed operation commitment;
    /// names, paths, input, resource and master epoch never enter this wrapper.
    /// The commitment must include those fields and the original absolute deadline.
    /// Approval binds the wrapper; it does not attest live material or file authority.
    /// # Errors
    /// Denies generic or master wrappers, refreshed TTLs, malformed commitments,
    /// hard-denied origins and expired or over-ceiling original deadlines.
    pub async fn begin_native_app_io(
        &self,
        mut request: EvaluateApprovalRequest2,
        expires_at_ms: u64,
    ) -> Result<ApprovalRow2> {
        Self::app_io_request(&request.request)?;
        if request.ttl_ms.is_some() {
            return Err(Error::Denied);
        }
        // This fixed description carries no owner operation data into public prompts.
        request.summary = "native app io grant".into();
        self.begin_inner(request, Some(expires_at_ms)).await
    }
    fn app_io_request(request: &EvaluateRequest) -> Result<()> {
        Self::native_request(request, "native_app_io_grant")?;
        if request.call.checks
            != [Check::Unknown {
                description: "native-app-io-authority".into(),
            }]
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn native_request(request: &EvaluateRequest, tool: &str) -> Result<()> {
        binding::native_safe_call(request)?;
        if request.call.tool != tool || request.caller.origin == Origin::Cron {
            return Err(Error::Denied);
        }
        Ok(())
    }
    async fn begin_inner(
        &self,
        request: EvaluateApprovalRequest2,
        deadline: Option<u64>,
    ) -> Result<ApprovalRow2> {
        // One snapshot: posture, policy reference and grants never mix replacements.
        let entry = self.entry(&request.scope_id)?;
        let reg = self.registered(&entry);
        let (bound, args_redacted, external_effect) =
            binding::original(&reg, &request.request, &self.redactor()?)?;
        Self::reject_raw_deny(&reg, &bound.origin, external_effect)?;
        let now = self.now()?;
        let ttl = self.begin_ttl(&request, &bound, deadline, now)?;
        Self::correlation(&request.audit, reg.generation)?;
        let (rows, rule) = self
            .begin_rows_and_rule(&entry, &reg, &request, &bound.origin, external_effect, now)
            .await?;
        self.reconcile_creations(&rows)?;
        if let Some(row) = self
            .existing_begin(&reg, &bound, &rows, now, deadline)
            .await?
        {
            return Ok(row);
        }
        let (reusable, human_only) = self
            .begin_reuse(&request, &reg, &bound, &rows, now, deadline.is_some())
            .await?;
        let eligible = !human_only && reusable.is_none();
        let granted = Self::automatic_grant(&entry, &reg, &rows, &request, rule, now, eligible);
        let automatic =
            !human_only && (rule == tinysecurity_auto::rules::Rule::Automatic || granted.is_some());
        let judge = if !human_only && reusable.is_none() && !automatic {
            self.score(&request, &bound, external_effect).await?
        } else {
            None
        };
        let qualified = judge
            .as_ref()
            .is_some_and(|e| e.outcome == tinysecurity_bus::JudgeOutcome2::Qualified);
        // Validate generation and expiry again after every external await, even cache hits.
        if reg.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        self.automatic_stands(&entry, &request.scope_id, automatic)?;
        let now = self.now()?;
        if reusable
            .as_ref()
            .is_some_and(|source| source.expires_at_ms <= now)
        {
            return Err(Error::Denied);
        }
        let approved = reusable.is_some() || automatic || qualified;
        let expiry = deadline.unwrap_or(now.checked_add(ttl).ok_or(Error::Invalid)?);
        if expiry <= now {
            return Err(Error::Denied);
        }
        let session_id = bound.caller.thread.clone();
        let row = ApprovalRow2 {
            request_id: binding::opaque()?,
            version: 1,
            binding: bound,
            host_instance: self.instance.clone(),
            nonce: binding::opaque()?,
            tool_name: self.begin_tool_label(&request.request.call.tool, deadline.is_some())?,
            session_id,
            audit_error: None,
            external_effect,
            args_redacted,
            summary: binding::text(&self.redactor()?, &request.summary, RedactMode::Text)?,
            created_at_ms: now,
            expires_at_ms: reusable
                .as_ref()
                .map_or(expiry, |r| expiry.min(r.expires_at_ms)),
            state: if approved {
                ApprovalLifecycle2::Approved
            } else {
                ApprovalLifecycle2::Pending
            },
            choice: approved.then_some(ApprovalChoice2::Once),
            attribution: Self::attribution(
                reusable.is_some(),
                qualified,
                granted,
                automatic.then(|| Self::automatic_label(&request.request.caller.origin)),
            ),
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: None,
            judge,
            audit: request.audit,
        };
        let row = self.memo_begin(row, deadline.is_some())?;
        let row = self
            .finish_native_begin(&reg, row, now, deadline.is_some())
            .await?;
        // The publication awaited too: never hand back an approval whose automatic
        // authority was replaced meanwhile (consumption would refuse it anyway).
        if row.state == ApprovalLifecycle2::Approved {
            self.automatic_stands(&entry, &request.scope_id, automatic)?;
        }
        Ok(row)
    }
    async fn begin_rows_and_rule(
        &self,
        entry: &ScopeEntry,
        reg: &ApprovalScope2,
        request: &EvaluateApprovalRequest2,
        origin: &Origin,
        external_effect: bool,
        now: u64,
    ) -> Result<(Vec<ApprovalRow2>, tinysecurity_auto::rules::Rule)> {
        let rows = self.rows(reg).await?;
        let durable_tool = Self::durable_tool_trust(reg, &rows, &request.request.call.tool, now);
        let rule = Self::origin_rule(entry, reg, origin, request, external_effect, durable_tool)?;
        Ok((rows, rule))
    }
    fn reject_raw_deny(reg: &ApprovalScope2, origin: &Origin, external_effect: bool) -> Result<()> {
        if tinysecurity_auto::rules::evaluate(reg, origin, external_effect)
            == tinysecurity_auto::rules::Rule::Deny
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn begin_ttl(
        &self,
        request: &EvaluateApprovalRequest2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        deadline: Option<u64>,
        now: u64,
    ) -> Result<u64> {
        let maximum = match bound.origin {
            Origin::Copilot | Origin::SubAgent => 180_000,
            _ => 600_000,
        };
        let ttl = request.ttl_ms.unwrap_or(maximum).min(maximum);
        if let Some(deadline) = deadline {
            self.check_native_deadline(bound, deadline, now, ttl)?;
        }
        if ttl == 0 {
            return Err(Error::Denied);
        }
        Ok(ttl)
    }
    /// The judge never qualifies a human-only tool, however the tool is named.
    fn judge_barred(tool: &str) -> bool {
        binding::is_native(tool) || HUMAN_ONLY_TOOLS2.contains(&tool)
    }
    /// The host-configured or durable grant that approves the call, when none of the
    /// human-only or reviewed-reuse paths already decided it.
    fn automatic_grant(
        entry: &ScopeEntry,
        reg: &ApprovalScope2,
        rows: &[ApprovalRow2],
        request: &EvaluateApprovalRequest2,
        rule: tinysecurity_auto::rules::Rule,
        now: u64,
        eligible: bool,
    ) -> Option<&'static str> {
        if !eligible {
            return None;
        }
        let durable_flow = Self::durable_flow_trust(reg, rows, &request.request, now);
        let durable_tool = Self::durable_tool_trust(reg, rows, &request.request.call.tool, now);
        entry.grant_for(request, rule, durable_flow, durable_tool)
    }
    /// The origin's shortcut for this call, or a denial: a Cron external effect is
    /// refused outright, and an origin nobody labelled is refused unless the scope
    /// holds a whole-tool grant for the tool (no prompt, no reuse, no judge).
    fn origin_rule(
        entry: &ScopeEntry,
        reg: &ApprovalScope2,
        origin: &Origin,
        request: &EvaluateApprovalRequest2,
        external_effect: bool,
        durable_tool: bool,
    ) -> Result<tinysecurity_auto::rules::Rule> {
        use tinysecurity_auto::rules::Rule;
        match tinysecurity_auto::rules::evaluate(reg, origin, external_effect) {
            Rule::Deny => Err(Error::Denied),
            Rule::GrantOnly
                if entry.tool_grant(&request.request.call.tool).is_none() && !durable_tool =>
            {
                Err(Error::Denied)
            }
            // A human-only tool needs a fresh human decision under every origin: the
            // trusted-origin shortcuts never cover it.
            Rule::Automatic
                if matches!(origin, Origin::TrustedAutomation | Origin::LocalOperator)
                    && (HUMAN_ONLY_TOOLS2.contains(&request.request.call.tool.as_str())
                        || binding::is_native(&request.request.call.tool)) =>
            {
                Ok(Rule::Approval)
            }
            rule => Ok(rule),
        }
    }
    /// An automatic approval stands only while the scope entry it was derived from is
    /// still the live one: a grant or posture replaced during an await revokes it.
    fn automatic_stands(&self, entry: &Arc<ScopeEntry>, id: &str, automatic: bool) -> Result<()> {
        if automatic && !Arc::ptr_eq(entry, &self.entry(id)?) {
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// Who approved a row that needed no human: reviewed reuse, the judge, a host
    /// grant or the scope's own automatic posture.
    fn attribution(
        reused: bool,
        qualified: bool,
        granted: Option<&'static str>,
        automatic: Option<&'static str>,
    ) -> Option<String> {
        if reused {
            Some("exact-reviewed-grant".into())
        } else if qualified {
            Some("auto:jev".into())
        } else {
            granted
                .map(Into::into)
                .or_else(|| automatic.map(Into::into))
        }
    }
    /// Attribution of an approval the scope's own posture or the origin made automatic.
    fn automatic_label(origin: &Origin) -> &'static str {
        match origin {
            Origin::TrustedAutomation => "auto:trusted-automation",
            Origin::LocalOperator => "auto:local-operator",
            _ => "auto:host-policy",
        }
    }
    fn begin_tool_label(&self, tool: &str, native: bool) -> Result<String> {
        if native {
            Ok(tool.into())
        } else if tool == "device_crypto" {
            // Fixed public classification controls the Human Once choice floor.
            Ok("device_crypto".into())
        } else {
            binding::text(&self.redactor()?, tool, RedactMode::Text)
        }
    }
    async fn finish_native_begin(
        &self,
        reg: &ApprovalScope2,
        row: ApprovalRow2,
        now: u64,
        native: bool,
    ) -> Result<ApprovalRow2> {
        if native {
            self.native_row(&row)?;
        }
        let result = self.finish_begin(reg, &row, now).await?;
        if native {
            self.native_row(&result)?;
            self.live(&result)?;
        }
        Ok(result)
    }
    async fn existing_begin(
        &self,
        reg: &ApprovalScope2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        rows: &[ApprovalRow2],
        now: u64,
        deadline: Option<u64>,
    ) -> Result<Option<ApprovalRow2>> {
        if let Some(row) = rows.iter().find(|r| &r.binding == bound) {
            if let Some(deadline) = deadline {
                self.native_row(row)?;
                if row.expires_at_ms != deadline {
                    return Err(Error::Denied);
                }
            }
            return self.resume(reg, row, now).await.map(Some);
        }
        Ok(None)
    }
    async fn begin_reuse(
        &self,
        request: &EvaluateApprovalRequest2,
        reg: &ApprovalScope2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        rows: &[ApprovalRow2],
        now: u64,
        native: bool,
    ) -> Result<(Option<ApprovalRow2>, bool)> {
        let scan_warning = request.request.call.checks.iter().any(|check| {
            matches!(
                check,
                Check::SkillScan {
                    verdict: tinysecurity_bus::SkillScanVerdict::Warn,
                    ..
                }
            )
        });
        let human_only = native
            || scan_warning
            || matches!(
                request.request.call.tool.as_str(),
                "sandbox_host_network" | "device_crypto"
            );
        // No human-only tool is ever approved by an earlier human decision of its content.
        let never_reused = human_only
            || binding::is_native(&request.request.call.tool)
            || HUMAN_ONLY_TOOLS2.contains(&request.request.call.tool.as_str());
        let reusable = if never_reused {
            None
        } else {
            self.live_reusable(reg, bound, rows, now).await?
        };
        Ok((reusable, human_only))
    }
    fn check_native_deadline(
        &self,
        bound: &tinysecurity_bus::ApprovalBinding2,
        deadline: u64,
        now: u64,
        ttl: u64,
    ) -> Result<()> {
        if deadline <= now || deadline - now > ttl.min(300_000) {
            return Err(Error::Denied);
        }
        self.prune_native(now, bound.generation)?;
        let intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        if intents.len() >= 32 && !intents.contains_key(&bound.call_sha256) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn memo_begin(&self, row: ApprovalRow2, native: bool) -> Result<ApprovalRow2> {
        let mut creations = self.creations.lock().map_err(|_| Error::Unavailable)?;
        let mut intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        if native && intents.len() >= 32 && !intents.contains_key(&row.binding.call_sha256) {
            return Err(Error::Unavailable);
        }
        if !creations.contains_key(&row.binding.call_sha256) && creations.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        let row = creations
            .entry(row.binding.call_sha256.clone())
            .or_insert(row)
            .clone();
        if native {
            if let Some(prior) = intents.get(&row.binding.call_sha256) {
                if prior.original != row {
                    return Err(Error::Denied);
                }
            } else {
                intents.insert(
                    row.binding.call_sha256.clone(),
                    NativeIntent {
                        original: row.clone(),
                        decision: None,
                        consumed: None,
                    },
                );
            }
        }
        Ok(row)
    }
    async fn audit_row(&self, row: ApprovalRow2) -> Result<()> {
        if binding::is_native(&row.tool_name) {
            self.native_identity(&row)?;
            let acknowledgement = self.ports.native_audit(row.clone()).await?;
            if acknowledgement.row != row {
                return Err(Error::Denied);
            }
            self.native_identity(&row)?;
            self.live(&row)?;
            Ok(())
        } else {
            self.ports.audit(row).await
        }
    }
    async fn audit_resolution(&self, row: ApprovalRow2) -> Result<()> {
        if row.binding.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        if binding::is_native(&row.tool_name) {
            let ack = self.ports.native_audit(row.clone()).await?;
            if ack.row != row {
                return Err(Error::Denied);
            }
        } else {
            self.ports.audit(row.clone()).await?;
        }
        if self.generation.load(Ordering::SeqCst) != row.binding.generation {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn reconcile_creations(&self, rows: &[ApprovalRow2]) -> Result<()> {
        // Durable identities replace retry identities once confirmed by exact
        // load. Retain every indeterminate creation not present in this snapshot.
        self.creations
            .lock()
            .map_err(|_| Error::Unavailable)?
            .retain(|_, pending| {
                !rows.iter().any(|row| {
                    row.request_id == pending.request_id && row.binding == pending.binding
                })
            });
        Ok(())
    }
    async fn live_reusable(
        &self,
        reg: &ApprovalScope2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        rows: &[ApprovalRow2],
        now: u64,
    ) -> Result<Option<ApprovalRow2>> {
        let Some(source) = reusable_grant(rows, bound, now) else {
            return Ok(None);
        };
        // Reconcile the exact source audit, then reload mutable state and time.
        // No callback lock is held, and an expired source never creates a row.
        self.audit_row(source.clone()).await?;
        let current = self.rows(reg).await?;
        let now = self.now()?;
        let live = reusable_grant(&current, bound, now)
            .filter(|row| row.request_id == source.request_id)
            .cloned()
            .ok_or(Error::Denied)?;
        Ok(Some(live))
    }
    async fn score(
        &self,
        request: &EvaluateApprovalRequest2,
        bound: &tinysecurity_bus::ApprovalBinding2,
        external_effect: bool,
    ) -> Result<Option<tinysecurity_bus::JudgeEvidence2>> {
        if Self::judge_barred(&request.request.call.tool) {
            return Ok(None);
        }
        let Some(engine) = self.automatic()? else {
            return Ok(None);
        };
        let input = tinysecurity_auto::Input {
            binding: bound.clone(), external_effect,
            intent: request.summary.clone(),
            context_json: serde_json::to_string(&serde_json::json!({"tool":request.request.call.tool,"checks":request.request.call.checks})).map_err(|_| Error::Invalid)?,
            arguments_json: request.request.call.arguments_json.clone(),
        };
        // No lock crosses the outbound await; scoring errors keep human approval.
        Ok(engine
            .evaluate(&input, &self.redactor()?)
            .await
            .ok()
            .flatten())
    }
    async fn finish_begin(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
        now: u64,
    ) -> Result<ApprovalRow2> {
        // A concurrent begin may have committed while this call loaded an older
        // snapshot and its memo was reclaimed. Use the durable winner rather
        // than creating a second request with a fresh random identity.
        let rows = self.rows(reg).await?;
        if binding::is_native(&row.tool_name) {
            // The load may outlive the private intent. Validate the prepared
            // original again before resuming or creating any durable row.
            self.native_row(row)?;
            self.live(row)?;
        }
        if let Some(current) = rows.iter().find(|current| current.binding == row.binding) {
            return self.resume(reg, current, now).await;
        }
        self.persist(None, row).await?;
        if row.state == ApprovalLifecycle2::Pending {
            self.deliver(row.clone()).await?;
        }
        self.delivered_winner(reg, row).await
    }
    async fn resume(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
        now: u64,
    ) -> Result<ApprovalRow2> {
        if binding::is_native(&row.tool_name) {
            self.native_row(row)?;
        }
        if row.host_instance != self.instance || row.expires_at_ms <= now {
            return Err(Error::Denied);
        }
        self.audit_row(row.clone()).await?;
        if row.state == ApprovalLifecycle2::Pending {
            self.deliver(row.clone()).await?;
        }
        self.delivered_winner(reg, row).await
    }
    async fn delivered_winner(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
    ) -> Result<ApprovalRow2> {
        let current = self.row(reg, &row.request_id).await?;
        if current.binding != row.binding || current.host_instance != self.instance {
            return Err(Error::Denied);
        }
        Self::current(reg, &current)?;
        if binding::is_native(&current.tool_name) {
            self.native_row(&current)?;
        }
        if &current != row {
            // Delivery acknowledges the prompt only. A reentrant decision may
            // have committed without an audit acknowledgement; replay its exact
            // durable phase before reporting the winning permission.
            self.audit_row(current.clone()).await?;
        }
        Ok(current)
    }
    /// Resolve a trusted registration to its full-digest durable scope handle.
    /// # Errors
    /// Rejects unknown registrations or malformed trusted identities.
    pub fn durable_scope(&self, id: &str) -> Result<SubjectScope> {
        binding::scope_handle(&self.registration(id)?.subject)
    }
    fn redactor(&self) -> Result<Redactor> {
        self.redactor
            .read()
            .map(|r| r.clone())
            .map_err(|_| Error::Unavailable)
    }
    /// Replace the initialized secret registry without changing owner bindings.
    /// # Errors
    /// Rejects poisoned state instead of forwarding unsanitized data.
    pub fn replace_redactor(&self, redactor: Redactor) -> Result<()> {
        *self.redactor.write().map_err(|_| Error::Unavailable)? = redactor;
        Ok(())
    }
    /// Import history without converting incomplete legacy bindings into live grants.
    /// # Errors
    /// Rejects invalid scopes, oversized history or unacknowledged durability.
    pub async fn import_history(&self, request: ApprovalHistoryImport2) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let encoded = serde_json::to_vec(&request.legacy).map_err(|_| Error::Invalid)?;
        if encoded.len() > 32768 {
            return Err(Error::Invalid);
        }
        let legacy_digest = binding::digest(b"tinysecurity/approval-legacy-history/v1\0", &encoded);
        let original = EvaluateRequest {
            caller: CallerContext {
                agent: reg.subject.agent.clone(),
                call_id: legacy_digest.clone(),
                tier: reg.ceiling.clone(),
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: serde_json::to_string(
                    &serde_json::json!({"history_sha256":legacy_digest}),
                )
                .map_err(|_| Error::Invalid)?,
                checks: vec![Check::LocalDiagnostic {}],
            },
        };
        let (bound, _, _) = binding::original(&reg, &original, &self.redactor()?)?;
        if let Some(existing) = self
            .rows(&reg)
            .await?
            .into_iter()
            .find(|r| r.binding == bound && r.legacy_history_json.is_some())
        {
            self.audit_row(existing.clone()).await?;
            return Ok(existing);
        }
        let now = self.now()?;
        let row = ApprovalRow2 {
            request_id: binding::opaque()?,
            version: 1,
            binding: bound,
            host_instance: self.instance.clone(),
            nonce: binding::opaque()?,
            tool_name: "imported-history".into(),
            session_id: None,
            audit_error: None,
            external_effect: false,
            args_redacted: "{}".into(),
            summary: "imported-history".into(),
            created_at_ms: now,
            expires_at_ms: now.checked_add(1).ok_or(Error::Invalid)?,
            state: ApprovalLifecycle2::Denied,
            choice: None,
            attribution: Some("legacy-history-only".into()),
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: Some(binding::text(
                &self.redactor()?,
                std::str::from_utf8(&encoded).map_err(|_| Error::Invalid)?,
                RedactMode::StructuredLogArguments,
            )?),
            judge: None,
            audit: request.audit,
        };
        self.persist(None, &row).await?;
        Ok(row)
    }
    fn prune_native(&self, now: u64, generation: u64) -> Result<()> {
        self.creations
            .lock()
            .map_err(|_| Error::Unavailable)?
            .retain(|_, row| {
                !binding::is_native(&row.tool_name)
                    || (row.expires_at_ms > now && row.binding.generation == generation)
            });
        self.native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .retain(|_, intent| {
                intent.original.expires_at_ms > now
                    && intent.original.binding.generation == generation
            });
        Ok(())
    }
    fn native_identity(&self, row: &ApprovalRow2) -> Result<()> {
        let now = self.now()?;
        let generation = self.generation.load(Ordering::SeqCst);
        self.prune_native(now, generation)?;
        let intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        let intent = intents.get(&row.binding.call_sha256).ok_or(Error::Denied)?;
        let original = &intent.original;
        if row.binding != original.binding
            || row.request_id != original.request_id
            || row.nonce != original.nonce
            || row.host_instance != self.instance
            || row.tool_name != original.tool_name
            || row.args_redacted != original.args_redacted
            || row.created_at_ms != original.created_at_ms
            || row.expires_at_ms != original.expires_at_ms
            || row.external_effect != original.external_effect
            || row.judge.is_some()
            || row.legacy_history_json.is_some()
            || (matches!(
                row.state,
                ApprovalLifecycle2::Approved
                    | ApprovalLifecycle2::Reserved
                    | ApprovalLifecycle2::Executed
            ) && (row.choice != Some(ApprovalChoice2::Once)
                || row.decision_ticket_sha256.is_none()))
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn native_row(&self, row: &ApprovalRow2) -> Result<()> {
        self.native_identity(row)?;
        let intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        let intent = intents.get(&row.binding.call_sha256).ok_or(Error::Denied)?;
        let original = &intent.original;
        match row.state {
            ApprovalLifecycle2::Pending if row != original => return Err(Error::Denied),
            ApprovalLifecycle2::Approved if intent.decision.as_ref() != Some(row) => {
                return Err(Error::Denied);
            }
            ApprovalLifecycle2::Reserved if intent.consumed.as_ref() != Some(row) => {
                return Err(Error::Denied);
            }
            ApprovalLifecycle2::Executed => return Err(Error::Denied),
            _ => {}
        }
        Ok(())
    }
    fn native_ack(&self, row: &ApprovalRow2, consumed: bool) -> Result<()> {
        if !binding::is_native(&row.tool_name) {
            return Ok(());
        }
        let mut intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        let intent = intents
            .get_mut(&row.binding.call_sha256)
            .ok_or(Error::Denied)?;
        if consumed {
            intent.consumed = Some(row.clone());
        } else {
            intent.decision = Some(row.clone());
        }
        Ok(())
    }
    /// Exact approval-owned policy digest for trusted native registration composition.
    /// # Errors
    /// Rejects unknown registrations.
    pub fn durable_policy_ref(&self, id: &str) -> Result<String> {
        Ok(binding::digest(
            b"tinysecurity/approval-policy/v1\0",
            self.registration(id)?.policy_ref.as_bytes(),
        ))
    }
    fn entry(&self, id: &str) -> Result<Arc<ScopeEntry>> {
        self.scopes
            .read()
            .map_err(|_| Error::Unavailable)?
            .by_id
            .get(id)
            .cloned()
            .ok_or(Error::Denied)
    }
    /// The registration of one snapshot, bound to the engine's current generation.
    fn registered(&self, entry: &ScopeEntry) -> ApprovalScope2 {
        let mut reg = entry.scope.clone();
        reg.generation = self.generation.load(Ordering::SeqCst);
        reg
    }
    fn registration(&self, id: &str) -> Result<ApprovalScope2> {
        let entry = self.entry(id)?;
        Ok(self.registered(&entry))
    }
    /// Return the current trusted scope snapshot for one live registration.
    /// This is used by sibling module adapters that must bind a secondary
    /// capability to the approval engine's canonical subject and generation.
    /// # Errors
    /// Rejects unknown registrations or poisoned approval state.
    pub fn scope_snapshot(&self, id: &str) -> Result<ApprovalScope2> {
        self.registration(id)
    }
    fn validate_scope(scope: &ApprovalScope2) -> Result<()> {
        if scope.scope_id.len() != 32
            || !scope.scope_id.bytes().all(|b| b.is_ascii_hexdigit())
            || scope.policy_ref.is_empty()
            || scope.policy_ref.len() > 1024
            || scope.generation == 0
            || [
                &scope.subject.user,
                &scope.subject.workspace,
                &scope.subject.agent,
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Validate a runtime request: scope shape, current generation, grants and stream.
    fn validate_runtime(&self, request: &RegisterApprovalScopeRequest2) -> Result<()> {
        Self::validate_scope(&request.scope)?;
        if !request.grants.is_valid() || !binding::hex(&request.audit_stream_id, 32) {
            return Err(Error::Invalid);
        }
        self.current_generation(&request.scope)
    }
    /// Deny a registration made against a generation that is no longer current.
    fn current_generation(&self, scope: &ApprovalScope2) -> Result<()> {
        if scope.generation == self.generation.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    fn receipt(
        scopes: &ScopeTable,
        scope: &ApprovalScope2,
        generation: u64,
        outcome: ApprovalScopeOutcome2,
        report_handle: bool,
    ) -> Result<ApprovalScopeReceipt2> {
        Ok(ApprovalScopeReceipt2 {
            scope_id: scope.scope_id.clone(),
            scope_handle: report_handle
                .then(|| binding::scope_handle(&scope.subject))
                .transpose()?,
            generation,
            outcome,
            live_scopes: u32::try_from(scopes.by_id.len()).map_err(|_| Error::Invalid)?,
        })
    }
    /// Add a runtime subject after init. An identical repeat is idempotent; any other
    /// reuse of the identity or of the subject conflicts. The ports admit the subject
    /// (store and audit stream) before it becomes usable.
    /// # Errors
    /// Rejects invalid, stale-generation, conflicting or over-capacity registrations
    /// and subjects the ports cannot admit.
    pub async fn register_scope(
        &self,
        request: RegisterApprovalScopeRequest2,
    ) -> Result<ApprovalScopeReceipt2> {
        self.validate_runtime(&request)?;
        let report = request.report_handle;
        let candidate = ScopeEntry::runtime(request);
        // Registration and retirement are serialized, so every check below still
        // holds when the entry is inserted and a failed admission is ours to undo.
        let _lifecycle = self.lifecycle.lock().await;
        // The generation may have advanced while waiting for the lifecycle.
        self.current_generation(&candidate.scope)?;
        {
            let scopes = self.scopes.read().map_err(|_| Error::Unavailable)?;
            if let Some(existing) = scopes.by_id.get(&candidate.scope.scope_id) {
                return if existing.same_posture(&candidate)
                    && existing.audit_stream_id == candidate.audit_stream_id
                {
                    Self::receipt(
                        &scopes,
                        &candidate.scope,
                        candidate.scope.generation,
                        ApprovalScopeOutcome2::Unchanged,
                        report,
                    )
                } else {
                    Err(Error::Conflict)
                };
            }
            if scopes.by_id.len() >= MAX_APPROVAL_SCOPES2 {
                return Err(Error::Unavailable);
            }
            if scopes.holds_subject(&candidate.scope) {
                return Err(Error::Conflict);
            }
        }
        let stream = candidate.audit_stream_id.clone().unwrap_or_default();
        if let Err(error) = self.ports.admit_scope(&candidate.scope, &stream).await {
            // No live scope holds this subject (checked above), so undoing is safe.
            let _ = self.ports.release_scope(&candidate.scope).await;
            return Err(error);
        }
        // Checked under the table lock that `advance_generation` also takes, so a
        // stale scope never goes live after the ports admitted its subject.
        let admitted = candidate.scope.clone();
        let created = {
            let mut scopes = self.scopes.write().map_err(|_| Error::Unavailable)?;
            self.current_generation(&candidate.scope).map(|()| {
                let (scope, generation) = (candidate.scope.clone(), candidate.scope.generation);
                scopes.insert(candidate);
                Self::receipt(
                    &scopes,
                    &scope,
                    generation,
                    ApprovalScopeOutcome2::Created,
                    report,
                )
            })
        };
        match created {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = self.ports.release_scope(&admitted).await;
                Err(error)
            }
        }
    }
    /// Atomically replace the posture, grants or policy reference of a live scope.
    /// Replacement waits for any in-flight whole-tool trust mutation to finish.
    /// The subject and, for runtime scopes, the audit stream cannot change. Pending
    /// rows bound to a different `policy_ref` stop being decidable, which is the
    /// intended invalidation.
    /// # Errors
    /// Rejects unknown scopes, a changed subject or stream, and invalid input.
    pub async fn replace_scope(
        &self,
        request: RegisterApprovalScopeRequest2,
    ) -> Result<ApprovalScopeReceipt2> {
        self.validate_runtime(&request)?;
        let _tool_trust = self.tool_trust_lock.lock().await;
        let report = request.report_handle;
        let candidate = ScopeEntry::runtime(request);
        let mut scopes = self.scopes.write().map_err(|_| Error::Unavailable)?;
        // `advance_generation` takes this lock too, so the check is the linearization
        // point: a replacement is installed before an advance or denied after it.
        self.current_generation(&candidate.scope)?;
        let existing = scopes
            .by_id
            .get(&candidate.scope.scope_id)
            .cloned()
            .ok_or(Error::Denied)?;
        if existing.scope.subject != candidate.scope.subject
            || existing
                .audit_stream_id
                .as_ref()
                .is_some_and(|stream| Some(stream) != candidate.audit_stream_id.as_ref())
        {
            return Err(Error::Denied);
        }
        let (scope, generation) = (candidate.scope.clone(), candidate.scope.generation);
        let same = existing.same_posture(&candidate);
        if !same {
            // Keep the original stream owner: init scopes stay on the base stream.
            let mut next = candidate;
            next.audit_stream_id.clone_from(&existing.audit_stream_id);
            scopes.insert(next);
        }
        Self::receipt(
            &scopes,
            &scope,
            generation,
            if same {
                ApprovalScopeOutcome2::Unchanged
            } else {
                ApprovalScopeOutcome2::Replaced
            },
            report,
        )
    }
    /// Remove a runtime scope. Calls already holding it finish; every later call
    /// denies. Initialized scopes can be replaced but not retired.
    /// # Errors
    /// Rejects unknown or initialized scopes and ports that cannot release the subject.
    pub async fn retire_scope(
        &self,
        request: RetireApprovalScopeRequest2,
    ) -> Result<ApprovalScopeReceipt2> {
        let _lifecycle = self.lifecycle.lock().await;
        // Initialized scopes (the base audit stream, possibly a native journal) are
        // replaced, never retired, so their subjects cannot come back on another backend.
        if self.entry(&request.scope_id)?.audit_stream_id.is_none() {
            return Err(Error::Denied);
        }
        let removed = self
            .scopes
            .write()
            .map_err(|_| Error::Unavailable)?
            .remove(&request.scope_id)
            .ok_or(Error::Denied)?;
        if let Err(error) = self.ports.release_scope(&removed.scope).await {
            // Keep ownership so the retirement can be retried; the ports fail closed
            // for whatever they already released.
            self.scopes
                .write()
                .map_err(|_| Error::Unavailable)?
                .reinstate(removed);
            return Err(error);
        }
        let scopes = self.scopes.read().map_err(|_| Error::Unavailable)?;
        Self::receipt(
            &scopes,
            &removed.scope,
            0,
            ApprovalScopeOutcome2::Retired,
            false,
        )
    }
    fn correlation(audit: &AuditCorrelation2, generation: u64) -> Result<()> {
        if !binding::hex(&audit.event_id, 32) || audit.generation != generation {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn now(&self) -> Result<u64> {
        let Some(wall) = self.clock.wall_ms() else {
            self.time.lock().map_err(|_| Error::Unavailable)?.3 = true;
            self.native_intents
                .lock()
                .map_err(|_| Error::Unavailable)?
                .clear();
            return Err(Error::Unavailable);
        };
        let mono = self.clock.monotonic_ms();
        let mut time = self.time.lock().map_err(|_| Error::Unavailable)?;
        if time.3 || wall < time.0 || mono < time.1 {
            time.3 = true;
            self.native_intents
                .lock()
                .map_err(|_| Error::Unavailable)?
                .clear();
            return Err(Error::Denied);
        }
        let elapsed = mono - time.1;
        let effective = wall.max(time.2.checked_add(elapsed).ok_or(Error::Invalid)?);
        // The effective monotonic deadline cannot move backwards even if wall freezes.
        *time = (wall, mono, effective, false);
        Ok(effective)
    }
    async fn rows(&self, reg: &ApprovalScope2) -> Result<Vec<ApprovalRow2>> {
        let requested = ApprovalLoadRequest2 {
            scope: binding::scope_handle(&reg.subject)?,
        };
        let response = self.ports.load(requested.clone()).await?;
        requested
            .verify_response(&response)
            .map_err(|_| Error::Invalid)?;
        response
            .records
            .iter()
            .map(|r| {
                let row = binding::parse(r, &requested.scope)?;
                Ok(row)
            })
            .collect()
    }
    async fn row(&self, reg: &ApprovalScope2, id: &str) -> Result<ApprovalRow2> {
        let row = self
            .rows(reg)
            .await?
            .into_iter()
            .find(|r| r.request_id == id)
            .ok_or(Error::Denied)?;
        if binding::is_native(&row.tool_name) {
            self.native_row(&row)?;
        }
        Ok(row)
    }
    async fn persist(&self, expected: Option<u64>, row: &ApprovalRow2) -> Result<()> {
        self.persist_mode(expected, row, false).await
    }
    async fn persist_mode(
        &self,
        expected: Option<u64>,
        row: &ApprovalRow2,
        terminal: bool,
    ) -> Result<()> {
        if terminal
            && (expected.is_none()
                || !matches!(
                    row.state,
                    ApprovalLifecycle2::Expired | ApprovalLifecycle2::Cancelled
                ))
        {
            return Err(Error::Denied);
        }
        if row.binding.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        if binding::is_native(&row.tool_name) && !terminal {
            self.native_identity(row)?;
            self.live(row)?;
        }
        let record = binding::envelope(row)?;
        let mutation_id = binding::digest(
            b"tinysecurity/approval-mutation/v1\0",
            record.record_json.as_bytes(),
        )[..32]
            .to_owned();
        let request = ApprovalCasRequest2 {
            scope: row.binding.scope.clone(),
            record_id: row.request_id.clone(),
            expected_version: expected,
            next_record: record,
            mutation_id,
        };
        // Retry the EXACT mutation. The store must retain the original receipt
        // after newer row versions, not synthesize one from its latest snapshot.
        let receipt = match self.ports.cas(request.clone()).await {
            Ok(receipt) => receipt,
            Err(Error::Unavailable) => {
                if binding::is_native(&row.tool_name) && !terminal {
                    self.native_identity(row)?;
                    self.live(row)?;
                }
                self.ports.cas(request.clone()).await?
            }
            Err(error) => return Err(error),
        };
        request
            .verify_receipt(&receipt)
            .map_err(|_| Error::Invalid)?;
        if terminal {
            self.audit_resolution(row.clone()).await?;
        } else {
            self.audit_row(row.clone()).await?;
        }
        if row.binding.generation != self.generation.load(Ordering::SeqCst) {
            return Err(Error::Denied);
        }
        Ok(())
    }
    async fn deliver(&self, row: ApprovalRow2) -> Result<()> {
        let response = self
            .ports
            .prompt(ApprovalDeliveryRequest2 { row: row.clone() })
            .await?;
        if !response.delivered
            || response.request_id != row.request_id
            || response.nonce != row.nonce
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    /// Apply only an exact authenticated-human ticket to a durable pending row.
    /// # Errors
    /// Denies missing authority, stale scope, expiry and conflicting decisions.
    pub async fn decide(&self, request: DecideRequest2) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let mut row = self.row(&reg, &request.request_id).await?;
        Self::current(&reg, &row)?;
        if request.decision_ticket.is_empty() || request.decision_ticket.len() > 4096 {
            return Err(Error::Denied);
        }
        let ticket = binding::digest(b"", request.decision_ticket.as_bytes());
        if row.state != ApprovalLifecycle2::Pending {
            if row.decision_ticket_sha256.as_ref() == Some(&ticket) && row.audit == request.audit {
                self.audit_row(row.clone()).await?;
                return Ok(row);
            }
            return Err(Error::Conflict);
        }
        self.live(&row)?;
        self.audit_row(row.clone()).await?;
        Self::correlation(&request.audit, reg.generation)?;
        let reviewed = self
            .ports
            .human(VerifyHumanRequest2 {
                row: row.clone(),
                decision_ticket: request.decision_ticket,
            })
            .await?;
        if reviewed.row != row
            || reviewed.ticket_sha256 != ticket
            || reviewed.actor.is_empty()
            || reviewed.actor.len() > 1024
            || (matches!(
                row.tool_name.as_str(),
                "native_secret_grant" | "native_app_io_grant" | "device_crypto"
            ) && !matches!(
                reviewed.choice,
                ApprovalChoice2::Once | ApprovalChoice2::Deny
            ))
            || (reviewed.choice == ApprovalChoice2::Flow && row.binding.caller.flow.is_none())
            || (row.host_instance != self.instance && reviewed.choice != ApprovalChoice2::Deny)
        {
            return Err(Error::Denied);
        }
        self.live(&row)?;
        Self::current(&reg, &row)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = if reviewed.choice == ApprovalChoice2::Deny {
            ApprovalLifecycle2::Denied
        } else {
            ApprovalLifecycle2::Approved
        };
        row.choice = Some(reviewed.choice);
        row.decision_ticket_sha256 = Some(ticket);
        row.attribution = Some(binding::text(
            &self.redactor()?,
            &reviewed.actor,
            RedactMode::IdentifierHash,
        )?);
        row.audit = request.audit;
        self.persist(Some(previous), &row).await?;
        self.native_ack(&row, false)?;
        Ok(row)
    }
    /// Reserve a reviewed execution exactly once, before the host dispatches it.
    /// # Errors
    /// Denies any changed call, stale grant, orphan, or repeat reservation.
    pub async fn consume(&self, request: ApprovalActionRequest2) -> Result<ApprovalRow2> {
        if binding::is_native(&request.request.call.tool) {
            return Err(Error::Denied);
        }
        self.consume_inner(request, false).await
    }
    /// Consume a live trusted native Human Once row and return its actual sink receipt.
    /// No backend authority is returned if audit is absent or acknowledgement fails.
    /// # Errors
    /// Denies generic rows, reuse, judge decisions, expired provenance and mismatched receipts.
    pub async fn consume_native_grant(
        &self,
        request: ApprovalActionRequest2,
    ) -> Result<(ApprovalRow2, NativeAuditAcknowledgement)> {
        Self::native_request(&request.request, "native_secret_grant")?;
        let row = self.consume_inner(request, true).await?;
        let receipt = self.ports.native_audit(row.clone()).await?;
        if receipt.row != row {
            return Err(Error::Denied);
        }
        self.native_row(&row)?;
        self.live(&row)?;
        Ok((row, receipt))
    }
    /// Consume exact live App I/O Human Once authority with actual required audit.
    /// Only this Engine's native begin and authenticated human decision can create it.
    /// The returned move-only authority still requires independent owner verification.
    /// # Errors
    /// Denies generic/master wrappers, reused rows, changed operations, orphaned
    /// provenance, non-human decisions, expired authority and failed native audit.
    pub async fn consume_native_app_io(
        &self,
        request: ApprovalActionRequest2,
    ) -> Result<NativeAppIoGrant> {
        Self::app_io_request(&request.request)?;
        let scope_id = request.scope_id.clone();
        let original = request.request.clone();
        let row = self.consume_inner(request, true).await?;
        let acknowledgement = self.ports.native_audit(row.clone()).await?;
        if acknowledgement.row != row {
            return Err(Error::Denied);
        }
        self.native_row(&row)?;
        self.live(&row)?;
        Ok(NativeAppIoGrant {
            scope_id,
            original,
            acknowledgement,
        })
    }
    /// A row approved without a human is only consumable while the scope still
    /// approves it: a grant that covers the call, or the posture that made it
    /// automatic. Replacing the scope revokes unconsumed approvals.
    async fn grant_still_holds(
        &self,
        request: &ApprovalActionRequest2,
        row: &ApprovalRow2,
    ) -> Result<()> {
        let posture = match row.attribution.as_deref() {
            Some("auto:tool-grant" | "auto:flow-grant") => false,
            Some("auto:host-policy" | "auto:trusted-automation" | "auto:local-operator") => true,
            _ => return Ok(()),
        };
        let entry = self.entry(&request.scope_id)?;
        // An unlabelled call is approved by a whole-tool grant alone; a flow grant
        // added since never keeps its approval alive.
        let mut granted = if matches!(row.binding.origin, Origin::Unlabelled | Origin::Unknown) {
            entry.tool_grant(&request.request.call.tool).is_some()
        } else {
            entry
                .grant(
                    &request.request.call.tool,
                    request.request.caller.flow.as_deref(),
                )
                .is_some()
        };
        if !granted && row.attribution.as_deref() == Some("auto:flow-grant") {
            // A durable flow-trust row can have been revoked since the approval.
            let reg = self.registered(&entry);
            let rows = self.rows(&reg).await?;
            granted = Self::durable_flow_trust(&reg, &rows, &request.request, self.now()?);
        }
        if !granted && row.attribution.as_deref() == Some("auto:tool-grant") {
            // A durable whole-tool grant may be revoked after evaluation but before
            // execution. Reload it at the consume boundary so queued approvals die.
            let reg = self.registered(&entry);
            let rows = self.rows(&reg).await?;
            granted =
                Self::durable_tool_trust(&reg, &rows, &request.request.call.tool, self.now()?);
        }
        let automatic = posture
            && tinysecurity_auto::rules::evaluate(
                &entry.scope,
                &row.binding.origin,
                row.external_effect,
            ) == tinysecurity_auto::rules::Rule::Automatic;
        if granted || automatic {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    async fn consume_inner(
        &self,
        request: ApprovalActionRequest2,
        native: bool,
    ) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let mut row = self.row(&reg, &request.request_id).await?;
        self.exact(&reg, &row, &request.request)?;
        self.live(&row)?;
        self.audit_row(row.clone()).await?;
        if (native
            || matches!(
                request.request.call.tool.as_str(),
                "sandbox_host_network" | "device_crypto"
            ))
            && (row.choice != Some(ApprovalChoice2::Once)
                || row.decision_ticket_sha256.is_none()
                || row.judge.is_some())
        {
            return Err(Error::Denied);
        }
        if row.state != ApprovalLifecycle2::Approved || row.host_instance != self.instance {
            return Err(Error::Denied);
        }
        let _tool_trust_serial = if row.attribution.as_deref() == Some("auto:tool-grant") {
            Some(self.tool_trust_lock.lock().await)
        } else {
            None
        };
        self.grant_still_holds(&request, &row).await?;
        // The loads and audit above awaited; judge the live scope, not the snapshot.
        let live = self.registration(&request.scope_id)?;
        Self::current(&live, &row)?;
        Self::correlation(&request.audit, live.generation)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = ApprovalLifecycle2::Reserved;
        row.reservation_id = Some(binding::opaque()?);
        row.audit = request.audit.clone();
        self.persist(Some(previous), &row).await?;
        // A replacement racing the CAS burns the reservation instead of authorizing it,
        // whether it changed the policy reference, a grant or the automatic posture.
        Self::current(&self.registration(&request.scope_id)?, &row)?;
        self.grant_still_holds(&request, &row).await?;
        self.live(&row)?;
        if native {
            self.native_ack(&row, true)?;
        }
        Ok(row)
    }
    /// Persist an immutable terminal outcome only for the exact consumed action.
    /// # Errors
    /// Denies pending, denied, unreserved or mismatched executions.
    pub async fn record_execution(&self, request: RecordExecutionRequest2) -> Result<ApprovalRow2> {
        if binding::is_native(&request.action.request.call.tool) {
            return Err(Error::Denied);
        }
        let reg = self.registration(&request.action.scope_id)?;
        let mut row = self.row(&reg, &request.action.request_id).await?;
        self.exact(&reg, &row, &request.action.request)?;
        if row.host_instance != self.instance {
            return Err(Error::Denied);
        }
        if row.state == ApprovalLifecycle2::Executed {
            if row.outcome.as_ref() == Some(&request.outcome) && row.audit == request.action.audit {
                self.audit_row(row.clone()).await?;
                return Ok(row);
            }
            return Err(Error::Conflict);
        }
        if row.state != ApprovalLifecycle2::Reserved {
            return Err(Error::Denied);
        }
        self.audit_row(row.clone()).await?;
        Self::correlation(&request.action.audit, reg.generation)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = ApprovalLifecycle2::Executed;
        row.outcome = Some(request.outcome);
        row.audit = request.action.audit;
        self.persist(Some(previous), &row).await?;
        Ok(row)
    }
    /// Persist only a redacted diagnostic after an audit sink failure.
    /// This metadata mutation never changes the approval lifecycle or grants authority.
    /// # Errors
    /// Rejects invalid diagnostics, stale rows, mismatched scopes or unavailable storage.
    pub async fn record_audit_error(
        &self,
        request: tinysecurity_bus::RecordAuditErrorRequest2,
    ) -> Result<ApprovalRow2> {
        if request.audit_error.is_empty() || request.audit_error.len() > 8192 {
            return Err(Error::Invalid);
        }
        let reg = self.registration(&request.scope_id)?;
        let mut row = self.row(&reg, &request.request_id).await?;
        Self::current(&reg, &row)?;
        let sanitized = binding::text(&self.redactor()?, &request.audit_error, RedactMode::Text)?;
        let sanitized = if sanitized.chars().count() > 512 {
            let head: String = sanitized.chars().take(511).collect();
            format!("{head}…")
        } else {
            sanitized
        };
        Self::correlation(&request.audit, reg.generation)?;
        if row.audit_error.as_deref() == Some(&sanitized) && row.audit == request.audit {
            return Ok(row);
        }
        if row.audit_error.is_some() {
            return Err(Error::Conflict);
        }
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.audit_error = Some(sanitized);
        row.audit = request.audit;
        self.persist(Some(previous), &row).await?;
        Ok(row)
    }
    fn current(reg: &ApprovalScope2, row: &ApprovalRow2) -> Result<()> {
        if row.binding.generation != reg.generation
            || row.binding.scope != binding::scope_handle(&reg.subject)?
            || row.binding.policy_ref
                != binding::digest(
                    b"tinysecurity/approval-policy/v1\0",
                    reg.policy_ref.as_bytes(),
                )
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn live(&self, row: &ApprovalRow2) -> Result<()> {
        if self.now()? >= row.expires_at_ms {
            Err(Error::Denied)
        } else {
            Ok(())
        }
    }
    fn exact(
        &self,
        reg: &ApprovalScope2,
        row: &ApprovalRow2,
        request: &EvaluateRequest,
    ) -> Result<()> {
        Self::current(reg, row)?;
        let (original, _, _) = binding::original(reg, request, &self.redactor()?)?;
        if row.binding != original {
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// Advance the existing partial-scope generation; old grants immediately invalidate.
    /// This is not a composed-policy activation transaction.
    /// # Errors
    /// Rejects zero, rollback or failed compare-and-swap.
    pub fn advance_generation(&self, next: u64) -> Result<()> {
        let previous = self.generation.load(Ordering::SeqCst);
        if next < previous || next == 0 {
            return Err(Error::Denied);
        }
        let mut creations = self.creations.lock().map_err(|_| Error::Unavailable)?;
        let mut intents = self.native_intents.lock().map_err(|_| Error::Unavailable)?;
        // Registrations and replacements validate their generation under this lock.
        let _table = self.scopes.write().map_err(|_| Error::Unavailable)?;
        self.generation
            .compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Error::Conflict)?;
        intents.retain(|_, intent| intent.original.binding.generation == next);
        creations
            .retain(|_, row| !binding::is_native(&row.tool_name) || row.binding.generation == next);
        Ok(())
    }
    /// Read scoped durable rows without promoting imported legacy broad grants.
    /// # Errors
    /// Rejects malformed, cross-owner or unavailable storage.
    pub async fn list(&self, scope_id: &str) -> Result<Vec<ApprovalRow2>> {
        self.rows(&self.registration(scope_id)?).await
    }
    /// Read the newest durable decisions across currently registered scopes.
    /// Pending requests are excluded; the result is bounded to 1..=500 rows.
    /// # Errors
    /// Rejects malformed rows or unavailable scope stores.
    pub async fn list_recent_decisions(&self, limit: usize) -> Result<Vec<ApprovalRow2>> {
        let scopes = self
            .scopes
            .read()
            .map_err(|_| Error::Unavailable)?
            .by_id
            .values()
            .map(|entry| entry.scope.clone())
            .collect::<Vec<_>>();
        let mut rows = Vec::new();
        for scope in scopes {
            rows.extend(
                self.rows(&scope)
                    .await?
                    .into_iter()
                    .filter(|row| row.state != ApprovalLifecycle2::Pending),
            );
        }
        rows.sort_by(|left, right| {
            right
                .created_at_ms
                .cmp(&left.created_at_ms)
                .then_with(|| left.request_id.cmp(&right.request_id))
        });
        rows.truncate(limit.clamp(1, 500));
        Ok(rows)
    }
    /// Remove undecided rows belonging to one session across registered subjects.
    /// The session identifier is redacted once and matched against stored row hashes.
    /// Decided rows remain as durable audit history.
    /// # Errors
    /// Rejects invalid identifiers, malformed responses or unavailable stores.
    pub async fn purge_session(&self, session_id: &str) -> Result<usize> {
        if session_id.trim().is_empty() || session_id.len() > 1024 {
            return Err(Error::Invalid);
        }
        let session_id = binding::text(&self.redactor()?, session_id, RedactMode::IdentifierHash)?;
        let scopes = self
            .scopes
            .read()
            .map_err(|_| Error::Unavailable)?
            .by_id
            .values()
            .map(|entry| entry.scope.clone())
            .collect::<Vec<_>>();
        let mut removed = 0_usize;
        for scope in scopes {
            let request = ApprovalPurgeSessionRequest2 {
                scope: binding::scope_handle(&scope.subject)?,
                session_id: session_id.clone(),
            };
            let response = self.ports.purge_session(request.clone()).await?;
            request
                .verify_response(&response)
                .map_err(|_| Error::Invalid)?;
            removed = removed
                .checked_add(response.removed as usize)
                .ok_or(Error::Invalid)?;
        }
        Ok(removed)
    }
    /// Resolve pending or approved state as cancelled, retaining its captured scope.
    /// # Errors
    /// Rejects already terminal, unrelated or unacknowledged transitions.
    pub async fn cancel(&self, request: ApprovalRecordRequest2) -> Result<ApprovalRow2> {
        self.resolve(request, ApprovalLifecycle2::Cancelled).await
    }
    /// Durably expire a row at the exact boundary, or after a clock rollback fault.
    /// # Errors
    /// Rejects still-live or already execution-reserved rows.
    pub async fn expire(&self, request: ApprovalRecordRequest2) -> Result<ApprovalRow2> {
        self.resolve(request, ApprovalLifecycle2::Expired).await
    }
    async fn resolve(
        &self,
        request: ApprovalRecordRequest2,
        state: ApprovalLifecycle2,
    ) -> Result<ApprovalRow2> {
        let reg = self.registration(&request.scope_id)?;
        let mut row = self
            .rows(&reg)
            .await?
            .into_iter()
            .find(|row| row.request_id == request.request_id)
            .ok_or(Error::Denied)?;
        Self::current(&reg, &row)?;
        if row.state == state && row.audit == request.audit {
            self.audit_resolution(row.clone()).await?;
            return Ok(row);
        }
        if !matches!(
            row.state,
            ApprovalLifecycle2::Pending | ApprovalLifecycle2::Approved
        ) {
            return Err(Error::Conflict);
        }
        if state == ApprovalLifecycle2::Expired && self.live(&row).is_ok() {
            return Err(Error::Denied);
        }
        self.audit_resolution(row.clone()).await?;
        Self::correlation(&request.audit, reg.generation)?;
        let previous = row.version;
        row.version = previous.checked_add(1).ok_or(Error::Invalid)?;
        row.state = state;
        row.audit = request.audit;
        self.persist_mode(Some(previous), &row, true).await?;
        Ok(row)
    }
    /// Validate at most 100 already human-reviewed exact flow grants. No wildcards.
    /// # Errors
    /// Rejects unreviewed, stale, mismatched or oversized flow inputs.
    pub async fn preauthorize_flow(
        &self,
        request: PreauthorizeFlowRequest2,
    ) -> Result<Vec<ApprovalRow2>> {
        if request.flow_id.trim().is_empty()
            || request.flow_id.len() > 1024
            || request.request_ids.is_empty()
            || request.request_ids.len() > 100
        {
            return Err(Error::Invalid);
        }
        let reg = self.registration(&request.scope_id)?;
        let flow = binding::text(
            &self.redactor()?,
            &request.flow_id,
            RedactMode::IdentifierHash,
        )?;
        let mut result = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for id in request.request_ids {
            if !ids.insert(id.clone()) {
                continue;
            }
            let row = self.row(&reg, &id).await?;
            Self::current(&reg, &row)?;
            self.live(&row)?;
            if binding::is_native(&row.tool_name)
                || row.choice != Some(ApprovalChoice2::Flow)
                || row.binding.caller.flow.as_ref() != Some(&flow)
                || row.decision_ticket_sha256.is_none()
                || !matches!(
                    row.state,
                    ApprovalLifecycle2::Approved
                        | ApprovalLifecycle2::Reserved
                        | ApprovalLifecycle2::Executed
                )
            {
                return Err(Error::Denied);
            }
            self.audit_row(row.clone()).await?;
            result.push(row);
        }
        Ok(result)
    }
}
fn reusable_grant<'a>(
    rows: &'a [ApprovalRow2],
    bound: &tinysecurity_bus::ApprovalBinding2,
    now: u64,
) -> Option<&'a ApprovalRow2> {
    rows.iter().find(|r| {
        !binding::is_native(&r.tool_name)
            && r.binding.content_sha256 == bound.content_sha256
            && r.binding.generation == bound.generation
            && r.binding.scope == bound.scope
            && r.binding.origin == bound.origin
            && r.expires_at_ms > now
            && matches!(
                r.state,
                ApprovalLifecycle2::Approved
                    | ApprovalLifecycle2::Reserved
                    | ApprovalLifecycle2::Executed
            )
            && (r.choice == Some(ApprovalChoice2::Tool)
                || (r.choice == Some(ApprovalChoice2::Flow) && bound.caller.flow.is_some()))
    })
}

#[path = "engine_flow_trust.rs"]
mod flow_trust;
#[path = "engine_import_trust.rs"]
mod import_trust;
#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
#[path = "engine_tool_trust.rs"]
mod tool_trust;
