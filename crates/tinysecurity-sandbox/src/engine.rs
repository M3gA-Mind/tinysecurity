//! Bounded immutable registrations and exact declarative plan binding.
use crate::{Error, Result, grants};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tinysecurity_bus::{
    AccessTier, CallerContext, Check, ConstraintEnforcement2, Decision, DenialReason,
    EvaluateRequest, IsolationLevel2, MAX_CREDENTIAL_ROOT_BYTES, MAX_CREDENTIAL_ROOTS,
    MAX_SANDBOX_SCOPES2, NetworkPolicy, Origin, ResourceLimits2, SandboxArtifact2, SandboxBackend,
    SandboxConfig2, SandboxConstraint2, SandboxDenial2, SandboxDeployment2, SandboxExecutor2,
    SandboxPlanRequest2, SandboxPlanResponse2, SandboxScope2, SandboxSetting2, SandboxSource2,
    SourceTrust, SubjectScope, ToolCall, Verdict,
};
use tinysecurity_policy::{PathPolicyRegistry, PathScope};
#[derive(Clone)]
struct Scope {
    facts: SandboxScope2,
    paths: Arc<PathScope>,
    /// Registered after init; only these can be retired.
    runtime: bool,
    /// Distinguishes this registration from any other under the same identity, so a
    /// candidate planned for a retired scope can never be staged under its successor.
    incarnation: u64,
}
/// Outcome of a runtime registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    /// A new scope is live.
    Created,
    /// An identical scope was already registered.
    Unchanged,
}
/// Private planner with facts admitted only through trusted native initialization.
#[derive(Clone)]
pub struct Engine {
    scopes: Arc<RwLock<BTreeMap<String, Scope>>>,
    incarnations: Arc<AtomicU64>,
    issued: crate::registry::Registry,
}
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SandboxEngine([REDACTED])")
    }
}
fn id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn valid_limits(limits: &ResourceLimits2) -> bool {
    limits.cpu_time_ms != Some(0)
        && limits.cpu_millicores != Some(0)
        && limits.memory_bytes != Some(0)
        && limits.pids_max != Some(0)
        && limits.disk_bytes != Some(0)
}
fn bounded<T: PartialOrd>(requested: Option<T>, ceiling: Option<T>) -> bool {
    match (requested, ceiling) {
        (Some(value), Some(limit)) => value <= limit,
        (None, Some(_)) => false,
        (_, None) => true,
    }
}
fn limits_within(request: &ResourceLimits2, ceiling: &ResourceLimits2) -> bool {
    bounded(request.cpu_time_ms, ceiling.cpu_time_ms)
        && bounded(request.cpu_millicores, ceiling.cpu_millicores)
        && bounded(request.memory_bytes, ceiling.memory_bytes)
        && bounded(request.pids_max, ceiling.pids_max)
        && bounded(request.disk_bytes, ceiling.disk_bytes)
}
/// Whether the request's identities, sizes, lifetime and bounds are acceptable at all.
fn well_formed(request: &SandboxPlanRequest2, facts: &SandboxScope2) -> bool {
    id(&request.call_id)
        && request.operation_json.len() <= 65_536
        && request.grants.len() <= 128
        && request.grants.iter().all(|g| g.path.len() <= 4096)
        && request.credential_denials.len() <= MAX_CREDENTIAL_ROOTS
        && request.credential_denials.iter().all(|path| {
            path.is_absolute()
                && path.as_os_str().len() <= MAX_CREDENTIAL_ROOT_BYTES
                && !path.to_string_lossy().contains('\0')
                && !path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
        })
        && request.ttl_ms != 0
        && request.ttl_ms <= facts.max_ttl_ms
        && valid_limits(&request.limits)
}
fn rank(network: &NetworkPolicy) -> u8 {
    match network {
        NetworkPolicy::None => 0,
        NetworkPolicy::EgressProxy => 1,
        NetworkPolicy::Host => 2,
    }
}
fn supports(executor: &SandboxExecutor2, constraint: SandboxConstraint2) -> bool {
    executor
        .constraints
        .iter()
        .any(|s| s.constraint == constraint && s.enforcement == ConstraintEnforcement2::Enforced)
}
/// Like [`supports`], but a best-effort declaration also counts. Only a plan the
/// request marked as an ordinary operator command may rely on it.
fn supports_best_effort(executor: &SandboxExecutor2, constraint: SandboxConstraint2) -> bool {
    executor.constraints.iter().any(|s| {
        s.constraint == constraint
            && matches!(
                s.enforcement,
                ConstraintEnforcement2::Enforced | ConstraintEnforcement2::BestEffort
            )
    })
}
/// A real backend (never `Noop`) reporting kernel or microVM isolation: the only
/// executors an untrusted tier or `SaaS` scope may ever be planned onto.
fn suitable_for_untrusted(executor: &SandboxExecutor2) -> bool {
    executor.backend != SandboxBackend::Noop
        && matches!(
            executor.isolation,
            IsolationLevel2::Kernel | IsolationLevel2::MicroVm
        )
}
fn minimum_isolation(
    executor: &SandboxExecutor2,
    constraints: &[SandboxConstraint2],
    isolation: bool,
) -> IsolationLevel2 {
    if !isolation {
        IsolationLevel2::None
    } else if suitable_for_untrusted(executor) && constraints.iter().all(|c| supports(executor, *c))
    {
        IsolationLevel2::Kernel
    } else {
        // Only an executor chosen for a request that accepted process isolation can be
        // here: the kernel-level pass found nothing exact. This is trusted folder
        // confinement (for example Seatbelt), not a kernel-isolation claim.
        IsolationLevel2::Process
    }
}
fn requirements(request: &SandboxPlanRequest2) -> Vec<SandboxConstraint2> {
    let mut constraints = vec![SandboxConstraint2::Filesystem, SandboxConstraint2::Network];
    for (required, constraint) in [
        (
            request.limits.cpu_millicores.is_some(),
            SandboxConstraint2::CpuMillicores,
        ),
        (
            request.limits.memory_bytes.is_some(),
            SandboxConstraint2::Memory,
        ),
        (
            request.limits.pids_max.is_some(),
            SandboxConstraint2::Processes,
        ),
        (
            request.limits.disk_bytes.is_some(),
            SandboxConstraint2::Disk,
        ),
        (request.deny_subprocesses, SandboxConstraint2::Subprocesses),
    ] {
        if required {
            constraints.push(constraint);
        }
    }
    constraints
}
/// Choose the executor. An executor that meets the kernel-isolation floor with every
/// constraint exactly enforced always wins; only when the request accepted process
/// isolation (an ordinary operator command) is a process-level jail with best-effort
/// constraints considered, and only if no exact executor is available.
fn select<'a>(
    facts: &'a SandboxScope2,
    request: &SandboxPlanRequest2,
    constraints: &[SandboxConstraint2],
    isolation: bool,
) -> std::result::Result<&'a SandboxExecutor2, SandboxDenial2> {
    match pick(facts, request, constraints, isolation, false) {
        Err(_) if isolation && request.accept_process_isolation => {
            pick(facts, request, constraints, isolation, true)
        }
        other => other,
    }
}
fn pick<'a>(
    facts: &'a SandboxScope2,
    request: &SandboxPlanRequest2,
    constraints: &[SandboxConstraint2],
    isolation: bool,
    process_level: bool,
) -> std::result::Result<&'a SandboxExecutor2, SandboxDenial2> {
    let preferred = request.options.preferred_backend.as_ref();
    let mut executors: Vec<_> = facts
        .executors
        .iter()
        .filter(|e| {
            !(request.options.require_preferred_backend
                && preferred.is_some_and(|backend| &e.backend != backend))
        })
        .collect();
    // A stable sort: the configured preference first, then a micro-VM, then the order the
    // host declared its executors in.
    executors.sort_by_key(|e| {
        (
            preferred.is_some_and(|backend| &e.backend != backend),
            e.backend != SandboxBackend::MicroVm,
        )
    });
    executors
        .into_iter()
        .find(|e| {
            e.available
                && (!isolation
                    || if process_level {
                        e.isolation != IsolationLevel2::None
                    } else {
                        suitable_for_untrusted(e)
                    })
                && e.backend != SandboxBackend::Noop
                && constraints.iter().all(|c| {
                    if process_level {
                        supports_best_effort(e, *c)
                    } else {
                        supports(e, *c)
                    }
                })
                && (request.network != NetworkPolicy::EgressProxy
                    || facts.proxy.as_ref().is_some_and(|p| {
                        p.pinned_destinations
                            && p.exclusive_egress
                            && p.executor_id == e.executor_id
                            && p.capability_id == e.capability_id
                    }))
        })
        .ok_or(if request.network == NetworkPolicy::EgressProxy {
            SandboxDenial2::Proxy
        } else {
            SandboxDenial2::Unsupported
        })
}
/// Validate one registration and prepare its owner filesystem policy.
fn admit(facts: SandboxScope2, runtime: bool) -> Result<Scope> {
    if !id(&facts.scope_id)
        || !id(&facts.subject.user)
        || !id(&facts.subject.workspace)
        || !id(&facts.subject.agent)
        || facts.max_ttl_ms == 0
        || facts.max_ttl_ms > 300_000
        || !valid_limits(&facts.limits)
        || facts.sources.is_empty()
        || facts.sources.len() > 128
        || facts.executors.len() > 32
        || facts.grant_ceiling.len() > 128
        || facts.sources.iter().enumerate().any(|(i, s)| {
            !id(&s.source_id)
                || !id(&s.provenance)
                || facts.sources[..i]
                    .iter()
                    .any(|p| p.source_id == s.source_id)
        })
        || facts.executors.iter().enumerate().any(|(i, e)| {
            !id(&e.executor_id)
                || !id(&e.capability_id)
                || e.constraints.len() > 8
                || facts.executors[..i]
                    .iter()
                    .any(|p| p.executor_id == e.executor_id)
                || e.constraints.iter().enumerate().any(|(j, c)| {
                    e.constraints[..j]
                        .iter()
                        .any(|p| p.constraint == c.constraint)
                })
        })
        || facts
            .grant_ceiling
            .iter()
            .any(|g| g.path.len() > 4096 || !std::path::Path::new(&g.path).is_absolute())
        || facts.proxy.as_ref().is_some_and(|p| {
            !id(&p.proxy_id)
                || !facts
                    .executors
                    .iter()
                    .any(|e| e.executor_id == p.executor_id && e.capability_id == p.capability_id)
        })
    {
        return Err(Error::InvalidConfig);
    }
    let mut registry = PathPolicyRegistry::default();
    let policy_id = registry
        .register(facts.paths.clone())
        .map_err(|_| Error::InvalidConfig)?;
    let paths = registry
        .get_owned(&policy_id)
        .map_err(|_| Error::InvalidConfig)?;
    Ok(Scope {
        facts,
        paths,
        runtime,
        incarnation: 0,
    })
}
impl Engine {
    /// Admit immutable facts supplied across the authenticated SDK initialization boundary.
    /// # Errors
    /// Rejects malformed, excessive, duplicate or invalid native registrations.
    pub fn new(config: SandboxConfig2) -> Result<Self> {
        if config.scopes.len() > 128 {
            return Err(Error::InvalidConfig);
        }
        let mut scopes = BTreeMap::new();
        let initial = config.scopes.len();
        let incarnations = Arc::new(AtomicU64::new(1));
        for facts in config.scopes {
            let mut scope = admit(facts, false)?;
            scope.incarnation = incarnations.fetch_add(1, Ordering::SeqCst);
            if scopes.insert(scope.facts.scope_id.clone(), scope).is_some() {
                return Err(Error::InvalidConfig);
            }
        }
        Ok(Self {
            scopes: Arc::new(RwLock::new(scopes)),
            incarnations,
            issued: crate::registry::Registry::new(initial, crate::registry::MAX_RUNTIME_ISSUED),
        })
    }
    fn table(&self) -> Result<std::sync::RwLockReadGuard<'_, BTreeMap<String, Scope>>> {
        self.scopes.read().map_err(|_| Error::InvalidOperation)
    }
    /// Number of live scopes, initialized and runtime.
    /// # Errors
    /// Fails closed if the table is poisoned.
    pub fn live_scopes(&self) -> Result<usize> {
        Ok(self.table()?.len())
    }
    /// Add a scope after init. An identical repeat is idempotent; reusing the identity
    /// with different facts conflicts. A full table refuses: a live scope is never
    /// evicted to make room, so policy is never silently dropped or replaced.
    /// # Errors
    /// `InvalidConfig` for malformed facts, `Conflict` for a changed identity and
    /// `Capacity` when `MAX_SANDBOX_SCOPES2` scopes are live.
    pub fn register_scope(&self, facts: SandboxScope2) -> Result<Registration> {
        let mut scope = admit(facts, true)?;
        let mut table = self.scopes.write().map_err(|_| Error::InvalidOperation)?;
        if let Some(existing) = table.get(&scope.facts.scope_id) {
            return if existing.facts == scope.facts {
                Ok(Registration::Unchanged)
            } else {
                Err(Error::Conflict)
            };
        }
        if table.len() >= MAX_SANDBOX_SCOPES2 {
            return Err(Error::Capacity);
        }
        self.issued.mark_runtime(&scope.facts.scope_id);
        scope.incarnation = self.incarnations.fetch_add(1, Ordering::SeqCst);
        table.insert(scope.facts.scope_id.clone(), scope);
        Ok(Registration::Created)
    }
    /// Remove a runtime scope and discard every artifact it issued, pending or active.
    /// Initialized scopes can never be retired. Returns the retired scope's subject.
    /// # Errors
    /// `Unknown` for a missing scope and `NotRetirable` for an initialized one.
    pub fn retire_scope(&self, scope_id: &str) -> Result<SubjectScope> {
        let mut table = self.scopes.write().map_err(|_| Error::InvalidOperation)?;
        match table.get(scope_id) {
            None => return Err(Error::Unknown),
            Some(scope) if !scope.runtime => return Err(Error::NotRetirable),
            Some(_) => {}
        }
        let removed = table.remove(scope_id).ok_or(Error::Unknown)?;
        // Purged under the table lock that `stage` also holds, so no artifact of a
        // retired scope can be staged after this point.
        self.issued.purge_scope(scope_id);
        Ok(removed.facts.subject)
    }
    /// Whether any scope, initialized or runtime, is registered under this identity.
    /// # Errors
    /// Fails closed if the table is poisoned.
    pub fn has_scope(&self, scope_id: &str) -> Result<bool> {
        Ok(self.table()?.contains_key(scope_id))
    }
    /// Whether a runtime (not initialized) scope is registered under this identity.
    /// # Errors
    /// Fails closed if the table is poisoned.
    pub fn is_runtime_scope(&self, scope_id: &str) -> Result<bool> {
        Ok(self.table()?.get(scope_id).is_some_and(|s| s.runtime))
    }
    /// Construct a bounded declarative plan at an injected trusted clock value.
    /// # Errors
    /// Returns invalid-operation only if canonical serialization fails.
    pub fn plan(
        &self,
        request: &SandboxPlanRequest2,
        generation: u64,
        now_ms: u64,
    ) -> Result<SandboxPlanResponse2> {
        let result = self.resolve(request, generation, now_ms);
        Ok(match result {
            Ok(ref artifact)
                if request.network == NetworkPolicy::Host
                    && !artifact.host_run
                    && !self.operator_host_network(request) =>
            {
                denied(generation, SandboxDenial2::Approval)
            }
            Ok(artifact) => SandboxPlanResponse2 {
                decision: Decision {
                    generation,
                    verdict: Verdict::Allow,
                    cacheable: false,
                },
                denial: None,
                artifact: Some(artifact),
                audit: None,
            },
            Err(reason) => denied(generation, reason),
        })
    }
    /// Whether the request's scope grants the host's own network from its owner's
    /// configuration, so no per-command human approval is needed. Never in `SaaS`.
    fn operator_host_network(&self, request: &SandboxPlanRequest2) -> bool {
        self.table().is_ok_and(|table| {
            table.get(&request.scope_id).is_some_and(|scope| {
                let facts = &scope.facts;
                facts.operator_host_network
                    && facts.network_ceiling == NetworkPolicy::Host
                    && facts.deployment != SandboxDeployment2::Saas
                    && !matches!(facts.origin, Origin::Saas | Origin::Unlabelled)
            })
        })
    }
    fn resolve(
        &self,
        request: &SandboxPlanRequest2,
        generation: u64,
        now_ms: u64,
    ) -> std::result::Result<SandboxArtifact2, SandboxDenial2> {
        if request.generation != generation {
            return Err(SandboxDenial2::Stale);
        }
        let table = self.table().map_err(|_| SandboxDenial2::InvalidContext)?;
        let scope = table
            .get(&request.scope_id)
            .ok_or(SandboxDenial2::InvalidContext)?;
        let facts = &scope.facts;
        let source = facts
            .sources
            .iter()
            .find(|s| s.source_id == request.source_id && s.provenance == request.provenance)
            .ok_or(SandboxDenial2::InvalidContext)?;
        if request.subject != facts.subject {
            return Err(SandboxDenial2::InvalidContext);
        }
        if !well_formed(request, facts) {
            return Err(SandboxDenial2::InvalidRequest);
        }
        let operation: serde_json::Value = serde_json::from_str(&request.operation_json)
            .map_err(|_| SandboxDenial2::InvalidRequest)?;
        if !operation.is_object() {
            return Err(SandboxDenial2::InvalidRequest);
        }
        let mandatory = facts.deployment == SandboxDeployment2::Saas
            || matches!(facts.origin, Origin::Saas | Origin::Unlabelled)
            || source.trust != SourceTrust::TrustedHost;
        if request.options.host_run {
            return Self::host_run(
                request, facts, source, mandatory, generation, now_ms, &operation,
            );
        }
        if request.grants.iter().any(|g| g.write) && facts.tier == AccessTier::Read {
            return Err(SandboxDenial2::Ceiling);
        }
        if rank(&request.network) > rank(&facts.network_ceiling)
            || !limits_within(&request.limits, &facts.limits)
        {
            return Err(SandboxDenial2::Ceiling);
        }
        // No current TinyBox port enforces consumed CPU time. Throughput is separate.
        if request.limits.cpu_time_ms.is_some() {
            return Err(SandboxDenial2::Unsupported);
        }
        // A workspace-less plan has no writable root: a container with nothing mounted.
        if request.options.no_workspace && request.grants.iter().any(|g| g.write) {
            return Err(SandboxDenial2::Ceiling);
        }
        let grants = grants::admit(facts, &scope.paths, &request.grants)?;
        if request.accept_process_isolation && mandatory {
            return Err(SandboxDenial2::Floor);
        }
        let isolation = mandatory
            || (facts.environment != SandboxSetting2::Disabled
                && (facts.agent_mode == SandboxSetting2::Enabled
                    || facts.configured == SandboxSetting2::Enabled));
        let constraints = requirements(request);
        let executor = select(facts, request, &constraints, isolation)?;
        let minimum_isolation = minimum_isolation(executor, &constraints, isolation);
        let deny_read = if minimum_isolation == IsolationLevel2::Process {
            grants::credential_denials(facts, request, &grants)?
        } else {
            Vec::new()
        };
        let expires_at_ms = now_ms
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(SandboxDenial2::InvalidRequest)?;
        let mut artifact = SandboxArtifact2 {
            minimum_isolation,
            approval_reservation_id: None,
            plan_id: String::new(),
            fingerprint: String::new(),
            scope_id: request.scope_id.clone(),
            subject: facts.subject.clone(),
            source_id: source.source_id.clone(),
            provenance: source.provenance.clone(),
            call_id: request.call_id.clone(),
            generation,
            expires_at_ms,
            executor_id: executor.executor_id.clone(),
            capability_id: executor.capability_id.clone(),
            backend: executor.backend.clone(),
            grants,
            deny_read,
            network: request.network.clone(),
            proxy_id: if request.network == NetworkPolicy::EgressProxy {
                facts.proxy.as_ref().map(|p| p.proxy_id.clone())
            } else {
                None
            },
            limits: request.limits.clone(),
            constraints,
            host_run: false,
            no_workspace: request.options.no_workspace,
        };
        seal(request, &mut artifact, operation)?;
        Ok(artifact)
    }
    /// The artifact of a spawn the operator disabled the sandbox for (contract 1.22): the
    /// host runs it without a jail. Only a trusted operator source of a local deployment and
    /// origin, under a scope that carries the disabled `environment` setting, gets one.
    fn host_run(
        request: &SandboxPlanRequest2,
        facts: &SandboxScope2,
        source: &SandboxSource2,
        mandatory: bool,
        generation: u64,
        now_ms: u64,
        operation: &serde_json::Value,
    ) -> std::result::Result<SandboxArtifact2, SandboxDenial2> {
        if mandatory || facts.environment != SandboxSetting2::Disabled {
            return Err(SandboxDenial2::Floor);
        }
        // Nothing is confined, so nothing may claim to be: no grants, no workspace
        // option, and no resource bound that no executor would enforce.
        if request.options.no_workspace || !request.grants.is_empty() {
            return Err(SandboxDenial2::InvalidRequest);
        }
        let none = ResourceLimits2::default();
        if request.limits != none || facts.limits != none || request.deny_subprocesses {
            return Err(SandboxDenial2::Unsupported);
        }
        let mut artifact = SandboxArtifact2 {
            minimum_isolation: IsolationLevel2::None,
            approval_reservation_id: None,
            plan_id: String::new(),
            fingerprint: String::new(),
            scope_id: request.scope_id.clone(),
            subject: facts.subject.clone(),
            source_id: source.source_id.clone(),
            provenance: source.provenance.clone(),
            call_id: request.call_id.clone(),
            generation,
            expires_at_ms: now_ms
                .checked_add(u64::from(request.ttl_ms))
                .ok_or(SandboxDenial2::InvalidRequest)?,
            executor_id: HOST_EXECUTOR.into(),
            capability_id: HOST_EXECUTOR.into(),
            backend: SandboxBackend::Noop,
            grants: Vec::new(),
            deny_read: Vec::new(),
            network: NetworkPolicy::Host,
            proxy_id: None,
            limits: none,
            constraints: Vec::new(),
            host_run: true,
            no_workspace: false,
        };
        seal(request, &mut artifact, operation.clone())?;
        Ok(artifact)
    }
    /// Compute a fully checked candidate and exact original for the module's human workflow.
    /// A candidate is not permission. The adapter must reserve a verified human grant first.
    /// # Errors
    /// Rejects all floors, unavailable enforcement, mismatched scope and malformed input.
    pub fn human_candidate(
        &self,
        request: &SandboxPlanRequest2,
        generation: u64,
        now_ms: u64,
    ) -> Result<(SandboxArtifact2, String, EvaluateRequest)> {
        let artifact = self
            .resolve(request, generation, now_ms)
            .map_err(|_| Error::InvalidOperation)?;
        let table = self.table()?;
        let facts = &table
            .get(&request.scope_id)
            .ok_or(Error::InvalidOperation)?
            .facts;
        let approval_scope = facts
            .approval_scope_id
            .clone()
            .filter(|value| id(value))
            .ok_or(Error::InvalidOperation)?;
        if request.network != NetworkPolicy::Host {
            return Err(Error::InvalidOperation);
        }
        let mut original = serde_json::to_value(request).map_err(|_| Error::InvalidOperation)?;
        original
            .as_object_mut()
            .ok_or(Error::InvalidOperation)?
            .remove("audit");
        original
            .as_object_mut()
            .ok_or(Error::InvalidOperation)?
            .remove("host_approval");
        original["operation_json"] =
            serde_json::from_str(&request.operation_json).map_err(|_| Error::InvalidOperation)?;
        original.sort_all_objects();
        let mut authority = serde_json::to_value(&artifact).map_err(|_| Error::InvalidOperation)?;
        let fields = authority.as_object_mut().ok_or(Error::InvalidOperation)?;
        // The durable human decision binds every effective authority field.
        // Registry identity and reservation exist only after approval. Expiry
        // is separately bounded by the approval engine and plan clock fences;
        // the public correlation hash also incorporates that temporal value.
        for phase_field in [
            "plan_id",
            "approval_reservation_id",
            "expires_at_ms",
            "fingerprint",
        ] {
            fields.remove(phase_field);
        }
        let mut binding = serde_json::json!({"operation": original, "effective_plan": authority});
        binding.sort_all_objects();
        let arguments_json =
            serde_json::to_string(&binding).map_err(|_| Error::InvalidOperation)?;
        let original = EvaluateRequest {
            caller: CallerContext {
                agent: facts.subject.agent.clone(),
                call_id: request.call_id.clone(),
                origin: facts.origin.clone(),
                tier: facts.tier.clone(),
                thread: None,
                flow: None,
            },
            call: ToolCall {
                tool: "sandbox_host_network".into(),
                arguments_json,
                checks: vec![Check::Unknown {
                    description: "sandbox_host_network".into(),
                }],
            },
        };
        Ok((artifact, approval_scope, original))
    }
    /// The registration a scope identity currently has, to be captured before planning
    /// and handed to [`Self::stage_for`]. `None` when no such scope is registered.
    /// # Errors
    /// Fails closed if the table is poisoned.
    pub fn incarnation(&self, scope_id: &str) -> Result<Option<u64>> {
        Ok(self.table()?.get(scope_id).map(|scope| scope.incarnation))
    }
    /// Stage a candidate in the bounded native registry before its canonical audit,
    /// only while the scope it was planned under is still the registration the caller
    /// captured. A scope that was retired, even if the same identity registered again
    /// since, refuses the candidate. This internal method grants no execution and must
    /// never be exposed on the bus.
    /// # Errors
    /// Rejects entropy failure, full registry, expired candidate, invalid identity and
    /// a scope that is no longer the captured incarnation.
    pub fn stage_for(
        &self,
        incarnation: u64,
        artifact: SandboxArtifact2,
        now_ms: u64,
    ) -> Result<SandboxArtifact2> {
        // Held across the insert so `retire_scope` (which purges under the write lock)
        // either removes this row or makes the scope check below fail.
        let table = self.table()?;
        if !table.get(&artifact.scope_id).is_some_and(|scope| {
            scope.facts.subject == artifact.subject && scope.incarnation == incarnation
        }) {
            return Err(Error::InvalidOperation);
        }
        self.issued.stage(artifact, now_ms)
    }
    /// [`Self::stage_for`] under the scope's current registration. For a caller that
    /// plans and stages with no retirement possible between the two.
    /// # Errors
    /// As [`Self::stage_for`].
    pub fn stage(&self, artifact: SandboxArtifact2, now_ms: u64) -> Result<SandboxArtifact2> {
        let incarnation = self
            .incarnation(&artifact.scope_id)?
            .ok_or(Error::InvalidOperation)?;
        self.stage_for(incarnation, artifact, now_ms)
    }
    /// Remove a failed pending artifact; activated permissions cannot be removed by this port.
    pub fn discard(&self, artifact: &SandboxArtifact2) {
        self.issued.discard(artifact);
    }
    /// Activate a staged exact candidate only after authoritative audit and generation recheck.
    /// This native adapter port is not exposed to callers.
    /// # Errors
    /// Rejects changed, expired, missing or previously activated candidates.
    pub fn activate(
        &self,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.issued.activate(artifact, generation, now_ms)
    }
    /// Check an actual issued artifact before its consume audit, without reserving it.
    /// # Errors
    /// Rejects forged, changed, expired, wrong-owner, stale or already consumed artifacts.
    pub fn check_issued(
        &self,
        artifact: &SandboxArtifact2,
        subject: &SubjectScope,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.issued.check(artifact, subject, generation, now_ms)
    }
    /// Atomically reserve an exact audited issued artifact once immediately before host launch.
    /// # Errors
    /// Rejects replay and every mismatch; this never substitutes for live `TinyBox` checks.
    pub fn consume(
        &self,
        artifact: &SandboxArtifact2,
        subject: &SubjectScope,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.issued.consume(artifact, subject, generation, now_ms)
    }
    /// Validate the concrete original operation against this engine's immutable executor registry.
    /// Actual backend availability must still be checked by `TinyBox` immediately before launch.
    /// # Errors
    /// Returns canonical serialization failure, without granting execution.
    pub fn validate_registered(
        &self,
        request: &SandboxPlanRequest2,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
    ) -> Result<bool> {
        if artifact.host_run {
            return Ok(self.validate_host_run(request, artifact, generation, now_ms));
        }
        // Cloned so no table lock is held across `validate`, which locks it again.
        let executor = self.table()?.get(&artifact.scope_id).and_then(|scope| {
            scope
                .facts
                .executors
                .iter()
                .find(|executor| executor.executor_id == artifact.executor_id)
                .cloned()
        });
        let Some(executor) = executor else {
            return Ok(false);
        };
        self.validate(request, artifact, generation, now_ms, &executor)
    }
    /// Validate a planned run on the host: it names no executor, so only the issued
    /// artifact, its live window and the exact re-derived plan are checked.
    fn validate_host_run(
        &self,
        request: &SandboxPlanRequest2,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
    ) -> bool {
        if !request.options.host_run
            || self
                .check_issued(artifact, &request.subject, generation, now_ms)
                .is_err()
            || artifact.generation != generation
            || now_ms >= artifact.expires_at_ms
        {
            return false;
        }
        let Some(issued) = artifact
            .expires_at_ms
            .checked_sub(u64::from(request.ttl_ms))
        else {
            return false;
        };
        let expected = self.resolve(request, generation, issued).ok();
        let mut normalized = artifact.clone();
        normalized.plan_id.clear();
        normalized.approval_reservation_id = None;
        expected.as_ref() == Some(&normalized) && now_ms >= issued
    }
    /// Validate exact plan identity, live generation/time and executor revision before launch.
    /// This verifies the declarative artifact only; `TinyBox` must still recheck actual enforcement.
    /// # Errors
    /// Returns canonical serialization failure, without granting execution.
    pub fn validate(
        &self,
        request: &SandboxPlanRequest2,
        artifact: &SandboxArtifact2,
        generation: u64,
        now_ms: u64,
        executor: &SandboxExecutor2,
    ) -> Result<bool> {
        if self
            .check_issued(artifact, &request.subject, generation, now_ms)
            .is_err()
            || executor.backend != artifact.backend
            || executor.backend == SandboxBackend::Noop
            || (artifact.minimum_isolation == IsolationLevel2::Kernel
                && !suitable_for_untrusted(executor))
            || (artifact.minimum_isolation == IsolationLevel2::Process
                && (!request.accept_process_isolation
                    || executor.isolation == IsolationLevel2::None))
            || artifact.generation != generation
            || now_ms >= artifact.expires_at_ms
            || artifact.executor_id != executor.executor_id
            || artifact.capability_id != executor.capability_id
            || !executor.available
            || !artifact.constraints.iter().all(|c| {
                if artifact.minimum_isolation == IsolationLevel2::Process {
                    supports_best_effort(executor, *c)
                } else {
                    supports(executor, *c)
                }
            })
        {
            return Ok(false);
        }
        let Some(issued) = artifact
            .expires_at_ms
            .checked_sub(u64::from(request.ttl_ms))
        else {
            return Ok(false);
        };
        let expected = self.resolve(request, generation, issued).ok();
        let mut normalized = artifact.clone();
        normalized.plan_id.clear();
        normalized.approval_reservation_id = None;
        Ok(expected.as_ref() == Some(&normalized) && now_ms >= issued)
    }
}
/// The executor identity of a planned run on the host.
const HOST_EXECUTOR: &str = "host";
/// Bind the exact original request and plan into the artifact's fingerprint.
fn seal(
    request: &SandboxPlanRequest2,
    artifact: &mut SandboxArtifact2,
    operation: serde_json::Value,
) -> std::result::Result<(), SandboxDenial2> {
    let mut original =
        serde_json::to_value((request, &*artifact)).map_err(|_| SandboxDenial2::InvalidRequest)?;
    original[0]["operation_json"] = operation;
    original.sort_all_objects();
    let mut hash = Sha256::new();
    hash.update(b"tinysecurity/sandbox-plan/v2\0");
    hash.update(serde_json::to_vec(&original).map_err(|_| SandboxDenial2::InvalidRequest)?);
    artifact.fingerprint = format!("{:x}", hash.finalize());
    Ok(())
}
pub(crate) fn denied(generation: u64, reason: SandboxDenial2) -> SandboxPlanResponse2 {
    SandboxPlanResponse2 {
        decision: Decision {
            generation,
            verdict: Verdict::Deny {
                reason: match reason {
                    SandboxDenial2::Floor => DenialReason::Floor,
                    SandboxDenial2::Path | SandboxDenial2::Ceiling => DenialReason::PathScope,
                    SandboxDenial2::Unsupported => DenialReason::UnsupportedEffect,
                    SandboxDenial2::Approval | SandboxDenial2::Audit => {
                        DenialReason::ApprovalUnavailable
                    }
                    _ => DenialReason::InvalidContext,
                },
            },
            cacheable: false,
        },
        denial: Some(reason),
        artifact: None,
        audit: None,
    }
}
#[cfg(test)]
#[path = "executor_choice_tests.rs"]
mod executor_choice_tests;
#[cfg(test)]
#[path = "operator_options_tests.rs"]
mod operator_options_tests;
#[cfg(test)]
#[path = "plan_matrix_tests.rs"]
mod plan_matrix_tests;
#[cfg(test)]
#[path = "runtime_scopes_tests.rs"]
mod runtime_scopes_tests;
#[cfg(test)]
#[path = "engine_tests.rs"]
pub(crate) mod tests;
