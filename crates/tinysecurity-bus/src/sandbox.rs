//! Scoped declarative sandbox planning. Only trusted native initialization supplies facts.
use crate::{
    AccessTier, AuditCorrelation2, AuditResponse2, Decision, NetworkPolicy, Origin, PathGrant,
    PathPolicy, SandboxBackend, SourceTrust, SubjectScope,
};
use serde::{Deserialize, Serialize};
/// Actual executor support, verified by the trusted host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintEnforcement2 {
    /// The executor enforces this exact constraint.
    Enforced,
    /// An approximation; never sufficient for a hard requirement.
    BestEffort,
    /// The executor cannot enforce this constraint.
    Unsupported,
}
/// Verified isolation level; a backend name is not evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel2 {
    /// No process boundary.
    None,
    /// Process-level restriction only.
    Process,
    /// Kernel namespace or equivalent verified isolation.
    Kernel,
    /// A separate verified guest kernel.
    MicroVm,
}
/// Hard execution requirements carried in the artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxConstraint2 {
    /// Filesystem grants and floor.
    Filesystem,
    /// The exact network policy.
    Network,
    /// CPU throughput in thousandths of one core.
    CpuMillicores,
    /// Consumed CPU time in milliseconds.
    CpuTime,
    /// Memory ceiling in bytes.
    Memory,
    /// Maximum process count.
    Processes,
    /// Disk ceiling in bytes.
    Disk,
    /// Deny child process creation.
    Subprocesses,
}
/// A verified executor declaration for one constraint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintSupport2 {
    /// Constraint identity.
    pub constraint: SandboxConstraint2,
    /// Actual support.
    pub enforcement: ConstraintEnforcement2,
}
/// Optional positive hard bounds; None means no bound, never zero or unlimited sentinel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits2 {
    /// Consumed CPU time. Current `TinyBox` has no enforceable mapping; requests deny.
    pub cpu_time_ms: Option<u64>,
    /// CPU throughput: 1000 is one core. Maps only to `TinyBox` `cpu_millis`.
    pub cpu_millicores: Option<u32>,
    /// Memory bytes.
    pub memory_bytes: Option<u64>,
    /// Maximum process count.
    pub pids_max: Option<u32>,
    /// Disk bytes.
    pub disk_bytes: Option<u64>,
}
/// Init-only capability snapshot, never accepted from planning arguments.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxExecutor2 {
    /// Bound executor identity.
    pub executor_id: String,
    /// Verified capability revision or digest; execution must revalidate it.
    pub capability_id: String,
    /// Mechanical backend vocabulary.
    pub backend: SandboxBackend,
    /// Availability verified at initialization; not a spawn guarantee.
    pub available: bool,
    /// Verified isolation level.
    pub isolation: IsolationLevel2,
    /// Exact declared support. Duplicate constraints reject initialization.
    pub constraints: Vec<ConstraintSupport2>,
}
impl std::fmt::Debug for SandboxExecutor2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxExecutor2([REDACTED])")
    }
}
/// Init-only source provenance admitted by the authenticated host.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSource2 {
    /// Opaque source identity.
    pub source_id: String,
    /// Verified immutable installation/content identity.
    pub provenance: String,
    /// Trust derived by the host, never a model claim.
    pub trust: SourceTrust,
}
impl std::fmt::Debug for SandboxSource2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxSource2([REDACTED])")
    }
}
/// Init-only transport capability; a URL string cannot establish enforcement.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProxy2 {
    /// Verified transport identity.
    pub proxy_id: String,
    /// Executor whose egress is exclusively mediated.
    pub executor_id: String,
    /// Exact verified executor capability revision.
    pub capability_id: String,
    /// Transport revalidates and pins approved DNS destinations/redirects.
    pub pinned_destinations: bool,
    /// Executor cannot bypass the mediated egress route.
    pub exclusive_egress: bool,
}
impl std::fmt::Debug for SandboxProxy2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxProxy2([REDACTED])")
    }
}
/// Immutable native host facts and ceilings. Narrowed policy cannot widen these.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxScope2 {
    /// Exact immutable human approval registration for host networking.
    pub approval_scope_id: Option<String>,
    /// Opaque registration identity.
    pub scope_id: String,
    /// Verified user/workspace/agent owner.
    pub subject: SubjectScope,
    /// Verified execution origin.
    pub origin: Origin,
    /// Maximum acting authority.
    pub tier: AccessTier,
    /// Verified deployment mode; mandatory isolation precedes all overrides.
    pub deployment: SandboxDeployment2,
    /// Verified environment override, relevant only to trusted local execution.
    pub environment: SandboxSetting2,
    /// Verified agent-mode isolation request.
    pub agent_mode: SandboxSetting2,
    /// Verified configuration isolation request.
    pub configured: SandboxSetting2,
    /// Owner filesystem policy, including internal-state reservations.
    pub paths: PathPolicy,
    /// Maximum grant reach and write authority.
    pub grant_ceiling: Vec<PathGrant>,
    /// Maximum admitted network reach.
    pub network_ceiling: NetworkPolicy,
    /// The owner's configuration already grants the host's own network up to
    /// `network_ceiling` (contract 1.21), so a plan for it needs no per-command human
    /// approval. Ignored in a `SaaS` deployment or origin, where host networking always
    /// needs an exact human approval. Absent means a human approval is required.
    #[serde(default)]
    pub operator_host_network: bool,
    /// Mandatory upper bounds; caller cannot remove or raise these.
    pub limits: ResourceLimits2,
    /// Immutable source provenance registry.
    pub sources: Vec<SandboxSource2>,
    /// Actual verified executor snapshots.
    pub executors: Vec<SandboxExecutor2>,
    /// Verified exclusive egress mediation.
    pub proxy: Option<SandboxProxy2>,
    /// Maximum artifact lifetime, at most five minutes.
    pub max_ttl_ms: u32,
}
impl std::fmt::Debug for SandboxScope2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxScope2([REDACTED])")
    }
}
/// Trusted SDK initialization only; unavailable configuration never becomes a fallback.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig2 {
    /// At most 128 immutable subject registrations.
    pub scopes: Vec<SandboxScope2>,
}
impl std::fmt::Debug for SandboxConfig2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxConfig2([REDACTED])")
    }
}
/// Requested operation only; trust, environment and executor facts derive from registration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPlanRequest2 {
    /// Exact authenticated human grant to reserve once, never a boolean permission.
    pub host_approval: Option<SandboxApprovalUse2>,
    /// Registered owner scope.
    pub scope_id: String,
    /// Host-derived requesting owner; must exactly match registration.
    pub subject: SubjectScope,
    /// Registered executable source.
    pub source_id: String,
    /// Expected immutable provenance; mismatches deny.
    pub provenance: String,
    /// Host-owned execution identity.
    pub call_id: String,
    /// Original argv/cwd/environment/input operation; canonical binding, never logged raw.
    pub operation_json: String,
    /// Requested filesystem roots and access.
    pub grants: Vec<PathGrant>,
    /// Requested reach.
    pub network: NetworkPolicy,
    /// Requested bounds, including every mandatory configured bound.
    pub limits: ResourceLimits2,
    /// Require child-process denial.
    pub deny_subprocesses: bool,
    /// The command is an ordinary tool command of the scope's operator (contract 1.21),
    /// so a process-level jail whose constraints are best effort (such as macOS Seatbelt)
    /// may provide trusted folder confinement. Honoured only for a trusted host source
    /// outside `SaaS`; a plan for untrusted code or mandatory isolation is refused when it
    /// sets this. Absent means the executor must meet the kernel-isolation floor with
    /// exactly enforced constraints.
    #[serde(default)]
    pub accept_process_isolation: bool,
    /// Additional credential files known to the trusted host. `TinySecurity` merges these
    /// with native credential roots for an allow-default folder jail and returns the
    /// canonical list in the artifact's `deny_read` field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_denials: Vec<std::path::PathBuf>,
    /// Executor preference, workspace-less and host-run options (contract 1.22). Absent
    /// means the module chooses the executor and the plan grants what is requested.
    #[serde(default, skip_serializing_if = "SandboxPlanOptions2::is_default")]
    pub options: SandboxPlanOptions2,
    /// Current policy generation.
    pub generation: u64,
    /// Requested artifact lifetime.
    pub ttl_ms: u32,
    /// Exact original plan/decision audit correlation.
    pub audit: AuditCorrelation2,
}
impl std::fmt::Debug for SandboxPlanRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxPlanRequest2([REDACTED])")
    }
}
/// Optional planning requests of one spawn (contract 1.22). Every field defaults to off, so
/// a 1.21 host keeps its behaviour against a 1.22 module and an older module refuses a
/// request that sets one (`deny_unknown_fields`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPlanOptions2 {
    /// The backend the owner's configuration prefers. The module plans onto an eligible
    /// executor of this backend first; it never makes an ineligible executor eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_backend: Option<SandboxBackend>,
    /// Plan only onto an executor of `preferred_backend`: no eligible one is `unsupported`
    /// instead of another executor. Ignored without a preferred backend.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_preferred_backend: bool,
    /// The spawn needs no workspace (a container with no workspace mount). The plan
    /// refuses a writable grant (`ceiling`) and its artifact records `no_workspace`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_workspace: bool,
    /// The operator disabled the sandbox and asks for a run on the host. Issued as a
    /// `host_run` artifact only for a trusted operator source under a local deployment and
    /// origin whose scope carries the disabled `environment` setting; any other request
    /// that sets it is refused (`floor`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_run: bool,
}
impl SandboxPlanOptions2 {
    /// Whether every option is off (the 1.21 shape of a request).
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}
/// Declarative plan, not a confinement attestation or reusable execution authorization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxArtifact2 {
    /// Minimum verified isolation required at launch. `Process` can represent trusted
    /// folder confinement such as Seatbelt; it never represents a kernel-isolation floor.
    pub minimum_isolation: IsolationLevel2,
    /// Opaque module-issued identity; a public fingerprint never supplies permission.
    pub plan_id: String,
    /// Verified once-only durable approval reservation, when host networking is granted.
    pub approval_reservation_id: Option<String>,
    /// Module-computed canonical original request/plan binding.
    pub fingerprint: String,
    /// Bound immutable registration.
    pub scope_id: String,
    /// Bound owner.
    pub subject: SubjectScope,
    /// Bound executable source.
    pub source_id: String,
    /// Bound immutable provenance.
    pub provenance: String,
    /// Exact execution identity.
    pub call_id: String,
    /// Policy generation; stale execution denies.
    pub generation: u64,
    /// Bounded expiry; execution checks live time.
    pub expires_at_ms: u64,
    /// Actual selected executor identity.
    pub executor_id: String,
    /// Verified capability revision; live launch checks all constraints again.
    pub capability_id: String,
    /// Selected declarative backend.
    pub backend: SandboxBackend,
    /// Canonical approved roots.
    pub grants: Vec<PathGrant>,
    /// Canonical credential paths to exclude from an allow-default folder jail. Hosts
    /// pass this list directly to `TinyBox` `NativeJailConfig::deny_read`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_read: Vec<std::path::PathBuf>,
    /// Exact admitted reach.
    pub network: NetworkPolicy,
    /// Bound exclusive mediation identity.
    pub proxy_id: Option<String>,
    /// Unit-correct hard bounds.
    pub limits: ResourceLimits2,
    /// Every required constraint must remain Enforced at execution.
    pub constraints: Vec<SandboxConstraint2>,
    /// The operator disabled the sandbox and the module planned a run on the host
    /// (contract 1.22): `backend` is `noop`, `minimum_isolation` is `none` and no grant or
    /// constraint applies. Never issued for `SaaS` or for a source that is not the trusted
    /// operator.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_run: bool,
    /// The plan grants no workspace (contract 1.22): it carries no writable root.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_workspace: bool,
}
impl std::fmt::Debug for SandboxArtifact2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxArtifact2([REDACTED])")
    }
}
/// Stable content-free sandbox denial category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenial2 {
    /// Missing or mismatched immutable authority.
    InvalidContext,
    /// Malformed, excessive or zero-bound request.
    InvalidRequest,
    /// Wrong generation or expired artifact.
    Stale,
    /// Protected root or a grant covering a protected subtree.
    Floor,
    /// Unresolvable path or grant outside immutable reach.
    Path,
    /// Attempt to widen an immutable ceiling.
    Ceiling,
    /// No available executor enforces every hard requirement.
    Unsupported,
    /// Exclusive validated egress mediation is unavailable.
    Proxy,
    /// Host networking requires an exact human approval; unavailable seam denies.
    Approval,
    /// Required canonical audit has no exact confirmed receipt.
    Audit,
}
/// Computed policy verdict, optional declarative artifact and independent audit durability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPlanResponse2 {
    /// Policy permission; never execution confinement evidence.
    pub decision: Decision,
    /// Specific stable denial category.
    pub denial: Option<SandboxDenial2>,
    /// Absent on denial.
    pub artifact: Option<SandboxArtifact2>,
    /// Exact receipt, retained even if a generation race denies permission.
    pub audit: Option<AuditResponse2>,
}
impl std::fmt::Debug for SandboxPlanResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxPlanResponse2([REDACTED])")
    }
}
/// Exact once-only durable human grant consumption correlation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxApprovalUse2 {
    /// Durable authenticated human grant identity.
    pub request_id: String,
    /// Separate exact consumption audit preceding the plan audit.
    pub audit: AuditCorrelation2,
}
impl std::fmt::Debug for SandboxApprovalUse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SandboxApprovalUse2([REDACTED])")
    }
}
/// Create an exact pending sandbox host-network human approval under current policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateSandboxApprovalRequest2 {
    /// Original sandbox operation with no approval claim.
    pub request: SandboxPlanRequest2,
    /// Sanitized human-facing summary.
    pub summary: String,
    /// Durable pending-row audit correlation.
    pub audit: AuditCorrelation2,
}
impl std::fmt::Debug for EvaluateSandboxApprovalRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvaluateSandboxApprovalRequest2([REDACTED])")
    }
}
/// Verified deployment identity; `SaaS` cannot disable isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDeployment2 {
    /// Trusted local host.
    Local,
    /// Remote service deployment.
    Saas,
}
/// Verified host isolation settings; these are init facts, never model parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxSetting2 {
    /// Explicit isolation request.
    Enabled,
    /// Disabled request; immutable `SaaS`/source floors take precedence.
    Disabled,
}
/// Exact registered-artifact execution reservation; live `TinyBox` verification remains host-owned.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeSandboxPlanRequest2 {
    /// Exact original plan envelope derived by the host from the concrete spawn operation.
    /// Changed argv, environment, cwd, input, provenance or constraints never reuse a plan.
    pub request: SandboxPlanRequest2,
    /// Complete expected artifact; any field change or fabricated identifier denies.
    pub artifact: SandboxArtifact2,
    /// Verified requesting owner.
    pub subject: SubjectScope,
    /// Separate exact consume audit correlation.
    pub audit: AuditCorrelation2,
}
impl std::fmt::Debug for ConsumeSandboxPlanRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsumeSandboxPlanRequest2([REDACTED])")
    }
}
/// Once-only execution admission result; no OS confinement attestation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeSandboxPlanResponse2 {
    /// True only after exact audit and atomic module-owned reservation.
    pub permitted: bool,
    /// Content-free refusal reason.
    pub denial: Option<SandboxDenial2>,
    /// Exact durability evidence, retained on stale/replayed denial.
    pub audit: Option<AuditResponse2>,
}
impl std::fmt::Debug for ConsumeSandboxPlanResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsumeSandboxPlanResponse2([REDACTED])")
    }
}
#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
