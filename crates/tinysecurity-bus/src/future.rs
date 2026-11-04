//! Reserved contracts plus compatibility re-exports for promoted redaction types.
pub use crate::redact::{
    RedactMode, RedactRequest, RedactResponse, ScanPromptRequest, ScanResponse,
    ScanToolDefinitionRequest, ScanVerdict,
};
use crate::{CallerContext, Decision};
use serde::{Deserialize, Serialize};
/// `ApprovalState` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Pending state.
    Pending,
    /// Allowed state.
    Allowed,
    /// Denied state.
    Denied,
    /// Expired state.
    Expired,
    /// Executed state.
    Executed,
}
/// Terminal execution result, including runs abandoned before their effects were known.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Succeeded state.
    Succeeded,
    /// Failed state.
    Failed,
    /// Cancelled state.
    Cancelled,
    /// The in-flight execution was abandoned before its effects could be determined.
    Abandoned,
}
/// `ReplyVerdict` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyVerdict {
    /// `AllowOnce` state.
    AllowOnce,
    /// Deny state.
    Deny,
    /// Unrecognized state.
    Unrecognized,
}

/// `SourceTrust` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTrust {
    /// `TrustedHost` state.
    TrustedHost,
    /// `UntrustedMcp` state.
    UntrustedMcp,
    /// `UntrustedSkill` state.
    UntrustedSkill,
    /// Downloaded state.
    Downloaded,
}
/// `SandboxBackend` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    /// Kernel namespace isolation. Legacy `firejail` and `bubblewrap` host
    /// settings map here; the module never plans them as separate backends.
    Namespace,
    /// `MicroVm` state.
    MicroVm,
    /// Path-jail executor. It is planned only when it reports enforced kernel
    /// isolation, so an untrusted tier never receives a best-effort jail.
    Jail,
    /// Docker state.
    Docker,
    /// Noop state.
    Noop,
}
/// `NetworkPolicy` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// None state.
    None,
    /// `EgressProxy` state.
    EgressProxy,
    /// Host state.
    Host,
}
/// `AuditKind` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// `PolicyChanged` state.
    PolicyChanged,
    /// Approval state.
    Approval,
    /// Judge state.
    Judge,
    /// Execution state.
    Execution,
    /// Sandbox state.
    Sandbox,
}
/// `StoreOperation` vocabulary, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreOperation {
    /// `LoadPending` state.
    LoadPending,
    /// `LoadDecisions` state.
    LoadDecisions,
    /// Persist state.
    Persist,
}
/// `ApprovalDecision` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecision {
    /// Persisted request identity.
    pub request_id: String,
    /// Human verdict.
    pub allow: bool,
    /// Verified deciding identity.
    pub caller: CallerContext,
}
/// `ApprovalRecord` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    /// Persisted approval identity.
    pub request_id: String,
    /// Canonical original call fingerprint.
    pub fingerprint: String,
    /// Original verified caller.
    pub caller: CallerContext,
    /// Absolute expiration in host clock milliseconds.
    pub expires_at_ms: u64,
    /// Durable lifecycle state.
    pub state: ApprovalState,
}
/// `ListPendingRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPendingRequest {
    /// Verified scope identity.
    pub caller: CallerContext,
}
/// `ListPendingResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPendingResponse {
    /// Pending records within caller scope.
    pub records: Vec<ApprovalRecord>,
}
/// `ListDecisionsRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListDecisionsRequest {
    /// Verified scope identity.
    pub caller: CallerContext,
    /// Bounded result limit.
    pub limit: u32,
}
/// `ListDecisionsResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListDecisionsResponse {
    /// Scoped durable records.
    pub records: Vec<ApprovalRecord>,
}
/// `RecordExecutionRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordExecutionRequest {
    /// Approval identity.
    pub request_id: String,
    /// Executed call fingerprint.
    pub fingerprint: String,
    /// Verified executor.
    pub caller: CallerContext,
    /// Terminal execution result.
    pub outcome: ExecutionOutcome,
}
/// `RecordExecutionResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordExecutionResponse {
    /// True only after confirmed persistence.
    pub committed: bool,
}
/// `PreauthorizeFlowRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreauthorizeFlowRequest {
    /// Verified origin and flow.
    pub caller: CallerContext,
    /// Exact reviewed call fingerprints.
    pub fingerprints: Vec<String>,
    /// Bounded expiration.
    pub expires_at_ms: u64,
}
/// `PreauthorizeFlowResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreauthorizeFlowResponse {
    /// Persisted grant identity.
    pub grant_id: String,
}
/// `ParseReplyRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParseReplyRequest {
    /// Pending identity.
    pub request_id: String,
    /// User reply; never persisted without redaction.
    pub reply: String,
}
/// `ParseReplyResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParseReplyResponse {
    /// Parsed intent, not permission by itself.
    pub verdict: ReplyVerdict,
}

/// `SandboxPlanRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPlanRequest {
    /// Verified access and origin.
    pub caller: CallerContext,
    /// Executable source trust.
    pub source: SourceTrust,
    /// Backends actually supported by the executor.
    pub capabilities: Vec<SandboxBackend>,
    /// Requested filesystem reach.
    pub grants: Vec<PathGrant>,
    /// Requested network reach.
    pub network: NetworkPolicy,
    /// Requested bounded resources.
    pub limits: ResourceLimits,
}
/// `SandboxPlanResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPlanResponse {
    /// Policy authorization.
    pub decision: Decision,
    /// Approved backend, absent on denial.
    pub backend: Option<SandboxBackend>,
    /// Effective filesystem grants.
    pub grants: Vec<PathGrant>,
    /// Effective network policy.
    pub network: NetworkPolicy,
    /// Effective resource limits.
    pub limits: ResourceLimits,
}
/// `PathGrant` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathGrant {
    /// Absolute grant root.
    pub path: String,
    /// Write authorization.
    pub write: bool,
}
/// `ResourceLimits` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Memory ceiling.
    pub memory_bytes: u64,
    /// CPU time ceiling.
    pub cpu_millis: u64,
    /// Process count ceiling.
    pub processes: u32,
}

/// `AuditRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRequest {
    /// Sanitized audit event.
    pub event: AuditEvent,
    /// Whether a persistence failure denies the associated operation.
    pub required: bool,
}
/// `AuditResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditResponse {
    /// True only after confirmed sink persistence.
    pub committed: bool,
}
/// `AuditEvent` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    /// Policy generation.
    pub generation: u64,
    /// Verified subject context.
    pub caller: CallerContext,
    /// Event category.
    pub kind: AuditKind,
    /// Sanitized actor attribution.
    pub attribution: String,
    /// Content-free applied rules.
    pub rule_ids: Vec<String>,
}
/// `ApprovalStoreRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStoreRequest {
    /// Load or persist operation.
    pub operation: StoreOperation,
    /// Verified scoped caller.
    pub caller: CallerContext,
    /// Records to persist, empty for reads.
    pub records: Vec<ApprovalRecord>,
}
/// `ApprovalStoreResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStoreResponse {
    /// Persisted scoped records.
    pub records: Vec<ApprovalRecord>,
    /// Whether requested writes are durably committed.
    pub committed: bool,
}
/// `ApprovalPromptRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPromptRequest {
    /// Approval awaiting the human.
    pub record: ApprovalRecord,
    /// Redacted user-facing summary.
    pub summary: String,
    /// Bounded callback deadline.
    pub timeout_ms: u32,
}
/// `ApprovalPromptResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPromptResponse {
    /// Verified human reply, absent if unavailable.
    pub decision: Option<ApprovalDecision>,
}
/// `AuditSinkRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkRequest {
    /// Sanitized ordered events.
    pub events: Vec<AuditEvent>,
    /// Bounded callback deadline.
    pub timeout_ms: u32,
}
/// `AuditSinkResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkResponse {
    /// True only after durable append.
    pub committed: bool,
}
/// `KeyringConsentRequest` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConsentRequest {
    /// Verified requesting identity.
    pub caller: CallerContext,
    /// Redacted purpose.
    pub purpose: String,
    /// Bounded wait.
    pub timeout_ms: u32,
}
/// `KeyringConsentResponse` payload, reserved until its engine is implemented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConsentResponse {
    /// Verified human consent.
    pub allowed: bool,
}
/// Verified human decision supplied to the reserved Decide member.
pub type DecideRequest = ApprovalDecision;
/// Durable record returned after the reserved Decide member confirms storage.
pub type DecideResponse = ApprovalRecord;
