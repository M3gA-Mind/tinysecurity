//! Durable exact approvals; legacy reserved payloads remain wire-compatible.
use crate::{
    AccessTier, AuditCorrelation2, CallerContext, EvaluateRequest, ExecutionOutcome, Origin,
    SubjectScope,
};
use serde::{Deserialize, Serialize};
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+};
}
/// Init-only immutable approvals and trusted callback configuration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig2 {
    /// Finite callback deadline in 1..=30000 milliseconds.
    pub timeout_ms: u32,
    /// Explicit verified-host subject registrations, bounded to 128.
    pub scopes: Vec<ApprovalScope2>,
}
/// Immutable owner registration; not a fully composed policy identifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScope2 {
    /// Opaque registration identity, never selected from model arguments.
    pub scope_id: String,
    /// Verified original user/workspace/agent subject.
    pub subject: SubjectScope,
    /// Immutable current partial policy reference.
    pub policy_ref: String,
    /// Current generation for the reference.
    pub generation: u64,
    /// Verified maximum authority.
    pub ceiling: AccessTier,
    /// Require explicit approval even for otherwise permitted operations.
    pub require_approval: bool,
    /// Explicit automatic approval; never overrides a denial or Cron external effects.
    pub auto_approve_all: bool,
}
/// Permission request selected by the trusted host adapter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateApprovalRequest2 {
    /// Trusted registration identity.
    pub scope_id: String,
    /// Actual original operation and verified context.
    pub request: EvaluateRequest,
    /// Optional caller deadline; may only shorten default expiration.
    pub ttl_ms: Option<u64>,
    /// User-facing summary, sanitized before persistence.
    pub summary: String,
    /// Exact host-reserved ordered audit correlation.
    pub audit: AuditCorrelation2,
}
/// Supported human choices; reusable grants retain exact reviewed arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChoice2 {
    /// Permit one execution only.
    Once,
    /// Permit exactly this reviewed tool and content in the same bound context.
    Tool,
    /// Permit exactly reviewed content in the same flow.
    Flow,
    /// Refuse execution.
    Deny,
}
/// Durable lifecycle. Reservation is irreversible before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLifecycle2 {
    /// Durably pending human action.
    Pending,
    /// Exact authenticated human or explicit automatic permission.
    Approved,
    /// Human refusal.
    Denied,
    /// Deadline elapsed or clock rollback.
    Expired,
    /// Host cancellation.
    Cancelled,
    /// Once-only execution reservation consumed before dispatch.
    Reserved,
    /// Immutable execution outcome.
    Executed,
}
/// Versioned full binding; 32-hex callback fingerprint is correlation only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding2 {
    /// Fixed canonical digest vocabulary, currently one.
    pub binding_version: u32,
    /// Sanitized durable subject mapped by the trusted host.
    pub scope: SubjectScope,
    /// Immutable partial-policy reference.
    pub policy_ref: String,
    /// Reviewed generation.
    pub generation: u64,
    /// Exact original-call SHA-256, including execution instance.
    pub call_sha256: String,
    /// Exact reusable-content SHA-256, excluding only execution instance.
    pub content_sha256: String,
    /// Verified origin.
    pub origin: Origin,
    /// Sanitized original context and execution correlation.
    pub caller: CallerContext,
}
/// Sanitized, strictly parsed versioned lifecycle JSON inside `ApprovalRecord2`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRow2 {
    /// Random durable request identity.
    pub request_id: String,
    /// Exact CAS version, cross-checked against outer row.
    pub version: u64,
    /// Full immutable call authority.
    pub binding: ApprovalBinding2,
    /// Per-host-instance opaque ownership; never exposed in product events.
    pub host_instance: String,
    /// Random prompt nonce.
    pub nonce: String,
    /// Sanitized tool name.
    pub tool_name: String,
    /// Session correlation copied from the trusted caller context, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Redacted audit sink failure detail, capped at 512 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_error: Option<String>,
    /// Concrete effect class derived from actual checks.
    pub external_effect: bool,
    /// Redacted canonical original argument JSON.
    pub args_redacted: String,
    /// Redacted summary.
    pub summary: String,
    /// Creation in epoch milliseconds.
    pub created_at_ms: u64,
    /// Exact expiry in epoch milliseconds.
    pub expires_at_ms: u64,
    /// Current lifecycle.
    pub state: ApprovalLifecycle2,
    /// Exact approved grant kind, absent until decision.
    pub choice: Option<ApprovalChoice2>,
    /// Verified sanitized human or automatic attribution.
    pub attribution: Option<String>,
    /// Exact idempotent decision ticket correlation.
    pub decision_ticket_sha256: Option<String>,
    /// Terminal execution result, absent before execution.
    pub outcome: Option<ExecutionOutcome>,
    /// Random reservation winner; identical CAS retries never create a second executor.
    pub reservation_id: Option<String>,
    /// Sanitized legacy history only; never grants exact new authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_history_json: Option<String>,
    /// Sanitized immutable judge evidence; omitted for legacy approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<crate::JudgeEvidence2>,
    /// Immutable audit correlation of this version.
    pub audit: AuditCorrelation2,
}
/// Exact pending binding sent only after confirmed store and audit receipts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDeliveryRequest2 {
    /// Exact durable pending row.
    pub row: ApprovalRow2,
}
/// Delivery acknowledgment grants no permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDeliveryResponse2 {
    /// Exact request identity.
    pub request_id: String,
    /// Exact prompt nonce.
    pub nonce: String,
    /// True only if the verified per-user prompt was delivered.
    pub delivered: bool,
}
/// Human action represented by a private opaque host ticket, not caller claims.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Exact pending request.
    pub request_id: String,
    /// Opaque host ticket issued only by authenticated human UI/session action.
    pub decision_ticket: String,
    /// Exact next-version audit identity.
    pub audit: AuditCorrelation2,
}
/// Host must verify this against its private authenticated-human ticket ledger.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyHumanRequest2 {
    /// Exact pending row, including nonce, expiration and full binding.
    pub row: ApprovalRow2,
    /// Private decision ticket; never persisted or logged.
    pub decision_ticket: String,
}
/// Authenticated host receipt; generic human booleans cannot satisfy it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDecisionReceipt2 {
    /// Exact reviewed row, including every immutable binding.
    pub row: ApprovalRow2,
    /// SHA-256 correlation of the exact ticket; not its plaintext.
    pub ticket_sha256: String,
    /// Host-authenticated verified deciding actor, sanitized before storage.
    pub actor: String,
    /// Choice verified by the host's private ticket ledger.
    pub choice: ApprovalChoice2,
}
/// Exact action used for reservation or terminal execution.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalActionRequest2 {
    /// Trusted subject registration.
    pub scope_id: String,
    /// Exact durable request identity.
    pub request_id: String,
    /// Actual original operation, rehashed by the owner.
    pub request: EvaluateRequest,
    /// Exact audit phase.
    pub audit: AuditCorrelation2,
}
/// Terminal outcome requires an exact consumed execution reservation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordExecutionRequest2 {
    /// Exact original executed action.
    pub action: ApprovalActionRequest2,
    /// Immutable terminal outcome.
    pub outcome: ExecutionOutcome,
}
/// Record a sanitized diagnostic after the host's audit sink failed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordAuditErrorRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Exact durable approval row.
    pub request_id: String,
    /// Raw sink error; the engine redacts and caps it before persistence.
    pub audit_error: String,
    /// Exact next-version audit correlation for the metadata CAS.
    pub audit: AuditCorrelation2,
}
/// Scoped listing, expiry or cancellation request; no ambient subject lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecordRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Exact request identity; empty is valid only for listing.
    pub request_id: String,
    /// Audit correlation for lifecycle changes.
    pub audit: AuditCorrelation2,
}
/// Bounded cross-scope recent-decision read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentApprovalDecisionsRequest2 {
    /// Maximum number of rows, clamped by the engine to 1..=500.
    pub limit: usize,
}
/// Cross-scope request to remove undecided rows for one session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeApprovalSessionRequest2 {
    /// Raw host session identity, redacted once by the engine before store calls.
    pub session_id: String,
}
impl std::fmt::Debug for PurgeApprovalSessionRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PurgeApprovalSessionRequest2([REDACTED])")
    }
}
/// Bounded flow review referencing already human-reviewed exact rows.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreauthorizeFlowRequest2 {
    /// Trusted registration.
    pub scope_id: String,
    /// Exact nonblank reviewed flow.
    pub flow_id: String,
    /// Exact approved request IDs, at most 100; no tool-name wildcard.
    pub request_ids: Vec<String>,
}
redacted_debug!(
    ApprovalConfig2,
    ApprovalScope2,
    EvaluateApprovalRequest2,
    ApprovalBinding2,
    ApprovalRow2,
    ApprovalDeliveryRequest2,
    ApprovalDeliveryResponse2,
    DecideRequest2,
    VerifyHumanRequest2,
    HumanDecisionReceipt2,
    ApprovalActionRequest2,
    RecordExecutionRequest2,
    RecordAuditErrorRequest2,
    ApprovalRecordRequest2,
    PreauthorizeFlowRequest2
);

/// Permission surface returned only after real durable approval phases.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateApprovalResponse2 {
    /// Pending yields `RequireApproval`; only approved state yields `Allow`.
    pub decision: crate::Decision,
    /// Sanitized durable lifecycle projection; host routes product events separately.
    pub record: ApprovalRow2,
}
redacted_debug!(EvaluateApprovalResponse2);

/// Trusted bounded migration preserving history without reviving legacy broad grants.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalHistoryImport2 {
    /// Verified registered owner; imported caller JSON supplies no authority.
    pub scope_id: String,
    /// Historical reserved-wire record, sanitized before durable storage.
    pub legacy: crate::ApprovalRecord,
    /// Exact durable migration audit phase.
    pub audit: AuditCorrelation2,
}
redacted_debug!(ApprovalHistoryImport2);

impl ExecutionOutcome {
    /// Explicit host compatibility translation; new wire names remain unchanged.
    /// # Errors
    /// Rejects any unknown legacy outcome rather than guessing.
    pub fn from_legacy(value: &str) -> crate::Result<Self> {
        match value {
            "success" => Ok(Self::Succeeded),
            "failure" => Ok(Self::Failed),
            "aborted" => Ok(Self::Cancelled),
            _ => Err(crate::Error::InvalidArguments),
        }
    }
}
#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
