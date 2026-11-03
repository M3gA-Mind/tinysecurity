//! Typed native permission checks with durable audit before a result is exposed.
use serde::{Deserialize, Serialize};

/// Read-only permission operations supported by the audited native boundary. This closed
/// vocabulary cannot invoke secret, approval, sandbox, or execution members.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PermissionRequest2 {
    /// Resolve and authorize an existing file.
    ValidatePath(crate::PathValidationRequest),
    /// Resolve and authorize a prospective destination parent.
    ValidateParent(crate::PathValidationRequest),
    /// Check one path against its registered scope.
    CheckPath(crate::PathCheckRequest),
    /// Check an ordered batch against its registered scope.
    CheckPaths(crate::PathBatchRequest2),
    /// Check command policy without reserving an action; execution still needs its own reservation.
    GateCommand(crate::CommandRequest),
    /// Inspect the registered hourly budget without spending.
    PeekBudget(crate::BudgetRequest2),
    /// Apply the descriptor-level disclosure policy.
    PrivacyCheck(crate::PrivacyCheckRequest2),
}
impl std::fmt::Debug for PermissionRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PermissionRequest2([REDACTED])")
    }
}

/// A computed permission result, exposed only after its audit is permitted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "result",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PermissionResult2 {
    /// Result of existing-path or prospective-parent validation.
    Path(crate::PathValidationResult),
    /// Result of one path check.
    PathAllowed(bool),
    /// Results of an ordered path batch.
    Paths(crate::PathBatchResponse2),
    /// Result of the registered command check.
    Command(crate::CommandDecision),
    /// Result of an action-budget peek.
    Budget(crate::BudgetDecision2),
    /// Result of the disclosure policy.
    Privacy(crate::PrivacyCheckResponse2),
}

/// Original permission operation and stable host correlation. No caller verdict.
pub type PermissionAuditRequest2 = crate::AuditedRequest2<PermissionRequest2>;
/// A result is absent on lost audit, stale generation, or indeterminate receipt.
/// The exact evidence is retained so the host can reconcile a committed event.
pub type PermissionAuditResponse2 = crate::AuditedResponse2<Option<PermissionResult2>>;
