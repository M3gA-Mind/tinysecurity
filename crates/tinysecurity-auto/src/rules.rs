//! Verified-scope approval shortcuts, with Cron and `SaaS` constraints first.
use tinysecurity_bus::{ApprovalScope2, Origin};
/// Rule outcome, consumed only through durable CAS and required audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// External Cron effect is a mandatory denial.
    Deny,
    /// Verified host scope allows automatic one-shot approval.
    Automatic,
    /// An authenticated human or explicitly configured judge is required.
    Approval,
    /// Origin the host could not label: no human is asked, no judge scores it and no
    /// posture approves it. Only an exact whole-tool grant of the scope can.
    GrantOnly,
}
/// Classify only a verified registered origin and concrete effect.
#[must_use]
pub fn evaluate(scope: &ApprovalScope2, origin: &Origin, external: bool) -> Rule {
    if external && *origin == Origin::Cron {
        return Rule::Deny;
    }
    match origin {
        // The host's own pre-declared automation and a local operator never park.
        Origin::TrustedAutomation | Origin::LocalOperator => return Rule::Automatic,
        Origin::Unlabelled | Origin::Unknown => return Rule::GrantOnly,
        _ => {}
    }
    if *origin != Origin::Saas
        && (scope.auto_approve_all || !scope.require_approval || *origin == Origin::Cron)
    {
        Rule::Automatic
    } else {
        Rule::Approval
    }
}
#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
