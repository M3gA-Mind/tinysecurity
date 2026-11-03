//! Immutable private host command scopes and noncacheable execution reservations.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
/// Agent's acting autonomy tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandAutonomy {
    /// Observation only.
    ReadOnly,
    /// Ask before acting.
    Supervised,
    /// Full access. Harness execution still prompts for network/install/destructive
    /// classes; legacy allowlisted execution uses only configured risk restrictions.
    Full,
}
/// Deterministic permission bucket in increasing severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    /// Curated observational commands.
    Read,
    /// Mutating or unknown commands.
    Write,
    /// Network access.
    Network,
    /// Global package installation.
    Install,
    /// Destructive or privileged operations.
    Destructive,
}
/// Legacy host command risk score, independent of class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandRisk {
    /// Routine observation.
    Low,
    /// Mutating or arbitrary-code execution.
    Medium,
    /// Irreversible or system control.
    High,
}
/// Gate result; a prompt is never permission to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandGate {
    /// May execute once after this noncacheable check.
    Allow,
    /// Host must park for a separately verified approval lifecycle.
    Prompt,
    /// Refuse outright.
    Block,
}
/// Stable content-free rejection categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandDenial {
    /// Unconditional literal credential/system/traversal floor.
    Protected,
    /// Read-only autonomy cannot act.
    ReadOnly,
    /// Hidden execution or off-allowlist executable/arguments.
    Command,
    /// Configured high risk prohibition.
    HighRisk,
    /// Hourly budget exhausted.
    RateLimit,
}
/// Trusted host's execution integration; requests cannot change this mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandExecutionMode {
    /// Harness class gate plus hidden execution defense; allowlist is diagnostic.
    HarnessGated,
    /// Legacy curated allowlist plus command risk restrictions.
    Allowlisted,
}
/// Shell grammar selected by the trusted host that executes the command.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellDialect {
    /// POSIX shell quoting and backslash escapes.
    #[default]
    Posix,
    /// `PowerShell` quoting and backtick escapes.
    PowerShell,
    /// Windows command interpreter quoting and caret escapes.
    Cmd,
}
/// Immutable settings registered by a trusted host for one acting agent.
/// Registering identical settings creates a distinct budget. Reinit never resets it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicy {
    /// Disable discretionary enforcement, retaining the literal protected floor.
    pub enabled: bool,
    /// Host execution integration, fixed for this scope.
    pub execution_mode: CommandExecutionMode,
    /// Actual execution backend grammar; requests cannot override it.
    #[serde(default)]
    pub shell_dialect: ShellDialect,
    /// Acting tier.
    pub autonomy: CommandAutonomy,
    /// Curated executable basenames for supervised legacy execution.
    pub allowed_commands: Vec<String>,
    /// Atomic allowed-execution reservation limit over a sliding hour.
    pub max_actions_per_hour: u32,
    /// Legacy supervised medium-risk approval requirement.
    pub require_approval_for_medium_risk: bool,
    /// Refuse high-risk commands even if full access.
    pub block_high_risk_commands: bool,
    /// Host-derived absolute acting directory for literal floor checks.
    pub action_dir: PathBuf,
    /// Host-derived absolute home; never reads the module environment.
    pub home_dir: Option<PathBuf>,
}
/// Opaque private scope reference; never exposes settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicyId(pub String);
/// Host-derived actual command invocation. Keep scope IDs and commands on a
/// confidential bus; neither registration nor invocation authenticates the caller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    /// Registered agent's scope.
    pub policy_id: CommandPolicyId,
    /// Actual executable input, never an LLM summary.
    pub command: String,
    /// Escalate-only hint; cannot lower the deterministic class.
    pub declared_class: Option<CommandClass>,
}
impl std::fmt::Debug for CommandRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandRequest")
            .field("command", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
/// Content-free result. Classify is informational and cannot authorize execution.
/// Check reserves one action atomically for Allow; repeated calls reserve again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDecision {
    /// Deterministic class raised by any declared hint.
    pub class: CommandClass,
    /// Legacy risk diagnostic.
    pub risk: CommandRisk,
    /// Execution gate.
    pub gate: CommandGate,
    /// Stable reason for a block; no command/arguments/error strings.
    pub denial: Option<CommandDenial>,
}

/// Original host-derived command checked before execution with stable audit correlation.
pub type CheckCommandAuditedRequest2 = crate::AuditedRequest2<CommandRequest>;

/// Command decision exposed only after its execution reservation is durably audited.
pub type CheckCommandAuditedResponse2 = crate::AuditedResponse2<Option<CommandDecision>>;

#[cfg(test)]
#[path = "command_policy_tests.rs"]
mod tests;
