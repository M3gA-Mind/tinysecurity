//! Policy invocation and SDK configuration types.
use crate::{CommandClass, CommandPolicyId, PolicyId};
use serde::{Deserialize, Serialize};
use std::fmt;
/// Verified host context; never populated directly from model arguments.
///
/// This is a trusted host-to-module contract, not an authentication mechanism.
/// Only the authenticated host adapter may construct it. The host must not expose
/// policy members to untrusted callers or forward their context/check claims.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerContext {
    /// Acting agent identity.
    pub agent: String,
    /// Conversation identity.
    pub thread: Option<String>,
    /// Workflow identity.
    pub flow: Option<String>,
    /// Original call identity.
    pub call_id: String,
    /// Verified request origin.
    pub origin: Origin,
    /// Verified access tier.
    pub tier: AccessTier,
}
/// Origin supplied by the host's authenticated dispatch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Local operator.
    #[default]
    Operator,
    /// Interactive copilot.
    Copilot,
    /// Delegated agent.
    SubAgent,
    /// Scheduled execution.
    Cron,
    /// Remote service caller.
    Saas,
    /// The host's own pre-declared automation: an internal background job or a
    /// workflow action the user already declared (contract 1.22). Approval
    /// evaluation allows it as an audited automatic approval and never parks it.
    TrustedAutomation,
    /// A local operator invoking the core directly, such as the CLI or a direct
    /// chat (contract 1.22). Approval evaluation allows it as an audited automatic
    /// approval and never parks it.
    LocalOperator,
    /// A call whose origin the host could not label (contract 1.22). Approval
    /// evaluation denies it unless the registered scope holds a whole-tool grant for
    /// the tool, which approves it as an audited automatic approval.
    Unlabelled,
    /// Origin classification failed or was unavailable; treated as untrusted.
    Unknown,
}
/// Access ceiling verified by the host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTier {
    /// Reads only.
    #[default]
    Read,
    /// Read and write authority, subject to policy.
    Write,
    /// Operator's full authority, subject to unconditional floor.
    Full,
}
/// Original tool call and complete host-derived checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    /// Stable tool name; unknown names fail closed.
    pub tool: String,
    /// Original arguments encoded as JSON text, never a credential carrier.
    pub arguments_json: String,
    /// Checks derived by the trusted host adapter from the operation it will execute.
    /// Never forward checks supplied by a model, tool client or remote caller.
    pub checks: Vec<Check>,
}

/// Host-computed verdict from scanning a skill before execution (contract 1.29).
/// The host must scan the exact installed document and resources it will expose;
/// this value is a trusted host assertion, never a model-supplied claim. It is
/// supplemental to the host-effect check and cannot authorize a tool call alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillScanVerdict {
    /// No findings require action.
    Pass,
    /// Findings require the existing host approval flow before execution.
    Warn,
    /// The scan found content that must not execute.
    Block,
}

/// A check of a concrete operation. The bootstrap has no URL authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// Filesystem operation over its actual target path.
    Path {
        /// Absolute native target resolved by the host against the operation's actual
        /// working directory. Relative paths fail closed in both policy modes.
        path: String,
        /// Whether mutation is requested.
        write: bool,
    },
    /// Shell command; caller-provided classification is never trusted.
    Command {
        /// Entire command text.
        command: String,
    },
    /// Pure local, side-effect-free diagnostic.
    LocalDiagnostic {},
    /// Replacement of a registered policy; always requires human approval.
    PolicyChange {
        /// SHA-256 over the previous id and the exact replacement.
        digest: String,
    },
    /// A host-registered tool with an external effect the module cannot inspect
    /// beyond its other checks (contract 1.17). Alone it always needs approval; it
    /// never relaxes a path or command check carried beside it, and it is valid only
    /// for tool names outside the reserved effect classes.
    HostTool {},
    /// A host tool judged by its declared permission level (contract 1.20), valid only
    /// for tool names outside the reserved effect classes. Unlike [`Check::HostTool`] it
    /// does not always need approval: the verdict follows the caller's tier, the cron
    /// origin, the registered command scope's autonomy and hourly budget, and the tool's
    /// declared external effect. Admission only: the module authorizes the call, the
    /// host executes it.
    HostAction {
        /// The tool's permission level for these arguments.
        permission: ToolPermission,
        /// Whether the tool declares an external effect for these arguments; a human
        /// must approve it.
        external_effect: bool,
        /// Reserve one action from the scope's hourly budget when the tool acts and no
        /// other check refuses the call. `false` only reads the budget.
        spend: bool,
        /// Registered command scope carrying the autonomy tier and the hourly budget.
        /// Absent, only the tier, origin and external-effect rules apply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_policy: Option<CommandPolicyId>,
    },
    /// A shell command gated under a registered command scope (contract 1.20), valid
    /// only for tool names outside the reserved effect classes. The scope's class gate
    /// decides: allowed, needs a human, or refused with a typed reason. Caller-provided
    /// classification can only raise the class.
    HostShell {
        /// Entire command text.
        command: String,
        /// Escalate-only class hint; it cannot lower the deterministic class.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        declared_class: Option<CommandClass>,
        /// Reserve one action from the scope's hourly budget when the command is
        /// allowed (an execution). `false` classifies without spending.
        spend: bool,
        /// Registered command scope. Absent, the bootstrap command rules apply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_policy: Option<CommandPolicyId>,
    },
    /// A trusted host's scan result for the exact skill bundle being executed
    /// (contract 1.29). `Warn` requires host approval; `Block` is a hard denial.
    SkillScan {
        /// Result computed by the host scanner.
        verdict: SkillScanVerdict,
        /// Lowercase SHA-256 of the exact document and resources the host will
        /// expose during this run. The approval binding includes this value.
        bundle_sha256: String,
    },
    /// An effect not supported by this engine.
    Unknown {
        /// Content-free descriptor.
        description: String,
    },
}
/// Declared permission level of a host tool (contract 1.20), mirroring the host's
/// ordered levels. Everything above [`ToolPermission::ReadOnly`] acts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPermission {
    /// Metadata-only; needs no permission.
    None,
    /// Reads only.
    ReadOnly,
    /// Writes.
    Write,
    /// Executes commands or scripts.
    Execute,
    /// Destructive or system-level.
    Dangerous,
}
impl ToolPermission {
    /// Whether a tool at this level acts rather than observes.
    #[must_use]
    pub fn acts(self) -> bool {
        self > Self::ReadOnly
    }
    /// The lowest caller tier that may use a tool at this level.
    #[must_use]
    pub fn minimum_tier(self) -> AccessTier {
        match self {
            Self::None | Self::ReadOnly => AccessTier::Read,
            Self::Write => AccessTier::Write,
            Self::Execute | Self::Dangerous => AccessTier::Full,
        }
    }
}
impl AccessTier {
    /// Whether this tier reaches `required`: `Read < Write < Full`.
    #[must_use]
    pub fn reaches(&self, required: &Self) -> bool {
        self.rank() >= required.rank()
    }
    fn rank(&self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Full => 2,
        }
    }
}
/// Evaluation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    /// Verified caller.
    pub caller: CallerContext,
    /// Original operation.
    pub call: ToolCall,
}
/// Ordered batch of in-tool checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    /// Verified caller.
    pub caller: CallerContext,
    /// Checks in execution order.
    pub checks: Vec<Check>,
}
/// Ordered batch results, from one policy generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResponse {
    /// Effective policy generation.
    pub generation: u64,
    /// One decision per input check.
    pub decisions: Vec<Decision>,
}
/// Policy decision; permission does not attest to later execution confinement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Effective policy generation.
    pub generation: u64,
    /// Permission outcome.
    pub verdict: Verdict,
    /// Whether static caching is authorized. Unscoped members always return false;
    /// scoped members set it per `docs/specs/scoped-policies.md`.
    pub cacheable: bool,
}
/// Permission outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Verdict {
    /// Policy permits the checked operation.
    Allow,
    /// Policy refuses the operation.
    Deny {
        /// Stable denial category, without sensitive payloads.
        reason: DenialReason,
    },
    /// Future approval engine parks an operation; bootstrap never returns this.
    RequireApproval {
        /// Persisted approval identity bound to the original call.
        request_id: String,
    },
}
/// Stable denial categories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// Unconditional credential/system/path safety floor.
    Floor,
    /// Unsupported effect or unknown tool.
    UnsupportedEffect,
    /// No usable human approval capability.
    ApprovalUnavailable,
    /// Caller has insufficient access.
    Access,
    /// Outside allowed root or configured forbidden root.
    PathScope,
    /// Path cannot be securely resolved.
    PathResolution,
    /// Command grammar or executable not safely supported.
    Command,
    /// Missing verified caller identity.
    InvalidContext,
    /// Original content was blocked by the semantic scanner.
    Content,
    /// The registered autonomy tier is read-only and the call would act (contract 1.20).
    ReadOnlyMode,
    /// The scope's hourly action budget is exhausted (contract 1.20).
    RateLimited {
        /// The configured actions per hour, for the model-facing message.
        max_per_hour: u32,
    },
    /// A scheduled (cron) turn may use read-only tools only (contract 1.20).
    ScheduledReadOnly,
    /// The command class is prohibited by the scope's high-risk setting (contract 1.20).
    HighRisk,
    /// The registered privacy mode refuses the transfer (contract 1.22).
    Privacy,
}
/// Effective policy settings. Bootstrap intentionally exposes no unimplemented budgets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Enables discretionary boundaries and approval gates.
    pub enabled: bool,
    /// Absolute permitted action root when enabled.
    pub action_dir: String,
    /// Internal host state root, inaccessible to enabled acting tools.
    pub workspace_dir: String,
    /// Allowed commands; bootstrap supports only argument-free diagnostics.
    pub allowed_commands: Vec<String>,
    /// Additional forbidden absolute roots when enabled.
    pub forbidden_paths: Vec<String>,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action_dir: String::new(),
            workspace_dir: String::new(),
            allowed_commands: vec!["pwd".into(), "date".into(), "uname".into(), "whoami".into()],
            forbidden_paths: vec![],
        }
    }
}
/// Secret injected at initialization only. Its Debug output is always redacted.
///
/// Serialization intentionally carries plaintext to SDK init/reinit over the
/// trusted in-process loading boundary. This is not a safe diagnostic serializer:
/// never serialize initialization configuration into logs, public RPC responses,
/// transcripts, approval records or audit events. No bus invocation or
/// [`PolicyInfo`] contains this type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
/// Init-only explicit endpoint/provider selection; no ambient credentials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeProvider {
    /// `TypeSafe` Jev endpoint.
    #[default]
    TypeSafe,
    /// `OpenRouter` Jev-compatible endpoint.
    OpenRouter,
    /// `OpenJev` endpoint.
    OpenJev,
}
fn zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}
/// Local probability thresholds, in thousandths. All comparisons are inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeThresholds {
    /// Minimum explicit intent score.
    pub intent: u16,
    /// Minimum reversibility score.
    pub reversible: u16,
    /// Maximum exfiltration score.
    pub exfiltrate: u16,
}
/// Per-origin and concrete-effect threshold selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeThresholdRule {
    /// Explicit origin selection.
    pub origin: Origin,
    /// Whether the verified concrete effect is external.
    pub external_effect: bool,
    /// Local score bounds.
    pub thresholds: JudgeThresholds,
}
/// Optional native judge configuration, absent by default.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeConfig {
    /// Init-only resolved backend credential.
    pub credential: Secret,
    /// Exact evaluation endpoint; never exposed in diagnostic output.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// Typed response-validation dialect.
    #[serde(default, skip_serializing_if = "zero")]
    pub provider: JudgeProvider,
    /// Default minimum intent/reversibility confidence in thousandths.
    pub threshold_millis: u16,
    /// Default maximum exfiltration confidence in thousandths.
    #[serde(default, skip_serializing_if = "zero")]
    pub exfiltrate_millis: u16,
    /// Additional class/origin thresholds; duplicates reject initialization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<JudgeThresholdRule>,
    /// Total request deadline, also the SDK single-attempt timeout.
    pub timeout_ms: u32,
    /// Explicit origin opt-ins.
    pub origins: Vec<Origin>,
    /// Shared request reservations per fixed window, including failed attempts.
    #[serde(default, skip_serializing_if = "zero")]
    pub max_requests: u32,
    /// Shared budget window duration.
    #[serde(default, skip_serializing_if = "zero")]
    pub budget_window_ms: u32,
    /// Maximum exact-binding cached score sets; zero disables caching.
    #[serde(default, skip_serializing_if = "zero")]
    pub cache_entries: u16,
    /// Score lifetime; zero disables caching.
    #[serde(default, skip_serializing_if = "zero")]
    pub cache_ttl_ms: u32,
}
impl fmt::Debug for JudgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JudgeConfig([REDACTED])")
    }
}
/// SDK init/reinit configuration, never a bus method argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfig {
    /// Immutable fixed confidential native config cipher consumer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_cipher: Option<crate::SecretCipherConfig2>,
    /// Init-only confidential password, keyring and pairing surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<crate::CryptoConfig2>,
    /// Init-only metadata for confidential native master resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<crate::SecretConfig2>,
    /// Init-only bounded native device registration; absent preserves older payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<crate::DeviceConfig2>,
    /// Init-only trusted paired-device lifecycle; absent preserves older payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pairing: Option<crate::DevicePairingConfig2>,
    /// Init-only immutable verified sandbox authority; absent preserves legacy payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<crate::SandboxConfig2>,
    /// Required wire vocabulary.
    pub contract_version: (u32, u32),
    /// Effective policy requested by the host.
    pub policy: PolicyConfig,
    /// Optional explicitly configured native judge.
    pub judge: Option<JudgeConfig>,
    /// Init-only registry, omitted when empty for legacy wire compatibility.
    #[serde(default, skip_serializing_if = "crate::RedactorConfig::is_empty")]
    pub redactor: crate::RedactorConfig,
    /// Exact trusted host unique connection, supplied only across SDK initialization.
    /// Absent legacy initialization remains load-compatible but cannot invoke privileged members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_host: Option<String>,
    /// Init-only ordered audit configuration; absent preserves legacy wire shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<crate::AuditConfig2>,
    /// Init-only immutable approval subjects and callbacks; omitted for older hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<crate::ApprovalConfig2>,
}
impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            contract_version: crate::CONTRACT_VERSION,
            device: None,
            device_pairing: None,
            crypto: None,
            secret: None,
            secret_cipher: None,
            sandbox: None,
            policy: PolicyConfig::default(),
            judge: None,
            redactor: crate::RedactorConfig::default(),
            trusted_host: None,
            audit: None,
            approvals: None,
        }
    }
}
/// Effective configuration and currently implemented capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// Wire version.
    pub contract_version: (u32, u32),
    /// Effective generation.
    pub generation: u64,
    /// Effective settings for the trusted host's policy UI; no judge credentials.
    /// Includes host paths, so this response must not be exposed to model tools
    /// or unauthenticated callers.
    pub policy: PolicyConfig,
    /// Advertised implemented methods.
    pub capabilities: Vec<String>,
    /// Nonsensitive native judge settings; never credentials or the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<JudgeInfo>,
    /// Which host callbacks and native authorities are configured.
    #[serde(default, skip_serializing_if = "zero")]
    pub callbacks: CallbackAvailability,
    /// Number of active registered scoped policies.
    #[serde(default, skip_serializing_if = "zero")]
    pub scoped_policies: u32,
}

/// Nonsensitive judge settings. Credentials and endpoint are init-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeInfo {
    /// Response dialect.
    pub provider: JudgeProvider,
    /// Default minimum intent/reversibility score.
    pub threshold_millis: u16,
    /// Default maximum exfiltration score.
    pub exfiltrate_millis: u16,
    /// Class/origin thresholds.
    pub thresholds: Vec<JudgeThresholdRule>,
    /// Total request deadline.
    pub timeout_ms: u32,
    /// Opted-in origins.
    pub origins: Vec<Origin>,
    /// Request reservations per window.
    pub max_requests: u32,
    /// Budget window.
    pub budget_window_ms: u32,
    /// Cache entries.
    pub cache_entries: u16,
    /// Cache lifetime.
    pub cache_ttl_ms: u32,
}

/// Availability of configured callbacks and native authorities.
#[allow(clippy::struct_excessive_bools)] // independent wire flags, one per authority
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackAvailability {
    /// Audit sink callback configured.
    pub audit: bool,
    /// Audit is required before permission.
    pub audit_required: bool,
    /// Approval store and prompt callbacks configured.
    pub approvals: bool,
    /// Native judge configured.
    pub judge: bool,
    /// Sandbox authority configured.
    pub sandbox: bool,
    /// Confidential secret authority configured.
    pub secret: bool,
    /// Confidential config cipher configured.
    pub secret_cipher: bool,
    /// Confidential device authority configured.
    pub device: bool,
    /// Confidential password, keyring and pairing authority configured.
    #[serde(default)]
    pub crypto: bool,
}
/// Accepted configuration change notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChanged {
    /// New generation.
    pub generation: u64,
    /// Scoped policy that was activated, absent for module reinit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    /// New lineage generation of that scoped policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<u64>,
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
