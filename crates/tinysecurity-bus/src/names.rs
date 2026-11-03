//! Stable interface and reserved member names.
/// Main policy interface.
pub const INTERFACE: &str = "ai.tinyhumans.tinysecurity.Policy";
/// Main policy object.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinysecurity/Policy";
/// Method names; availability is reported by `PolicyInfo`.
pub mod methods {
    /// Password encryption and decryption over the legacy Argon2id/AES-256-GCM format.
    pub const PASSWORD_CRYPT2: &str = "PasswordCrypt2";
    /// Consent-gated named secret access on the configured native keyring backend.
    pub const KEYRING_ACCESS2: &str = "KeyringAccess2";
    /// Nonsecret pairing lifecycle and constant-time bearer authentication.
    pub const PAIRING_CONTROL2: &str = "PairingControl2";
    /// Admit a bounded routine operation against a real acquired config master.
    pub const EVALUATE_SECRET_CIPHER2: &str = "EvaluateSecretCipher2";
    /// Consume exact private pending cipher authority once.
    pub const EXECUTE_SECRET_CIPHER2: &str = "ExecuteSecretCipher2";
    /// Begin `HumanOnly` confidential master review.
    pub const EVALUATE_SECRET2: &str = "EvaluateSecret2";
    /// Resolve a master after exact Human Once and required audit.
    pub const EXECUTE_SECRET2: &str = "ExecuteSecret2";
    /// Begin exact authenticated-human review for confidential native device work.
    pub const EVALUATE_DEVICE2: &str = "EvaluateDevice2";
    /// Execute exact reviewed confidential work using scoped opaque handles.
    pub const EXECUTE_DEVICE2: &str = "ExecuteDevice2";
    /// Seal or open a frame through a live tunnel handle created by approved device work.
    pub const DEVICE_FRAME2: &str = "DeviceFrame2";
    /// Host-attested pairing, renewal and revocation of device tunnel identities (contract 1.25).
    pub const DEVICE_PAIRING2: &str = "DevicePairing2";
    /// Trusted legacy history migration without broad grant revival.
    pub const IMPORT_APPROVAL_HISTORY2: &str = "ImportApprovalHistory2";
    /// Durable exact approval evaluation.
    pub const EVALUATE_APPROVAL2: &str = "EvaluateApproval2";
    /// Exact opaque authenticated-human ticket decision.
    pub const DECIDE2: &str = "Decide2";
    /// Once-only exact execution reservation.
    pub const CONSUME_APPROVAL2: &str = "ConsumeApproval2";
    /// Exact durable terminal execution phase.
    pub const RECORD_EXECUTION2: &str = "RecordExecution2";
    /// Scoped sanitized durable rows.
    pub const LIST_APPROVALS2: &str = "ListApprovals2";
    /// Bounded recent decisions across active approval scopes (contract 1.30).
    pub const LIST_RECENT_DECISIONS2: &str = "ListRecentDecisions2";
    /// Purge undecided rows for one session across active approval scopes (contract 1.30).
    pub const PURGE_APPROVAL_SESSION2: &str = "PurgeApprovalSession2";
    /// Persist redacted metadata after an audit sink failure (contract 1.30).
    pub const RECORD_AUDIT_ERROR2: &str = "RecordAuditError2";
    /// Captured-scope cancellation phase.
    pub const CANCEL_APPROVAL2: &str = "CancelApproval2";
    /// Durable exact-boundary expiry phase.
    pub const EXPIRE_APPROVAL2: &str = "ExpireApproval2";
    /// Bounded exact already-reviewed flow grant validation.
    pub const PREAUTHORIZE_FLOW2: &str = "PreauthorizeFlow2";
    /// Durably trust one tool inside one flow (contract 1.22).
    pub const GRANT_FLOW_TOOL2: &str = "GrantFlowTool2";
    /// Withdraw durable trust of one tool inside one flow (contract 1.22).
    pub const REVOKE_FLOW_TOOL2: &str = "RevokeFlowTool2";
    /// Read the live durable flow trust of one scope (contract 1.22).
    pub const LIST_FLOW_TRUST2: &str = "ListFlowTrust2";
    /// Durably trust one exact whole tool in a registered scope (contract 1.26).
    pub const GRANT_TOOL2: &str = "GrantTool2";
    /// Withdraw durable trust of one exact whole tool (contract 1.26).
    pub const REVOKE_TOOL2: &str = "RevokeTool2";
    /// Withdraw a listed whole-tool grant by opaque row identity (contract 1.27).
    pub const REVOKE_TOOL_BY_ID2: &str = "RevokeToolById2";
    /// Read the live durable whole-tool trust of one scope (contract 1.26).
    pub const LIST_TOOL_TRUST2: &str = "ListToolTrust2";
    /// Host-only import-once receipt for a legacy tool or flow-tool trust item.
    pub const IMPORT_TRUST_SOURCE2: &str = "ImportTrustSource2";
    /// Register a runtime approval scope and its tool and flow grants (contract 1.17).
    pub const REGISTER_APPROVAL_SCOPE2: &str = "RegisterApprovalScope2";
    /// Atomically replace one scope's posture, grants or policy reference (contract 1.17).
    pub const REPLACE_APPROVAL_SCOPE2: &str = "ReplaceApprovalScope2";
    /// Retire a scope so later calls under it deny (contract 1.17).
    pub const RETIRE_APPROVAL_SCOPE2: &str = "RetireApprovalScope2";
    /// Register a secret resolver for an already-live approval scope (contract 1.29).
    pub const REGISTER_SECRET_SCOPE2: &str = "RegisterSecretScope2";
    /// Register paired-device support for a canonical live approval scope.
    pub const REGISTER_DEVICE_PAIRING_SCOPE2: &str = "RegisterDevicePairingScope2";
    /// Evaluate member.
    pub const EVALUATE: &str = "Evaluate";
    /// Check member.
    pub const CHECK: &str = "Check";
    /// `PolicyInfo` member.
    pub const POLICY_INFO: &str = "PolicyInfo";
    /// Audit a typed native permission query before exposing its result.
    pub const CHECK_PERMISSION_AUDITED2: &str = "CheckPermissionAudited2";
    /// Register an immutable filesystem policy scope.
    pub const REGISTER_PATH_POLICY: &str = "RegisterPathPolicy";
    /// Resolve and authorize an existing read path.
    pub const VALIDATE_PATH: &str = "ValidatePath";
    /// Resolve and authorize a prospective write path.
    pub const VALIDATE_PARENT: &str = "ValidateParent";
    /// Boolean filesystem policy query.
    pub const CHECK_PATH: &str = "CheckPath";
    /// One boolean filesystem query kind over an ordered batch of paths (contract 1.22).
    pub const CHECK_PATHS2: &str = "CheckPaths2";
    /// Unconditional protected-path floor over paths outside any scope (contract 1.22).
    pub const PROTECTED_PATH2: &str = "ProtectedPath2";
    /// The floor's component, file, pair and prefix vocabulary (contract 1.22).
    pub const PROTECTED_FLOOR2: &str = "ProtectedFloor2";
    /// Resolves concrete native credential-store roots for a host-provided home.
    pub const CREDENTIAL_ROOTS2: &str = "CredentialRoots2";
    /// Reserve one action from a registered command scope's hourly ledger (contract 1.22).
    pub const SPEND_ACTION2: &str = "SpendAction2";
    /// Read a registered command scope's hourly ledger without spending (contract 1.22).
    pub const PEEK_BUDGET2: &str = "PeekBudget2";
    /// Reserve one action with an exact, committed audit receipt (contract 1.35).
    pub const RESERVE_ACTION_BUDGET_AUDITED2: &str = "ReserveActionBudgetAudited2";
    /// Informational class of a host action by permission and external effect (contract 1.22).
    pub const CLASSIFY_HOST_ACTION2: &str = "ClassifyHostAction2";
    /// Descriptor-level privacy decision for a transfer with no pinned destination (contract 1.22).
    pub const PRIVACY_CHECK2: &str = "PrivacyCheck2";
    /// Classify a configured provider host as same-machine or external (contract 1.32).
    pub const CLASSIFY_PROVIDER_ENDPOINT2: &str = "ClassifyProviderEndpoint2";
    /// Register an immutable per-subject policy over path and command scopes.
    pub const REGISTER_POLICY: &str = "RegisterPolicy";
    /// Atomically replace an active policy, with human review when it widens.
    pub const SUPERSEDE_POLICY: &str = "SupersedePolicy";
    /// Evaluate an original call under a registered policy.
    pub const EVALUATE_SCOPED: &str = "EvaluateScoped";
    /// Check an ordered batch under a registered policy.
    pub const CHECK_SCOPED: &str = "CheckScoped";
    /// Effective settings of one registered policy.
    pub const SCOPED_POLICY_INFO: &str = "ScopedPolicyInfo";
    /// Register a fresh immutable agent command scope and hourly budget.
    pub const REGISTER_COMMAND_POLICY: &str = "RegisterCommandPolicy";
    /// Informational classification; never an execution grant.
    pub const CLASSIFY_COMMAND: &str = "ClassifyCommand";
    /// Noncacheable execution check and atomic action reservation.
    pub const CHECK_COMMAND: &str = "CheckCommand";
    /// Command execution check whose decision is exposed only after its action reservation is audited (contract 1.35).
    pub const CHECK_COMMAND_AUDITED2: &str = "CheckCommandAudited2";
    /// Register immutable host-only destination and data policy.
    pub const REGISTER_EGRESS_POLICY: &str = "RegisterEgressPolicy";
    /// Owner-bound pinned destination authorization.
    pub const SCOPED_URL_GUARD: &str = "ScopedUrlGuard";
    /// Original-payload privacy and pinned destination authorization.
    pub const SCOPED_EGRESS_CHECK: &str = "ScopedEgressCheck";
    /// Consume an exact live grant once before sending.
    pub const CONSUME_EGRESS_AUTHORIZATION: &str = "ConsumeEgressAuthorization";
    /// Authorize one browser destination and return its exact vetted socket set (contract 1.28).
    pub const AUTHORIZE_BROWSER_DIAL: &str = "AuthorizeBrowserDial";
    /// Consume a browser destination grant immediately before dialing one exact socket (contract 1.28).
    pub const CONSUME_BROWSER_DIAL: &str = "ConsumeBrowserDial";
    /// Check a consumed browser tunnel lease until close or expiry (contract 1.28).
    pub const VALIDATE_BROWSER_DIAL: &str = "ValidateBrowserDial";
    /// Decide member.
    pub const DECIDE: &str = "Decide";
    /// `ListPending` member.
    pub const LIST_PENDING: &str = "ListPending";
    /// `ListDecisions` member.
    pub const LIST_DECISIONS: &str = "ListDecisions";
    /// `RecordExecution` member.
    pub const RECORD_EXECUTION: &str = "RecordExecution";
    /// `PreauthorizeFlow` member.
    pub const PREAUTHORIZE_FLOW: &str = "PreauthorizeFlow";
    /// `ParseReply` member.
    pub const PARSE_REPLY: &str = "ParseReply";
    /// Redact member.
    pub const REDACT: &str = "Redact";
    /// Redact with exact credentials supplied for this call only (contract 1.16).
    pub const REDACT_WITH: &str = "RedactWith";
    /// `ScanPrompt` member.
    pub const SCAN_PROMPT: &str = "ScanPrompt";
    /// Scored prompt screening: tier, score and rule codes (contract 1.22).
    pub const SCAN_PROMPT2: &str = "ScanPrompt2";
    /// `ScanToolDefinition` member.
    pub const SCAN_TOOL_DEFINITION: &str = "ScanToolDefinition";
    /// `EgressCheck` member.
    pub const EGRESS_CHECK: &str = "EgressCheck";
    /// `UrlGuard` member.
    pub const URL_GUARD: &str = "UrlGuard";
    /// Plan member.
    pub const PLAN: &str = "Plan";
    /// Immutable-scoped declarative sandbox planning.
    pub const PLAN2: &str = "Plan2";
    /// Register a runtime sandbox scope for one subject (contract 1.19).
    pub const REGISTER_SANDBOX_SCOPE2: &str = "RegisterSandboxScope2";
    /// Retire a runtime sandbox scope so later calls under it deny (contract 1.19).
    pub const RETIRE_SANDBOX_SCOPE2: &str = "RetireSandboxScope2";
    /// Exact human approval creation for immutable-ceiling sandbox host networking.
    pub const EVALUATE_SANDBOX_APPROVAL2: &str = "EvaluateSandboxApproval2";
    /// Exact audited once-only execution admission for an issued declarative artifact.
    pub const CONSUME_SANDBOX_PLAN2: &str = "ConsumeSandboxPlan2";
    /// Exact durable version-two audit member.
    pub const AUDIT2: &str = "Audit2";
    /// Host-recorded audit event appended to one subject's registered stream (contract 1.21).
    pub const RECORD_AUDIT2: &str = "RecordAudit2";
    /// Original operation evaluation bound to exact pre-execution audit.
    pub const EVALUATE_AUDITED2: &str = "EvaluateAudited2";
    /// Ordered check evaluation bound to exact pre-execution audit.
    pub const CHECK_AUDITED2: &str = "CheckAudited2";
    /// Scoped original-operation evaluation bound to exact pre-execution audit.
    pub const EVALUATE_SCOPED_AUDITED: &str = "EvaluateScopedAudited";
    /// Scoped ordered check evaluation bound to exact pre-execution audit.
    pub const CHECK_SCOPED_AUDITED: &str = "CheckScopedAudited";
    /// Audit member.
    pub const AUDIT: &str = "Audit";
}
/// Bootstrap implemented methods only.
pub const METHODS: &[&str] = &[
    methods::EVALUATE_SECRET_CIPHER2,
    methods::EXECUTE_SECRET_CIPHER2,
    methods::EVALUATE_SECRET2,
    methods::EXECUTE_SECRET2,
    methods::PASSWORD_CRYPT2,
    methods::KEYRING_ACCESS2,
    methods::PAIRING_CONTROL2,
    methods::EVALUATE_DEVICE2,
    methods::EXECUTE_DEVICE2,
    methods::DEVICE_PAIRING2,
    methods::DEVICE_FRAME2,
    methods::PLAN,
    methods::EVALUATE_SANDBOX_APPROVAL2,
    methods::CONSUME_SANDBOX_PLAN2,
    methods::PLAN2,
    methods::EVALUATE,
    methods::CHECK,
    methods::EVALUATE_AUDITED2,
    methods::CHECK_AUDITED2,
    methods::CHECK_PERMISSION_AUDITED2,
    methods::REGISTER_PATH_POLICY,
    methods::VALIDATE_PATH,
    methods::VALIDATE_PARENT,
    methods::CHECK_PATH,
    methods::CHECK_PATHS2,
    methods::PROTECTED_PATH2,
    methods::PROTECTED_FLOOR2,
    methods::CREDENTIAL_ROOTS2,
    methods::SPEND_ACTION2,
    methods::RESERVE_ACTION_BUDGET_AUDITED2,
    methods::PEEK_BUDGET2,
    methods::CLASSIFY_HOST_ACTION2,
    methods::PRIVACY_CHECK2,
    methods::CLASSIFY_PROVIDER_ENDPOINT2,
    methods::REGISTER_COMMAND_POLICY,
    methods::CLASSIFY_COMMAND,
    methods::CHECK_COMMAND,
    methods::CHECK_COMMAND_AUDITED2,
    methods::REGISTER_EGRESS_POLICY,
    methods::SCOPED_URL_GUARD,
    methods::SCOPED_EGRESS_CHECK,
    methods::CONSUME_EGRESS_AUTHORIZATION,
    methods::AUTHORIZE_BROWSER_DIAL,
    methods::CONSUME_BROWSER_DIAL,
    methods::VALIDATE_BROWSER_DIAL,
    methods::URL_GUARD,
    methods::EGRESS_CHECK,
    methods::REDACT,
    methods::REDACT_WITH,
    methods::SCAN_PROMPT,
    methods::SCAN_PROMPT2,
    methods::SCAN_TOOL_DEFINITION,
    methods::AUDIT2,
    methods::RECORD_AUDIT2,
    methods::EVALUATE_APPROVAL2,
    methods::DECIDE2,
    methods::CONSUME_APPROVAL2,
    methods::RECORD_EXECUTION2,
    methods::LIST_APPROVALS2,
    methods::LIST_RECENT_DECISIONS2,
    methods::PURGE_APPROVAL_SESSION2,
    methods::RECORD_AUDIT_ERROR2,
    methods::CANCEL_APPROVAL2,
    methods::EXPIRE_APPROVAL2,
    methods::PREAUTHORIZE_FLOW2,
    methods::GRANT_FLOW_TOOL2,
    methods::REVOKE_FLOW_TOOL2,
    methods::LIST_FLOW_TRUST2,
    methods::GRANT_TOOL2,
    methods::REVOKE_TOOL2,
    methods::REVOKE_TOOL_BY_ID2,
    methods::LIST_TOOL_TRUST2,
    methods::IMPORT_TRUST_SOURCE2,
    methods::REGISTER_APPROVAL_SCOPE2,
    methods::REGISTER_SECRET_SCOPE2,
    methods::REGISTER_DEVICE_PAIRING_SCOPE2,
    methods::REPLACE_APPROVAL_SCOPE2,
    methods::RETIRE_APPROVAL_SCOPE2,
    methods::REGISTER_SANDBOX_SCOPE2,
    methods::RETIRE_SANDBOX_SCOPE2,
    methods::IMPORT_APPROVAL_HISTORY2,
    methods::PARSE_REPLY,
    methods::POLICY_INFO,
    methods::REGISTER_POLICY,
    methods::SUPERSEDE_POLICY,
    methods::EVALUATE_SCOPED,
    methods::CHECK_SCOPED,
    methods::SCOPED_POLICY_INFO,
    methods::EVALUATE_SCOPED_AUDITED,
    methods::CHECK_SCOPED_AUDITED,
];
/// Accepted policy activation event.
pub const POLICY_CHANGED: &str = "PolicyChanged";
/// Reserved host callback identities.
pub mod callbacks {
    /// `ApprovalStore` callback interface.
    pub const APPROVAL_STORE: &str = "ai.tinyhumans.tinysecurity.ApprovalStore";
    /// `ApprovalPrompt` callback interface.
    pub const APPROVAL_PROMPT: &str = "ai.tinyhumans.tinysecurity.ApprovalPrompt";
    /// `AuditSink` callback interface.
    pub const AUDIT_SINK: &str = "ai.tinyhumans.tinysecurity.AuditSink";
    /// `KeyringConsent` callback interface.
    pub const KEYRING_CONSENT: &str = "ai.tinyhumans.tinysecurity.KeyringConsent";
}
