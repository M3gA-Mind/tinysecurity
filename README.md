# TinySecurity

TinySecurity supplies security policy through a native TinyBus module. Hosts
compile the transport-free `tinysecurity-bus` contract and load the isolated
`tinysecurity-module` artifact. The bootstrap implements `Evaluate`, batched
`Check`, `PolicyInfo`, validated SDK configuration and policy generations.
Contract 1.23 adds confidential per-frame `DeviceFrame2` calls over the live
opaque tunnel capability issued by approved `ExecuteDevice2` work; see the
[device contract](MODULE.md#confidential-device-handles).
Contract 1.25 adds `DevicePairing2`, which owns the paired-device static
identity, ciphertext-only persistence, host-attested enrollment/reconnect,
session refresh and revocation while preserving the existing v2/v3/v4 wire;
see the [pairing lifecycle specification](docs/specs/device-pairing-contract-1.25.md).
Contract 1.1 also supplies immutable native [filesystem scopes](docs/specs/immutable-path-scopes.md)
through `RegisterPathPolicy`, `ValidatePath`, `ValidateParent` and `CheckPath`.
Contract 1.3 adds native `Redact`, `ScanPrompt` and `ScanToolDefinition`, with a
validated initialization-only literal registry and [bounded surface modes](crates/tinysecurity-redact/README.md).
Blocked original content denies; suspicious content denies with
approval-unavailable in unbound policy methods. Scan verdicts
never grant permission, and redaction never clears an existing scan finding.

Contract 1.34 adds `CheckPermissionAudited2`: a closed, typed vocabulary for native path checks, non-reserving command gates, budget peeks, and privacy checks. A result is exposed only after its own durable audit receipt. Lost audit and stale generations withhold the result, while legacy unaudited permission members remain refused under required audit. These queries neither execute commands nor reserve actions. See [MODULE.md](MODULE.md#audited-native-permission-queries-contract-134).

Contract 1.35 adds `CheckCommandAudited2`, which exposes the registered command decision only after its guarded execution reservation has a committed audit receipt, and `ReserveActionBudgetAudited2`, an execution-side accounting operation bound to a committed audit receipt. Exact command retries do not reserve twice; audit failure or cancellation refunds pending command reservations. The separate `CheckPermissionAudited2::GateCommand` remains non-reserving. See [MODULE.md](MODULE.md#audited-command-execution-and-action-budget-reservations-contract-135).

Contract 1.22 adds policy and egress gap members: `CheckPaths2` (batch path checks), `ProtectedPath2` and `ProtectedFloor2` (the unconditional lexical floor and its vocabulary), `SpendAction2` and `PeekBudget2` (the hourly action ledger outside the harness), `ClassifyHostAction2` (the informational class of a host tool) and `PrivacyCheck2` (a descriptor-level privacy decision) (see [MODULE.md](MODULE.md#policy-and-egress-gap-members-contract-122)). Contract 1.22 adds `SandboxPlanRequest2.options` (an executor preference, a workspace-less plan and the operator's planned run on the host, never for `SaaS` or an untrusted source) and the artifact flags `host_run` and `no_workspace` (see [MODULE.md](MODULE.md#executor-choice-workspace-less-plans-and-the-operators-host-run-contract-122)). Contract 1.22 also adds the approval origin classes `TrustedAutomation`, `LocalOperator` and `Unlabelled`, durable flow trust (`GrantFlowTool2`, `RevokeFlowTool2`, `ListFlowTrust2`) and scored prompt screening (`ScanPrompt2`) (see [MODULE.md](MODULE.md#approval-origin-classes-durable-flow-trust-and-scored-prompt-screening-contract-122)). Contract 1.21 adds `RecordAudit2` and `AuditKind2::PolicyDecision`, so the host appends execution and no-prompt policy-decision events to a real subject's audit stream (see [MODULE.md](MODULE.md#host-recorded-audit-events-contract-121)), `SandboxScope2.operator_host_network` (host network granted by the owner's configuration, never under `SaaS`) and `SandboxPlanRequest2.accept_process_isolation` (a best-effort process jail may run an ordinary operator command, never untrusted code) (see [MODULE.md](MODULE.md#operator-host-network-and-process-level-jails-contract-121)). Contract 1.20 adds host-tool admission: `Check::HostAction` judges a host tool by its permission level, the caller's tier and origin and a registered command scope's autonomy and hourly budget; `Check::HostShell` gates a shell command under that scope's class gate, hidden-execution defence and budget without reserving an action. Refusals are typed (`read_only_mode`, `rate_limited`, `scheduled_read_only`, `high_risk`) (see [MODULE.md](MODULE.md#host-tool-admission-contract-120)). Contract 1.19 adds runtime sandbox scopes (`RegisterSandboxScope2`, `RetireSandboxScope2`), so a host that serves unbounded subjects can plan sandboxes per subject (see [MODULE.md](MODULE.md#runtime-sandbox-scopes-contract-119)). Contract 1.18 returns the sanitized subject handle in `ApprovalScopeReceipt2` and keeps the path, command and egress members available when approvals are configured (see [MODULE.md](MODULE.md#subject-handles-and-unbound-members-contract-118)). Contract 1.17 adds runtime approval scopes (`RegisterApprovalScope2`, `ReplaceApprovalScope2`, `RetireApprovalScope2`), tool and flow grants, and `Check::HostTool` (see [MODULE.md](MODULE.md#runtime-approval-scopes-and-host-tools-contract-117)). Contract 1.16 adds `RedactWith`, redaction with exact credentials supplied for one call (see [MODULE.md](MODULE.md#per-call-exact-credentials-redactwith-contract-116)). Contract 1.15 adds `RedactMode::CredentialsOnly` and the `EgressPolicy` fields `open_public` and `preflight_transports` (see [MODULE.md](MODULE.md#credentials-only-redaction-and-open-public-egress-contract-115)). Contract 1.14 adds confidential `PasswordCrypt2`, `KeyringAccess2` and `PairingControl2` (see [MODULE.md](MODULE.md)). Contract 1.13 added `EvaluateScopedAudited` and `CheckScopedAudited` for registered policies under required audit (see [`docs/specs/scoped-policies.md`](docs/specs/scoped-policies.md)).

Contract 1.26 adds durable whole-tool trust (`GrantTool2`, `RevokeTool2` and
`ListToolTrust2`), persisted and audited through the approval store. See the
[whole-tool trust spec](docs/specs/durable-tool-trust.md). The private
`ImportTrustSource2` host member adds import-once receipts for legacy whole-tool
and flow-tool grants, retained after revocation so partial migration retries cannot
restore removed authority.
Contract 1.27 adds `RevokeToolById2`, allowing a host to revoke a listed grant by
its opaque row identity when the display label is redacted.
Contract 1.28 adds `AuthorizeBrowserDial`, `ConsumeBrowserDial`, and
`ValidateBrowserDial` for session-bound, destination-only authorization of
opaque browser sockets. It vets every resolved address, issues a one-use grant
for an exact socket, and requires transports to close CONNECT/WebSocket streams
when a lease expires or policy generation changes. Sensitive and local-only
privacy modes deny this uninspectable traffic; TinyComputer remains responsible
for enforcing the proxy and dialing the approved socket. See the
[browser-dial contract specification](docs/specs/browser-dial-contract-1.28.md).
Contract 1.29 adds the host-only `RegisterSecretScope2` member for adding a
secret resolver bound to an already-live approval scope, without reinitializing
the process-global secret registry. Approval-scope replacement or retirement
revokes the associated secret handles and runtime registrations; see the
[runtime secret-scope specification](docs/specs/runtime-secret-scopes-contract-1.29.md).

Contract 1.29 adds `Check::SkillScan` so the trusted host can submit the scan
verdict and exact bundle digest before an installed skill runs. `Block` is a
content denial, `Warn` enters the host's approval flow, and `Pass` leaves the
remaining policy checks authoritative. See the
[host skill-scan specification](docs/specs/skill-scan-contract-1.29.md).

Contract 1.6 supplies `Audit2`, `EvaluateAudited2` and `CheckAudited2` with
authenticated exact audit callbacks and a bounded [native journal](crates/tinysecurity-audit/README.md).
The audited permission methods derive events from the actual original request,
computed decision and current generation. Required audit disables unbound
`Evaluate`/`Check` permission and other unbound path/command/egress authorization;
exact durable evidence precedes an audited allow. Scope registration and
descriptive classification remain available.
Windows local journals require an externally preprovisioned, protected NTFS
namespace and preexisting restricted authority; see the native journal contract.

The engine denies unknown tools and unsupported effects. Argument-free `pwd`,
`date`, `uname`, and `whoami` are its supported shell diagnostics. Paths pass
an unconditional credential/system/traversal floor and native ancestor
resolution; enabled policy adds action-root, workspace and forbidden-root
checks. Enabled writes require the durable approval surface. Pure local
diagnostics work with disabled autonomy, which is the default.

This is bootstrap infrastructure for [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328)
and [TinySecurity #1](https://github.com/tinyhumansai/tinysecurity/issues/1).
It does **not** complete the migration. Concrete sandbox spawning, connection pinning and production host configuration/adapter migration remain unavailable. Linux release artifacts enable the opt-in Secret Service backend, while default development builds still fail closed unless the feature is enabled. Contract 1.25 supplies the module-owned pairing and tunnel lifecycle; the host must provide the server-trusted controller/socket/reconnect callbacks and encrypted persistence plumbing described in its specification. The optional [native device handle surface](MODULE.md#confidential-device-handles) uses authenticated confidential calls; initial master unlock remains HumanOnly. Reserved wire types do not advertise callable handlers.
There is no production host migration until an upstream release and checksum
manifest exist.

Contract 1.7 adds [durable exact approvals](crates/tinysecurity-approval/README.md)
with authenticated store/CAS, delivery and human-ticket callbacks. Approval
configuration disables older permission shortcuts. Pending rows and audits
precede prompts; exact original-call bindings and CAS reservations govern execution.

Contract 1.8 enables optional [native Jev scoring](crates/tinysecurity-auto/README.md)
through explicit endpoint/key initialization and per-origin opt-in. Redacted
scores meet local thresholds before durable `auto:jev` one-shot approval;
all uncertain/error/budget paths keep the authenticated human flow. Required
CAS/audit receipts and fresh policy floors still gate permission.

Contract 1.10 adds [confidential injected master resolution](docs/module-crypto.md#confidential-injected-master-resolution) with opaque native aliases. Configured-secret reinit is conservatively denied pending a coherent owner transaction. This is an injected-store prerequisite, not production keyring or password migration.

Contract 1.9 adds [scoped declarative sandbox planning](crates/tinysecurity-sandbox/README.md).
`Plan2` uses immutable host-registered source provenance, ceilings and executor
capability declarations. Exact committed audit precedes activation of an opaque
artifact; `ConsumeSandboxPlan2` reserves that artifact once. Host networking
requires an exact authenticated human Once decision through
`EvaluateSandboxApproval2`, even when generic automatic approvals are enabled.
These ports do not prove OS confinement or launch a child: TinyBox must enforce
and revalidate the plan at the actual execution boundary.

## Workspace

| Crate | Role |
| --- | --- |
| `tinysecurity-bus` | Wire types, errors, names and compatibility; normal dependencies only serde and thiserror |
| `tinysecurity-policy` | Native conservative policy engine |
| `tinysecurity-sandbox` | Internal scoped planner and bounded opaque artifact registry |
| `tinysecurity-redact` | Internal immutable redaction registry and semantic intent scanner |
| `tinysecurity-auto` | Internal optional Jev, approval rules, shared request budget and exact-score cache |
| `tinysecurity-approval` | Internal durable exact approval, expiry and reservation engine |
| `tinysecurity-audit` | Internal bounded authoritative journal and sanitized exact receipts |
| `tinysecurity` | Internal implementation re-export |
| `tinysecurity-module` | SDK initialization, bus dispatch and ABI cdylib |

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo run -p tinysecurity-module --example verify_module -- target/debug/libtinysecurity_module.so
cargo run -p tinysecurity-module --example judge_native_contract -- target/debug/libtinysecurity_module.so
```

Use `.dylib` on macOS and `tinysecurity_module.dll` on Windows. The loader
example proves allow/deny, malformed/unsupported invocation rejection,
reconfiguration retention and generation, then prints real bus latency.

See [module boundary](MODULE.md), [confidential crypto members](docs/module-crypto.md),
[registered subject policies](docs/module-subject-policies.md), [accepted specification](docs/specs/security-module.md),
[implementation sequence](docs/plans/security-module.md), and [roadmap](ROADMAP.md).

`ConsumeSandboxPlan2` carries the original typed `Plan2` envelope as well as the
opaque artifact. The host derives that envelope from the exact prepared spawn:
argv, environment, cwd and input belong in its bounded original operation.
The owner validates its canonical binding before audit and again after the
callback; changed operations cannot consume a copied artifact. This does not
replace TinyBox's live isolation and capability checks.
