# TinySecurity module behavior

- Status: Accepted design; incremental implementation
- Tracks: [TinySecurity #1](https://github.com/tinyhumansai/tinysecurity/issues/1),
  [OpenHuman #7328](https://github.com/tinyhumansai/openhuman/issues/7328)
- Implementation: [ordered plan](../plans/security-module.md)

## Ownership and delivery

TinySecurity decides policy, approval, privacy, audit and sandbox placement.
TinyBox executes isolation plans. OpenHuman owns authentication, configuration
translation, storage and interactive callbacks, RPC presentation and execution.
Generic harness behavior remains in TinyAgents and generic tool types in
TinyTools. A fix belongs in the repository that owns that behavior.

The production boundary is a native TinyBus module. Hosts depend only on
`tinysecurity-bus`, whose normal dependencies are `serde` and `thiserror`.
It contains wire types, version rules, errors and member constants, with no
runtime, transport, filesystem access or policy implementation. All engines
and their dependencies are private to the module. Host callbacks cross the
bus; Rust traits, futures and task-local state do not cross the ABI.

The interface is `ai.tinyhumans.tinysecurity.Policy`, at
`/ai/tinyhumans/tinysecurity/Policy`. Advertise only implemented members.
The bootstrap has four implemented roles: `tinysecurity-bus` contract,
`tinysecurity-policy` engine, `tinysecurity` internal umbrella re-exporting
policy, and `tinysecurity-module` native adapter/cdylib. Released artifact names
use `tinysecurity-module`; none of these implementation crates is host-linked.
Removing greeting examples and shipping real `Evaluate` and batched `Check`
is the initial useful milestone. `PolicyInfo` exposes effective configuration;
`PolicyChanged` identifies accepted generation changes. Approval, redaction,
network, sandbox, audit
and crypto members become available only when their engines and tests exist.
Do not create empty engine crates or claim full tracker completion at bootstrap.

OpenHuman cannot migrate a caller until the upstream capability has merged,
released and published platform archives and `checksum.toml`. Registry digests
must be copied from that release, never a local build. Keep one cumulative PR
per affected repository for this work; stages below are implementation and
verification boundaries, not instructions to open additional PRs.

## Trust and module lifecycle

The host admits the module through digest verification and `attested_proxy`.
It supplies policy through SDK init/reinit configuration, not invented `Init`
or `Reinit` RPC members. A request's origin,
agent, thread, flow and access tier come from verified host context, never
model arguments. `CallerContext` and operation checks are serialized only by
that trusted adapter; the module is not a public authentication endpoint.
Hosts must not expose its members to untrusted callers or forward their claims.
Filesystem checks require an absolute native path resolved against the actual
operation's working directory; the module rejects relative targets even when
discretionary policy is disabled. A claimed command class cannot authorize a
call: the engine must compute it or conservatively strengthen it. Unknown commands are writes.

Judge credentials are resolved by the host's backend credential resolver and
injected only at init/reinit. They never appear in per-call arguments, debug
formatting, logs, approval records or audit events. Debug output for any config
carrying secrets is redacted. Init configuration serialization intentionally
carries credentials to the trusted SDK loading boundary and must never be used
for diagnostics or public responses. `PolicyInfo` excludes judge configuration;
its effective roots are available only to trusted host policy UI, not acting
tools or unauthenticated callers. Configuration validation precedes activation;
failed reinit retains the old effective policy and generation.

Missing, incompatible, uninitialized, faulted or timed-out modules deny external
effects. A fault is latched for that process: no repeated initialization, retry
or fallback to linked policy code. Reinit cannot clear a fault. A host restart
and fresh attestation are required. An ordinary policy denial is a successful
decision and does not fault the module. Pure local diagnostics may continue
only when they cannot cause an external effect.

## Policy decisions

`Evaluate` returns `Allow`, `Deny` with a stable reason, or `RequireApproval`
when the approval capability exists. `Check` evaluates an ordered batch of
in-tool path, command and eventually URL checks with individual decisions.
The bootstrap may return an explicit approval-required denial before it has
an approval store; it must not mint unusable request identifiers.

Autonomy is disabled by default. When disabled, command allowlists, action
budgets, workspace boundaries and interactive policy gates are inactive.
The unconditional floor still denies credential stores (`.ssh`, `.gnupg`,
`.aws`), protected system roots (including Unix executables/libraries, device
roots and Windows roots on every drive), parent traversal and NUL paths. It applies
before discretionary allowances and trusted-root grants. Enabled policy
honors action roots, forbidden roots, read/write grants, command classes,
tool rules and rate limits. Symlink and OS path normalization failures deny;
full path enforcement is not claimed by a lexical bootstrap check.

Time, resolver, filesystem and approval dependencies are deterministic seams
inside the module, with production adapters and non-network test adapters.
Security checks must address the operation's actual path and connection,
including time-of-check/time-of-use constraints; a decision over a string alone
cannot promise confinement of an unrelated later operation.

Remove OpenHuman's unused `max_cost_per_day_cents` during host configuration
migration. No cost cap is advertised until a cost accounting/reservation
callback and explicit accounting semantics exist. Do not silently accept an
unenforced replacement setting.

## Generation and performance

Every accepted policy change advances the generation and emits `PolicyChanged`.
Evaluation results identify the effective generation. Hosts reject stale
results. Cache keys cover generation, canonical call fingerprint and verified
caller identity/tier/origin. Never cache mutable approval grants, flow trust,
rate reservations, execution outcomes or DNS authorization across requests.
Generation alone does not describe those states. Static policy decisions can
be cached only when the result explicitly permits it; default to uncached.

Before migration, measure released-module `Evaluate` and `Check` p50/p99 and
bus calls per representative turn against the in-process characterization
baseline. Commit the workload, machine details and agreed budget. Resolve a
miss with batching or safe caching; do not bypass the module boundary. No
latency or coverage result is claimed without measured evidence.

## Redaction and network privacy

One redactor owns secret-token, PII/identifier, endpoint, home-path, structured
argument and free-text modes. The existing host redactors become a shared
acceptance corpus before deletion. Redaction is idempotent, bounded and applied
before persistence, broadcast, judge submission and audit. Diagnostics cannot
leak secrets when the module is unavailable: suppress sensitive payloads or
retain a documented minimum floor until boot makes the module mandatory.

`LocalOnly` denies nonlocal egress. `Standard` applies declared data and endpoint
policy. `Sensitive` requires a separately tested stricter descriptor policy;
remove/migrate it if no meaningful semantics are implemented. Prompt and tool
definition scanning returns typed verdicts integrated into policy; ownership
of existing TinyMCP/TinySkills scanning is resolved before duplication.

The URL guard rejects forbidden literal addresses and resolves and validates
every candidate address, including metadata/link-local, CGNAT, IPv6 ULA,
IPv4-mapped IPv6 and unusual numeric forms. DNS rebinding protection additionally
requires the caller's actual transport to connect to approved pinned addresses
while preserving TLS hostname verification. Redirects are rechecked and pinned
individually. A returned address list or URL validator without that connection
seam is not DNS rebinding protection. Browser and proxy transports that cannot
honor pinning require a verified egress proxy or deny the protected operation.

## Approvals, auto-approval and audit

The module owns the approval state machine and expiration; the host owns the
parked future and prompt surface. Host-served `ApprovalStore`, `ApprovalPrompt`,
`AuditSink` and `KeyringConsent` callbacks have typed errors and bounded waits.
State and decisions survive restart through the storage callback. Approval
identities bind to the original call fingerprint, origin and caller context.
Expired, mismatched, replayed or denied grants cannot authorize execution.
Default TTL is ten minutes; copilot and sub-agent TTL is three minutes.
`RecordExecution` produces the terminal execution outcome, separately from
permission. Cron external effects deny. SaaS has no implicit bypass: configure
a verified per-user prompt channel or deny when human approval is needed.

`ExecutionOutcome::Abandoned` records an in-flight execution that was abandoned
before the host could determine its effects. This is not a cancellation and does
not claim that the tool had no effects. Use `Cancelled` only for a definite
cancelled result; map legacy `aborted` values to `Abandoned` because aborting a
wait or task does not establish the execution's outcome. The `ExecutionOutcome`
wire enum is closed, so this value requires contract 2.0: 1.x hosts must reject
2.x providers rather than admit a provider whose result they cannot decode.

Jev is an optional judge, disabled by default and enabled per origin. It can
only convert `RequireApproval` to `Allow`; it cannot override any `Deny`, floor,
privacy or sandbox requirement. Redacted input and independent questions test
user intent, reversibility and exfiltration. Thresholds and budgets belong to
TinySecurity. Error, timeout, malformed response, unavailable service or low
confidence preserve human approval; an unavailable human channel denies.
Every verdict records sanitized scores, thresholds and `auto:jev` attribution.
`auto_approve_all` also writes audit rows. Judge-result caching cannot become a
reusable approval for a different call or bypass mutable authorization checks.

Audit covers policy changes, approvals, judge verdicts, execution and sandbox
decisions, with configurable bounded rotation and OS-appropriate restricted
permissions. Audit delivery failure behavior is explicit for required-audit
operations: when a required sink cannot confirm a row within its bounded wait,
deny the associated operation before execution. Optional audit may report a
sanitized degraded-health event without claiming persistence. Contract 1.6 adds
strict `EvaluateAudited2` and `CheckAudited2` requests containing the original
permission request and stable event ID, expected tail and generation. The module
constructs and sanitizes the event from that request and its computed result;
an internally computed SHA-256 digest of versioned, domain-separated canonical
original content binds retries even when redaction would collapse two inputs.
This unkeyed digest is correlation, not authentication or anonymization:
low-entropy originals may be guessed offline. No caller-supplied digest is trusted;
scope and stream come from trusted initialization. The native manifest advertises both
audited permission methods and the implemented `AuditSink2` callback as an optional
dependency. The SDK uses the package version as its spoken version and caret
minimum compatible range. Callback forwarding runs only when audit is configured
without native storage; absent audit or native storage needs no callback. Required
audit still denies permission when its configured callback is unavailable. Contract 1.7 additionally advertises implemented `ApprovalStore2` and
`ApprovalPrompt2` callbacks and durable approval lifecycle methods; their
[exact callback and human authority contract](../../crates/tinysecurity-approval/README.md)
requires explicit trusted initialization. Caller verdicts, replacement
arguments and committed booleans cannot supply permission. Required audit makes
unbound `Evaluate`/`Check` allows unavailable and refuses other unbound path,
command and scoped egress authorization/consumption methods before they grant or
reserve execution. Registration, classification and descriptive members remain
available; audited workflows for those additional scopes are later work.
Exact retries retain all correlation
metadata; tail overflow or a mismatched generation denies before callback. A
generation change during callback denies every allow while retaining committed
receipt evidence. Terminal execution audit is a separate event. The module never
claims an audit row committed before authoritative storage confirms it. Windows
local storage requires a preprovisioned protected current-user NTFS directory and
restricted preexisting journal. Actual ancestor handles retain directory-list
access without delete sharing; trusted ownership, restricted inherited ACLs and
reparse checks precede candidate writes. Unsafe or unsupported namespaces deny.
The stable journal supplies receipt authority; rotated files are reconstructable
views. Process termination/recovery tests do not imply physical power-loss or
Windows directory-creation durability guarantees.


### Audit versus Audit2

One ordered, contiguous audit stream per trusted scope and stream identity carries
policy-change, native-routine, approval, judge, shell, execution and sandbox
decisions as `AuditKind2` events. `Audit2` (callback `AuditSink2`) is the only
served audit member. The legacy `Audit` name and `AuditKind`/bool-receipt
vocabulary are reserved and never served: a bool cannot prove which event
committed, in what order, or against which tail. Every legacy kind keeps its
serialized name in `AuditKind2`; `shell` is the one added category.

`Audit2` takes an exact sanitized batch with `expected_tail` and returns an exact
receipt (`AuditEventReceipt2` per event, `new_tail`) only after data and metadata
sync. `EvaluateAudited2`/`CheckAudited2` (and the scoped variants) derive the
pre-execution event from the original request and computed verdict, so the host
never supplies the verdict. Terminal `RecordExecution2` events are a separate
phase. `RecordAudit2` (contract 1.21) lets the host append an `Execution` or
`PolicyDecision` event to the stream of any subject it names, under the same
sanitation, correlation and receipt rules as `Audit2`; see MODULE.md.

Contract 1.22 adds `CheckPaths2`, `ProtectedPath2`, `ProtectedFloor2`, `SpendAction2`,
`PeekBudget2`, `ClassifyHostAction2` and `PrivacyCheck2`: batch path checks, the unscoped
lexical floor and its vocabulary, the shared hourly action ledger, host-action
classification and a pure privacy decision. All fail closed; see MODULE.md.

Local files: Unix creates journal, lock and JSONL projections fd-relative with
mode 0600 and verifies owner and mode on every open. Windows requires a
preprovisioned protected current-user DACL and creates new views with restricted
inherited access; it never widens an existing ACL. Rotation runs before the
journal append, so a rotation failure (including a Windows sharing/lock violation
on rename) denies the candidate before any journal byte is written, and the same
retry commits exactly once after the blocker releases.

Failure semantics: required audit denies pre-execution on any callback or storage
failure, timeout, malformed receipt or stale generation. Optional audit reports
degraded health, never fabricates a receipt and never sets `committed`; scope and
sanitation failures deny even when audit is optional.
## Sandbox and crypto

Contract 1.9 implements `Plan2`, `EvaluateSandboxApproval2` and
`ConsumeSandboxPlan2`. The legacy reserved `Plan` payload retains its strict
wire form and always denies. Initialization authenticates the unique host peer
and fixes source provenance, deployment, mode settings, path/network/resource
ceilings and executor capability identity. Callers select those facts by ID;
they cannot supply their own trust, availability or enforcement claims.

SaaS and untrusted sources require kernel isolation and enforced filesystem
protection before any disabled mode is considered. Every requested hard
constraint must be `Enforced`; Noop, BestEffort, unsupported CPU time, unvalidated
proxy routing and credential-covering roots deny. `ResourceLimits2.cpu_time_ms`
means CPU time, while `cpu_millicores` means thousandths of a core. The legacy
`ResourceLimits.cpu_millis` remains CPU time; it must never be translated into
TinyBox 0.1.17's same-named millicore setting.

Recursive filesystem grants use the owner's subtree admission port. The complete
credential vocabulary for anchored home stores and credential containers, native
system ancestors and canonical aliases, host state reservations (including prospective prefix children), and readonly write rights
are checked before admission. Trusted roots cannot waive the credential or
internal-state floor; individual noncredential cache children remain available.
Configurable forbidden paths retain their existing explicit-trust precedence.
Individual tool path checks retain their arbitrary-depth credential-name floor.
An additive directory grant does not promise exclusions for every possible future
credential-named child; a launcher requiring that broader recursive-name contract
must supply verified enforcement or deny it.

Host networking requires permission under the immutable network ceiling plus
an authenticated human Once ticket bound durably to the exact canonical
operation, resolved grants, resources, constraints, network, source, scope,
generation and executor capability. Registry IDs, reservation metadata and the
independently checked temporal expiry do not enter the durable human binding.
Retargeting a symlink requires a fresh human decision for the new resolved plan.
Automatic judge approval, generic reusable grants and caller approval flags do not qualify.
Exact sanitized Sandbox audit commits before an opaque artifact becomes active.
Pending artifacts are discarded on every failed or cancelled publication path.
The initialized scopes share a 1024-row pool with an equal quota each; scopes
registered at runtime ([runtime sandbox scopes](runtime-sandbox-scopes.md)) hold at
most 8 rows per subject (across all of its scope identities) from a separate pool,
so neither starves the other. Consuming an artifact removes its row, and missing identities always deny replay.
A fingerprint is correlation only. Consume validates the full registered
artifact and owner, audits the exact phase, then rechecks expiry and generation
before atomically reserving it once. Registry capacity and pending expiry are
bounded; callbacks execute without policy or registry locks.

Planning and admission do not spawn processes or prove native confinement.
TinyBox owns actual enforcement and must recheck live backend availability,
capability identity and every hard constraint immediately before spawning.
The Task 14 launcher must revalidate grant root objects, protected-location and
alias snapshots, and the exact checked consume envelope before launch; refusal
must never fall back to an unvalidated raw spawn.
The native sandbox fixture proves loaded-module policy, authenticated human
approval, audit and artifact admission only. The current Landlock filesystem
floor, Seatbelt BestEffort and AppContainer unsupported subprocess isolation
cannot satisfy constraints they do not enforce.

Crypto is last: password encryption, keyring backends, device encryption and
pairing have one implementation with consent callbacks. Authentication,
credential ownership, sockets and consent UX stay host-side. Existing encrypted
data compatibility and migration are acceptance requirements. The incremental
[native device handle surface](../../MODULE.md#confidential-device-handles) now
adds optional SDK-init registrations, confidential authenticated dispatch and
exact human/audit receipts over the frozen device primitives. Scoped lifecycle,
bootstrap replay bounds and owned cleanup are implemented in the module; no
production host migration is implied. Contract 1.14 adds confidential password, keyring (consent-gated) and pairing status/authenticate/revoke members ([MODULE.md](../../MODULE.md#confidential-password-keyring-and-pairing-members-contract-114)); Linux Secret Service and pairing challenge delivery remain unavailable.

Contract 1.8 adds bounded init-only judge settings and optional typed judge
evidence on durable approval rows. Older init payloads retain their wire shape;
a legacy judge payload without explicit endpoint and bounded budget cannot activate.
The native scorer shares request reservations across caller scopes and reinit,
including disabled periods. Scores bind the original canonical call, generation,
origin, scope and fresh question/configuration version. See the
[native scoring contract](../../crates/tinysecurity-auto/README.md).

## Verification and completion

Each moved behavior first receives a characterization test in OpenHuman and a
matching contract/engine regression test. Golden serde fixtures pin versioned
wire forms. Tests cover allow, denial and every typed error. Unit tests avoid
live services and wall clocks. Native integration loads the real module and
tests bad digests, timeouts, latching and accepted reinit.

Linux, macOS and Windows CI exercises path/command semantics, native loading,
approval restart, audit permissions, network pinning, sandbox capability and
keyring behavior. Explicit unsupported-platform records explain any omission.
Full completion also requires fuzz/property tests, 90% per-file coverage,
dependency/license checks, MSRV and warning-free rustdoc, released artifacts,
OpenHuman migration and deletion of duplicated implementations. Bootstrap
checks passing establish only bootstrap completion.

`ConsumeSandboxPlan2` carries the original typed `Plan2` envelope as well as the
opaque artifact. The host derives that envelope from the exact prepared spawn:
argv, environment, cwd and input belong in its bounded original operation.
The owner validates its canonical binding before audit and again after the
callback; changed operations cannot consume a copied artifact. This does not
replace TinyBox's live isolation and capability checks.

The [contract 1.10 master subset](../module-crypto.md#confidential-injected-master-resolution)
implements only confidential config/app master resolution through immutable injected
callbacks, exact Human Once consumption and opaque native aliases. Per-binding
resolver uncertainty persists for the supplied broker lifetime across accepted
reinit. Device and native generation checks complete under retained registry locks
before publication. A rejected publication with valid clocks preserves prior
authority; accepted reinit clears pending native work and aliases without replacing
brokers or resolvers. Clock faults retain their permanent native close behavior. It provides no native OS/file access, password/plaintext operations or
production host adoption.
