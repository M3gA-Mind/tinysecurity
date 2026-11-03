# Native security module

The artifact is `tinysecurity-module`, exporting TinyBus ABI v1. Its interface
is `ai.tinyhumans.tinysecurity.Policy`, with object
`/ai/tinyhumans/tinysecurity/Policy`. Its methods are `Evaluate`, `Check`,
`PolicyInfo`, `RegisterPathPolicy`, `ValidatePath`, `ValidateParent`, and `CheckPath`.
Accepted SDK reinit advances a generation and emits `PolicyChanged`; rejected
configurations retain the old policy and generation. There are no Init/Reinit
RPC methods. Configuration requires `contract_version` and `policy`. The optional
`judge` field may be omitted or set to `null`, which leaves automatic scoring off.

```json
{
  "contract_version": [1, 12],
  "policy": {
    "enabled": false,
    "action_dir": "",
    "workspace_dir": "",
    "allowed_commands": ["pwd", "date", "uname", "whoami"],
    "forbidden_paths": []
  },
  "judge": null
}
```

Judge configuration has redacted Debug and travels only in SDK config. A non-null
`judge` is accepted only with its full trusted initialization (resolved credential,
exact endpoint, approval store and configured audit); otherwise init or reinit
rejects and keeps the old policy. See [native approval scoring](crates/tinysecurity-auto/README.md).
Invalid thresholds/timeouts are rejected before capability admission.
`PolicyInfo` never returns credentials. The wire version is separate from
release version. Hosts require matching major and module minor >= host minor;
unknown security input fields and enum tags reject rather than authorize.
SDK configuration states the host's required version: initialization and reinit
reject a required minor newer than this module supports, preserving the old
configuration and generation on rejected reinit.

## Trust and supported behavior

Caller agent, thread, flow, call ID, origin and access tier are verified host
facts. Only trusted host adapters may construct checks; model arguments never
supply authority. The original arguments travel as JSON text, keeping the
contract free of serde_json as a normal dependency. Supported bootstrap tool
identities are `local_diagnostic`, `path_check`, and `command_check`, each
requiring matching nonempty checks. Unknown tools deny even with claimed safe
checks. Check is an internal trusted-host operation, not a model-visible tool.

Path checks require the host's absolute operation-resolved target, resolve existing
ancestors including symlinks, and enforce the
credential/system/traversal floor on lexical and resolved forms even when
policy is disabled. Traversal is any segment that starts with `..` and holds only dots and
spaces (`..`, `.. `, `...`), on every OS. Windows treats exact `..` as a parent
component; some Windows path APIs separately normalize trailing spaces or periods.
The policy also rejects `...` as a conservative cross-platform rule, even though
it can remain a distinct name on Windows. Such a `forbidden_paths` entry is rejected
at registration. Unknown native path dialects, broken symlinks and failed
resolution deny. Enabled action roots must resolve to existing directories;
workspace and configured forbidden roots deny before approval. New files can
be checked through their existing parent. Permission does not guarantee
confinement against a later concurrent filesystem mutation; execution must
retain its own safe-open/jail boundary. Full Windows alias/ADS/device handling
and rich shell grammar parity remain T2. Bootstrap commands allow only exact,
argument-free `pwd`, `date`, `uname`, `whoami` through a trusted host executable
search path. Compound commands, expansions, heredocs, arguments, executable
paths and unrecognized commands deny conservatively on every OS.

Enabled bootstrap Evaluate/Check writes deny with `approval_unavailable`; no unusable request IDs are
minted. Unknown tools/effects deny. Cron writes deny even with disabled policy.
Readonly callers cannot write. Decisions include generation and are uncached.
The host must reject stale generations and never retry/fallback after module
faults/timeouts. SDK faults remain latched; ordinary denials do not fault.

## Immutable filesystem scopes

Contract 1.1's filesystem members register independent immutable agent scopes.
They accept host-owned native roots and state reservations, preserve scope IDs
across SDK reinit, and authorize canonical reads or prospective writes without
requesting approval. Approval gating remains the caller's separate responsibility.
See [the scope contract](docs/specs/immutable-path-scopes.md) for configurable
floor differences from conservative bootstrap checks, registry bounds, symlink
handling and read-only grants. These members do not add command grammar parity.

## Reserved capabilities

Durable approval lifecycle/flow/reply, redaction/scanning, scoped egress guards
and audit have implemented members in the generated method inventory.
Contract 1.7 approvals use explicit initialization and authenticated callbacks;
see [durable exact approvals](crates/tinysecurity-approval/README.md).
Scoped egress ([egress](docs/egress.md)) issues DNS-vetted, single-use socket grants;
this module never opens the connection, so each transport owner must connect only to
the approved sockets (connection pinning is the transport's job, not claimed here).
Sandbox planning ([sandbox](crates/tinysecurity-sandbox/README.md)) selects and audits
a plan; TinyBox enforces isolation at launch. The optional judge
([scoring](crates/tinysecurity-auto/README.md)) only scores requests that still need
approval and never grants human-only authority. Keyring consent and the password and
pairing members are documented with the other [confidential crypto members](docs/module-crypto.md).
Unsupported member calls return the bus's unknown-member error.

## Packaging and smoke checks

CI builds/tests on Linux, macOS and Windows, checks the host contract dependency
tree and enforces per-file coverage. The release workflow builds eleven native
platforms and five distro variants, then produces platform archives,
modules.toml and checksum.toml. Its verifier requires all sixteen archives and
checks every manifest digest against the hosted release files.

The OpenHuman migration #8369 roll-up keeps the additive contract 1.x line.
The proposed `abandoned` outcome in `tinyhumansai/tinysecurity#43` changes the
wire contract to 2.0 and remains a separate change.

Releases are dispatched only from canonical `tinyhumansai/tinysecurity` on
`main`, after the module changes merge. Fork repositories and epic branches
cannot enter the release job; the CI release-policy regression checks those
repository/ref combinations.

```sh
cargo run -p tinysecurity-module --example verify_module -- <native-library>
cargo run -p tinysecurity-module --example verify_module -- <release-tag-url> <archive> <sha256>
```

The same verifier is used for local and downloaded release artifacts. Local
verification also rejects a wrong digest and tampered bytes before activation,
rejects missing SDK configuration, and confirms stopped modules refuse reinit.
Fault-injection and timeout latching remain SDK conformance work, not a
bootstrap claim. Timing uses 500 sequential calls per method, one Evaluate call for one diagnostic or
one Check call for two checks per sample. See measured results and the enforced
release budget in [performance](docs/performance.md). OpenHuman's host-side view is
the [security architecture page](https://github.com/tinyhumansai/openhuman/blob/main/gitbooks/developing/architecture/security.md).

## Confidential device handles
Full details: [`Confidential device handles`](docs/module-crypto.md#confidential-device-handles).

## Confidential paired-device lifecycle (contract 1.25)
Full details: [paired-device lifecycle specification](docs/specs/device-pairing-contract-1.25.md).

## Browser destination authorization (contract 1.28)
Full details: [browser dial specification](docs/specs/browser-dial-contract-1.28.md).

## Host skill-scan decisions (contract 1.29)
Full details: [host skill-scan specification](docs/specs/skill-scan-contract-1.29.md).

## Confidential injected master resolution
Full details: [`Confidential injected master resolution`](docs/module-crypto.md#confidential-injected-master-resolution).

## Registered subject policies (contract 1.12, extended in 1.13)
Full details: [`Registered subject policies (contract 1.12, extended in 1.13)`](docs/module-subject-policies.md#registered-subject-policies-contract-112-extended-in-113).

## Confidential password, keyring and pairing members (contract 1.14)
Full details: [`Confidential password, keyring and pairing members (contract 1.14)`](docs/module-crypto.md#confidential-password-keyring-and-pairing-members-contract-114).

## Credentials-only redaction and open public egress (contract 1.15)

Both additions are additive. A 1.14 host keeps working against a 1.15 module,
and a 1.15 host refuses a 1.14 module.

`RedactMode::CredentialsOnly` (`credentials_only`) is for free-form tool output,
where `Text` over-redacts. It removes the exact initialization registry, provider
token shapes (`sk-`, `gh*_`, `github_pat_`, `AKIA`/`ASIA`, `xox*`, Stripe, Google,
npm, GitLab), JWTs, PEM private keys, `Cookie`/`Set-Cookie` headers, and labelled
values (`token`, `api_key`, `password`, `secret`, `Authorization: Bearer ...`) that
look like a credential. It keeps e-mail, phone, card, address, IP, URL and home-path
content, and keeps labelled values that read as source code (`token = get_token()`,
`accessToken: string`, `password = None`, numbers, `<placeholders>`). It is not a
privacy surface: use `Text` for logs and audit. Rotating a credential is a policy
`Reinit` with the new `RedactorConfig`; the registry is immutable per generation.

`EgressPolicy.open_public` registers every `http`/`https` destination, so
`destinations` and `local_capabilities` must be empty and `LocalOnly` is refused.
The address floor is unchanged: loopback, private, link-local, metadata, CGNAT and
reserved addresses are refused for literals and for every resolved candidate, and
the privacy mode and data-category checks still run first.

`EgressPolicy.preflight_transports` (`browser`, `proxy`; no duplicates) lets those
transports receive a verdict. The module cannot verify that a browser or proxy
pins the returned sockets, so the grant is a preflight: DNS rebinding after the
verdict is the executor's risk. `PinnedDirect` stays the only pinned transport, and
a local capability never accepts a preflight transport. Both fields are omitted from
the wire when unset, so existing policies serialize unchanged.

## Runtime approval scopes and host tools (contract 1.17)

Additive: a 1.16 host keeps working against a 1.17 module, and a 1.17 host refuses
a 1.16 module (it requires the three scope members and `Check::HostTool`).

`ApprovalConfig2` fixes at most 128 operator scopes at init. A host that serves
many subjects (SaaS tenants, derived embedded agents) registers each one later:

| Member | Effect |
| --- | --- |
| `RegisterApprovalScope2` | Adds a scope. An identical repeat is `unchanged`; the same identity or the same subject with anything else is a conflict. A stale generation, bad grants or a malformed stream deny. |
| `ReplaceApprovalScope2` | Atomically changes posture, grants or `policy_ref` of a live scope (init scopes included). The subject and, for runtime scopes, the audit stream cannot change. Rows bound to another `policy_ref` stop being decidable. |
| `RetireApprovalScope2` | Removes a runtime scope (initialized scopes are replaced, never retired); every later call under it denies and the ports release the subject. A failed release keeps the scope registered so the retirement can be retried. |

All three are private host-only members served to the authenticated init peer,
like the other registrations. The table holds at most 65,536 live scopes. The
ports must admit a subject (its store scope and audit stream) before it becomes
usable: runtime scopes carry a host-persisted `audit_stream_id` and always forward
audit to the host `AuditSink2`; they never open a native journal. The engine owns
the generation, so repeating a registration after a policy advance is `unchanged`
rather than a new scope. A live subject keeps its audit stream, and a retired one
keeps it for an hour (far past any callback deadline): registering it again with
another stream in that window is refused, so a call still in flight for a retired
scope can never reach another scope's ledger. Pins older than that are reclaimed, so
only live and recently retired subjects count against a bound of about one million.
Initialized scopes can be replaced but not retired, so their (possibly native)
audit backend never changes.

`ApprovalGrants2` rides on a registration: exact tool names, and exact tool names
inside one named flow. A grant only converts a required approval into an
automatic one (`auto:tool-grant`, `auto:flow-grant`), persisted and audited like
every other row. It applies to SaaS origins (the scope is the tenant's own), but
never overrides a denial, a Cron external effect, reviewed reuse or a human-only
tool (`HUMAN_ONLY_TOOLS2`, `native_*`), which registration also refuses to name.
Names are never wildcards. Name-wide permanence is therefore host configuration
re-registered with `ReplaceApprovalScope2`, not a persisted human row: durable
`Tool`/`Flow` choices stay exact-content grants.

`Check::HostTool {}` lets the host request approval for a tool whose effect the
module cannot inspect (`gmail_send`, a Composio action). The module never
authorizes it by itself (alone it is `approval_unavailable`, which the approval
path treats as "needs a human"), and it never relaxes a `Path` or `Command`
check carried beside it. It is valid only for tool names outside the module's own
effect classes (`local_diagnostic`, `path_check`, `command_check`), the human-only
tools and `native_*`, and never beside `Unknown` or `PolicyChange`. Audit
correlations stay host-allocated (`AuditCorrelation2.event_id` and the tail it
tracks per stream); the module does not mint them.

### Subject handles and unbound members (contract 1.18)

Additive: a 1.17 host keeps working against a 1.18 module (its wire shapes do not
change), and a 1.18 host refuses a 1.17 module.

A registration (`RegisterApprovalScopeRequest2.report_handle`) can ask the receipt
(`ApprovalScopeReceipt2.scope_handle`) to carry the sanitized subject handle the module
sends in every host callback (`ApprovalStore2`, `AuditSink2`, `ApprovalPrompt2`) for
that registration. A host that serves many subjects keys its stores by it, so it reads
the handle from the receipt instead of reproducing the derivation. A request that does
not ask, and every retirement, gets the 1.17 receipt without the field.

Configuring approvals no longer refuses the filesystem, command and egress members
(`ValidatePath`, `ValidateParent`, `CheckPath`, `CheckCommand`, `ScopedUrlGuard`,
`ScopedEgressCheck`, `ConsumeEgressAuthorization`). They are separate permissions that
never ask a human, so only a required audit (a durable event per permission) refuses
them. The tool-permission members (`Evaluate`, `Check` and their scoped and audited
forms) still cannot return `Allow` once approvals are configured, because a tool call
must go through the durable lifecycle.

## Runtime sandbox scopes (contract 1.19)

Additive: a 1.18 host keeps working against a 1.19 module, and a 1.19 host refuses a
1.18 module (it requires the two scope members).

`SandboxConfig2` fixes at most 128 immutable scopes at init, and each scope's subject
must equal the audit scope's subject. A host that serves an unbounded set of subjects
(profiles, tenants, derived agents) registers each subject's scope later, the same way
it registers runtime approval scopes:

| Member | Effect |
| --- | --- |
| `RegisterSandboxScope2` | Adds a scope validated exactly like an init scope. An identical repeat on the same stream is `unchanged`; the same identity with other facts or another stream, or an initialized identity, is refused. |
| `RetireSandboxScope2` | Removes a runtime scope and discards every artifact it issued, pending or active, so none can be checked or consumed afterwards. Initialized scopes are never retired. |

Both are private host-only members served to the authenticated init peer. They need a
configured sandbox engine (an empty `SandboxConfig2` is enough) and a configured audit:
every runtime scope carries a host-persisted `audit_stream_id` and records its plans and
consumes on the host `AuditSink2` under its own subject and stream, never in a native
journal. A scope's `approval_scope_id` must name a live approval scope of the same
subject. The receipt (`SandboxScopeReceipt2.scope_handle`, only when
`report_handle` is set, never on a retirement) carries the subject exactly as
`AuditSink2` receives it, so a host keys its ledgers by it.

Bounds and eviction never widen policy. The table holds at most 65,536 live scopes; a
full table refuses a new registration (`capacity`) and never evicts a live scope, so a
subject's ceilings are never silently dropped or replaced. Retirement is the only way a
scope leaves, and the registry slot, artifacts and audit client go with it. A runtime
subject holds at most 8 staged or active artifacts across all of its scope identities, runtime scopes share a pool of 15,360 and
initialized scopes keep their own 1024, so one subject cannot exhaust another's capacity and
busy runtime scopes cannot starve the initialized ones. A plan in flight keeps the audit
stream it started on if its scope is retired meanwhile, and a retired or unknown runtime
identity never falls back to the base stream. A live subject keeps its audit
stream and a retired one keeps it for an hour: registering it again with another stream
in that window is refused, so a plan still in flight for a retired scope cannot reach
another ledger. Several scope identities may share a subject; its stream is released
only when the last of them retires. Changing a live scope's facts is a retirement
followed by a new registration, which also invalidates its outstanding artifacts.

## Operator host network and process-level jails (contract 1.21)

Additive: both fields default to off, so a 1.20 host keeps its behaviour against a 1.21
module, and a 1.21 host refuses a 1.20 module.

- `SandboxScope2.operator_host_network` declares that the owner's configuration already
  grants the host's own network up to `network_ceiling`. A `Plan2` for `NetworkPolicy::Host`
  under such a scope is planned without a per-command human approval (the artifact carries no
  approval reservation). A request above the ceiling is still refused (`ceiling`), and the
  field is ignored when the scope's deployment or origin is `SaaS`, where host networking
  always needs an exact human approval.
- `SandboxPlanRequest2.accept_process_isolation` marks an ordinary tool command of the
  scope's operator. Only then may a process-level jail whose constraints are best effort
  (macOS Seatbelt) run it; the artifact's `minimum_isolation` is `process`. An executor that
  meets the kernel floor with every constraint enforced is always preferred. A request that
  sets the flag for an untrusted source or a mandatory-isolation (`SaaS`) scope is refused
  (`floor`), and an executor with no isolation or the `noop` backend is never accepted.

## Policy and egress gap members (contract 1.22)

Additive. Seven members close the gaps that kept host-side security code alive. Every external
effect fails closed: an unknown scope, a malformed or oversized input, or a required audit that
cannot bind the call answers an error, never an allow. Latency budgets are per call.

- `CheckPaths2` (`PathBatchRequest2` -> `PathBatchResponse2`): one `PathCheckKind` over up to
  4096 paths (each at most 4096 bytes) under a registered path scope. The answer has the
  request's length and order and equals the per-path `CheckPath` answers; no result is shared
  between entries. Budget: one `spawn_blocking` for the whole batch, filesystem metadata per
  path, so a directory walk pays one bus round trip per batch. Refused with required audit,
  like `CheckPath`.
- `ProtectedPath2` (`ProtectedPathRequest2` -> `ProtectedPathResponse2`): the unconditional
  lexical floor with no scope and no filesystem access: credential stores, system and
  installation roots, parent-directory traversal (`..` and any segment of two or more dots
  followed only by dots and spaces, such as `.. ` or `...`), NUL bytes and Windows roots and
  extended prefixes, on every OS. Exact `..` is a Windows parent component; trailing spaces
  and periods are a separate API-specific normalization case, while `...` can remain a
  distinct Windows name. At most 4096 paths. Budget: in memory, sub-millisecond.
- `ProtectedFloor2` (no arguments): the floor's vocabulary (credential directories, single-file
  stores, segment pairs, lower-cased absolute prefixes), built from the constants the matcher
  uses, so a host handing it to a jail grant resolver cannot drift from `ProtectedPath2`.
  Budget: in memory, sub-millisecond.
- `SpendAction2` and `PeekBudget2` (`BudgetRequest2` -> `BudgetDecision2`): the registered
  command scope's hourly ledger, the one `CheckCommand` and `Check::HostAction` spend. For an
  enabled scope, a read-only tier answers `read_only_mode` before anything is spent; otherwise
  `PeekBudget2` answers `rate_limited` when the ledger is spent and `SpendAction2` reserves one
  action or answers `rate_limited` (reservations are not refunded). A disabled scope always
  answers `allow` and spends nothing. An unknown scope is an error. The ledger survives
  reinit. Budget: in memory, sub-millisecond. Refused with required audit.
- `ClassifyHostAction2` (`HostActionClassRequest2` -> `HostActionClassResponse2`): the
  informational `CommandClass` of a host tool from its permission level and external effect.
  Never an execution grant and independent of audit configuration. Budget: in memory,
  sub-millisecond.
- `PrivacyCheck2` (`PrivacyCheckRequest2` -> `PrivacyCheckResponse2`): the privacy half of
  egress for call sites with no destination to pin. `Standard`, a local destination and the
  control plane always pass; `local_only` refuses every external transfer that is not control
  plane; `sensitive` refuses external user content unless it was assessed `none` or `low`
  with no identifying category (credential, secret, token, password, identifier, email,
  phone, ssn, card) and refuses an unassessed payload. A refusal is
  `Verdict::Deny { reason: DenialReason::Privacy }`, `cacheable: false`, stamped with the live
  policy generation. Budget: a pure in-memory decision. Refused with required audit.

## Native credential-store roots (contract 1.24)

- `CredentialRoots2` (`CredentialRootsRequest2` -> `CredentialRootsResponse2`): resolves bounded
  native credential-store denial roots from the host's optional operator home; see
  [credential roots](docs/module-credential-roots.md). Filesystem canonicalization runs on a
  blocking worker so the module's async bus executor remains responsive.

<a id="approval-origin-classes-durable-flow-trust-and-scored-prompt-screening-contract-122"></a>

## Approval origin classes, durable trust and scored prompt screening (contracts 1.22, 1.26 and 1.27)

Additive: every new member and enum value is absent from a 1.21 host's traffic, and a 1.22 host
refuses a 1.21 module.

### Origin classes for `EvaluateApproval2`

`Origin` gains `TrustedAutomation`, `LocalOperator` and `Unlabelled`. The module, not the host,
decides what each answers, without parking the call:

| Origin | Answer |
| --- | --- |
| `Cron` | An external effect is denied; a read stays automatic (unchanged). |
| `TrustedAutomation` | Audited automatic approval, attribution `auto:trusted-automation`. The host's internal background jobs and workflow actions the user already declared. |
| `LocalOperator` | Audited automatic approval, attribution `auto:local-operator`. The CLI and a direct chat. |
| `Unlabelled` | Denied, unless the scope holds a whole-tool grant for the tool: then an audited approval attributed `auto:tool-grant`. No prompt, no reviewed-reuse row, no judge, and neither `auto_approve_all` nor a flow grant approves it. |

A human-only tool (`sandbox_host_network`, `device_crypto`, `policy_change` and the native
grants) still needs its own fresh human decision under every origin, and no earlier decision of its content is reused. A sandbox scope whose origin is `Unlabelled` is treated like `SaaS` for the operator privileges (mandatory isolation, no operator host network, no unjailed host run). The automatic approvals are
persisted and audited through the same callbacks as any other row and are consumed once like any
other row; replacing the scope or a grant revokes an unconsumed one.

### Durable flow trust: `GrantFlowTool2`, `RevokeFlowTool2`, `ListFlowTrust2`

Flow trust persists exact flow/tool digests in the host-served approval store, with bounded,
audited grants and consume-time revocation checks. Listing exposes sanitized display labels.
See [durable flow trust](docs/specs/durable-flow-trust.md) for lifecycle and scope details.

Contract 1.26 adds durable whole-tool trust through `GrantTool2`, `RevokeTool2` and
`ListToolTrust2`. Its Standard-scope eligibility and lifecycle rules are in
[`docs/specs/durable-tool-trust.md`](docs/specs/durable-tool-trust.md).
The private host-only `ImportTrustSource2` records one durable source/item receipt
alongside its imported trust row, so retries after partial migration or revocation
cannot restore legacy authority.

Contract 1.27 adds `RevokeToolById2`. A host can revoke the opaque `request_id`
returned by `ListToolTrust2` even when the tool's display label is redacted; the
module verifies the row belongs to the supplied registered scope and records the
usual audited cancellation.

### Scored prompt screening: `ScanPrompt2`

`ScanPrompt2 { text }` answers `{ tier, score_milli, rule_ids }`. The tier is `allow`, `review` or
`block` (thresholds 550 and 700 thousandths); the score is the additive rule weight in
thousandths, capped at 1000; `rule_ids` are content-free codes in detection order. It carries the
detector the host used to run itself: the override, role-hijack, system-prompt, credential and
tool-abuse rules, the obfuscated-instruction and exfiltration-intent heuristics, leet, Cyrillic,
fullwidth and invisible-character normalization, and three matching variants (lowered, collapsed,
compact) so space-padded single-token triggers still score. Its false-positive tuning is kept:
recalled-memory transcripts that merely mention "system prompt" or a "token push", the plural
"tokens" of language-model text, and a colleague named Dan. A base64-like run and an
invisible character are reported (`obfuscation.base64_run`, `obfuscation.invisible_character`) but
carry no weight: they are common in benign content. The optional
`OPENHUMAN_PROMPT_INJECTION_CLASSIFIER=heuristic` host classifier is dropped;
the deterministic owner scorer is the only classifier signal. A tier is context
and never authorizes execution. Input is bounded at 64 KiB; larger `ScanPrompt2`
input returns `review` with `input.oversized`, never a partial score. Latency budget: about 20 us per KiB in release
(1 KiB 19 us, 4 KiB 65 us, 64 KiB 1.0 ms on the reference machine), so p99 under 5 ms for any
accepted input.

`ScanPrompt` and `ScanToolDefinition` keep their verdict wire. The latter accepts a
serialized JSON object, which the MCP registry caller must build from the tool's
complete definition; arrays, scalars and malformed JSON are refused. Their scanner now also reports a
space-padded `jailbreak` as `override.obfuscated_role`, so a remote tool description with spaced-out
trigger words no longer slips through.

## Executor choice, workspace-less plans and the operator's host run (contract 1.22)

Additive: `SandboxPlanRequest2.options` (`SandboxPlanOptions2`) and two `SandboxArtifact2`
flags (`host_run`, `no_workspace`) default to off and are absent from the wire when off, so
a 1.21 host keeps its behaviour and its fingerprints against a 1.22 module. A 1.22 host
refuses a 1.21 module, and a 1.21 module rejects a request that sets an option
(`deny_unknown_fields`).

- **Executor choice.** A scope declares every verified executor of the host; `Plan2` picks
  one. With no option it is the first eligible one (a micro-VM first, then the host's
  declaration order). `options.preferred_backend` moves that backend's eligible executors to
  the front; with `options.require_preferred_backend` no other backend is planned and none
  eligible is `unsupported`. A preference never makes an executor eligible: availability,
  isolation, the exactly enforced constraints and the mediated proxy are all still required.
  The host maps `artifact.backend` to the executor it drives.
- **Workspace-less plan.** `options.no_workspace` is for a container with no workspace mount.
  A writable grant in the request is refused (`ceiling`); the artifact records
  `no_workspace` and carries only read-only grants.
- **The operator's host run.** `options.host_run` asks for a run with no jail. The module
  issues a `host_run` artifact (`backend` `noop`, `minimum_isolation` `none`, `executor_id`
  `host`, network `host`, no grants and no constraints) only when all hold: the deployment
  and origin are not `SaaS`, the source is `trusted_host`, and the scope carries
  `environment: disabled` (the operator's setting). Anything else is refused (`floor`), so
  an untrusted source (a hook, a scheduled job, a registry MCP server) and every `SaaS`
  scope get a refusal, never a host run. A host run claims no confinement: a request with
  grants or `no_workspace` is `invalid_request` and one with a resource bound or
  `deny_subprocesses` is `unsupported`. The plan is audited, staged and admitted exactly once like any other, and
  `ConsumeSandboxPlan2` re-derives it from the request, so a request that does not ask for
  the host run cannot reuse it.

Latency: all three are in-memory decisions inside the existing `Plan2` and
`ConsumeSandboxPlan2` calls (no new member, no I/O besides the audit append those calls
already make), so they keep the budget of those calls: p50 <= 1 ms, p99 <= 10 ms excluding
the audit callback.

## Host-recorded audit events (contract 1.21)

Additive. `Audit2` accepts only the module's init-time scope and stream, which a host that
serves many subjects never evaluates anything under. `RecordAudit2` appends one host event
to the stream of the subject the host names:

- `AuditRecordRequest2` carries the `subject`, its persisted `stream_id`, an `AuditKind2`, the
  `attribution`, `arguments_json`, `rule_ids` and the exact `AuditCorrelation2` (event id,
  committed tail, policy generation) the host reserved under its own stream lock.
- The module sanitizes the payload with the policy's redactor (identifier-hashed subject, text
  attribution, structured arguments), forwards it through the same `AuditSink2.Append`
  callback and answers with the `AuditResponse2` evidence of `Audit2`. A host must treat an
  answer without `committed` as a failed record; the module never fabricates a receipt.
- Only `AuditKind2::Execution` and the new `AuditKind2::PolicyDecision` are accepted
  (`AuditKind2::host_recordable`), so a host record cannot impersonate a module decision
  (permission check, approval, judge, sandbox, policy change, native routine). `PolicyDecision`
  is a call the host let through without a prompt: `auto_approve_all`, approvals switched off
  for the agent, or an allowlist match.
- A subject is bound to the first stream it is recorded under; a different stream for it, a
  stale generation, a malformed identity or an oversized payload answers denied and uncommitted.
  The member needs a configured audit client and errors without one.

## Host-tool admission (contract 1.20)

Additive ([specification](docs/specs/host-tool-admission.md)). `Check::HostAction` and `Check::HostShell` judge a host
tool or shell command by its permission level, the caller's tier and origin and a registered command scope's autonomy
and hourly budget, with typed refusals (`read_only_mode`, `rate_limited`, `scheduled_read_only`, `high_risk`). An allowed
`spend: true` call reserves one action from the scope's ledger, shared with `CheckCommand`, and gives it back if a later gate refuses it.

## Per-call exact credentials: `RedactWith` (contract 1.16)

Additive: a 1.15 host keeps working against a 1.16 module, and a 1.16 host
refuses a 1.15 module (it requires `RedactWith`).

`RedactWith` takes a `RedactRequest` plus `secrets`, exact credentials that apply
to that call only. They supplement the initialization registry; they never
replace it, and the next call does not see them. A host that serves many tenants
(each with its own provider key) therefore redacts a tenant's own credential from
that tenant's output without a process-wide `Reinit`, which would serialize the
tenants and let one tenant's key set be visible to another's call.

Limits match the initialization registry: at most 128 literals of 4 to 4096 bytes,
16384 bytes in all, none equal to or containing a redaction marker. A violation is
a refused request (`InvalidArguments`), never echoed. The module keeps a bounded
cache (32) of compiled registries keyed by a digest of the literals, so repeated
calls with the same key do not recompile the rule set; an evicted registry is
rebuilt on demand. The member is confidential: the literals are not logged or
observable on the bus.



## Audited native permission queries (contract 1.34)

`CheckPermissionAudited2` takes `PermissionAuditRequest2`: the original typed
`PermissionRequest2` and a stable `AuditCorrelation2`. It supports path and
prospective-parent validation, individual and batched path checks, command gates,
budget peeks, and descriptor privacy decisions. This closed vocabulary cannot
invoke secret, approval, sandbox, execution, or action-reservation members.
Command gates do not reserve an action; execution still needs its own reservation.

The module computes the result from its registered scopes, derives and sanitizes
the audit payload itself, and returns `PermissionAuditResponse2`. Its `decision`
is present only when the matching event is committed and permitted under the
current policy generation. Audit loss, stale generation, or an indeterminate
receipt withholds the result. The separate audit evidence remains available for
reconciliation. Legacy unaudited permissions continue to refuse calls when audit
is required. Hosts serialize correlations against the configured stream and must
check both `audit.permitted` and `audit.committed` before using a result.

## Audited command execution and action-budget reservations (contract 1.35)

`CheckCommandAudited2` evaluates a command under its currently registered
command scope and returns the exact existing `CommandDecision` only after a
durable audit receipt. An Allow carries a guarded action reservation: audit
failure, cancellation, or a stale policy generation refunds it; a committed
receipt commits the reservation. Exact retries return the same decision and
receipt, while changed requests using the same event id are refused. Current
scope ownership is checked before replay lookup. Read-only commands retain the
command policy's existing Allow and accounting behavior; the separate
`CheckPermissionAudited2::GateCommand` remains a non-reserving authorization
query.

`ReserveActionBudgetAudited2` takes a `BudgetRequest2` and stable
`AuditCorrelation2`. It reserves only the registered command scope's hourly
action accounting. It is not an execution permit: the host must independently
complete tool, path, command, approval, and other authorization checks before
dispatching any operation.

The module returns the budget decision only with a committed audit receipt. The
audit event id identifies this accounting operation; exact retries return the
same committed result without reserving again, while reuse with changed request
or correlation is refused. A failed or indeterminate audit drops the pending
reservation. Replay records live no longer than the in-memory action ledger.
Hosts must keep the correlation stable for a retry and serialize audit stream
tails as required by the configured sink.
