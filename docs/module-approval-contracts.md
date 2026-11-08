# Approval contracts: runtime scopes, host tools and origin classes

These sections hold the detailed contract notes that `MODULE.md` summarizes. The
headings match the anchors `MODULE.md` links to, so existing references still resolve.

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
See [durable flow trust](specs/durable-flow-trust.md) for lifecycle and scope details.

Contract 1.26 adds durable whole-tool trust through `GrantTool2`, `RevokeTool2` and
`ListToolTrust2`. Its Standard-scope eligibility and lifecycle rules are in
[`docs/specs/durable-tool-trust.md`](specs/durable-tool-trust.md).
The private host-only `ImportTrustSource2` records one durable source/item receipt
alongside its imported trust row, so retries after partial migration or revocation
cannot restore legacy authority.

Contract 1.27 adds `RevokeToolById2`. A host can revoke the opaque `request_id`
returned by `ListToolTrust2` even when the tool's display label is redacted; the
module verifies the row belongs to the supplied registered scope and records the
usual audited cancellation.

Approval execution outcomes and the contract 2.0 compatibility boundary are
described in [`docs/specs/approval-execution-outcomes.md`](specs/approval-execution-outcomes.md).

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
