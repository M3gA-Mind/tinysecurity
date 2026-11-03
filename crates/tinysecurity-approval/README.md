# Durable exact approvals

`tinysecurity-approval` is an internal module engine. Hosts link only
`tinysecurity-bus` and use contract 1.7's `EvaluateApproval2`, `Decide2`,
`ConsumeApproval2`, `RecordExecution2`, `ListApprovals2`, `CancelApproval2`,
`ExpireApproval2`, `PreauthorizeFlow2`, and `ImportApprovalHistory2`.
`ParseReply` recognizes intent and never supplies human authority.
Contract 1.17 adds `RegisterApprovalScope2`, `ReplaceApprovalScope2` and
`RetireApprovalScope2` for subjects registered after init, tool and flow grants
(`auto:tool-grant`, `auto:flow-grant`) and `Check::HostTool`; see
[MODULE.md](../../MODULE.md#runtime-approval-scopes-and-host-tools-contract-117).

## Initialization and callbacks

Trusted SDK initialization supplies optional `approvals` containing a finite
`timeout_ms` in 1..=30000 and up to 128 immutable scope registrations. Each
registration binds the verified original user/workspace/agent, access ceiling,
origin-independent policy reference and current generation. The reference is
an immutable partial scope, not a fully composed policy ID. Audit configuration
is required. The exact unique initialization peer is captured as callback
identity; a well-known replacement peer cannot take over.

The host serves `ApprovalStore2.Load` and `.Cas` and `ApprovalPrompt2.Prompt`
and `.VerifyHuman` at the callback object path. Every handler must enforce
transport-authenticated module provenance and exact registered scope. The
existing reserved `ApprovalPromptRequest2` and `ApprovalPromptResponse2` wire
shapes remain unchanged: the implemented `Prompt` member instead uses
`ApprovalDeliveryRequest2` and `ApprovalDeliveryResponse2`, which acknowledge
delivery only. `VerifyHumanRequest2` and `HumanDecisionReceipt2` are separate
explicit authority verification. An existing host must opt in to these new
members and configure approvals before any of them can grant permission.

`Load` returns bounded strictly parsed rows. `Cas` atomically compares the
expected version and durably commits the next row plus a mutation receipt
ledger. An identical mutation retry must return its original exact receipt,
even after later row versions; reuse with changed content must reject. Store
and audit acknowledgment precede both prompt delivery and `RequireApproval`.
Creation retries keep at most 1024 unresolved identities in memory. Exact durable
loads retire confirmed identities; concurrent stale loads reconcile the stored
winner before creating a new row. This bound applies to outstanding creation
retries, not the lifetime number of completed actions. The host must keep its
bounded load history without dropping active rows or unexpired reusable grants.
Fresh and replayed prompt delivery reload the durable winner and reconcile its
exact audit phase after reentrant decisions, including a swallowed decision error.
A failed or indeterminate acknowledgment denies execution; `Load` never guesses
whether an unacknowledged mutation succeeded.

The host owns parked futures, verified prompt routing and product events. Its
private human-action ledger issues an opaque ticket only after authenticating
the deciding user/session. `VerifyHuman` must bind that ticket to every byte of
the pending typed row, including request ID, nonce, subject, origin, generation,
expiry and full original-call binding, and return the verified actor and choice.
Being the trusted bus peer alone does not make model input a human action.
Tickets are never persisted or printed by the module; only their SHA-256
correlation and sanitized attribution enter durable rows.

Forced, user-requested approval is a host routing mode: the host may start it
only from a validated WebChat request, must suppress all allowlists and
automatic decisions, and must allow only a once choice. A forced request from
any other origin is denied before `EvaluateApproval2`. Detached sub-agent
classification and keeping its approval card visible after the parent turn
ends also remain host responsibilities; the host must preserve the verified
origin when delegating and must not infer it from prompt or tool arguments.
The approval engine owns only the typed origin and durable decision. When a
parked request reaches its deadline, the host should call `ExpireApproval2` so
the row records `expired`; `CancelApproval2` is reserved for explicit host
cancellation.

Rows carry optional `session_id`, copied from the already identifier-redacted
caller thread and checked against that binding when loaded. `ListRecentDecisions2`
reads terminal/approved decisions across currently registered scopes and omits
pending rows. `PurgeSession` receives that same hashed session identifier once
per registered scope; the host store removes only pending rows for the exact
scope/session pair and preserves decision history. The engine verifies each
scope/session echo and caps each callback's removal count.

After an audit sink failure, the host may call `RecordAuditError2` with the raw
failure detail and a new audit correlation. The engine applies the configured
`RedactMode::Text` redactor, then caps the sanitized text to 512 characters,
and CAS-persists only `ApprovalRow2.audit_error`. This metadata update never
changes approval state or grants authority. The host must store/use the
returned sanitized row value and must never persist the raw callback argument.

## Authority and lifecycle

Version-one bindings use domain-separated SHA-256 of bounded original parsed
JSON, canonical object ordering, ordered arrays, tool identity, actual checks,
verified context, origin, exact policy generation and subject. The full 64-hex
digest remains in the typed stored row; the existing outer 32-hex fingerprint
is correlation only. Redacted argument equality cannot authorize different
original content. Durable subject and policy handles also use full digests.
Digests are unkeyed binding/correlation, not authentication or anonymization.

Pending requests become approved or denied through first-winner CAS. An exact
approved call must win a unique irreversible reservation before execution;
only that reservation can receive one immutable terminal outcome. Reusable
tool/flow choices reconcile the source row's exact required audit phase before
deriving new permission. They retain exact reviewed content and context, with flow review
restricted to at most 100 already human-approved exact row IDs. Cancellation,
expiry and stale generation deny; a rollback in wall or monotonic time faults
approval use. Default TTL is 600000 ms, or 180000 ms for copilot/sub-agent;
callers may only shorten it.

Restart preserves history and unexpired exact reusable grants. A fresh module
instance cannot resume another instance's pending or once-only execution.
Legacy imports preserve sanitized history in denied rows and never revive broad
grants. Cron external effects deny before automatic or reusable shortcuts.
SaaS has no automatic bypass and needs a verified prompt when approval is due.
An optional [native Jev scorer](../tinysecurity-auto/README.md) can qualify a
verified pending request before prompt delivery. Its sanitized evidence is stored
in the exact row, with `auto:jev` attribution and once-only choice. It never
creates a human ticket or reusable tool/flow grant. Caller-provided judge verdicts
and parsed replies still grant nothing. Memoized indeterminate creations retain
their original lifecycle and evidence even if newer scores differ.
When approvals are configured, unbound permission methods and the older audited
permission methods cannot bypass the durable lifecycle.

## Judge and auto-approve evidence matrix

Proven by `judge_matrix_tests` and the native `judge_native_contract`, with a
stub judge and no real service: the judge is off by default and per-origin
opt-in (a non-opted origin, including SaaS, makes no request); a qualified
verdict only converts a pending approval to a once-only `auto:jev` Allow, never
a hard denial, floor, privacy or isolation requirement; low confidence, an
invalid reply, timeout, SDK error and budget exhaustion fall to a human; an
unavailable human channel denies; each row, with scores, thresholds and the
fixed question IDs, is durably audited before permission; the endpoint and
credential exist only in SDK init configuration and never in `PolicyInfo`.
`auto_approve_all` writes an audited `auto:host-policy` row and fails closed when
the audit append fails. SaaS has no automatic bypass and denies when its
verified prompt callback is absent. No wire change: contract stays 1.13.

## Native evidence

`approval_native_contract` loads the actual cdylib in two independent processes.
The fixture host persists row mutations and original receipts with append and
fsync, and privately persists authenticated-human ticket receipts. It checks
reentrant `Decide2`, reservation, terminal replay, exact old-mutation receipt
replay after later versions and reopening the ledger, exact reusable grants
after restart, orphan denial, native expiry, cancellation and absent prompt denial. CI executes it on Linux, macOS and Windows from the owner root
and an unrelated working directory. Windows uses a protected preprovisioned
current-user fixture namespace, following the native audit contract.

Each native CI runner collects JSON and LCOV from all features and targets,
requires 90% line coverage per compiled source and 80% coverage of changed
executable production lines against the canonical base, and uploads the reports
with checkout, base, toolchain and platform metadata. Platform admission requires
Windows audit sources on Windows and the native sink/journal/rotation on Unix.
