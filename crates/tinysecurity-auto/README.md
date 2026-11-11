# Native approval scoring

This internal crate owns optional Jev scoring, local threshold comparisons,
shared request reservations and bounded exact-score caching. Hosts compile only
`tinysecurity-bus`; the engine and its inference SDK run inside the native module.

The durable approval engine verifies the registered user/workspace/agent, access
ceiling and original canonical call first. Cron external effects deny before any
shortcut. Existing exact human grants and host automatic rules retain their CAS
and audit requirements. Only a request still requiring approval reaches Jev.

## Trusted initialization

`ModuleConfig.judge` is absent by default; hosts turn it on by default when they
hold a credential (ADR 0008). Enabling it requires the explicit
resolved backend credential, exact endpoint and typed provider, an authenticated
approval store/prompt registration and configured audit. No environment credential
lookup or per-call credential is supported. Invalid init/reinit rejects without
changing the active policy. The credential and init endpoint are registered as
redaction literals. Configuration, clients and prepared inputs have redacted Debug.

A host that can only read the credential through the admitted module (from its
keyring) leaves `credential` out. The module then asks the init-bound trusted host
through the confidential `JudgeCredentialHost2.Credential` callback on the first
judgement, never during load, within the judge's `timeout_ms`. It reuses the client
for five minutes (`HOST_CREDENTIAL_TTL_MS`). An endpoint rejection (401/403) drops
it at once, and the next ask says `rejected`. A reinit drops it too. No credential,
or a failed ask, sends that request to a person, the same as an unavailable judge.
A credential supplied this way arrives after init, so it is not registered as a
redaction literal; it is used only in the outbound request header.

`threshold_millis` is the default inclusive minimum for both intent and
reversibility. `exfiltrate_millis` is the inclusive maximum for exfiltration.
`thresholds` can override these three bounds by origin and verified local/external
effect class. Values are in 0..=1000; duplicate origins or class rules reject.
The three fixed Noul questions are `intent`, `reversible` and `exfiltrate`.
The module compares finite 0..=1 probabilities locally. Confidence does not
establish human identity or permission.

The SDK validates endpoint/key and response IDs, primitive types and model.
Its retry count is zero with valid nonzero backoff settings. The native engine
also wraps every evaluation in a total Tokio deadline. Timeout is 1..=30000 ms.
Intent, concrete context and argument JSON pass through the shared bounded
redactor before submission. Sanitation failure sends no request. No transcript,
authorization ticket, caller identity or init endpoint is included in model state.

## Budget and cache

`max_requests` is 1..=10000 per `budget_window_ms` (1..=86400000 ms). A shared
atomic reservation occurs before HTTP, and failures consume the reservation.
Cache hits recheck current budget/clock state. An injected monotonic rollback
latches closed. Scorer disable/re-enable retains the previous reservation ledger.
No guessed token accounting or provider-reported usage permits extra requests.

`cache_entries` is at most 1024 and `cache_ttl_ms` at most 600000 ms; zero disables
caching. Entries contain only validated scores. Their digest binds the full
original approval binding, origin, concrete class, redacted request and fresh
configuration/question version. Expiration is strict at the TTL boundary. Fresh
policy/grant/expiry/generation checks still run; cache entries never authorize a
changed call or become reusable permissions. No lock crosses an external await.

## Durable result and fallback

Qualified results store `JudgeEvidence2` with fixed question IDs, local thresholds,
sanitized outcome, configuration digest and conservatively rounded numeric scores
in millionths. Exact floating-point comparisons decide qualification; rounding is
only audit presentation. `auto:jev` uses a once-only approved row, never a human
ticket. Confirmed CAS and exact required audit acknowledgment precede Allow.
A generation change during scoring or persistence strips permission.

Low confidence, invalid scores, HTTP/decode errors, timeout, exhausted budget or
unavailable scoring leaves the request pending for the existing authenticated
human callback. Missing human delivery denies. Human review still uses its private
verified ticket and first-winner CAS. The winning durable/memoized row governs
whether a prompt is required; newer scores cannot rewrite an indeterminate phase.

`judge_native_contract` loads the real cdylib and uses a literal-loopback HTTP
stub, fake credential, real sender-bound disk callbacks and the native audit
journal. CI runs it on Linux, macOS and Windows from both working directories.
Unit tests inject a typed client and clock for exact thresholds, malformed
responses, deadlines, concurrent budgets, rollback and cache isolation. No test
calls production inference or reads operator credentials.
