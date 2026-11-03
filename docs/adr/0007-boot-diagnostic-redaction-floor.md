# 7. Fixed redaction floor for boot and log-path diagnostics

- Status: Accepted
- Date: 2026-10-14

## Context

Phase 3 of the OpenHuman migration (tinyhumansai/openhuman#7328) moves every
redactor to the module's `Redact` member. Two host paths cannot always wait for
the module: the Sentry `before_send` scrubber and the JSON-RPC request logger
(`rpc_log`). Both run before the module is loaded and admitted, while it is
faulted (ADR 3), and on hot logging paths where a bus round trip per line is
unaffordable. A host that logs nothing until the module is ready loses the boot
diagnostics needed to explain why the module never became ready. A host that
logs raw payloads in that window leaks credentials.

## Decision

The host keeps one minimal, fixed redaction floor for these two paths only, and
the module remains the single owner of every other redaction surface.

1. The floor is a short, documented set of linear-time rules, not a
   configurable registry: credential assignments (`token`, `password`, `secret`,
   `api_key`, `authorization` with its scheme), `Bearer` values, `Cookie` and
   `Set-Cookie` lists, URL userinfo, query strings and fragments, and the
   native home-directory prefix. It carries no configured literals, because the
   exact-secret registry only exists after module initialization.
2. The floor is a strict subset of the module's `Text` mode. A conformance test
   in the host runs the shared corpus (`crates/tinysecurity-redact/tests/
   fixtures/security-redaction-corpus.json`) through both and fails when the
   floor removes something the module keeps, or keeps a corpus needle the
   module removes without the corpus marking the case as module-only.
3. Once the module reports ready, these paths call `Redact` through a cached,
   batched client. The floor is the fallback only while the module is
   unavailable, uninitialized or faulted, never a second opinion beside it.
4. On a malformed or oversized input the floor suppresses the payload rather
   than printing it, matching the module's content-free refusal.
5. Nothing else may use the floor: approvals, structured arguments, endpoint
   display, audit, egress privacy checks and prompts call the module and deny
   their effect when it is unavailable.

The exception includes synchronous Sentry `before_send` and pre-module
request logging. Those hooks must scrub without awaiting module startup or
making a bus call, so they keep the fixed floor until the admitted redactor is
ready. Their early-boot use does not authorize the floor for ordinary product
surfaces or permit logging the original payload on refusal.

## Consequences

Boot diagnostics survive a missing module, with weaker coverage than the module
(no exact-secret literals, no validated identifiers such as cards and IBANs, no
structured-key redaction). Operators must treat boot-window logs as less
sanitized than steady-state logs. The duplicate rule set is small enough to
audit, and the corpus test stops it drifting from the module. Retiring the floor
requires a module that loads before logging starts, which is a separate
decision.
