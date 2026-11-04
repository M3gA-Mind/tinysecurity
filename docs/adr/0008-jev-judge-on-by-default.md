# 8. Turn the Jev judge on by default in the host

- Status: Accepted
- Date: 2026-11-04
- Supersedes: the "off by default" clause of [ADR 0005](0005-jev-judge-only.md)

## Context

ADR 0005 kept the judge off until a host opted in, one origin at a time. In
practice no host opted in, so every call needing approval went to a person,
including calls the person had plainly asked for. Hosts want to ask people less.

## Decision

A host turns the judge on by default whenever it holds a Jev credential, and
gives people a way to turn it off. The default lives in the host, not here:
`ModuleConfig.judge` stays absent by default, because the judge needs an explicit
credential and this module does no ambient credential lookup.

Every other rule of ADR 0005 stands. The judge changes only RequireApproval to
Allow, never Deny or a mandatory privacy or isolation rule. Redaction precedes
submission. Timeout, error, malformed response, low confidence or an unavailable
judge keeps human approval required. Origins are still listed explicitly, and a
host must leave out any origin with no person to fall back on.

## Consequences

Redacted call details leave the machine by default, so a host must keep the judge
off under a local-only privacy posture. A host must also validate its judge
settings before init: a rejected configuration fails the module closed, and that
costs every call rather than one question.
