# Approval execution outcomes

Contract 2.0 adds `ExecutionOutcome::Abandoned` for an in-flight execution that
was abandoned before the host could determine its effects. It is persisted as
an immutable terminal outcome and does not claim that the tool had no effects.
Use `Cancelled` only when the host has a definite cancelled result. A host that
sees the legacy `aborted` value maps it to `Abandoned` because aborting a wait or
task does not prove that execution had no effects.

This closed enum change is a contract-major bump: a 1.x host cannot safely
decode an `abandoned` result, so 1.x hosts reject a 2.x module during version
compatibility checks.
