# Documentation

This directory holds documentation that does not belong in rustdoc: the shape
of the system, the reasoning behind it, and the constraints a reader needs
before touching the code. API reference lives in doc comments next to the code,
where it cannot drift.

## Layout

```text
docs/
├── README.md      # this index
├── specs/         # behavior and architecture specifications
├── plans/         # implementation plans derived from approved specs
└── adr/           # architecture decision records, numbered and immutable
```

- **[`specs/`](specs/README.md)** — one file per feature, module, or subsystem,
  describing its behavior, public surface, invariants, and acceptance criteria.
- **[`module-crypto.md`](module-crypto.md)** — confidential device, master, cipher, password, keyring and pairing members of the TinySecurity module contract.
- **[`module-subject-policies.md`](module-subject-policies.md)** — registered subject policy members and their generation-bound authorization rules.
- **[`specs/device-pairing-contract-1.25.md`](specs/device-pairing-contract-1.25.md)** — host-attested paired-device lifecycle contract and trust boundaries.
- **[`specs/local-provider-endpoint-1.32.md`](specs/local-provider-endpoint-1.32.md)** — same-machine-only provider locality for `LocalOnly` privacy checks.
- **[`plans/local-provider-endpoint-1.32.md`](plans/local-provider-endpoint-1.32.md)** — ordered implementation and verification steps for provider locality classification.
- **[`plans/device-pairing-contract-1.25.md`](plans/device-pairing-contract-1.25.md)** — ordered implementation and verification steps for pairing lifecycle support.
- **[`specs/browser-dial-contract-1.28.md`](specs/browser-dial-contract-1.28.md)** — destination-only, one-use socket authorization for opaque browser traffic.
- **[`specs/runtime-secret-scopes-contract-1.29.md`](specs/runtime-secret-scopes-contract-1.29.md)** — host-only runtime secret registration bound to live approval scopes.
- **[`specs/skill-scan-contract-1.29.md`](specs/skill-scan-contract-1.29.md)** — host skill-scan verdicts and approval behavior before execution.
- **[`plans/`](plans/README.md)** — implementation-ordered, test-first steps for
  delivering an approved specification. Plans name exact files and verification
  commands, and are updated as the work progresses.
- **`adr/`** — a dated record per significant decision. Use
  [`adr/0001-record-architecture-decisions.md`](adr/0001-record-architecture-decisions.md)
  as the template. An accepted ADR is not edited; it is superseded by a later
  one.

Complex modules also carry a module-level `README.md` inside `src/<module>/`
covering their design, public surface, and important constraints.

The current module-release contract is in
[`specs/tinybus-module-release.md`](specs/tinybus-module-release.md), with its
implementation sequence in
[`plans/tinybus-module-release.md`](plans/tinybus-module-release.md).

## Conventions

- Keep every Markdown file at 500 lines or fewer. When a topic outgrows that,
  split it into focused files and link them from the nearest `README.md`.
- Update documentation in the same commit as the behavior it describes.
- Prefer a concrete example over an abstract description.
- Link between documents rather than duplicating content; one fact lives in one
  place.
- Write a specification before a plan: the spec defines the outcome and
  constraints, while the plan defines the implementation sequence.
