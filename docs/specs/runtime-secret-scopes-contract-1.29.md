# Runtime secret-scope registration (contract 1.29)

`RegisterSecretScope2` lets a trusted host adapter add a secret resolver after
the module has initialized. This supports tenant and embedded-agent approval
scopes without reinitializing the process-global secret registry.

The host must register the corresponding approval scope first. The request
carries only the immutable `SecretRegistration2` descriptor and its approval
scope ID. The module resolves the live scope from its approval engine and
derives the native subject, durable subject, policy reference, and generation
from that canonical scope. A caller cannot supply or override those fields.

Registration is bounded by the native registry's 65,536 lifetime scope
identities. An exact repeat is idempotent and preserves the existing resolver,
including its persistent failure state. Reusing a registration ID with a
different descriptor is denied. Revoked runtime IDs stay tombstoned for the
life of the native registry and cannot be reactivated by registering the same
descriptor again; a replacement needs a new ID. Native admission checks the
expected approval generation while holding the registry lock, so an in-flight
generation change cannot add stale authority.

Retiring or replacing an approval scope first revokes native secret handles,
drops pending secret grants and aliases, and removes its runtime secret
registrations. Re-registering requires a live approval scope and an immutable
secret descriptor. Initialized secret registrations remain configured but
their old handles are invalidated by the same retirement boundary.

The new member is host-only, uses the authenticated module connection, and
returns only the opaque registration ID and active status. It does not return
subjects, backend contents, keys, or plaintext. Older modules do not implement
this member and therefore do not satisfy contract 1.29.

## Registration-owned ciphers (contract 2.1)

Contract 2.1 adds an optional `cipher: Option<SecretScopeCipher2>` to
`RegisterSecretScopeRequest2`. A host can boot the module under a neutral scope
(an empty `SecretConfig2.registrations` list and no `secret_cipher` init config)
and give each tenant its own routine cipher at runtime. The field is skipped
when absent, so the 2.0 wire form is unchanged. Rust callers that build the
request with a struct literal must add `cipher: None`.

`SecretScopeCipher2` carries a consumer ID, the encryption setting, the slot
count (1..=128), the callback timeout (1..=30000 ms) and the audit stream ID.
It names no registration and no subject. The module binds the cipher to the
enclosing registration and audits it under that registration's approval
subject. Only a `ConfigUserMaster` registration can own a cipher.

The module enforces tenant isolation itself:

- Every `EvaluateSecretCipher2` and `ExecuteSecretCipher2` call selects its
  cipher by `request.registration_id`. A master handle works only with the
  registration that acquired it, so one tenant's ciphertext never opens under
  another tenant's master.
- All ciphers share one pending inventory, so generation activation still holds
  it while it switches. Execute looks a pending entry up by ID and checks that it
  belongs to the requesting registration before removing it. Another
  registration's request can neither execute nor discard it.
- A consumer ID is bound to one registration and its slot vector for the life of
  the process. The static init consumer is reserved the same way. A slot left
  uncertain by a failed, canceled or late delivery stays occupied and is never
  handed to anyone, including a later cipher of the same registration. Delivery
  goes only to the registration's own consumer, so one tenant's failed delivery
  never touches another tenant's slots.
- Each cipher audits through its own client for the registration's subject and
  stream. A runtime approval scope already owns a stream, and the cipher must
  use that stream. An init approval scope shares the init stream, and only the
  init subject may use it. The init subject can never be moved to another
  stream. Any other subject is pinned to its stream in the same table that
  `RecordAudit2` uses, so a subject never writes to two ledgers. Those pins are
  kept after retirement, so a retired subject cannot come back on a different
  stream in the same process. Approval scopes, sandbox scopes and host-recorded
  audit each hold a subject's pin separately; a release by one path frees the
  stream only after the last holder lets go.
- Two live cipher registrations never share one master. At each cipher request
  the module computes a keyed, non-secret fingerprint of the registration's
  master (HMAC-SHA256 keyed by the master over the label
  `tinysecurity/master-fingerprint/v1`) and binds it to the registration. A second
  live registration whose fingerprint is already bound is refused, with the typed
  message `secret master already bound to another live registration`, before any
  ciphertext is produced or opened under that master. Retiring a registration
  releases its fingerprint, so the master may be registered again. The master is
  never stored, returned or logged. Master bytes are only loaded on acquisition,
  so the check runs at the first cipher request rather than at registration. The
  check covers cipher-owning registrations; a registration without a cipher can
  never decrypt through the cipher path.
- A `HumanOnce` master grant still needs an authenticated human decision. A
  cipher adds routine operations over an acquired master; it never acquires one.

Registration checks the cipher request before anything is registered. It
refuses a malformed cipher, a consumer bound to another registration or to a
different slot count, a stream other than the subject's, and a cipher on a
static registration. A refused request leaves no registration behind. If the
cipher still fails to build after the secret registration was admitted, the
module retires that registration again, so a master is never left registered
without the cipher it asked for. That retirement tombstones the ID, like any
other retirement.

An exact repeat, with the same descriptor and the same cipher (or none), is
idempotent. A repeat with a different cipher, a dropped cipher or an added one
is denied. Retiring or replacing the approval scope removes the registration's
cipher and its pending work. The consumer binding stays.

A registration also stays dead after an uncertain store readback, by design. A
failed or timed-out `TargetReadback` leaves the persistent resolver failed for
the life of the process, so its cipher can never acquire a master again. The
host recovers by retiring the approval scope and registering a new ID.

The process-wide native work budgets are shared by every registration:
`max_in_flight` and `max_pending_bytes` (`work_budget.rs`) and `max_handles`
(`native_handles.rs`). One tenant can therefore exhaust them for everyone.
Per-registration budgets are a follow-up.
