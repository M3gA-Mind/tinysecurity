# Confidential crypto and secret members

## Confidential device handles

Optional `ModuleConfig.device: DeviceConfig2` adds `EvaluateDevice2` and
`ExecuteDevice2` to the native interface. Existing omitted-device payloads and
v2/v3/v4 wire frames keep their serialized forms. These members require TinyBus
confidential transport and the immutable verified `trusted_host` peer. Missing
configuration, another sender, public identity claims, unconfidential calls,
missing callbacks and required audit failures deny native authority.

Each configured device scope references a subject already registered in
`approvals`, captures its verified origin, and optionally consumes one static
X25519 credential during SDK init. Absent credentials generate native static
keys. Neither variant exports private material. Device calls select only an
existing scope and a bounded operation: issue a static/ephemeral key handle,
derive a role-bound tunnel, seal/open v2, seal/open v3 handshake or v4 ack,
revoke a handle, or cancel the authenticated scope. Public keys retain the
canonical 32-byte URL-safe unpadded base64 format.

Evaluate builds the exact content digest internally and uses the existing
verified approval callbacks. Execute requires the resulting exact human Once
receipt and fresh required audit correlation; automatic, durable-tool or
caller-asserted decisions cannot issue native authority. Every callback/worker
await is followed by live generation/scope/deadline checks. Plaintext, keys,
frames and handles do not reach approval/audit payloads, errors, Debug or
`PolicyInfo`.

Explicit init bounds cover registrations, handles, concurrent reservations,
per-scope control-operation rate, per-tunnel frame rate, TTL, message bytes and
retained bootstrap nonces. `frames_per_minute` defaults to 12000 (200 frames per
second), independently of `operations_per_minute`, and accepts 1 through 60000.
Older device configs receive the default. Reinit may change bounds without
reimporting credentials or changing immutable subjects.
It invalidates all old handles; successful new-generation receipts issue new
handles. Revoke removes dependent tunnels; scoped Cancel fences pending work.
Bootstrap replay evidence survives alias issuance, Cancel and reinit and fails
closed at capacity. Clock rollback/unavailability faults device authority for
that process. Shutdown closes owned credentials even when an SDK observer
retains the connection. See the [owned cleanup and replay limits](../crates/tinysecurity-crypto/README.md#scoped-device-handles).

Contract 1.23 adds confidential `DeviceFrame2` for streaming v2 frames. It
accepts only a live tunnel handle returned by `ExecuteDevice2`; it cannot issue
or extend a handle and checks scope, generation, TTL, revocation, per-tunnel
frame rate and message bounds. It reuses the native v2 codec and direction-bound
tunnel keys. Frame calls reuse the approved tunnel capability and need no new
human receipt; handshake and acknowledgement operations remain on the approved
Device2 path. The actual native module example exercises this member through
confidential TinyBus dispatch.

Contract 1.25 adds confidential `DevicePairing2` for the paired-device lifecycle.
The module retains the static private identity behind the configured HumanOnly
master, persists only authenticated ciphertext through a fixed callback, and
owns `Unlock`, `Begin`, `Handshake`, `Confirm`, `Renew`, `RefreshSession`,
`EndSession`, `Revoke`, `Lock`, `ImportLegacy` and `Recover`. Enrollment is durable
only after the first frame proves possession of the static device key. Renewal
proves that same key on the fresh socket; refresh keeps live tunnel keys and
replay counters. Session lifetime is bounded by both the authenticated
host-channel expiry and configured maximum. Import preserves each available
channel's legacy key inside the module; bounded revocation tombstones prevent
stale host ciphertext from reviving a revoked device. Recover reconciles a
durable pairing after a lost response and returns public metadata only. The
module does not establish UI provenance: host callbacks must derive
user-controller, socket and reconnect authority from trusted dispatcher/server
state. See the [contract specification](specs/device-pairing-contract-1.25.md).

The module capability is a prerequisite for host migration, not that migration
itself. The host still owns credentials, backend pairing registration, QR/socket
UX and consent presentation; it must wire the trusted callbacks and persistence
backend to this contract and remove its parallel `secrets.enc` and tunnel-crypto
ownership only after consuming a released artifact.

`device_native_contract` loads the hashed shared library and exercises actual
confidential dispatch, verified approval/audit callback continuity, v2/v3/v4,
replay/revoke, valid generation-two receipts, old-handle denial and SDK shutdown.
Run the retained runner with the absolute library path from both owner and
non-owner working directories. Linux proves Linux behavior; macOS and Windows
require their native runners. This does not release artifacts or migrate a host.

## Confidential injected master resolution

Contract 1.10 implements optional `ModuleConfig.secret` and confidential
`EvaluateSecret2` / `ExecuteSecret2`. The only operations are
`ResolveConfigMaster` and `ResolveAppMaster`. Init registers metadata: an exact
existing approval scope, purpose, opaque backend descriptor, target named slot
and at most three compatible historical readers. App authority is separately
registered; calls cannot override subjects, origins, backends, slots or paths.

Evaluation retains the same bounded native reservation, private challenge and
keyed safe correlation through execution. Registered auto approval, reusable
choices and judges cannot issue this grant. Actual confidential `VerifyHuman`,
Human Once decision and reservation CAS, and the exact required audit sink
receipt finish before backend load or mint. A canceled begin holds its admitted
reservation until expiry; retry requires a fresh original call id. There is no
second wait queue.

The fixed `SecretBackend2` callback has confidential `Load` and `Set` only.
Every reply echoes backend, registration, generation, operation id, phase and
slot before status interpretation. Denial is not absence. Encodings are bounded
to 4096 bytes. A valid target skips all historical readers; compatible sources
must parse and agree before mutation. Their original uppercase/whitespace
encoding is copied unchanged and verified by exact target readback. No source
is deleted. File is only a named injected store entry, not physical file access.

One resolver and exclusive callback context persist for each immutable binding.
Live native authority is checked before and after each await and before mint
and publication. Cancellation after Set begins, timeout, wrong readback and
indeterminate mutation permanently fence that resolver. The host callback broker
must independently serialize each actual target slot, retain detached provider
workers and block fresh reads/mint/Set until trusted quiescence and exact readback.
Operation ids and Stored acknowledgements do not provide generic CAS or durability.
Recreating a resolver, restarting a process or dropping a service tree is not
recovery authority. This checkpoint provides no recovery member.

Results contain a bounded random alias, purpose and generation only. The master
and underlying native handle remain internal, with no alias-use/read/export
member. Aliases are pruned on expiry or revocation and cleared at close. Owned
successfully decoded callback values and unpublished output are wiped; SDK
serialization, frame copies and partially decoded serde values are outside that
cleanup guarantee.

Configured-secret SDK reinit keeps the same process owner, store brokers and
master resolvers. Native and device transitions retain their state locks through
policy publication; valid-clock publication rejection preserves old authority.
Accepted generations invalidate pending native work and clear aliases, while
persistent resolver uncertainty remains unavailable. Native clock faults still
close authority permanently. Device replay capacity and every scope epoch are
checked before publication; bootstrap evidence survives accepted reinit. Physical files, plaintext delivery and routine native consumers remain outside
this subset; password, OS keyring and pairing members are in contract 1.14 below
(`PasswordCrypt2`, `KeyringAccess2`, `PairingControl2`).

## Confidential native config cipher (contract 1.11)

`EvaluateSecretCipher2` and `ExecuteSecretCipher2` are confidential routine
operations over an actual `ExecuteSecret2` ConfigUserMaster acquisition. They
never prompt for routine fields or create master authority from a receipt.
`secret_cipher` SDK metadata fixes one existing registration, consumer identity,
enabled setting, callback timeout and physical slot count. It cannot change on
reinit. Older 1.10 initialization omits it and retains its original behavior.
An older decoder does not know the additive `native_routine` audit kind; hosts
using this capability must negotiate the new contract vocabulary.

Evaluate owns the real private crypto pending reservation, then commits required
sanitized NativeRoutine intent through the existing AuditClient. Execute removes
it once, requires unchanged metadata and confidential input, and checks actual
execution, output-stage and publication audit acknowledgements. Audit arguments
contain keyed operation/output correlations, Engine-derived durable scope/policy
and fixed classifications. Caller-supplied audit event identities reserve stream
order; they never construct a private routine acknowledgement or cipher grant.

Plaintext, disabled/empty passthrough and disabled migration replacements go only
to the fixed confidential `SecretCipherConsumer2.Deliver` port. A real trusted
receiver authenticates the pinned loaded module and stages zeroizing output in
an exclusive bounded physical slot. It refuses overwrite and releases locally
only after the matching successful owner response. A staged callback reply is
not product plaintext publication. The owner retains its original reservation
through final required audit and live validation; only true ciphertext appears
in ordinary result fields. A failed/canceled/late/invalid stage leaves its sender
slot permanently occupied across generation changes and reinit. Operation-ID
or status echoes cannot clear uncertainty. A successful response permits the
receiver to consume/wipe its exact slot before accepting another stage there.

The broker currently requires every confidential destination to be an admitted
native module. Ordinary unattested host callbacks are denied, including master
HumanOnly prompt and secret backend delivery. The tracked native fixture loads
the real hashed TinySecurity cdylib and a separately admitted host-trusted native
callback fixture. This proves module-to-admitted-native-consumer composition;
it does not prove ordinary OpenHuman host callback admission. That TinyBus
integration gap remains open. SDK serde/frame/partial-decode copies and process
abort are outside the owned-buffer wiping guarantee. App document storage remains a separate unfinished capability.

## Confidential password, keyring and pairing members (contract 1.14)

Optional `ModuleConfig.crypto: CryptoConfig2` adds three confidential members,
`PasswordCrypt2`, `KeyringAccess2` and `PairingControl2`. Like the device and
secret members they require TinyBus confidential transport and the immutable
verified `trusted_host` peer; an unconfigured module denies all three. Config is
init-only and immutable across reinit. It bounds payload bytes (at most 1 MiB)
and operations per monotonic minute (at most 4096).

`PasswordCrypt2` preserves the existing Argon2id v0x13 (64 MiB, 3 passes, 1 lane)
plus AES-256-GCM format. The payload keeps the legacy byte-array shape
(`ciphertext`, `nonce`, `salt`); encrypt generates a sixteen-byte salt unless the
caller supplies one for the legacy separate-salt layout. Frozen host fixtures
decrypt unchanged. At most two derivations run at once and there is no wait queue.

`KeyringAccess2` reads, writes or deletes a named secret on a backend chosen at
init: platform default (Keychain, Credential Manager, Linux kernel keyring),
Linux kernel keyring, or a protected encrypted file in an absolute directory.
Linux Secret Service is enabled in Linux release artifacts; other builds keep
the feature opt-in and fail closed when it is not compiled. Every
operation first calls the host's `ai.tinyhumans.tinysecurity.KeyringConsent2`
`Consent` callback with the verified caller, purpose, access kind and secret name
(never the value), and proceeds only on an explicit allow. Invalid names or
purposes, oversized values and denied or timed-out consent never reach the backend.

`PairingControl2` exposes `Status`, `Authenticate` (constant-time bearer check
against legacy tokens), `Invalidate` and `Revoke` for accounts registered at init.
Challenge issuance and numeric verification (`Begin`/`Verify`) are not exposed:
they need confidential delivery to an admitted native destination, the same open
TinyBus gap as the config cipher consumer. Their ports fail closed.

Passwords, plaintext, secret values and bearers are wiped after use and never
appear in `Debug`, errors, `PolicyInfo` (only `callbacks.crypto`) or audit rows.
The X25519/HKDF device tunnel remains the `EvaluateDevice2`/`ExecuteDevice2`
surface above. The OS keyring test runs on every platform and is required to
use the real credential store when `TINYSECURITY_REQUIRE_OS_KEYRING=1`; it
always removes its entry.
