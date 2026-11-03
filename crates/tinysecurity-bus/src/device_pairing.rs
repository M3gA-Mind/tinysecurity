//! Confidential host-attested paired-device tunnel lifecycle.

use serde::{Deserialize, Serialize};

/// Immutable paired-device scope and module-owned identity persistence binding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingScope2 {
    /// Existing native device scope whose static public key is used on the wire.
    pub scope_id: String,
    /// Existing `HumanOnly` master registration used to encrypt the private identity.
    pub secret_registration_id: String,
    /// Opaque fixed backend id for the encrypted module-owned state record:
    /// 1..=128 UTF-8 bytes, with no Unicode control characters.
    pub persistence_backend_id: String,
    /// Fixed backend containing channel-keyed legacy device metadata and ciphertext.
    /// `None` disables migration; it never causes a replacement identity to be minted.
    pub legacy_device_backend_id: Option<String>,
    /// Fixed source registration for the legacy encrypted private-key records.
    pub legacy_source_registration_id: Option<String>,
}

/// Init-only bounds for paired-device enrollment and reconnect.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingConfig2 {
    /// Existing trusted device scopes, at most 128.
    pub scopes: Vec<DevicePairingScope2>,
    /// Host-fixed defaults for runtime scopes. Runtime requests can select only
    /// a live approval scope; they cannot choose persistence or legacy authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_scope: Option<DevicePairingRuntimeScope2>,
    /// Maximum enrolled devices per scope, in 1..=4096.
    pub max_pairings: u32,
    /// Maximum pending enrollments and renewals per scope, in 1..=128.
    pub max_pending: u32,
    /// Maximum pending enrollment/renewal receipt lifetime in 1..=300000 milliseconds.
    pub max_pending_ttl_ms: u32,
    /// Maximum active session lifetime in 1..=604800000 milliseconds (seven days).
    /// Active expiry is also bounded by the authenticated host channel expiry.
    pub max_session_ttl_ms: u32,
    /// Maximum plaintext serialized state snapshot, in 1..=1048576 bytes.
    pub max_state_bytes: u32,
    /// Bounded context and persistence callback wait, in 1..=30000 milliseconds.
    pub callback_timeout_ms: u32,
}

/// Init-only authority defaults for runtime paired-device scopes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingRuntimeScope2 {
    /// Fixed host persistence backend shared by the module's scoped records.
    pub persistence_backend_id: String,
    /// Optional fixed source for one-time import of historical host identities.
    pub legacy_device_backend_id: Option<String>,
    /// Origins the host permits for dynamically registered device scopes.
    pub allowed_origins: Vec<crate::Origin>,
}

/// Request to bind pairing to an already registered live approval scope.
///
/// `approval_scope_id` is only a lookup key: the module resolves the canonical
/// live registration and derives the device and secret bindings itself. This
/// request cannot supply a subject, master registration, backend, or origin.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDevicePairingScopeRequest2 {
    /// Existing approval scope to bind; never treated as a subject claim.
    pub approval_scope_id: String,
}

/// Confirmation that one canonical approval scope is paired-device capable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingScopeReceipt2 {
    /// Canonical approval scope id registered by `TinySecurity`.
    pub scope_id: String,
    /// Whether the exact scope is active.
    pub active: bool,
}

/// Exact paired-device action. Context claims are resolved through fixed host callbacks.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DevicePairingOperation2 {
    /// Load or create the encrypted module-owned identity after master approval.
    Unlock {
        /// Server-owned authenticated controller event; never a user or model field.
        host_event_id: String,
    },
    /// Wipe one authenticated user's loaded identity and all its transient tunnels on logout.
    Lock {
        /// Server-owned logout/session-invalidation event.
        host_event_id: String,
    },
    /// Start a new QR enrollment under an authenticated user controller.
    Begin {
        /// Server-owned authenticated controller event.
        host_event_id: String,
    },
    /// Import the host's available channel-specific legacy keys under the approved master.
    ImportLegacy {
        /// One-shot authenticated user-controller event.
        host_event_id: String,
    },
    /// Recover public metadata for a durable pairing whose confirmation response was lost.
    Recover {
        /// Host-known channel id; the callback independently authorizes this exact channel.
        channel_id: String,
        /// One-shot authenticated user-controller event.
        host_event_id: String,
    },
    /// Process the existing versioned handshake and return its wire reply.
    Handshake {
        /// Single-use module-minted receipt.
        receipt: String,
        /// Server-owned socket event for this channel and connection.
        host_event_id: String,
        /// Confidential unchanged protocol handshake bytes.
        frame: Vec<u8>,
    },
    /// Prove static device-key possession and commit enrollment or renewal.
    Confirm {
        /// Single-use module-minted receipt.
        receipt: String,
        /// Server-owned socket event for this channel and connection.
        host_event_id: String,
        /// Confidential first authenticated frame under the static device key.
        frame: Vec<u8>,
    },
    /// Start a fresh proof for the same enrolled device on a newly registered channel.
    Renew {
        /// Existing module-minted pairing identity.
        pairing_id: String,
        /// Server-owned reconnect event, not a user assertion.
        host_event_id: String,
    },
    /// Extend a live session from fresh host attestation without client re-handshake.
    RefreshSession {
        /// Existing module-minted transient session capability.
        session_id: String,
        /// Server-owned event for the same still-authenticated socket.
        host_event_id: String,
    },
    /// Revoke an enrolled device from an authenticated user controller.
    Revoke {
        /// Existing module-minted pairing identity.
        pairing_id: String,
        /// Server-owned authenticated controller event.
        host_event_id: String,
    },
    /// End one transient socket session while retaining durable device enrollment.
    EndSession {
        /// Existing module-minted transient session capability.
        session_id: String,
        /// Server-owned close event for this exact channel and nonce.
        host_event_id: String,
    },
}

/// Confidential trusted-host operation; identity and transport facts are callback-derived.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingRequest2 {
    /// Exact host execution identity, bounded to 128 bytes.
    pub call_id: String,
    /// One paired-device lifecycle operation.
    pub operation: DevicePairingOperation2,
}

/// Pairing result. Optional fields are populated only for the matching operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingResponse2 {
    /// Owner-minted pending receipt for Begin or Renew.
    pub receipt: Option<String>,
    /// Owner-minted enrolled identity for Confirm or Renew completion.
    pub pairing_id: Option<String>,
    /// Transient frame capability created by Confirm; retired on socket close.
    pub session_id: Option<String>,
    /// Stable public core identity for Begin or Unlock.
    pub core_public_key: Option<String>,
    /// Verified device public identity after successful Confirm.
    pub device_public_key: Option<String>,
    /// Unchanged wire-format response for Handshake.
    pub frame: Vec<u8>,
    /// Absolute bounded expiry of pending receipt or active session, for host scheduling.
    pub expires_at_ms: u64,
}

/// Why the module is asking the host to attest an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePairingPurpose2 {
    /// Direct authenticated user-controller action for unlock, begin or revoke.
    UserController,
    /// One-shot direct-user authorization to import available legacy device keys.
    LegacyImport,
    /// Authenticated logout or user-scope invalidation observed by the host.
    UserLogout,
    /// A currently active authenticated event on a registered socket channel.
    SocketEvent,
    /// A backend-attested reconnect for an already enrolled device.
    Reconnect,
    /// A server-observed closure or expiry of one socket connection.
    SocketClosed,
}

/// Callback lookup; caller supplies only an opaque event id and purpose.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingContextRequest2 {
    /// Opaque server-owned event identity.
    pub host_event_id: String,
    /// Required host authority for this operation.
    pub purpose: DevicePairingPurpose2,
    /// Optional channel being authorized by a direct controller action.
    /// The host must bind it to authenticated server-owned state.
    pub requested_channel_id: Option<String>,
}

/// Facts independently resolved from the authenticated host and server-owned state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingContextResponse2 {
    /// Existing configured device scope.
    pub scope_id: String,
    /// Opaque stable user binding; no user identifier is exported in clear text.
    pub user_binding: String,
    /// Existing Secret2 alias for this exact authenticated scope, when Unlock is authorized.
    /// This module-issued alias is validated against `secret_registration_id` and generation;
    /// it is never accepted from the pairing request.
    pub secret_master_handle: Option<String>,
    /// One-shot host-issued capability returned only for a `LegacyImport` lookup.
    pub legacy_import_handle: Option<String>,
    /// Registered backend channel, empty for user-controller operations.
    pub channel_id: String,
    /// Host-minted backend pairing token, present only for registered socket events.
    /// It is bound to the pairing context and is never accepted from a module request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_token: Option<String>,
    /// Fresh connection nonce, empty for user-controller operations.
    pub connection_nonce: String,
    /// Current module generation captured by the trusted host.
    pub generation: u64,
    /// Actual host dispatch/socket source independently checked for this purpose.
    pub source: DevicePairingSource2,
    /// Absolute backend/session expiry, in milliseconds.
    pub expires_at_ms: u64,
}

/// Trusted source class returned by the host callback, never accepted from a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePairingSource2 {
    /// Authenticated direct user controller call, not an agent tool invocation.
    AuthenticatedUserController,
    /// Server-observed end of the authenticated user's active scope.
    AuthenticatedUserLogout,
    /// Agent-tool or sub-agent invocation; pairing authority is denied.
    Agent,
    /// Host automation; pairing authority is denied.
    Automation,
    /// Authenticated event on the existing registered socket channel.
    RegisteredSocket,
    /// Backend-authenticated reconnect for an enrolled device.
    BackendReconnect,
    /// Server-observed socket closure; no user interaction required.
    SocketClosed,
}

/// Fixed persistence operation; only encrypted module-owned record bytes cross the callback.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DevicePairingPersistenceOperation2 {
    /// Read the encrypted state and its compare-and-swap revision.
    Load,
    /// Store ciphertext only if the supplied revision still matches.
    Store {
        /// Revision returned by Load or the preceding successful Store.
        expected_revision: String,
        /// Ciphertext produced and authenticated by the module's native cipher owner.
        ciphertext: Vec<u8>,
    },
}

/// Legacy encrypted device private-key format selected by the fixed host store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePairingLegacyFormat2 {
    /// Authenticated ChaCha20-Poly1305 `enc2:` value.
    Enc2,
    /// Historical `enc:` value; decoded only inside the module and immediately re-encrypted.
    Enc,
}

/// One old channel's ciphertext and public device identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingLegacyRecord2 {
    /// Existing host/backend channel id.
    pub channel_id: String,
    /// Public X25519 device identity from the existing paired-device metadata.
    pub device_public_key: String,
    /// Historical format identified by the fixed source callback.
    pub format: DevicePairingLegacyFormat2,
    /// Encrypted private identity only; never plaintext key bytes.
    pub ciphertext: Vec<u8>,
    /// Revoked entries are represented explicitly and must be refused by the module.
    pub revoked: bool,
}

/// One-shot callback request for existing channel-specific identity ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingLegacyLoadRequest2 {
    /// Opaque host capability issued by the one-shot `LegacyImport` context lookup.
    pub handle: String,
}

/// Bounded existing identities from an exact trusted source; ciphertext only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingLegacyLoadResponse2 {
    /// Exact pairing scope bound by the host event.
    pub scope_id: String,
    /// Exact authenticated user binding; no clear user identifier is exported.
    pub user_binding: String,
    /// Module generation captured by the one-shot event lookup.
    pub generation: u64,
    /// Exact configured source backend.
    pub backend_id: String,
    /// Exact configured legacy source registration.
    pub source_registration_id: String,
    /// At most the configured per-scope pairing capacity.
    pub records: Vec<DevicePairingLegacyRecord2>,
}

/// Exact fixed persistence binding captured during module initialization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingPersistenceRequest2 {
    /// Configured opaque backend.
    pub backend_id: String,
    /// Existing configured scope.
    pub scope_id: String,
    /// Exact registered Secret2 master binding.
    pub secret_registration_id: String,
    /// One bounded load or compare-and-swap store.
    pub operation: DevicePairingPersistenceOperation2,
}

/// Load/store result; absent ciphertext means the trusted store has no record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingPersistenceResponse2 {
    /// Exact backend echoed by the fixed callback.
    pub backend_id: String,
    /// Exact scope echoed by the fixed callback.
    pub scope_id: String,
    /// Exact master registration echoed by the fixed callback.
    pub secret_registration_id: String,
    /// Current immutable-store revision.
    pub revision: String,
    /// Encrypted record only; private key bytes are never returned here.
    pub ciphertext: Option<Vec<u8>>,
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$ (
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([REDACTED])"))
            }
        }
    )+};
}
redacted!(
    DevicePairingRuntimeScope2,
    RegisterDevicePairingScopeRequest2,
    DevicePairingScopeReceipt2,
    DevicePairingScope2,
    DevicePairingConfig2,
    DevicePairingOperation2,
    DevicePairingRequest2,
    DevicePairingResponse2,
    DevicePairingContextRequest2,
    DevicePairingContextResponse2,
    DevicePairingPersistenceOperation2,
    DevicePairingPersistenceRequest2,
    DevicePairingPersistenceResponse2,
    DevicePairingLegacyRecord2,
    DevicePairingLegacyLoadRequest2,
    DevicePairingLegacyLoadResponse2,
);

#[cfg(test)]
#[path = "device_pairing_tests.rs"]
mod tests;
