//! Confidential injected master resolution; initialization contains metadata only.
use crate::{AuditCorrelation2, Origin};
use serde::{Deserialize, Serialize};
/// Immutable master purpose; no password or plaintext operation is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MasterPurpose2 {
    /// Per-user configuration encryption master.
    ConfigUserMaster,
    /// Explicitly registered application encryption master.
    AppEncryptionMaster,
}
/// Exact historical named entry; File does not authorize filesystem access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MasterSlotKind2 {
    /// The application master entry.
    App,
    /// Registered subject's configuration master entry.
    User,
    /// The named `.secret_key` entry of an injected store.
    File,
}
/// Immutable backend descriptor and slot, independently verified by the callback owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding2 {
    /// Opaque configured backend descriptor, never a path or ambient account.
    pub backend_id: String,
    /// Exact entry kind.
    pub slot: MasterSlotKind2,
}
/// A read-only historical source binding.
pub type SecretSourceBinding2 = SecretBinding2;
/// Trusted init-only registration; references the existing verified approval subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRegistration2 {
    /// Opaque immutable native registration.
    pub registration_id: String,
    /// Exact existing approval scope.
    pub approval_scope_id: String,
    /// Verified origin captured during SDK initialization.
    pub origin: Origin,
    /// Exactly one purpose; App must be separately registered.
    pub purpose: MasterPurpose2,
    /// Immutable target descriptor.
    pub target: SecretBinding2,
    /// At most three compatible read-only historical entries.
    pub legacy: Vec<SecretSourceBinding2>,
}
/// Host-only runtime registration for a secret scope whose approval scope is live.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterSecretScopeRequest2 {
    /// Immutable secret registration; the module resolves the approval scope itself.
    pub registration: SecretRegistration2,
    /// Optional routine cipher owned by this registration alone (contract 2.1).
    ///
    /// Absent, the request keeps its 2.0 wire form. Present, the module binds a
    /// cipher, delivery slots and audit stream to this registration only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<SecretScopeCipher2>,
}
/// Routine cipher of one runtime `ConfigUserMaster` registration (contract 2.1).
///
/// It names no registration and no subject: the module binds it to the enclosing
/// registration and audits it under that registration's own approval subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretScopeCipher2 {
    /// Opaque consumer identity, unique to this registration for the process lifetime.
    pub consumer_id: String,
    /// Immutable encryption setting.
    pub enabled: bool,
    /// Physical receiver slots of this registration alone, in 1..=128.
    pub slots: u16,
    /// Fixed confidential callback timeout, 1..=30000 milliseconds.
    pub timeout_ms: u32,
    /// Opaque audit stream of the registration's subject; one stream per subject.
    pub audit_stream_id: String,
}
/// Safe confirmation of one active secret registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretScopeReceipt2 {
    /// Opaque registration identity supplied by the trusted host.
    pub registration_id: String,
    /// Whether the registration is currently active.
    pub active: bool,
}
/// Bounded retention and reservation ceilings, matching the internal registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLimits2 {
    /// Live registry entries, in 1..=4096.
    pub max_handles: u32,
    /// Simultaneous pending/native operations, in 1..=32; no queue.
    pub max_in_flight: u32,
    /// Per-registration operations per minute, in 1..=4096.
    pub operations_per_minute: u32,
    /// Maximum operation/handle lifetime, in 1..=300000 milliseconds.
    pub max_ttl_ms: u32,
}
impl Default for SecretLimits2 {
    fn default() -> Self {
        Self {
            max_handles: 128,
            max_in_flight: 4,
            operations_per_minute: 120,
            max_ttl_ms: 30000,
        }
    }
}
/// Metadata-only SDK initialization. Backends are injected confidential callbacks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig2 {
    /// One to 128 immutable verified registrations.
    pub registrations: Vec<SecretRegistration2>,
    /// Finite native retention and admission ceilings.
    pub limits: SecretLimits2,
    /// Callback deadline, in 1..=30000 milliseconds.
    pub callback_timeout_ms: u32,
}
/// Only implemented native master operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOperation2 {
    /// Resolve the registered user's configuration master.
    ResolveConfigMaster,
    /// Resolve the separately registered application's encryption master.
    ResolveAppMaster,
}
/// Exact authenticated original invocation; identity and backend overrides are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequest2 {
    /// Immutable registration selected by the trusted host.
    pub registration_id: String,
    /// Original call identity, bounded to 128 bytes.
    pub call_id: String,
    /// May only shorten the configured deadline.
    pub ttl_ms: u32,
    /// Registered master operation.
    pub operation: SecretOperation2,
}
/// Persist `HumanOnly` review of the exact admitted native reservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateSecretRequest2 {
    /// Exact original operation.
    pub request: SecretRequest2,
    /// Required ordered audit correlation.
    pub audit: AuditCorrelation2,
}
/// Consume Human Once and its actual audit receipt before any backend I/O.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteSecretRequest2 {
    /// Unchanged admitted operation.
    pub request: SecretRequest2,
    /// Exact reviewed pending identity.
    pub request_id: String,
    /// Required reservation audit correlation.
    pub audit: AuditCorrelation2,
}
/// Only opaque native alias and safe metadata are publicly returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretResponse2 {
    /// Native master stays inside the registry; this alias has no read/export member.
    MasterHandle {
        /// Random process-private alias, never historical key or registry identity.
        handle: String,
        /// Immutable registered purpose.
        purpose: MasterPurpose2,
        /// Current live module generation.
        generation: u64,
    },
}
/// Ordered resolver phase; Set is distinct from every read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPhase2 {
    /// First target read; valid contents skip every source.
    TargetRead,
    /// Ordered historical source read.
    LegacyRead,
    /// Target mutation, fenced before polling the provider.
    TargetSet,
    /// Exact terminal target encoding readback.
    TargetReadback,
}
/// Full immutable callback identity echoed before interpreting status or contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBackendIdentity2 {
    /// Configured descriptor.
    pub backend_id: String,
    /// Captured native registration.
    pub registration_id: String,
    /// Captured live generation.
    pub generation: u64,
    /// Private per-execution correlation; provides no CAS or durability claim.
    pub operation_id: String,
    /// Exact resolver phase.
    pub phase: SecretPhase2,
    /// Exact registered slot.
    pub slot: MasterSlotKind2,
}
/// Confidential fixed-backend load request; cannot enumerate entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBackendLoadRequest2 {
    /// Exact captured callback identity.
    pub identity: SecretBackendIdentity2,
}
/// Confirmed absence is distinct from every failure.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretBackendLoadStatus2 {
    /// Explicitly confirmed absence.
    Absent,
    /// Historical encoding, bounded to 4096 bytes before interpretation.
    Present {
        /// Confidential historical HEX and compatible whitespace.
        encoded: Vec<u8>,
    },
    /// Access denied; never absence.
    Denied,
    /// Provider unavailable; never absence.
    Unavailable,
    /// Invalid provider response; never absence.
    Invalid,
}
/// Confidential exact load reply.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBackendLoadResponse2 {
    /// Echo of all requested identity fields.
    pub identity: SecretBackendIdentity2,
    /// Confirmed status.
    pub status: SecretBackendLoadStatus2,
}
/// Confidential target mutation; host broker must fence detached provider workers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBackendSetRequest2 {
    /// Exact captured target-set identity.
    pub identity: SecretBackendIdentity2,
    /// Original historical encoding, at most 4096 bytes.
    pub encoded: Vec<u8>,
}
/// Set acknowledgement is correlation only; exact readback is still required.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackendSetStatus2 {
    /// Provider finished this exact mutation.
    Stored,
    /// Access denied.
    Denied,
    /// Provider unavailable or completion unknown.
    Unavailable,
    /// Invalid provider result.
    Invalid,
}
/// Confidential exact target mutation acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBackendSetResponse2 {
    /// Echo of all requested identity fields.
    pub identity: SecretBackendIdentity2,
    /// Provider status, not native CAS or recovery authority.
    pub status: SecretBackendSetStatus2,
}
macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($ty), "([REDACTED])")) }
    })+};
}
redacted!(
    SecretBackendLoadStatus2,
    SecretBackendLoadResponse2,
    SecretBackendSetRequest2
);
#[cfg(test)]
#[path = "secret_tests.rs"]
mod tests;
