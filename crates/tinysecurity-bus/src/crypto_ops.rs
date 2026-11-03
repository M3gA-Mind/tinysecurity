//! Confidential password, keyring and pairing members (contract 1.14).
//!
//! Every payload here travels only over `TinyBus` confidential transport from
//! the immutable verified `trusted_host` peer. Secrets are never echoed in
//! `Debug`, `PolicyInfo` or audit rows. Handles and identities come from SDK
//! initialization, never from the request.
use crate::CallerContext;
use serde::{Deserialize, Serialize};

/// Largest accepted password, keyring value or plaintext, in bytes.
pub const MAX_CRYPTO_PAYLOAD_BYTES: u32 = 1_048_576;

/// Native OS or file-backed secret store selected at initialization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyringBackend2 {
    /// Platform default: Keychain, Credential Manager or the Linux kernel keyring.
    Os,
    /// Linux kernel keyring, independent of the compiled default provider.
    LinuxKernel,
    /// Linux Secret Service over encrypted D-Bus; unavailable unless built in.
    SecretService,
    /// Protected encrypted local file store in a module-owned directory.
    EncryptedFile {
        /// Absolute directory holding the store and its key file.
        directory: String,
    },
}

/// Init-only keyring settings; consent is mandatory for every operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConfig2 {
    /// Credential service namespace, 1..=128 bytes.
    pub service: String,
    /// Backend selection.
    pub backend: KeyringBackend2,
    /// Bounded `KeyringConsent2` callback wait, in 1..=300000 milliseconds.
    pub consent_timeout_ms: u32,
}

/// One registered pairing account; tokens are legacy configuration bearer values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingAccount2 {
    /// Trusted scope.
    pub scope: String,
    /// Registered provider.
    pub provider: String,
    /// Immutable account name used by `PairingRequest2`.
    pub account: String,
    /// Account lifecycle label.
    pub lifecycle: String,
    /// Whether an empty token set requires numeric pairing.
    pub require_pairing: bool,
    /// Existing bearer tokens, plaintext or lowercase SHA-256 hex.
    pub tokens: Vec<String>,
}

/// Init-only pairing engine bounds and accounts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingConfig2 {
    /// Registered accounts, at most 256.
    pub accounts: Vec<PairingAccount2>,
    /// Concurrent engine operations, in 1..=32.
    pub in_flight: u32,
    /// Per-account operations per minute, in 1..=4096.
    pub rate: u32,
}

/// Init-only crypto surface. Absent preserves older payloads.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig2 {
    /// Payload bound for passwords, plaintext and secret values, in 1..=1048576.
    pub max_payload_bytes: u32,
    /// Password, keyring and pairing operations per monotonic minute, in 1..=4096.
    pub operations_per_minute: u32,
    /// Keyring backend; absent leaves keyring members denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring: Option<KeyringConfig2>,
    /// Pairing registry; absent leaves pairing members denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<PairingConfig2>,
}

/// Existing `OpenHuman` password payload shape: byte arrays with a separate salt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPayload2 {
    /// Ciphertext followed by the sixteen-byte GCM tag.
    pub ciphertext: Vec<u8>,
    /// Twelve-byte GCM nonce.
    pub nonce: Vec<u8>,
    /// Sixteen-byte Argon2id salt.
    pub salt: Vec<u8>,
}

/// Password operation over the legacy Argon2id and AES-256-GCM format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PasswordOperation2 {
    /// Encrypt with a fresh salt unless a sixteen-byte salt is supplied.
    Encrypt {
        /// Confidential password, at most 4096 bytes.
        password: String,
        /// Confidential plaintext.
        plaintext: Vec<u8>,
        /// Optional caller-held salt for the legacy separate-salt layout.
        salt: Option<Vec<u8>>,
    },
    /// Authenticate and decrypt a payload carrying its salt.
    Decrypt {
        /// Confidential password.
        password: String,
        /// Payload to open.
        payload: PasswordPayload2,
    },
}

/// Password request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordRequest2 {
    /// Exact operation.
    pub operation: PasswordOperation2,
}

/// Password result; exactly one of the fields is populated.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResponse2 {
    /// Sealed payload for encrypt.
    pub payload: Option<PasswordPayload2>,
    /// Plaintext for decrypt.
    pub bytes: Vec<u8>,
}

/// Bounded keyring operation on a named secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyringOperation2 {
    /// Read a secret; absence is reported only when confirmed.
    Get {
        /// Secret name accepted by the storage driver.
        name: String,
    },
    /// Store a secret.
    Set {
        /// Secret name.
        name: String,
        /// Confidential value.
        value: Vec<u8>,
    },
    /// Remove a secret.
    Delete {
        /// Secret name.
        name: String,
    },
}

/// Keyring request with verified caller facts for the consent prompt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringRequest2 {
    /// Verified host caller facts shown to the human.
    pub caller: CallerContext,
    /// Human-readable purpose, 1..=256 bytes without control characters.
    pub purpose: String,
    /// Exact operation.
    pub operation: KeyringOperation2,
}

/// Keyring result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringResponse2 {
    /// Get found a value, or Delete removed one.
    pub found: bool,
    /// Value for Get; empty otherwise.
    pub bytes: Vec<u8>,
}

/// Kind of access shown to the consenting human.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringAccess2 {
    /// Read a secret.
    Read,
    /// Write a secret.
    Write,
    /// Delete a secret.
    Delete,
}

/// `KeyringConsent2.Consent` callback request; carries no secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConsentRequest2 {
    /// Verified requesting identity.
    pub caller: CallerContext,
    /// Redacted purpose.
    pub purpose: String,
    /// Access kind.
    pub access: KeyringAccess2,
    /// Secret name, never its value.
    pub name: String,
    /// Bounded wait.
    pub timeout_ms: u32,
}

/// Outcome from the host's keyring consent decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringConsentOutcome2 {
    /// The human approved this exact operation.
    Allowed,
    /// The request is still waiting for a human decision.
    ConsentPending,
    /// The human refused this exact operation.
    ConsentDenied,
    /// The consent service could not make a decision.
    Unavailable,
}

/// `KeyringConsent2.Consent` callback reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConsentResponse2 {
    /// Explicit outcome for exactly this request.
    pub outcome: KeyringConsentOutcome2,
}

/// Pairing operation on a registered account.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PairingOperation2 {
    /// Nonsecret lifecycle state.
    Status,
    /// Constant-time check of a presented bearer against stored tokens.
    Authenticate {
        /// Presented bearer; never echoed.
        bearer: String,
    },
    /// Invalidate a pending challenge.
    Invalidate,
    /// Revoke all accepted authority for the account.
    Revoke,
}

/// Pairing request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest2 {
    /// Registered account name.
    pub account: String,
    /// Exact operation.
    pub operation: PairingOperation2,
}

/// Pairing result; state is nonsecret.
///
/// `Authenticate` charges one engine admission and so reports only its outcome;
/// `is_paired` and `active` are then absent rather than a second rate-limited read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingResponse2 {
    /// Configuration flag.
    pub require_pairing: bool,
    /// Whether any token exists; absent for `Authenticate`.
    pub is_paired: Option<bool>,
    /// Whether an acknowledged challenge can be verified; absent for `Authenticate`.
    pub active: Option<bool>,
    /// Authenticate outcome, absent for other operations.
    pub authenticated: Option<bool>,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "([REDACTED])"))
        }
    })+};
}
redacted_debug!(
    KeyringBackend2,
    KeyringConfig2,
    PairingAccount2,
    PairingConfig2,
    CryptoConfig2,
    PasswordPayload2,
    PasswordOperation2,
    PasswordRequest2,
    PasswordResponse2,
    KeyringOperation2,
    KeyringRequest2,
    KeyringResponse2,
    PairingRequest2,
    PairingOperation2,
);
#[cfg(test)]
#[path = "crypto_ops_tests.rs"]
mod tests;
