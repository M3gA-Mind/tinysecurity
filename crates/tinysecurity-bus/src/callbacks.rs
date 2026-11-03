//! Exact version-two durable callback vocabulary; legacy bool receipts remain reserved.
use crate::SubjectScope;
use serde::{Deserialize, Serialize};
/// Typed read seam; carries no write receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLoadRequest2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
}
impl std::fmt::Debug for ApprovalLoadRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalLoadRequest2([REDACTED])")
    }
}
/// Complete typed scoped read result; rows have no write-commit semantics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLoadResponse2 {
    /// Exact requested durable scope.
    pub scope: SubjectScope,
    /// Scoped sanitized rows, uniquely identified within this snapshot.
    pub records: Vec<ApprovalRecord2>,
}
/// Delete undecided approval rows for one redacted session within one subject.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPurgeSessionRequest2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Session identifier after the configured identifier redactor.
    pub session_id: String,
}
impl std::fmt::Debug for ApprovalPurgeSessionRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalPurgeSessionRequest2([REDACTED])")
    }
}
/// Exact response to an undecided-row session purge.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPurgeSessionResponse2 {
    /// Exact requested durable scope.
    pub scope: SubjectScope,
    /// Exact requested redacted session identifier.
    pub session_id: String,
    /// Number of undecided rows removed, at most the bounded store inventory.
    pub removed: u32,
}
impl std::fmt::Debug for ApprovalPurgeSessionResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalPurgeSessionResponse2([REDACTED])")
    }
}
impl ApprovalPurgeSessionRequest2 {
    /// Verify that a purge response matches this exact scope and session.
    ///
    /// # Errors
    /// Rejects malformed identifiers, mismatched echoes or an impossible count.
    pub fn verify_response(&self, response: &ApprovalPurgeSessionResponse2) -> crate::Result<()> {
        validate_scope(&self.scope)?;
        if self.session_id.is_empty()
            || self.session_id.len() > 1024
            || self.scope != response.scope
            || self.session_id != response.session_id
            || response.removed > 1024
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}
impl std::fmt::Debug for ApprovalLoadResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalLoadResponse2([REDACTED])")
    }
}
impl ApprovalLoadRequest2 {
    /// Require exact scope and bounded valid uniquely identified rows.
    ///
    /// # Errors
    /// Rejects an unrelated, unscoped, oversized or malformed read response.
    pub fn verify_response(&self, response: &ApprovalLoadResponse2) -> crate::Result<()> {
        validate_scope(&self.scope)?;
        let mut ids = std::collections::BTreeSet::new();
        if self.scope != response.scope || response.records.len() > 1024 {
            return Err(crate::Error::InvalidArguments);
        }
        for record in &response.records {
            validate_record(record)?;
            if !ids.insert(&record.record_id) {
                return Err(crate::Error::InvalidArguments);
            }
        }
        Ok(())
    }
}
/// Scoped versioned redacted row; lifecycle engine belongs to approvals.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord2 {
    /// Opaque durable record identity.
    pub record_id: String,
    /// Stored CAS version.
    pub version: u64,
    /// Immutable scoped policy reference.
    pub policy_id: String,
    /// Immutable policy generation.
    pub generation: u64,
    /// Opaque original-call binding.
    pub fingerprint: String,
    /// Sanitized typed approval-engine row JSON.
    pub record_json: String,
}
impl std::fmt::Debug for ApprovalRecord2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalRecord2([REDACTED])")
    }
}
/// Atomic scoped compare-and-swap, with immutable retry identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCasRequest2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Exact target record.
    pub record_id: String,
    /// None is create-only; Some requires exactly that stored version.
    pub expected_version: Option<u64>,
    /// Sanitized replacement with immutable owner/policy binding.
    pub next_record: ApprovalRecord2,
    /// Opaque identity reused unchanged after an indeterminate timeout.
    pub mutation_id: String,
}
impl std::fmt::Debug for ApprovalCasRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalCasRequest2([REDACTED])")
    }
}
/// Exact atomic receipt, produced after durable row commit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCasResponse2 {
    /// Sanitized durable scope, mapped by the verified trusted host adapter.
    pub scope: SubjectScope,
    /// Exact requested target.
    pub record_id: String,
    /// Exact immutable retry identity.
    pub mutation_id: String,
    /// Exact committed next version.
    pub resulting_version: u64,
}
impl std::fmt::Debug for ApprovalCasResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalCasResponse2([REDACTED])")
    }
}
impl ApprovalCasRequest2 {
    /// Require an exact scoped mutation receipt after durable CAS.
    ///
    /// # Errors
    /// Rejects mismatched scope, record, mutation or checked next version.
    pub fn verify_receipt(&self, receipt: &ApprovalCasResponse2) -> crate::Result<()> {
        validate_scope(&self.scope)?;
        validate_record(&self.next_record)?;
        if !opaque(&self.record_id) || !opaque(&self.mutation_id) {
            return Err(crate::Error::InvalidArguments);
        }
        let next = self
            .expected_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(crate::Error::InvalidArguments)?;
        if self.scope != receipt.scope
            || self.record_id != self.next_record.record_id
            || self.record_id != receipt.record_id
            || self.mutation_id != receipt.mutation_id
            || self.next_record.version != next
            || receipt.resulting_version != next
        {
            return Err(crate::Error::InvalidArguments);
        }
        Ok(())
    }
}
/// Fixed new callback identities; incompatible semantics never reuse legacy interfaces.
pub mod callback_names2 {
    /// Fixed trusted-host pairing context and encrypted-state callback.
    pub const DEVICE_PAIRING_HOST: &str = "ai.tinyhumans.tinysecurity.DevicePairingHost2";
    /// Resolve one server-owned pairing/socket event against authenticated host state.
    pub const RESOLVE_PAIRING_EVENT: &str = "ResolvePairingEvent";
    /// Load or compare-and-swap ciphertext for the fixed module-owned identity record.
    pub const PERSIST_DEVICE_PAIRING: &str = "PersistDevicePairing";
    /// Consume a one-shot import handle and load bounded legacy device ciphertext.
    pub const LOAD_LEGACY_DEVICE_IDENTITIES: &str = "LoadLegacyDeviceIdentities";
    /// Fixed init-bound response-controlled confidential native output slots.
    pub const SECRET_CIPHER_CONSUMER: &str = "ai.tinyhumans.tinysecurity.SecretCipherConsumer2";
    /// Stage exact bound output privately until successful owner response.
    pub const DELIVER: &str = "Deliver";
    /// Confidential injected secret backend; only exact Load and Set.
    pub const SECRET_BACKEND: &str = "ai.tinyhumans.tinysecurity.SecretBackend2";
    /// Exact confidential target mutation.
    pub const SET: &str = "Set";
    /// Confidential-transport-free human consent for native keyring access.
    pub const KEYRING_CONSENT: &str = "ai.tinyhumans.tinysecurity.KeyringConsent2";
    /// Exact keyring consent member.
    pub const CONSENT: &str = "Consent";
    /// Versioned durable audit callback.
    pub const AUDIT_SINK: &str = "ai.tinyhumans.tinysecurity.AuditSink2";
    /// Versioned scoped storage callback seam.
    pub const APPROVAL_STORE: &str = "ai.tinyhumans.tinysecurity.ApprovalStore2";
    /// Future verified-human prompt callback identity; not advertised by Task 6.
    pub const APPROVAL_PROMPT: &str = "ai.tinyhumans.tinysecurity.ApprovalPrompt2";
    /// Immutable callback object path.
    pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinysecurity/Callbacks2";
    /// Durable ordered append member.
    pub const APPEND: &str = "Append";
    /// Atomic storage mutation member.
    pub const CAS: &str = "Cas";
    /// Remove only undecided approval rows bound to the exact session.
    pub const PURGE_SESSION: &str = "PurgeSession";
    /// Scoped read member.
    pub const LOAD: &str = "Load";
    /// Deliver a real per-user prompt; delivery alone is never authority.
    pub const PROMPT: &str = "Prompt";
    /// Verify an exact opaque authenticated-human ticket idempotently.
    pub const VERIFY_HUMAN: &str = "VerifyHuman";
}

pub(crate) fn validate_scope(scope: &SubjectScope) -> crate::Result<()> {
    if [&scope.user, &scope.workspace, &scope.agent]
        .iter()
        .any(|identity| identity.is_empty() || identity.len() > 1024)
    {
        return Err(crate::Error::InvalidArguments);
    }
    Ok(())
}
pub(crate) fn validate_record(record: &ApprovalRecord2) -> crate::Result<()> {
    if !opaque(&record.record_id)
        || !opaque(&record.fingerprint)
        || record.version == 0
        || record.policy_id.is_empty()
        || record.policy_id.len() > 1024
        || record.generation == 0
        || record.record_json.is_empty()
        || record.record_json.len() > 65536
    {
        return Err(crate::Error::InvalidArguments);
    }
    Ok(())
}

fn opaque(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}
#[cfg(test)]
#[path = "callbacks_tests.rs"]
mod tests;
