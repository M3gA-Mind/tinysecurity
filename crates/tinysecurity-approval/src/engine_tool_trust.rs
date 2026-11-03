//! Durable whole-tool trust: exact global grants held by the host-served approval store.
//!
//! A tool-trust row is an `Approved` row with the `Tool` choice and the
//! `tool-trust-grant` attribution. Its binding digest is domain-separated from call
//! digests, so it cannot be consumed, resumed or reused as a reviewed decision.
use super::{
    ApprovalChoice2, ApprovalGrants2, ApprovalLifecycle2, ApprovalRecordRequest2, ApprovalRow2,
    ApprovalScope2, CallerContext, Engine, Error, Origin, RedactMode, Result, binding,
};
use tinysecurity_bus::{
    GrantToolRequest2, ListToolTrustRequest2, RevokeToolByIdRequest2, RevokeToolRequest2,
    TOOL_TRUST_LIFETIME_MS2, ToolTrustEntry2, ToolTrustList2, ToolTrustOutcome2, ToolTrustReceipt2,
};

const ATTRIBUTION: &str = "tool-trust-grant";
pub(super) const IMPORT_ATTRIBUTION: &str = "tool-trust-import";
const MAX_SCOPE_ROWS: usize = 960;

/// Digest of an exact tool name, disjoint from call and flow trust bindings.
pub(super) fn trust_key(tool: &str) -> String {
    binding::digest(b"tinysecurity/tool-trust/v1\0", tool.as_bytes())
}

pub(super) fn is_trust_row(row: &ApprovalRow2) -> bool {
    matches!(
        row.attribution.as_deref(),
        Some(ATTRIBUTION | IMPORT_ATTRIBUTION)
    ) && row.choice == Some(ApprovalChoice2::Tool)
        && row.state == ApprovalLifecycle2::Approved
        && row.decision_ticket_sha256.is_none()
        && row.binding.caller.flow.is_none()
}

fn is_tool_trust_binding(row: &ApprovalRow2) -> bool {
    matches!(
        row.attribution.as_deref(),
        Some(ATTRIBUTION | IMPORT_ATTRIBUTION)
    ) && row.choice == Some(ApprovalChoice2::Tool)
        && row.decision_ticket_sha256.is_none()
        && row.binding.caller.flow.is_none()
}

fn matches_tool_trust_binding(row: &ApprovalRow2, key: &str) -> bool {
    matches!(
        row.attribution.as_deref(),
        Some(ATTRIBUTION | IMPORT_ATTRIBUTION)
    ) && row.choice == Some(ApprovalChoice2::Tool)
        && row.decision_ticket_sha256.is_none()
        && row.binding.caller.flow.is_none()
        && row.binding.content_sha256 == key
        && (row.binding.call_sha256 == key
            || row.attribution.as_deref() == Some(IMPORT_ATTRIBUTION))
}

pub(super) fn valid_tool(tool: &str) -> bool {
    ApprovalGrants2 {
        tools: vec![tool.to_owned()],
        flows: Vec::new(),
    }
    .is_valid()
}

impl Engine {
    /// Whether a live durable whole-tool grant covers exactly this tool.
    pub(super) fn durable_tool_trust(
        reg: &ApprovalScope2,
        rows: &[ApprovalRow2],
        tool: &str,
        now: u64,
    ) -> bool {
        if !valid_tool(tool) {
            return false;
        }
        let key = trust_key(tool);
        rows.iter().any(|row| {
            is_trust_row(row)
                && row.binding.content_sha256 == key
                && (row.binding.call_sha256 == key
                    || row.attribution.as_deref() == Some(IMPORT_ATTRIBUTION))
                && row.expires_at_ms > now
                && Self::current(reg, row).is_ok()
        })
    }

    pub(super) fn live_tool_trust<'a>(
        reg: &ApprovalScope2,
        rows: &'a [ApprovalRow2],
        tool: &str,
        now: u64,
    ) -> Option<&'a ApprovalRow2> {
        let key = trust_key(tool);
        rows.iter().find(|row| {
            is_trust_row(row)
                && matches_tool_trust_binding(row, &key)
                && row.expires_at_ms > now
                && Self::current(reg, row).is_ok()
        })
    }

    /// Durably trust one exact whole tool. A live repeat is `Unchanged`.
    /// # Errors
    /// Rejects unknown scopes, human-only or native tools, malformed names, stale
    /// audit correlations, unavailable storage, and unacknowledged durability.
    pub async fn grant_tool(&self, request: GrantToolRequest2) -> Result<ToolTrustReceipt2> {
        if !valid_tool(&request.tool) {
            return Err(Error::Invalid);
        }
        let _serial = self.tool_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let key = trust_key(&request.tool);
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        if let Some(existing) = Self::live_tool_trust(&reg, &rows, &request.tool, now) {
            self.audit_row(existing.clone()).await?;
            return Ok(ToolTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ToolTrustOutcome2::Unchanged,
                request_id: Some(existing.request_id.clone()),
            });
        }
        // Revoked and expired grants still occupy durable rows. Reissuing them would
        // append another row and eventually exceed the module's load bound.
        if rows.len() >= MAX_SCOPE_ROWS {
            return Err(Error::Unavailable);
        }
        let redactor = self.redactor()?;
        let caller = CallerContext {
            agent: binding::text(&redactor, &reg.subject.agent, RedactMode::IdentifierHash)?,
            thread: None,
            flow: None,
            call_id: binding::text(&redactor, &key, RedactMode::IdentifierHash)?,
            origin: Origin::Operator,
            tier: reg.ceiling.clone(),
        };
        let row = ApprovalRow2 {
            request_id: binding::opaque()?,
            version: 1,
            binding: tinysecurity_bus::ApprovalBinding2 {
                binding_version: 1,
                scope: binding::scope_handle(&reg.subject)?,
                policy_ref: binding::digest(
                    b"tinysecurity/approval-policy/v1\0",
                    reg.policy_ref.as_bytes(),
                ),
                generation: reg.generation,
                call_sha256: key.clone(),
                content_sha256: key,
                origin: Origin::Operator,
                caller,
            },
            host_instance: self.instance.clone(),
            nonce: binding::opaque()?,
            tool_name: binding::text(&redactor, &request.tool, RedactMode::Text)?,
            session_id: None,
            audit_error: None,
            external_effect: true,
            args_redacted: "{}".into(),
            summary: "whole-tool trust".into(),
            created_at_ms: now,
            expires_at_ms: now
                .checked_add(TOOL_TRUST_LIFETIME_MS2)
                .ok_or(Error::Invalid)?,
            state: ApprovalLifecycle2::Approved,
            choice: Some(ApprovalChoice2::Tool),
            attribution: Some(ATTRIBUTION.into()),
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: None,
            judge: None,
            audit: request.audit,
        };
        self.persist(None, &row).await?;
        Ok(ToolTrustReceipt2 {
            scope_id: request.scope_id,
            outcome: ToolTrustOutcome2::Granted,
            request_id: Some(row.request_id),
        })
    }

    /// Withdraw whole-tool trust. A missing or expired grant is `Absent`.
    /// # Errors
    /// Rejects malformed names, unknown scopes, stale audit correlations, unavailable
    /// storage, and unacknowledged durability.
    pub async fn revoke_tool(&self, request: RevokeToolRequest2) -> Result<ToolTrustReceipt2> {
        if !valid_tool(&request.tool) {
            return Err(Error::Invalid);
        }
        let _serial = self.tool_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        let Some(live) = Self::live_tool_trust(&reg, &rows, &request.tool, now) else {
            let key = trust_key(&request.tool);
            if let Some(cancelled) = rows.iter().find(|row| {
                row.state == ApprovalLifecycle2::Cancelled
                    && matches_tool_trust_binding(row, &key)
                    && row.audit == request.audit
                    && Self::current(&reg, row).is_ok()
            }) {
                let request_id = cancelled.request_id.clone();
                self.cancel(ApprovalRecordRequest2 {
                    scope_id: request.scope_id.clone(),
                    request_id: request_id.clone(),
                    audit: request.audit,
                })
                .await?;
                return Ok(ToolTrustReceipt2 {
                    scope_id: request.scope_id,
                    outcome: ToolTrustOutcome2::Revoked,
                    request_id: Some(request_id),
                });
            }
            return Ok(ToolTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ToolTrustOutcome2::Absent,
                request_id: None,
            });
        };
        let request_id = live.request_id.clone();
        self.cancel(ApprovalRecordRequest2 {
            scope_id: request.scope_id.clone(),
            request_id: request_id.clone(),
            audit: request.audit,
        })
        .await?;
        Ok(ToolTrustReceipt2 {
            scope_id: request.scope_id,
            outcome: ToolTrustOutcome2::Revoked,
            request_id: Some(request_id),
        })
    }

    /// Withdraw one listed whole-tool grant by its opaque durable row identity.
    /// # Errors
    /// Rejects unknown scopes, stale audit correlations, unavailable storage, and
    /// unacknowledged durability.
    pub async fn revoke_tool_by_id(
        &self,
        request: RevokeToolByIdRequest2,
    ) -> Result<ToolTrustReceipt2> {
        if request.request_id.is_empty() || request.request_id.len() > 128 {
            return Err(Error::Invalid);
        }
        let _serial = self.tool_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        let Some(row) = rows.iter().find(|row| {
            is_tool_trust_binding(row)
                && row.request_id == request.request_id
                && Self::current(&reg, row).is_ok()
        }) else {
            return Ok(ToolTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ToolTrustOutcome2::Absent,
                request_id: None,
            });
        };
        if row.state == ApprovalLifecycle2::Cancelled && row.audit == request.audit {
            self.cancel(ApprovalRecordRequest2 {
                scope_id: request.scope_id.clone(),
                request_id: request.request_id.clone(),
                audit: request.audit,
            })
            .await?;
            return Ok(ToolTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ToolTrustOutcome2::Revoked,
                request_id: Some(request.request_id),
            });
        }
        if row.state != ApprovalLifecycle2::Approved || row.expires_at_ms <= now {
            return Ok(ToolTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ToolTrustOutcome2::Absent,
                request_id: None,
            });
        }
        self.cancel(ApprovalRecordRequest2 {
            scope_id: request.scope_id.clone(),
            request_id: request.request_id.clone(),
            audit: request.audit,
        })
        .await?;
        Ok(ToolTrustReceipt2 {
            scope_id: request.scope_id,
            outcome: ToolTrustOutcome2::Revoked,
            request_id: Some(request.request_id),
        })
    }

    /// The live whole-tool grants of a scope, ordered by exact tool name.
    /// # Errors
    /// Rejects unknown scopes and unavailable storage.
    pub async fn list_tool_trust(&self, request: ListToolTrustRequest2) -> Result<ToolTrustList2> {
        let reg = self.registration(&request.scope_id)?;
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        let mut entries: Vec<ToolTrustEntry2> = rows
            .iter()
            .filter(|row| {
                is_trust_row(row) && row.expires_at_ms > now && Self::current(&reg, row).is_ok()
            })
            .map(|row| ToolTrustEntry2 {
                tool: row.tool_name.clone(),
                request_id: row.request_id.clone(),
                granted_at_ms: row.created_at_ms,
            })
            .collect();
        entries.sort_by(|a, b| (&a.tool, &a.request_id).cmp(&(&b.tool, &b.request_id)));
        Ok(ToolTrustList2 { entries })
    }
}
