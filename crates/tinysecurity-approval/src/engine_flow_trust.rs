//! Durable flow trust: "always allow this tool in this flow", kept as one audited
//! approval row per pair in the host-served store, so it survives a restart.
//!
//! A flow-trust row is an `Approved` row with the `Flow` choice and the
//! `flow-trust-grant` attribution. Its binding digests live in their own domain, so
//! it can never equal the binding of a real call: it is never consumed, never
//! resumed and never satisfies `PreauthorizeFlow2` (it carries no human ticket).
//! `EvaluateApproval2` reads it only to convert a required approval of the exact
//! tool inside the exact flow into an `auto:flow-grant` approval.
use super::{
    ApprovalChoice2, ApprovalGrants2, ApprovalLifecycle2, ApprovalRecordRequest2, ApprovalRow2,
    ApprovalScope2, CallerContext, Engine, Error, EvaluateRequest, HUMAN_ONLY_TOOLS2, Origin,
    RedactMode, Result, binding,
};
use tinysecurity_bus::{
    FLOW_TRUST_LIFETIME_MS2, FlowTrustEntry2, FlowTrustList2, FlowTrustOutcome2, FlowTrustReceipt2,
    GrantFlowToolRequest2, ListFlowTrustRequest2, RevokeFlowToolRequest2,
};

const ATTRIBUTION: &str = "flow-trust-grant";
pub(super) const IMPORT_ATTRIBUTION: &str = "flow-trust-import";

/// Rows a scope may hold before a new grant is refused, below the 1024 the module's
/// load contract accepts so ordinary approvals keep a margin.
const MAX_SCOPE_ROWS: usize = 960;

/// Digest of the exact `(flow, tool)` pair, domain-separated from every call digest.
pub(super) fn trust_key(flow_id: &str, tool: &str) -> String {
    let mut bytes = Vec::with_capacity(flow_id.len() + tool.len() + 8);
    bytes.extend_from_slice(&(flow_id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(flow_id.as_bytes());
    bytes.extend_from_slice(tool.as_bytes());
    binding::digest(b"tinysecurity/flow-trust/v1\0", &bytes)
}

pub(super) fn is_trust_row(row: &ApprovalRow2) -> bool {
    is_trust_identity(row) && row.state == ApprovalLifecycle2::Approved
}

fn is_trust_identity(row: &ApprovalRow2) -> bool {
    matches!(
        row.attribution.as_deref(),
        Some(ATTRIBUTION | IMPORT_ATTRIBUTION)
    ) && row.choice == Some(ApprovalChoice2::Flow)
        && row.decision_ticket_sha256.is_none()
}

fn matches_trust_binding(row: &ApprovalRow2, key: &str) -> bool {
    is_trust_identity(row)
        && (row.binding.call_sha256 == key
            || (row.attribution.as_deref() == Some(IMPORT_ATTRIBUTION)
                && row.binding.content_sha256 == key))
}

impl Engine {
    /// Whether a live durable flow-trust row covers exactly this call's tool and flow.
    pub(super) fn durable_flow_trust(
        reg: &ApprovalScope2,
        rows: &[ApprovalRow2],
        request: &EvaluateRequest,
        now: u64,
    ) -> bool {
        let Some(flow) = request.caller.flow.as_deref() else {
            return false;
        };
        let tool = &request.call.tool;
        if HUMAN_ONLY_TOOLS2.contains(&tool.as_str()) || binding::is_native(tool) {
            return false;
        }
        let key = trust_key(flow, tool);
        rows.iter().any(|row| {
            is_trust_row(row)
                && row.binding.content_sha256 == key
                && (row.binding.call_sha256 == key
                    || row.attribution.as_deref() == Some(IMPORT_ATTRIBUTION))
                && row.expires_at_ms > now
                && Self::current(reg, row).is_ok()
        })
    }

    pub(super) fn live_trust<'a>(
        reg: &ApprovalScope2,
        rows: &'a [ApprovalRow2],
        key: &str,
        now: u64,
    ) -> Option<&'a ApprovalRow2> {
        rows.iter().find(|row| {
            is_trust_row(row)
                && matches_trust_binding(row, key)
                && row.expires_at_ms > now
                && Self::current(reg, row).is_ok()
        })
    }

    /// Whether a flow and a tool name could ever name a grant: the flow may be as
    /// long as a caller's flow identity (1024 bytes), the tool follows the shared
    /// grant-name rules.
    pub(super) fn trust_pair_valid(flow_id: &str, tool: &str) -> bool {
        !flow_id.trim().is_empty()
            && flow_id.len() <= 1024
            && !flow_id.chars().any(char::is_control)
            && ApprovalGrants2 {
                tools: vec![tool.into()],
                flows: Vec::new(),
            }
            .is_valid()
    }

    /// Durably trust one tool inside one flow. Granting a live pair changes nothing.
    /// # Errors
    /// Rejects unknown scopes, human-only or native tools, blank or oversized names,
    /// a stale audit correlation and unacknowledged durability.
    pub async fn grant_flow_tool(
        &self,
        request: GrantFlowToolRequest2,
    ) -> Result<FlowTrustReceipt2> {
        if !Self::trust_pair_valid(&request.flow_id, &request.tool) {
            return Err(Error::Invalid);
        }
        let _serial = self.flow_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let key = trust_key(&request.flow_id, &request.tool);
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        if let Some(existing) = Self::live_trust(&reg, &rows, &key, now) {
            // Reconcile the exact audit phase of the existing row, as a resume does.
            self.audit_row(existing.clone()).await?;
            return Ok(FlowTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: FlowTrustOutcome2::Unchanged,
                request_id: Some(existing.request_id.clone()),
            });
        }
        // Revoked and expired grants still occupy durable rows. Reissuing them would
        // append another row and eventually exceed the module's load bound.
        if rows.len() >= MAX_SCOPE_ROWS {
            return Err(Error::Unavailable);
        }
        let redactor = self.redactor()?;
        let flow = binding::text(&redactor, &request.flow_id, RedactMode::IdentifierHash)?;
        let caller = CallerContext {
            agent: binding::text(&redactor, &reg.subject.agent, RedactMode::IdentifierHash)?,
            thread: None,
            flow: Some(flow),
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
            summary: "flow trust".into(),
            created_at_ms: now,
            expires_at_ms: now
                .checked_add(FLOW_TRUST_LIFETIME_MS2)
                .ok_or(Error::Invalid)?,
            state: ApprovalLifecycle2::Approved,
            choice: Some(ApprovalChoice2::Flow),
            attribution: Some(ATTRIBUTION.into()),
            decision_ticket_sha256: None,
            outcome: None,
            reservation_id: None,
            legacy_history_json: None,
            judge: None,
            audit: request.audit,
        };
        self.persist(None, &row).await?;
        Ok(FlowTrustReceipt2 {
            scope_id: request.scope_id,
            outcome: FlowTrustOutcome2::Granted,
            request_id: Some(row.request_id),
        })
    }

    /// Withdraw trust of one tool inside one flow. A pair with no live grant is
    /// `Absent`, so revoking twice is harmless.
    /// # Errors
    /// Rejects unknown scopes, a stale audit correlation and unacknowledged durability.
    pub async fn revoke_flow_tool(
        &self,
        request: RevokeFlowToolRequest2,
    ) -> Result<FlowTrustReceipt2> {
        if !Self::trust_pair_valid(&request.flow_id, &request.tool) {
            return Err(Error::Invalid);
        }
        let _serial = self.flow_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let key = trust_key(&request.flow_id, &request.tool);
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        let Some(live) = Self::live_trust(&reg, &rows, &key, now) else {
            if let Some(cancelled) = rows.iter().find(|row| {
                row.state == ApprovalLifecycle2::Cancelled
                    && matches_trust_binding(row, &key)
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
                return Ok(FlowTrustReceipt2 {
                    scope_id: request.scope_id,
                    outcome: FlowTrustOutcome2::Revoked,
                    request_id: Some(request_id),
                });
            }
            return Ok(FlowTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: FlowTrustOutcome2::Absent,
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
        Ok(FlowTrustReceipt2 {
            scope_id: request.scope_id,
            outcome: FlowTrustOutcome2::Revoked,
            request_id: Some(request_id),
        })
    }

    /// The live flow-trust grants of a scope, ordered by flow then tool.
    /// # Errors
    /// Rejects unknown scopes and unavailable storage.
    pub async fn list_flow_trust(&self, request: ListFlowTrustRequest2) -> Result<FlowTrustList2> {
        let reg = self.registration(&request.scope_id)?;
        let wanted = match request.flow_id.as_deref() {
            Some(flow) if flow.is_empty() || flow.len() > 1024 => return Err(Error::Invalid),
            Some(flow) => Some(binding::text(
                &self.redactor()?,
                flow,
                RedactMode::IdentifierHash,
            )?),
            None => None,
        };
        let rows = self.rows(&reg).await?;
        let now = self.now()?;
        let mut entries: Vec<FlowTrustEntry2> = rows
            .iter()
            .filter(|row| {
                is_trust_row(row) && row.expires_at_ms > now && Self::current(&reg, row).is_ok()
            })
            .filter_map(|row| {
                let flow = row.binding.caller.flow.clone()?;
                (wanted.as_ref().is_none_or(|w| *w == flow)).then(|| FlowTrustEntry2 {
                    flow,
                    tool: row.tool_name.clone(),
                    request_id: row.request_id.clone(),
                    granted_at_ms: row.created_at_ms,
                })
            })
            .collect();
        entries.sort_by(|a, b| {
            (&a.flow, &a.tool, &a.request_id).cmp(&(&b.flow, &b.tool, &b.request_id))
        });
        Ok(FlowTrustList2 { entries })
    }
}
