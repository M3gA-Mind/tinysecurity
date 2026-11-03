//! Import-once receipts for host-owned legacy trust sources.
//!
//! Each source item is recorded in the same durable row that carries its grant.
//! Cancellation changes the row state but leaves the source marker in the store,
//! so a later startup retry cannot recreate revoked authority.
use super::{
    ApprovalChoice2, ApprovalLifecycle2, ApprovalRow2, ApprovalScope2, CallerContext, Engine,
    Error, EvaluateRequest, Origin, RedactMode, Result, binding, flow_trust, tool_trust,
};
use tinysecurity_bus::{
    FLOW_TRUST_LIFETIME_MS2, ImportTrustItem2, ImportTrustOutcome2, ImportTrustReceipt2,
    ImportTrustSourceRequest2, TOOL_TRUST_LIFETIME_MS2,
};

const MAX_SCOPE_ROWS: usize = 960;

struct ImportPlan {
    attribution: &'static str,
    choice: ApprovalChoice2,
    tool: String,
    flow: Option<String>,
    grant_key: String,
    lifetime_ms: u64,
    active_exists: bool,
}

fn valid_source(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn source_marker(reg: &ApprovalScope2, request: &ImportTrustSourceRequest2) -> Result<String> {
    let scope = binding::scope_handle(&reg.subject)?;
    let item = serde_json::to_vec(&request.item).map_err(|_| Error::Invalid)?;
    let mut bytes = Vec::with_capacity(scope.user.len() + scope.agent.len() + item.len() + 256);
    for value in [
        scope.user.as_str(),
        scope.workspace.as_str(),
        scope.agent.as_str(),
        request.source_id.as_str(),
        request.source_version.as_str(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&(item.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&item);
    Ok(binding::digest(
        b"tinysecurity/trust-source-item/v1\0",
        &bytes,
    ))
}

fn marker_exists<'a>(
    rows: &'a [ApprovalRow2],
    marker: &str,
    attribution: &str,
) -> Option<&'a ApprovalRow2> {
    rows.iter().find(|row| {
        row.attribution.as_deref() == Some(attribution)
            && row.binding.call_sha256 == marker
            && row.decision_ticket_sha256.is_none()
    })
}

fn import_plan(
    engine: &Engine,
    reg: &ApprovalScope2,
    rows: &[ApprovalRow2],
    item: &ImportTrustItem2,
) -> Result<ImportPlan> {
    let now = engine.now()?;
    match item {
        ImportTrustItem2::Tool { tool } => {
            if !tool_trust::valid_tool(tool) {
                return Err(Error::Invalid);
            }
            Ok(ImportPlan {
                attribution: tool_trust::IMPORT_ATTRIBUTION,
                choice: ApprovalChoice2::Tool,
                tool: tool.clone(),
                flow: None,
                grant_key: tool_trust::trust_key(tool),
                lifetime_ms: TOOL_TRUST_LIFETIME_MS2,
                active_exists: Engine::durable_tool_trust(reg, rows, tool, now),
            })
        }
        ImportTrustItem2::FlowTool { flow_id, tool } => {
            if !Engine::trust_pair_valid(flow_id, tool) {
                return Err(Error::Invalid);
            }
            let request = EvaluateRequest {
                caller: CallerContext {
                    flow: Some(flow_id.clone()),
                    ..Default::default()
                },
                call: tinysecurity_bus::ToolCall {
                    tool: tool.clone(),
                    arguments_json: "{}".into(),
                    checks: Vec::new(),
                },
            };
            Ok(ImportPlan {
                attribution: flow_trust::IMPORT_ATTRIBUTION,
                choice: ApprovalChoice2::Flow,
                tool: tool.clone(),
                flow: Some(flow_id.clone()),
                grant_key: flow_trust::trust_key(flow_id, tool),
                lifetime_ms: FLOW_TRUST_LIFETIME_MS2,
                active_exists: Engine::durable_flow_trust(reg, rows, &request, now),
            })
        }
    }
}

fn imported_row(
    engine: &Engine,
    reg: &ApprovalScope2,
    request: ImportTrustSourceRequest2,
    marker: String,
    plan: ImportPlan,
    now: u64,
) -> Result<ApprovalRow2> {
    let redactor = engine.redactor()?;
    let flow = plan
        .flow
        .as_deref()
        .map(|flow_id| binding::text(&redactor, flow_id, RedactMode::IdentifierHash))
        .transpose()?;
    let caller = CallerContext {
        agent: binding::text(&redactor, &reg.subject.agent, RedactMode::IdentifierHash)?,
        thread: None,
        flow,
        call_id: binding::text(&redactor, &marker, RedactMode::IdentifierHash)?,
        origin: Origin::Operator,
        tier: reg.ceiling.clone(),
    };
    Ok(ApprovalRow2 {
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
            call_sha256: marker,
            content_sha256: plan.grant_key,
            origin: Origin::Operator,
            caller,
        },
        host_instance: engine.instance.clone(),
        nonce: binding::opaque()?,
        tool_name: binding::text(&redactor, &plan.tool, RedactMode::Text)?,
        session_id: None,
        audit_error: None,
        external_effect: true,
        args_redacted: "{}".into(),
        summary: "imported trust source item".into(),
        created_at_ms: now,
        expires_at_ms: now.checked_add(plan.lifetime_ms).ok_or(Error::Invalid)?,
        state: if plan.active_exists {
            ApprovalLifecycle2::Cancelled
        } else {
            ApprovalLifecycle2::Approved
        },
        choice: Some(plan.choice),
        attribution: Some(plan.attribution.into()),
        decision_ticket_sha256: None,
        outcome: None,
        reservation_id: None,
        legacy_history_json: None,
        judge: None,
        audit: request.audit,
    })
}

impl Engine {
    /// Record one stable host source item exactly once in the approval store.
    ///
    /// The host calls once per item, allowing a partially completed source import to
    /// retry safely. Re-importing a revoked item returns its original receipt without
    /// restoring authority. Ordinary explicit grants remain independent.
    /// # Errors
    /// Rejects invalid source identifiers or trust names, unknown scopes, stale audit
    /// correlations, unavailable storage, and unacknowledged durability.
    pub async fn import_trust_source(
        &self,
        request: ImportTrustSourceRequest2,
    ) -> Result<ImportTrustReceipt2> {
        if !valid_source(&request.source_id, 128) || !valid_source(&request.source_version, 64) {
            return Err(Error::Invalid);
        }
        // The two trust kinds have separate existing locks. Taking both here makes
        // source import linearizable with either kind of grant or revocation.
        let _tool_serial = self.tool_trust_lock.lock().await;
        let _flow_serial = self.flow_trust_lock.lock().await;
        let reg = self.registration(&request.scope_id)?;
        Self::correlation(&request.audit, reg.generation)?;
        let marker = source_marker(&reg, &request)?;
        let rows = self.rows(&reg).await?;
        let plan = import_plan(self, &reg, &rows, &request.item)?;
        if let Some(existing) = marker_exists(&rows, &marker, plan.attribution) {
            // A prior CAS may have committed while its audit acknowledgement was
            // lost. Reconcile that exact durable row before acknowledging the retry.
            self.audit_row(existing.clone()).await?;
            return Ok(ImportTrustReceipt2 {
                scope_id: request.scope_id,
                outcome: ImportTrustOutcome2::AlreadyImported,
                request_id: existing.request_id.clone(),
            });
        }
        if rows.len() >= MAX_SCOPE_ROWS {
            return Err(Error::Unavailable);
        }
        let now = self.now()?;
        let scope_id = request.scope_id.clone();
        let row = imported_row(self, &reg, request, marker, plan, now)?;
        self.persist(None, &row).await?;
        Ok(ImportTrustReceipt2 {
            scope_id,
            outcome: ImportTrustOutcome2::Imported,
            request_id: row.request_id,
        })
    }
}
