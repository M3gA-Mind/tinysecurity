//! Bounded canonical original-call identity, independent of redacted persistence.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use tinysecurity_bus::{
    AccessTier, ApprovalBinding2, ApprovalChoice2, ApprovalLifecycle2, ApprovalRecord2,
    ApprovalRow2, ApprovalScope2, Check, EvaluateRequest, RedactMode, RedactRequest, SubjectScope,
};
use tinysecurity_redact::Redactor;
pub(crate) fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}
pub(crate) fn opaque() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    Ok(out)
}
pub(crate) fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn text(redactor: &Redactor, value: &str, mode: RedactMode) -> Result<String> {
    redactor
        .redact(&RedactRequest {
            text: value.into(),
            mode,
        })
        .map(|r| r.text)
        .map_err(|_| Error::Invalid)
}
/// Full-digest durable subject handles; no truncated index provides owner authority.
/// # Errors
/// Rejects empty or oversized trusted identities.
pub fn scope_handle(original: &SubjectScope) -> Result<SubjectScope> {
    if [&original.user, &original.workspace, &original.agent]
        .iter()
        .any(|s| s.is_empty() || s.len() > 1024)
    {
        return Err(Error::Invalid);
    }
    let subject = |kind: &str, value: &str| {
        digest(
            format!("tinysecurity/approval-subject/{kind}/v1\0").as_bytes(),
            value.as_bytes(),
        )
    };
    Ok(SubjectScope {
        user: subject("user", &original.user),
        workspace: subject("workspace", &original.workspace),
        agent: subject("agent", &original.agent),
    })
}

fn depth(value: &serde_json::Value, level: usize) -> Result<()> {
    if level > 32 {
        return Err(Error::Invalid);
    }
    match value {
        serde_json::Value::Array(values) => {
            for v in values {
                depth(v, level + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            for v in values.values() {
                depth(v, level + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(crate) fn is_native(tool: &str) -> bool {
    matches!(tool, "native_secret_grant" | "native_app_io_grant")
}
pub(crate) fn native_safe_call(request: &EvaluateRequest) -> Result<String> {
    let (argument, prefix) = match request.call.tool.as_str() {
        "native_secret_grant" => ("native_authorization_v1", "native-"),
        "native_app_io_grant" => ("native_app_io_authorization_v1", "native-app-io-"),
        _ => return Err(Error::Denied),
    };
    let args: serde_json::Value =
        serde_json::from_str(&request.call.arguments_json).map_err(|_| Error::Invalid)?;
    let commitment = args
        .get(argument)
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::Denied)?;
    let safe_call = format!("{prefix}{commitment}");
    if args.as_object().is_none_or(|a| a.len() != 1)
        || !hex(commitment, 64)
        || request.caller.call_id != safe_call
    {
        return Err(Error::Denied);
    }
    Ok(safe_call)
}

fn contains_blocked_skill_scan(checks: &[Check]) -> bool {
    checks.iter().any(|check| {
        matches!(
            check,
            Check::SkillScan {
                verdict: tinysecurity_bus::SkillScanVerdict::Block,
                ..
            }
        )
    })
}

pub(crate) fn original(
    reg: &ApprovalScope2,
    request: &EvaluateRequest,
    redactor: &Redactor,
) -> Result<(ApprovalBinding2, String, bool)> {
    if request.caller.agent != reg.subject.agent
        || request.caller.call_id.is_empty()
        || request.caller.call_id.len() > 1024
        || request.call.tool.is_empty()
        || request.call.tool.len() > 256
        || request.call.arguments_json.len() > 32768
        || request.call.checks.is_empty()
        || request.call.checks.len() > 128
        || contains_blocked_skill_scan(&request.call.checks)
        || (reg.ceiling == AccessTier::Read && request.caller.tier != AccessTier::Read)
        || (reg.ceiling == AccessTier::Write && request.caller.tier == AccessTier::Full)
        || request
            .caller
            .thread
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 1024)
        || request
            .caller
            .flow
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 1024)
    {
        return Err(Error::Denied);
    }
    let mut args: serde_json::Value =
        serde_json::from_str(&request.call.arguments_json).map_err(|_| Error::Invalid)?;
    if !args.is_object() {
        return Err(Error::Invalid);
    }
    depth(&args, 0)?;
    args.sort_all_objects();
    let canonical = serde_json::to_string(&args).map_err(|_| Error::Invalid)?;
    let external = request.call.checks.iter().any(|check| match check {
        Check::LocalDiagnostic {} | Check::SkillScan { .. } => false,
        Check::Path { write, .. } => *write,
        Check::HostAction {
            external_effect, ..
        } => *external_effect,
        Check::Command { .. }
        | Check::HostShell { .. }
        | Check::PolicyChange { .. }
        | Check::HostTool {}
        | Check::Unknown { .. } => true,
    });
    let mut value = serde_json::json!({"scope":reg.subject,"policy_ref":reg.policy_ref,"generation":reg.generation,"caller":request.caller,"tool":request.call.tool,"checks":request.call.checks,"arguments":args,"external_effect":external});
    depth(&value, 0)?;
    value.sort_all_objects();
    let encoded = serde_json::to_vec(&value).map_err(|_| Error::Invalid)?;
    if encoded.len() > 49152 {
        return Err(Error::Invalid);
    }
    let call_sha256 = digest(b"tinysecurity/approval-call/v1\0", &encoded);
    value["caller"]
        .as_object_mut()
        .ok_or(Error::Invalid)?
        .remove("call_id");
    let content_sha256 = digest(
        b"tinysecurity/approval-content/v1\0",
        &serde_json::to_vec(&value).map_err(|_| Error::Invalid)?,
    );
    let mut caller = request.caller.clone();
    caller.agent = text(redactor, &caller.agent, RedactMode::IdentifierHash)?;
    caller.call_id = if is_native(&request.call.tool) {
        native_safe_call(request)?
    } else {
        text(redactor, &caller.call_id, RedactMode::IdentifierHash)?
    };
    caller.thread = caller
        .thread
        .as_deref()
        .map(|v| text(redactor, v, RedactMode::IdentifierHash))
        .transpose()?;
    caller.flow = caller
        .flow
        .as_deref()
        .map(|v| text(redactor, v, RedactMode::IdentifierHash))
        .transpose()?;
    Ok((
        ApprovalBinding2 {
            binding_version: 1,
            scope: scope_handle(&reg.subject)?,
            policy_ref: digest(
                b"tinysecurity/approval-policy/v1\0",
                reg.policy_ref.as_bytes(),
            ),
            generation: reg.generation,
            call_sha256,
            content_sha256,
            origin: caller.origin.clone(),
            caller,
        },
        text(redactor, &canonical, RedactMode::StructuredArguments)?,
        external,
    ))
}
pub(crate) fn envelope(row: &ApprovalRow2) -> Result<ApprovalRecord2> {
    let json = serde_json::to_string(row).map_err(|_| Error::Invalid)?;
    if row.created_at_ms >= row.expires_at_ms
        || json.len() > 65536
        || !hex(&row.binding.call_sha256, 64)
        || !hex(&row.binding.content_sha256, 64)
    {
        return Err(Error::Invalid);
    }
    // Correlation is independently domain-separated; it never supplies authority.
    let fingerprint = digest(
        b"tinysecurity/approval-index/v1\0",
        row.binding.call_sha256.as_bytes(),
    )[..32]
        .to_owned();
    Ok(ApprovalRecord2 {
        record_id: row.request_id.clone(),
        version: row.version,
        policy_id: row.binding.policy_ref.clone(),
        generation: row.binding.generation,
        fingerprint,
        record_json: json,
    })
}
pub(crate) fn parse(record: &ApprovalRecord2, scope: &SubjectScope) -> Result<ApprovalRow2> {
    let row: ApprovalRow2 =
        serde_json::from_str(&record.record_json).map_err(|_| Error::Invalid)?;
    if envelope(&row)? != *record
        || &row.binding.scope != scope
        || row.binding.binding_version != 1
        || row.binding.origin != row.binding.caller.origin
        || row
            .session_id
            .as_ref()
            .is_some_and(|session| Some(session) != row.binding.caller.thread.as_ref())
        || row
            .session_id
            .as_ref()
            .is_some_and(|session| session.is_empty() || session.len() > 1024)
        || row
            .audit_error
            .as_ref()
            .is_some_and(|error| error.chars().count() > 512)
        || !hex(&row.request_id, 32)
        || !hex(&row.host_instance, 32)
        || !hex(&row.nonce, 32)
        || !hex(&row.audit.event_id, 32)
        || row.judge.as_ref().is_some_and(|e| !e.is_valid())
        || !lifecycle_valid(&row)
        || row.version == 0
        || row.created_at_ms >= row.expires_at_ms
        || row.audit.generation != row.binding.generation
        || row
            .decision_ticket_sha256
            .as_ref()
            .is_some_and(|s| !hex(s, 64))
        || (matches!(
            row.state,
            ApprovalLifecycle2::Approved
                | ApprovalLifecycle2::Reserved
                | ApprovalLifecycle2::Executed
        ) && row.choice.is_none())
        || row.reservation_id.as_ref().is_some_and(|s| !hex(s, 32))
        || matches!(
            row.state,
            ApprovalLifecycle2::Reserved | ApprovalLifecycle2::Executed
        ) != row.reservation_id.is_some()
        || (row.state == ApprovalLifecycle2::Executed) != row.outcome.is_some()
    {
        return Err(Error::Invalid);
    }
    Ok(row)
}

fn lifecycle_valid(row: &ApprovalRow2) -> bool {
    match row.state {
        ApprovalLifecycle2::Pending => {
            row.choice.is_none()
                && row.attribution.is_none()
                && row.decision_ticket_sha256.is_none()
        }
        ApprovalLifecycle2::Approved
        | ApprovalLifecycle2::Reserved
        | ApprovalLifecycle2::Executed => {
            row.choice
                .is_some_and(|choice| choice != ApprovalChoice2::Deny)
                && row
                    .attribution
                    .as_ref()
                    .is_some_and(|actor| !actor.is_empty())
                && (row.decision_ticket_sha256.is_some()
                    || matches!(
                        row.attribution.as_deref(),
                        Some(
                            "auto:host-policy"
                                | "auto:trusted-automation"
                                | "auto:local-operator"
                                | "auto:tool-grant"
                                | "auto:flow-grant"
                                | "flow-trust-grant"
                                | "flow-trust-import"
                                | "tool-trust-grant"
                                | "tool-trust-import"
                                | "exact-reviewed-grant"
                        )
                    )
                    || (row.attribution.as_deref() == Some("auto:jev")
                        && row.choice == Some(ApprovalChoice2::Once)
                        && row.judge.as_ref().is_some_and(|e| {
                            e.outcome == tinysecurity_bus::JudgeOutcome2::Qualified
                        })))
                && row.legacy_history_json.is_none()
        }
        ApprovalLifecycle2::Denied => {
            row.choice == Some(ApprovalChoice2::Deny) || row.legacy_history_json.is_some()
        }
        ApprovalLifecycle2::Expired | ApprovalLifecycle2::Cancelled => true,
    }
}
