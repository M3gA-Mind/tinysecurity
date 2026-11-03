//! Contract 1.22: origin classes for approval evaluation and durable flow trust.
use super::*;
use tinysecurity_bus::{
    FlowTrustOutcome2, GrantFlowToolRequest2, GrantToolRequest2, ImportTrustItem2,
    ImportTrustOutcome2, ImportTrustSourceRequest2, ListFlowTrustRequest2, ListToolTrustRequest2,
    RedactorConfig, RevokeFlowToolRequest2, RevokeToolByIdRequest2, RevokeToolRequest2, Secret,
    ToolTrustOutcome2,
};

fn shell(n: u64, flow: Option<&str>, origin: Origin, call: &str) -> EvaluateApprovalRequest2 {
    let mut req = begin_for(n, "shell", flow, origin);
    req.request.caller.call_id = call.into();
    req.request.call.checks = vec![Check::Command {
        command: "pwd".into(),
    }];
    req
}
fn at(tail: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{tail:032x}"),
        expected_tail: tail - 1,
        generation: 1,
    }
}
fn grant(n: u64, flow: &str, tool: &str, tail: u64) -> GrantFlowToolRequest2 {
    GrantFlowToolRequest2 {
        scope_id: id(n),
        flow_id: flow.into(),
        tool: tool.into(),
        audit: at(tail),
    }
}
fn revoke(n: u64, flow: &str, tool: &str, tail: u64) -> RevokeFlowToolRequest2 {
    RevokeFlowToolRequest2 {
        scope_id: id(n),
        flow_id: flow.into(),
        tool: tool.into(),
        audit: at(tail),
    }
}
fn listing(n: u64, flow: Option<&str>) -> ListFlowTrustRequest2 {
    ListFlowTrustRequest2 {
        scope_id: id(n),
        flow_id: flow.map(Into::into),
    }
}
fn tool_grant(n: u64, tool: &str, tail: u64) -> GrantToolRequest2 {
    GrantToolRequest2 {
        scope_id: id(n),
        tool: tool.into(),
        audit: at(tail),
    }
}
fn tool_revoke(n: u64, tool: &str, tail: u64) -> RevokeToolRequest2 {
    RevokeToolRequest2 {
        scope_id: id(n),
        tool: tool.into(),
        audit: at(tail),
    }
}
fn tool_listing(n: u64) -> ListToolTrustRequest2 {
    ListToolTrustRequest2 { scope_id: id(n) }
}
fn import_tool_source(n: u64, source_id: &str, tool: &str, tail: u64) -> ImportTrustSourceRequest2 {
    ImportTrustSourceRequest2 {
        scope_id: id(n),
        source_id: source_id.into(),
        source_version: "v1".into(),
        item: ImportTrustItem2::Tool { tool: tool.into() },
        audit: at(tail),
    }
}
fn prompts(fixture: &Fixture) -> Result<usize> {
    Ok(fixture
        .order
        .lock()
        .map_err(|_| Error::Unavailable)?
        .iter()
        .filter(|step| **step == "prompt")
        .count())
}

#[tokio::test]
async fn trusted_automation_and_local_operator_are_audited_automatic_and_never_prompt() -> Result<()>
{
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (index, (origin, label)) in [
        (Origin::TrustedAutomation, "auto:trusted-automation"),
        (Origin::LocalOperator, "auto:local-operator"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = shell(7, None, origin, &format!("call-{index}"));
        req.audit = at(index as u64 + 1);
        let row = owner.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Approved);
        assert_eq!(row.attribution.as_deref(), Some(label));
        assert_eq!(row.choice, Some(ApprovalChoice2::Once));
        assert!(row.decision_ticket_sha256.is_none());
    }
    assert_eq!(prompts(&fixture)?, 0);
    // Both approvals were durably audited before they were returned.
    assert_eq!(
        fixture.audits.lock().map_err(|_| Error::Unavailable)?.len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn automatic_origin_approvals_are_consumable_once_and_record_their_outcome() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let req = shell(7, None, Origin::TrustedAutomation, "call-1");
    let row = owner.begin(req.clone()).await?;
    let action = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id: row.request_id.clone(),
        request: req.request.clone(),
        audit: at(2),
    };
    assert_eq!(
        owner.consume(action.clone()).await?.state,
        ApprovalLifecycle2::Reserved
    );
    assert!(owner.consume(action).await.is_err());
    Ok(())
}

#[tokio::test]
async fn automatic_origins_never_approve_a_human_only_tool() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let mut sequence = 0;
    for tool in [
        "sandbox_host_network",
        "device_crypto",
        "policy_change",
        "native_secret_grant",
    ] {
        for origin in [Origin::TrustedAutomation, Origin::LocalOperator] {
            sequence += 1;
            let mut req = begin_for(7, tool, None, origin.clone());
            req.request.caller.call_id = format!("plan-{sequence}");
            req.request.call.checks = vec![Check::Unknown {
                description: tool.into(),
            }];
            req.audit = at(sequence);
            // The native grants are refused outright; the rest wait for a person.
            match owner.begin(req).await {
                Ok(row) => {
                    assert_eq!(row.state, ApprovalLifecycle2::Pending, "{tool} {origin:?}");
                    assert!(row.attribution.is_none());
                }
                Err(error) => assert_eq!(error, Error::Denied, "{tool} {origin:?}"),
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn cron_external_effects_still_deny_and_cron_reads_stay_automatic() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    assert!(
        owner
            .begin(shell(7, None, Origin::Cron, "call-1"))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        0
    );
    let read = begin_for(7, "local_diagnostic", None, Origin::Cron);
    assert_eq!(owner.begin(read).await?.state, ApprovalLifecycle2::Approved);
    Ok(())
}

#[tokio::test]
async fn unlabelled_origin_is_denied_without_a_whole_tool_grant_and_leaves_nothing_behind()
-> Result<()> {
    let (fixture, owner) = owner()?;
    let mut req = register(7);
    // A flow grant and a grant of another tool do not approve an unlabelled call.
    req.grants = grants(&["http_request"], &[("flow-1", "shell")]);
    owner.register_scope(req).await?;
    for flow in [None, Some("flow-1")] {
        let denied = owner
            .begin(shell(7, flow, Origin::Unlabelled, "call-1"))
            .await;
        assert_eq!(denied.err(), Some(Error::Denied), "{flow:?}");
    }
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        0
    );
    assert_eq!(prompts(&fixture)?, 0);
    Ok(())
}

#[tokio::test]
async fn unknown_origin_denies_without_a_whole_tool_grant() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let mut request = shell(7, None, Origin::Unknown, "unknown-origin");
    request.audit = at(1);
    assert_eq!(owner.begin(request).await.err(), Some(Error::Denied));
    assert_eq!(prompts(&fixture)?, 0);
    Ok(())
}

#[tokio::test]
async fn recent_decisions_include_all_registered_scopes_and_skip_pending_rows() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner.register_scope(register(8)).await?;
    let mut first = shell(7, None, Origin::TrustedAutomation, "decision-1");
    first.audit = at(1);
    let first_row = owner.begin(first).await?;
    let mut pending = shell(7, None, Origin::Operator, "pending");
    pending.audit = at(2);
    let pending_row = owner.begin(pending).await?;
    let mut second = shell(8, None, Origin::TrustedAutomation, "decision-2");
    second.audit = at(3);
    let second_row = owner.begin(second).await?;

    let rows = owner.list_recent_decisions(10).await?;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.state == ApprovalLifecycle2::Approved)
    );
    assert!(
        rows.iter()
            .any(|row| row.request_id == first_row.request_id)
    );
    assert!(
        rows.iter()
            .any(|row| row.request_id == second_row.request_id)
    );
    assert!(
        !rows
            .iter()
            .any(|row| row.request_id == pending_row.request_id)
    );
    Ok(())
}

#[tokio::test]
async fn session_purge_matches_one_redacted_id_across_scopes_and_keeps_decisions() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner.register_scope(register(8)).await?;
    let mut pending_a = shell(7, None, Origin::Operator, "pending-a");
    pending_a.request.caller.thread = Some("session-A".into());
    pending_a.audit = at(1);
    let pending_a = owner.begin(pending_a).await?;
    let mut pending_b = shell(8, None, Origin::Operator, "pending-b");
    pending_b.request.caller.thread = Some("session-A".into());
    pending_b.audit = at(2);
    owner.begin(pending_b).await?;
    let mut other_session = shell(7, None, Origin::Operator, "other-session");
    other_session.request.caller.thread = Some("session-B".into());
    other_session.audit = at(3);
    let other_session = owner.begin(other_session).await?;
    let mut decided = shell(8, None, Origin::TrustedAutomation, "decided");
    decided.request.caller.thread = Some("session-A".into());
    decided.audit = at(4);
    let decided = owner.begin(decided).await?;

    assert_eq!(owner.purge_session("session-A").await?, 2);
    assert_eq!(owner.purge_session("").await.err(), Some(Error::Invalid));
    let first_scope = owner.list(&id(7)).await?;
    let second_scope = owner.list(&id(8)).await?;
    assert!(
        !first_scope
            .iter()
            .any(|row| row.request_id == pending_a.request_id)
    );
    assert!(
        first_scope
            .iter()
            .any(|row| row.request_id == other_session.request_id)
    );
    assert!(
        second_scope
            .iter()
            .any(|row| row.request_id == decided.request_id)
    );
    Ok(())
}

#[tokio::test]
async fn audit_error_is_redacted_before_persistence_and_capped_after_redaction() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let redactor_secret = "private-audit-secret";
    let mut redactor_config = RedactorConfig::default();
    redactor_config.secrets.push(Secret(redactor_secret.into()));
    let owner = Engine::new(
        config(),
        fixture.clone(),
        Arc::new(TestClock::default()),
        Redactor::new(&redactor_config).map_err(|_| Error::Invalid)?,
    )?;
    owner.register_scope(register(7)).await?;
    let mut request = shell(7, None, Origin::Operator, "audit-error");
    request.audit = at(1);
    let row = owner.begin(request).await?;
    let raw = format!("sink rejected {redactor_secret} {}", "x".repeat(700));

    let recorded = owner
        .record_audit_error(tinysecurity_bus::RecordAuditErrorRequest2 {
            scope_id: id(7),
            request_id: row.request_id.clone(),
            audit_error: raw.clone(),
            audit: at(2),
        })
        .await?;

    let value = recorded.audit_error.as_deref().ok_or(Error::Invalid)?;
    assert!(value.chars().count() <= 512);
    assert!(!value.contains(redactor_secret));
    assert!(!value.contains(&"x".repeat(700)));
    assert_eq!(recorded.state, ApprovalLifecycle2::Pending);
    assert!(
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains_key(&row.request_id)
    );
    Ok(())
}

#[tokio::test]
async fn audit_error_short_value_is_idempotent_and_conflicting_updates_are_rejected() -> Result<()>
{
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let mut request = shell(7, None, Origin::Operator, "audit-error-short");
    request.audit = at(1);
    let row = owner.begin(request).await?;
    let input = tinysecurity_bus::RecordAuditErrorRequest2 {
        scope_id: id(7),
        request_id: row.request_id.clone(),
        audit_error: "sink unavailable".into(),
        audit: at(2),
    };
    let recorded = owner.record_audit_error(input.clone()).await?;
    assert_eq!(recorded.audit_error.as_deref(), Some("sink unavailable"));
    assert_eq!(owner.record_audit_error(input).await?, recorded);
    assert_eq!(
        owner
            .record_audit_error(tinysecurity_bus::RecordAuditErrorRequest2 {
                scope_id: id(7),
                request_id: row.request_id,
                audit_error: "different failure".into(),
                audit: at(3),
            })
            .await
            .err(),
        Some(Error::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn audit_error_rejects_empty_diagnostic_before_loading_a_row() -> Result<()> {
    let (_, owner) = owner()?;
    let result = owner
        .record_audit_error(tinysecurity_bus::RecordAuditErrorRequest2 {
            scope_id: id(7),
            request_id: "missing".into(),
            audit_error: String::new(),
            audit: at(1),
        })
        .await;
    assert_eq!(result.err(), Some(Error::Invalid));
    Ok(())
}

#[tokio::test]
async fn default_session_purge_port_fails_closed() -> Result<()> {
    #[derive(Debug)]
    struct DefaultPurgePort;
    #[async_trait::async_trait]
    impl Ports for DefaultPurgePort {
        async fn load(&self, _: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
            Err(Error::Unavailable)
        }
        async fn cas(&self, _: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
            Err(Error::Unavailable)
        }
        async fn prompt(&self, _: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
            Err(Error::Unavailable)
        }
        async fn human(&self, _: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
            Err(Error::Unavailable)
        }
        async fn audit(&self, _: ApprovalRow2) -> Result<()> {
            Err(Error::Unavailable)
        }
    }
    let result = Ports::purge_session(
        &DefaultPurgePort,
        tinysecurity_bus::ApprovalPurgeSessionRequest2 {
            scope: tinysecurity_bus::SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            session_id: "redacted-session".into(),
        },
    )
    .await;
    assert_eq!(result.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn unlabelled_origin_is_approved_only_by_the_exact_whole_tool_grant() -> Result<()> {
    let (fixture, owner) = owner()?;
    let mut req = register(7);
    req.scope.require_approval = false;
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    let row = owner
        .begin(shell(7, None, Origin::Unlabelled, "call-1"))
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:tool-grant"));
    assert_eq!(prompts(&fixture)?, 0);
    let mut other = begin_for(7, "http_request", None, Origin::Unlabelled);
    other.request.caller.call_id = "call-2".into();
    other.audit = at(2);
    assert_eq!(owner.begin(other).await.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn unlabelled_grant_posture_cannot_be_borrowed_from_auto_approve_all() -> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.scope.auto_approve_all = true;
    req.scope.require_approval = false;
    owner.register_scope(req).await?;
    assert_eq!(
        owner
            .begin(shell(7, None, Origin::Unlabelled, "call-1"))
            .await
            .err(),
        Some(Error::Denied)
    );
    Ok(())
}

#[tokio::test]
async fn whole_tool_trust_can_be_revoked_by_listed_request_id() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let receipt = owner
        .grant_tool(GrantToolRequest2 {
            scope_id: id(7),
            tool: "gmail_send".into(),
            audit: at(1),
        })
        .await?;
    let request_id = receipt.request_id.ok_or(Error::Invalid)?;
    owner.register_scope(register(8)).await?;

    let listed = owner
        .list_tool_trust(ListToolTrustRequest2 { scope_id: id(7) })
        .await?;
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].request_id, request_id);

    let wrong_scope = owner
        .revoke_tool_by_id(RevokeToolByIdRequest2 {
            scope_id: id(8),
            request_id: request_id.clone(),
            audit: at(1),
        })
        .await?;
    assert_eq!(wrong_scope.outcome, ToolTrustOutcome2::Absent);
    assert_eq!(
        owner
            .list_tool_trust(ListToolTrustRequest2 { scope_id: id(7) })
            .await?
            .entries
            .len(),
        1
    );

    let revoked = owner
        .revoke_tool_by_id(RevokeToolByIdRequest2 {
            scope_id: id(7),
            request_id: request_id.clone(),
            audit: at(2),
        })
        .await?;
    assert_eq!(revoked.outcome, ToolTrustOutcome2::Revoked);
    assert_eq!(revoked.request_id.as_deref(), Some(request_id.as_str()));
    let retry = owner
        .revoke_tool_by_id(RevokeToolByIdRequest2 {
            scope_id: id(7),
            request_id: request_id.clone(),
            audit: at(2),
        })
        .await?;
    assert_eq!(retry.outcome, ToolTrustOutcome2::Revoked);
    assert_eq!(
        owner
            .list_tool_trust(ListToolTrustRequest2 { scope_id: id(7) })
            .await?
            .entries
            .len(),
        0
    );
    let rows = fixture.rows.lock().map_err(|_| Error::Unavailable)?;
    assert_eq!(rows.len(), 1);
    Ok(())
}

#[tokio::test]
async fn flow_trust_survives_restart_and_covers_only_its_exact_tool_and_flow() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let first = engine(fixture.clone(), clock.clone())?;
    first.register_scope(register(7)).await?;
    let receipt = first
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    assert_eq!(receipt.outcome, FlowTrustOutcome2::Granted);
    assert!(receipt.request_id.is_some());

    // A fresh module instance over the same store: nothing in memory carries over.
    let restarted = engine(fixture.clone(), clock)?;
    restarted.register_scope(register(7)).await?;
    let row = restarted
        .begin({
            let mut r = shell(7, Some("flow-1"), Origin::Operator, "call-1");
            r.audit = at(2);
            r
        })
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:flow-grant"));
    assert_eq!(prompts(&fixture)?, 0);
    for (index, (tool, flow)) in [
        ("shell", Some("flow-2")),
        ("shell", None),
        ("http_request", Some("flow-1")),
    ]
    .into_iter()
    .enumerate()
    {
        let mut req = begin_for(7, tool, flow, Origin::Operator);
        req.request.caller.call_id = format!("other-{index}");
        req.audit = at(index as u64 + 3);
        let row = restarted.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{tool} {flow:?}");
    }
    Ok(())
}

#[tokio::test]
async fn redacted_tool_labels_do_not_break_exact_flow_grant_identity() -> Result<()> {
    let tool = "private-flow-tool-label";
    let mut redactor = RedactorConfig::default();
    redactor.secrets.push(Secret(tool.into()));
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = Engine::new(
        config(),
        fixture,
        clock,
        Redactor::new(&redactor).map_err(|_| Error::Invalid)?,
    )?;
    owner.register_scope(register(7)).await?;

    assert_eq!(
        owner
            .grant_flow_tool(grant(7, "flow-direct", tool, 1))
            .await?
            .outcome,
        FlowTrustOutcome2::Granted
    );
    let mut direct = shell(
        7,
        Some("flow-direct"),
        Origin::Operator,
        "redacted-flow-direct",
    );
    direct.request.call.tool = tool.into();
    direct.audit = at(2);
    assert_eq!(
        owner.begin(direct).await?.state,
        ApprovalLifecycle2::Approved
    );
    assert_eq!(
        owner
            .revoke_flow_tool(revoke(7, "flow-direct", tool, 3))
            .await?
            .outcome,
        FlowTrustOutcome2::Revoked
    );

    let imported = ImportTrustSourceRequest2 {
        scope_id: id(7),
        source_id: "legacy-redacted-flow".into(),
        source_version: "v1".into(),
        item: ImportTrustItem2::FlowTool {
            flow_id: "flow-imported".into(),
            tool: tool.into(),
        },
        audit: at(4),
    };
    assert_eq!(
        owner.import_trust_source(imported).await?.outcome,
        ImportTrustOutcome2::Imported
    );
    let mut imported_call = shell(
        7,
        Some("flow-imported"),
        Origin::Operator,
        "redacted-flow-imported",
    );
    imported_call.request.call.tool = tool.into();
    imported_call.audit = at(5);
    assert_eq!(
        owner.begin(imported_call).await?.state,
        ApprovalLifecycle2::Approved
    );
    assert_eq!(
        owner
            .revoke_flow_tool(revoke(7, "flow-imported", tool, 6))
            .await?
            .outcome,
        FlowTrustOutcome2::Revoked
    );
    let mut after_revoke = shell(
        7,
        Some("flow-imported"),
        Origin::Operator,
        "redacted-flow-after-revoke",
    );
    after_revoke.request.call.tool = tool.into();
    after_revoke.audit = at(7);
    assert_eq!(
        owner.begin(after_revoke).await?.state,
        ApprovalLifecycle2::Pending
    );
    Ok(())
}

#[tokio::test]
async fn granting_a_live_pair_twice_changes_nothing_and_lists_it_once() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let first = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let rows = fixture.rows.lock().map_err(|_| Error::Unavailable)?.len();
    let second = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 2))
        .await?;
    assert_eq!(second.outcome, FlowTrustOutcome2::Unchanged);
    assert_eq!(second.request_id, first.request_id);
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        rows
    );
    owner
        .grant_flow_tool(grant(7, "flow-1", "http_request", 2))
        .await?;
    owner
        .grant_flow_tool(grant(7, "flow-2", "shell", 3))
        .await?;
    let all = owner.list_flow_trust(listing(7, None)).await?.entries;
    assert_eq!(all.len(), 3);
    let one = owner
        .list_flow_trust(listing(7, Some("flow-1")))
        .await?
        .entries;
    assert_eq!(
        one.iter().map(|e| e.tool.as_str()).collect::<Vec<_>>(),
        vec!["http_request", "shell"]
    );
    assert!(
        one.iter()
            .all(|e| e.flow == all[0].flow || e.flow == all[1].flow || e.flow == all[2].flow)
    );
    let none = owner
        .list_flow_trust(listing(7, Some("flow-9")))
        .await?
        .entries;
    assert_eq!(none.len(), 0);
    Ok(())
}

#[tokio::test]
async fn revoking_flow_trust_stops_new_approvals_and_is_idempotent() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let granted = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let revoked = owner
        .revoke_flow_tool(revoke(7, "flow-1", "shell", 2))
        .await?;
    assert_eq!(revoked.outcome, FlowTrustOutcome2::Revoked);
    assert_eq!(revoked.request_id, granted.request_id);
    let again = owner
        .revoke_flow_tool(revoke(7, "flow-1", "shell", 3))
        .await?;
    assert_eq!(again.outcome, FlowTrustOutcome2::Absent);
    assert!(again.request_id.is_none());
    let none = owner.list_flow_trust(listing(7, None)).await?.entries;
    assert_eq!(none.len(), 0);
    let mut req = shell(7, Some("flow-1"), Origin::Operator, "call-1");
    req.audit = at(3);
    assert_eq!(owner.begin(req).await?.state, ApprovalLifecycle2::Pending);
    // A later grant of the same pair works again.
    let regrant = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 4))
        .await?;
    assert_eq!(regrant.outcome, FlowTrustOutcome2::Granted);
    Ok(())
}

#[tokio::test]
async fn an_approval_from_flow_trust_dies_with_a_revocation_before_consumption() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let mut req = shell(7, Some("flow-1"), Origin::Operator, "call-1");
    req.audit = at(2);
    let row = owner.begin(req.clone()).await?;
    assert_eq!(row.attribution.as_deref(), Some("auto:flow-grant"));
    owner
        .revoke_flow_tool(revoke(7, "flow-1", "shell", 3))
        .await?;
    let consumption = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id: row.request_id,
        request: req.request,
        audit: at(4),
    };
    assert!(owner.consume(consumption).await.is_err());
    Ok(())
}

#[tokio::test]
async fn flow_trust_rejects_human_only_native_blank_and_oversized_names() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (flow, tool) in [
        ("flow-1", "device_crypto"),
        ("flow-1", "sandbox_host_network"),
        ("flow-1", "policy_change"),
        ("flow-1", "native_secret_grant"),
        ("flow-1", " "),
        ("", "shell"),
        ("flow-1", "a\nb"),
    ] {
        assert_eq!(
            owner.grant_flow_tool(grant(7, flow, tool, 1)).await.err(),
            Some(Error::Invalid),
            "{flow:?} {tool:?}"
        );
    }
    let long = "f".repeat(1025);
    assert!(
        owner
            .grant_flow_tool(grant(7, &long, "shell", 1))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn flow_trust_needs_a_registered_scope_and_a_current_audit_generation() -> Result<()> {
    let (_, owner) = owner()?;
    assert!(
        owner
            .grant_flow_tool(grant(9, "flow-1", "shell", 1))
            .await
            .is_err()
    );
    owner.register_scope(register(7)).await?;
    let mut stale = grant(7, "flow-1", "shell", 1);
    stale.audit.generation = 2;
    assert!(owner.grant_flow_tool(stale).await.is_err());
    assert!(owner.list_flow_trust(listing(9, None)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn flow_trust_is_stale_after_the_policy_generation_advances() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    assert_eq!(
        owner.list_flow_trust(listing(7, None)).await?.entries.len(),
        1
    );
    owner.advance_generation(2)?;
    // The row belongs to generation 1: it neither lists nor approves, so the call
    // needs a human again.
    let mut next = shell(7, Some("flow-1"), Origin::Operator, "call-2");
    next.audit = AuditCorrelation2 {
        generation: 2,
        ..at(2)
    };
    assert_eq!(owner.begin(next).await?.state, ApprovalLifecycle2::Pending);
    let none = owner.list_flow_trust(listing(7, None)).await?.entries;
    assert_eq!(none.len(), 0);
    Ok(())
}

#[tokio::test]
async fn flow_trust_never_overrides_a_cron_external_denial() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    assert!(
        owner
            .begin(shell(7, Some("flow-1"), Origin::Cron, "call-1"))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_flow_trust_row_cannot_be_preauthorized_decided_or_consumed_as_a_human_grant()
-> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let granted = owner
        .grant_flow_tool(grant(7, "flow-1", "shell", 1))
        .await?;
    let request_id = granted.request_id.ok_or(Error::Invalid)?;
    let review = tinysecurity_bus::PreauthorizeFlowRequest2 {
        scope_id: id(7),
        flow_id: "flow-1".into(),
        request_ids: vec![request_id.clone()],
    };
    assert!(owner.preauthorize_flow(review).await.is_err());
    let decide = DecideRequest2 {
        scope_id: id(7),
        request_id: request_id.clone(),
        decision_ticket: "private-human-ticket".into(),
        audit: at(2),
    };
    assert!(owner.decide(decide).await.is_err());
    let mut req = shell(7, Some("flow-1"), Origin::Operator, "call-1");
    req.audit = at(2);
    let consume = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id,
        request: req.request,
        audit: at(2),
    };
    assert!(owner.consume(consume).await.is_err());
    Ok(())
}

#[tokio::test]
async fn whole_tool_trust_survives_restart_and_is_exactly_scoped() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let first = engine(fixture.clone(), clock.clone())?;
    first.register_scope(register(7)).await?;
    first.register_scope(register(8)).await?;
    let granted = first.grant_tool(tool_grant(7, "shell", 1)).await?;
    assert_eq!(granted.outcome, ToolTrustOutcome2::Granted);
    assert!(granted.request_id.is_some());
    let repeated = first.grant_tool(tool_grant(7, "shell", 2)).await?;
    assert_eq!(repeated.outcome, ToolTrustOutcome2::Unchanged);
    assert_eq!(repeated.request_id, granted.request_id);

    let restarted = engine(fixture, clock)?;
    restarted.register_scope(register(7)).await?;
    restarted.register_scope(register(8)).await?;
    let approved = restarted
        .begin(shell(7, None, Origin::Operator, "matching-tool"))
        .await?;
    assert_eq!(approved.state, ApprovalLifecycle2::Approved);
    assert_eq!(approved.attribution.as_deref(), Some("auto:tool-grant"));

    let mut other_tool = shell(7, None, Origin::Operator, "other-tool");
    other_tool.request.call.tool = "http_request".into();
    other_tool.audit = at(3);
    assert_eq!(
        restarted.begin(other_tool).await?.state,
        ApprovalLifecycle2::Pending
    );

    let other_scope = restarted
        .begin(shell(8, None, Origin::Operator, "other-scope"))
        .await?;
    assert_eq!(other_scope.state, ApprovalLifecycle2::Pending);
    assert_eq!(
        restarted
            .list_tool_trust(tool_listing(8))
            .await?
            .entries
            .len(),
        0
    );
    let listed = restarted.list_tool_trust(tool_listing(7)).await?.entries;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].tool, "shell");
    Ok(())
}

#[tokio::test]
async fn whole_tool_revoke_retry_reconciles_a_committed_cancellation_audit() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let granted = owner.grant_tool(tool_grant(7, "shell", 1)).await?;
    let request = tool_revoke(7, "shell", 2);

    // The cancellation CAS succeeds, then the required terminal audit sink fails.
    fixture.fail_cancelled_audit.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.revoke_tool(request.clone()).await.err(),
        Some(Error::Unavailable)
    );
    let request_id = granted.request_id.clone().ok_or(Error::Invalid)?;
    let cancelled = owner
        .list(&id(7))
        .await?
        .into_iter()
        .find(|row| row.request_id == request_id)
        .ok_or(Error::Invalid)?;
    assert_eq!(cancelled.state, ApprovalLifecycle2::Cancelled);
    assert!(
        !fixture
            .audit_receipts
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains_key(&(cancelled.request_id.clone(), cancelled.version))
    );

    let retry = owner.revoke_tool(request).await?;
    assert_eq!(retry.outcome, ToolTrustOutcome2::Revoked);
    assert_eq!(retry.request_id.as_deref(), granted.request_id.as_deref());
    assert!(
        fixture
            .audit_receipts
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains_key(&(cancelled.request_id.clone(), cancelled.version))
    );
    Ok(())
}

#[tokio::test]
async fn imported_flow_tool_revoke_retry_reconciles_a_committed_cancellation_audit() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let imported = owner
        .import_trust_source(ImportTrustSourceRequest2 {
            scope_id: id(7),
            source_id: "legacy-flow-trust".into(),
            source_version: "v1".into(),
            item: ImportTrustItem2::FlowTool {
                flow_id: "flow-imported".into(),
                tool: "shell".into(),
            },
            audit: at(1),
        })
        .await?;
    let request = revoke(7, "flow-imported", "shell", 2);

    // The cancellation CAS succeeds, then the required terminal audit sink fails.
    fixture.fail_cancelled_audit.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.revoke_flow_tool(request.clone()).await.err(),
        Some(Error::Unavailable)
    );
    let request_id = imported.request_id;
    let cancelled = owner
        .list(&id(7))
        .await?
        .into_iter()
        .find(|row| row.request_id == request_id)
        .ok_or(Error::Invalid)?;
    assert_eq!(cancelled.state, ApprovalLifecycle2::Cancelled);
    assert!(
        !fixture
            .audit_receipts
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains_key(&(cancelled.request_id.clone(), cancelled.version))
    );

    let retry = owner.revoke_flow_tool(request).await?;
    assert_eq!(retry.outcome, FlowTrustOutcome2::Revoked);
    assert_eq!(
        retry.request_id.as_deref(),
        Some(cancelled.request_id.as_str())
    );
    assert!(
        fixture
            .audit_receipts
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains_key(&(cancelled.request_id.clone(), cancelled.version))
    );
    Ok(())
}

#[tokio::test]
async fn redacted_tool_labels_do_not_break_exact_grant_identity() -> Result<()> {
    let tool = "private-tool-label";
    let mut redactor = RedactorConfig::default();
    redactor.secrets.push(Secret(tool.into()));
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = Engine::new(
        config(),
        fixture,
        clock,
        Redactor::new(&redactor).map_err(|_| Error::Invalid)?,
    )?;
    owner.register_scope(register(7)).await?;

    assert_eq!(
        owner.grant_tool(tool_grant(7, tool, 1)).await?.outcome,
        ToolTrustOutcome2::Granted
    );
    let listed = owner.list_tool_trust(tool_listing(7)).await?.entries;
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0].tool, tool);

    let mut matching = shell(7, None, Origin::Operator, "redacted-tool-call");
    matching.request.call.tool = tool.into();
    matching.audit = at(2);
    assert_eq!(
        owner.begin(matching).await?.state,
        ApprovalLifecycle2::Approved
    );

    assert_eq!(
        owner.revoke_tool(tool_revoke(7, tool, 3)).await?.outcome,
        ToolTrustOutcome2::Revoked
    );
    let mut after_revoke = shell(7, None, Origin::Operator, "redacted-tool-after-revoke");
    after_revoke.request.call.tool = tool.into();
    after_revoke.audit = at(4);
    assert_eq!(
        owner.begin(after_revoke).await?.state,
        ApprovalLifecycle2::Pending
    );
    Ok(())
}

#[tokio::test]
async fn whole_tool_revocation_before_consume_revokes_queued_automatic_approval() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner.grant_tool(tool_grant(7, "shell", 1)).await?;
    let mut request = shell(7, None, Origin::Operator, "queued-call");
    request.audit = at(2);
    let row = owner.begin(request.clone()).await?;
    assert_eq!(row.attribution.as_deref(), Some("auto:tool-grant"));

    owner.revoke_tool(tool_revoke(7, "shell", 3)).await?;
    let consume = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id: row.request_id,
        request: request.request,
        audit: at(4),
    };
    assert_eq!(owner.consume(consume).await.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn whole_tool_trust_keeps_cron_unlabelled_and_human_only_boundaries() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner.grant_tool(tool_grant(7, "shell", 1)).await?;

    assert_eq!(
        owner
            .begin(shell(7, None, Origin::Cron, "cron-external"))
            .await
            .err(),
        Some(Error::Denied)
    );
    let mut unlabelled = shell(7, None, Origin::Unlabelled, "unlabelled");
    unlabelled.audit = at(2);
    let granted = owner.begin(unlabelled).await?;
    assert_eq!(granted.attribution.as_deref(), Some("auto:tool-grant"));
    for (index, tool) in ["policy_change", "native_test_action"]
        .into_iter()
        .enumerate()
    {
        assert!(
            owner
                .grant_tool(tool_grant(7, tool, index as u64 + 2))
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn require_approval_overrides_whole_tool_allowlist() -> Result<()> {
    let (_, owner) = owner()?;
    let mut scope = register(7);
    scope.scope.require_approval = true;
    scope.grants = grants(&["shell"], &[]);
    owner.register_scope(scope).await?;

    let mut request = shell(7, None, Origin::Operator, "required-call");
    request.audit = at(2);
    let row = owner.begin(request).await?;

    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(row.attribution, None);
    Ok(())
}

#[tokio::test]
async fn whole_tool_grant_fails_closed_when_the_store_cannot_persist() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    fixture.fail.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.grant_tool(tool_grant(7, "shell", 1)).await.err(),
        Some(Error::Unavailable)
    );
    assert_eq!(
        owner.list_tool_trust(tool_listing(7)).await?.entries.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn whole_tool_trust_rejects_invalid_names_and_expires_with_its_generation() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let too_long = "x".repeat(257);
    for tool in [
        "",
        "  ",
        "shell\n",
        &too_long,
        "policy_change",
        "native_tool",
    ] {
        assert_eq!(
            owner.grant_tool(tool_grant(7, tool, 1)).await.err(),
            Some(Error::Invalid),
            "{tool:?}"
        );
    }
    owner.grant_tool(tool_grant(7, "shell", 1)).await?;
    assert_eq!(
        owner.list_tool_trust(tool_listing(7)).await?.entries.len(),
        1
    );

    owner.advance_generation(2)?;
    assert_eq!(
        owner.list_tool_trust(tool_listing(7)).await?.entries.len(),
        0
    );
    let mut request = shell(7, None, Origin::Operator, "new-generation");
    request.audit = AuditCorrelation2 {
        generation: 2,
        ..at(2)
    };
    assert_eq!(
        owner.begin(request).await?.state,
        ApprovalLifecycle2::Pending
    );
    Ok(())
}

#[tokio::test]
async fn whole_tool_trust_fails_closed_when_the_store_cannot_be_loaded() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner.grant_tool(tool_grant(7, "shell", 1)).await?;
    fixture.load_fail.store(1, Ordering::SeqCst);

    let mut request = shell(7, None, Origin::Operator, "store-unavailable");
    request.audit = at(2);
    assert_eq!(owner.begin(request).await.err(), Some(Error::Unavailable));
    assert_eq!(
        owner.list_tool_trust(tool_listing(7)).await.err(),
        Some(Error::Unavailable)
    );
    Ok(())
}

#[tokio::test]
async fn whole_tool_trust_serializes_scope_replacement_while_loading_rows() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    fixture.pause_load.store(1, Ordering::SeqCst);

    let owner = Arc::new(owner);
    let granting_owner = owner.clone();
    let grant =
        tokio::spawn(async move { granting_owner.grant_tool(tool_grant(7, "shell", 1)).await });
    fixture.loaded.notified().await;

    let replacing_owner = owner.clone();
    let replace = tokio::spawn(async move {
        let mut request = register(7);
        request.scope.policy_ref = "runtime-policy-v2".into();
        replacing_owner.replace_scope(request).await
    });
    tokio::task::yield_now().await;
    assert!(!replace.is_finished());

    fixture.release_load.notify_one();
    assert_eq!(
        grant.await.map_err(|_| Error::Unavailable)??.outcome,
        ToolTrustOutcome2::Granted
    );
    assert_eq!(
        replace.await.map_err(|_| Error::Unavailable)??.outcome,
        ApprovalScopeOutcome2::Replaced
    );
    assert_eq!(
        owner.list_tool_trust(tool_listing(7)).await?.entries,
        Vec::new()
    );
    Ok(())
}

#[tokio::test]
async fn source_import_retries_only_items_missing_from_a_partial_import() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let first = owner
        .import_trust_source(import_tool_source(
            7,
            "legacy-autonomy-auto-approve",
            "shell",
            1,
        ))
        .await?;
    assert_eq!(first.outcome, ImportTrustOutcome2::Imported);

    fixture.fail.store(1, Ordering::SeqCst);
    assert_eq!(
        owner
            .import_trust_source(import_tool_source(
                7,
                "legacy-autonomy-auto-approve",
                "http_request",
                2,
            ))
            .await
            .err(),
        Some(Error::Unavailable)
    );
    fixture.fail.store(0, Ordering::SeqCst);

    let restarted = engine(fixture, Arc::new(TestClock::default()))?;
    restarted.register_scope(register(7)).await?;
    let first_retry = restarted
        .import_trust_source(import_tool_source(
            7,
            "legacy-autonomy-auto-approve",
            "shell",
            3,
        ))
        .await?;
    assert_eq!(first_retry.outcome, ImportTrustOutcome2::AlreadyImported);
    assert_eq!(first_retry.request_id, first.request_id);
    let second_retry = restarted
        .import_trust_source(import_tool_source(
            7,
            "legacy-autonomy-auto-approve",
            "http_request",
            4,
        ))
        .await?;
    assert_eq!(second_retry.outcome, ImportTrustOutcome2::Imported);
    assert_eq!(
        restarted
            .list_tool_trust(tool_listing(7))
            .await?
            .entries
            .len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn expired_import_receipts_do_not_recreate_legacy_trust() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let first = engine(fixture.clone(), clock.clone())?;
    first.register_scope(register(7)).await?;
    let imported = first
        .import_trust_source(import_tool_source(
            7,
            "legacy-autonomy-auto-approve",
            "shell",
            1,
        ))
        .await?;
    assert_eq!(imported.outcome, ImportTrustOutcome2::Imported);

    clock.wall.store(
        1000 + tinysecurity_bus::TOOL_TRUST_LIFETIME_MS2 + 1,
        Ordering::SeqCst,
    );
    let restarted = engine(fixture, clock)?;
    restarted.register_scope(register(7)).await?;
    let repeated = restarted
        .import_trust_source(import_tool_source(
            7,
            "legacy-autonomy-auto-approve",
            "shell",
            2,
        ))
        .await?;
    assert_eq!(repeated.outcome, ImportTrustOutcome2::AlreadyImported);
    assert_eq!(repeated.request_id, imported.request_id);
    assert_eq!(
        restarted
            .list_tool_trust(tool_listing(7))
            .await?
            .entries
            .len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn imported_source_retry_reconciles_a_committed_row_after_audit_failure() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let request = import_tool_source(7, "legacy-autonomy-auto-approve", "shell", 1);

    fixture.fail.store(2, Ordering::SeqCst);
    assert_eq!(
        owner.import_trust_source(request.clone()).await.err(),
        Some(Error::Unavailable)
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        1
    );
    assert!(
        fixture
            .audit_receipts
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );

    fixture.fail.store(0, Ordering::SeqCst);
    let retry = owner.import_trust_source(request).await?;
    assert_eq!(retry.outcome, ImportTrustOutcome2::AlreadyImported);
    assert_eq!(
        fixture
            .audit_receipts
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn source_import_receipts_are_bound_to_subject_version_and_exact_item() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    owner.register_scope(register(8)).await?;
    let first = owner
        .import_trust_source(import_tool_source(
            7,
            "legacy-autonomy-auto-approve",
            "shell",
            1,
        ))
        .await?;
    assert_eq!(first.outcome, ImportTrustOutcome2::Imported);

    let mut other_subject = import_tool_source(8, "legacy-autonomy-auto-approve", "shell", 2);
    other_subject.source_version = "v1".into();
    assert_eq!(
        owner.import_trust_source(other_subject).await?.outcome,
        ImportTrustOutcome2::Imported
    );
    let mut new_item = import_tool_source(7, "legacy-autonomy-auto-approve", "http_request", 3);
    assert_eq!(
        owner.import_trust_source(new_item.clone()).await?.outcome,
        ImportTrustOutcome2::Imported
    );
    new_item.source_version = "v2".into();
    new_item.audit = at(4);
    assert_eq!(
        owner.import_trust_source(new_item).await?.outcome,
        ImportTrustOutcome2::Imported
    );
    Ok(())
}

#[tokio::test]
async fn source_import_validation_and_store_errors_fail_closed() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (source_id, source_version, item) in [
        (
            "",
            "v1",
            ImportTrustItem2::Tool {
                tool: "shell".into(),
            },
        ),
        (
            "legacy-source",
            "bad version",
            ImportTrustItem2::Tool {
                tool: "shell".into(),
            },
        ),
        (
            "legacy-source",
            "v1",
            ImportTrustItem2::Tool {
                tool: "policy_change".into(),
            },
        ),
    ] {
        let mut request = import_tool_source(7, source_id, "shell", 1);
        request.source_version = source_version.into();
        request.item = item;
        assert_eq!(
            owner.import_trust_source(request).await.err(),
            Some(Error::Invalid)
        );
    }
    fixture.fail.store(1, Ordering::SeqCst);
    assert_eq!(
        owner
            .import_trust_source(import_tool_source(
                7,
                "legacy-autonomy-auto-approve",
                "shell",
                1,
            ))
            .await
            .err(),
        Some(Error::Unavailable)
    );
    fixture.fail.store(0, Ordering::SeqCst);
    assert_eq!(
        owner.list_tool_trust(tool_listing(7)).await?.entries.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn an_unlabelled_approval_dies_when_only_a_flow_grant_remains() -> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.scope.require_approval = false;
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req.clone()).await?;
    let call = shell(7, Some("flow-1"), Origin::Unlabelled, "call-1");
    let row = owner.begin(call.clone()).await?;
    assert_eq!(row.attribution.as_deref(), Some("auto:tool-grant"));
    // The whole-tool grant is replaced by a flow grant for the same tool and flow.
    req.grants = grants(&[], &[("flow-1", "shell")]);
    owner.replace_scope(req).await?;
    let consumption = ApprovalActionRequest2 {
        scope_id: id(7),
        request_id: row.request_id,
        request: call.request,
        audit: at(2),
    };
    assert!(owner.consume(consumption).await.is_err());
    Ok(())
}

#[tokio::test]
async fn a_reviewed_human_only_tool_is_never_reused_by_a_trusted_origin() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    fixture.choice.store(1, Ordering::SeqCst); // the human answers "this tool"
    let ask = |call: &str, tail: u64| {
        let mut req = begin_for(7, "policy_change", None, Origin::LocalOperator);
        req.request.caller.call_id = call.into();
        req.request.call.checks = vec![Check::Unknown {
            description: "policy_change".into(),
        }];
        req.audit = at(tail);
        req
    };
    let first = owner.begin(ask("call-1", 1)).await?;
    assert_eq!(first.state, ApprovalLifecycle2::Pending);
    let decision = DecideRequest2 {
        scope_id: id(7),
        request_id: first.request_id,
        decision_ticket: "private-human-ticket".into(),
        audit: at(2),
    };
    owner.decide(decision).await?;
    let again = owner.begin(ask("call-2", 3)).await?;
    assert_eq!(
        again.state,
        ApprovalLifecycle2::Pending,
        "asked a person again"
    );
    Ok(())
}

#[tokio::test]
async fn revocation_refuses_names_a_grant_could_never_carry() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for (flow, tool) in [
        ("flow-1", "device_crypto"),
        ("flow-1", "native_secret_grant"),
        ("flow-1", " "),
        ("flow\n1", "shell"),
        ("", "shell"),
    ] {
        assert_eq!(
            owner.revoke_flow_tool(revoke(7, flow, tool, 1)).await.err(),
            Some(Error::Invalid),
            "{flow:?} {tool:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_flow_identity_may_be_as_long_as_a_callers_but_a_tool_name_keeps_its_bound() -> Result<()>
{
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let flow = "f".repeat(1024);
    let receipt = owner.grant_flow_tool(grant(7, &flow, "shell", 1)).await?;
    assert_eq!(receipt.outcome, FlowTrustOutcome2::Granted);
    assert!(
        owner
            .grant_flow_tool(grant(7, &"f".repeat(1025), "shell", 2))
            .await
            .is_err()
    );
    assert!(
        owner
            .grant_flow_tool(grant(7, "flow-1", &"t".repeat(257), 2))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_full_scope_takes_no_new_flow_trust_but_still_answers_for_a_live_one() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for n in 0..960u64 {
        owner
            .grant_flow_tool(grant(7, &format!("flow-{n}"), "shell", n + 1))
            .await?;
    }
    assert_eq!(
        owner
            .grant_flow_tool(grant(7, "one-more", "shell", 961))
            .await
            .err(),
        Some(Error::Unavailable)
    );
    let again = owner
        .grant_flow_tool(grant(7, "flow-0", "shell", 962))
        .await?;
    assert_eq!(again.outcome, FlowTrustOutcome2::Unchanged);
    // The scope still loads.
    assert_eq!(
        owner.list_flow_trust(listing(7, None)).await?.entries.len(),
        960
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_pair_cannot_cross_the_scope_row_cap_when_regranted() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for n in 0..960u64 {
        owner
            .grant_flow_tool(grant(7, &format!("flow-{n}"), "shell", n + 1))
            .await?;
    }
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        960
    );
    let revoked = owner
        .revoke_flow_tool(revoke(7, "flow-0", "shell", 961))
        .await?;
    assert_eq!(revoked.outcome, FlowTrustOutcome2::Revoked);
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        960
    );
    assert_eq!(
        owner
            .grant_flow_tool(grant(7, "flow-0", "shell", 962))
            .await
            .err(),
        Some(Error::Unavailable)
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        960
    );
    Ok(())
}

#[tokio::test]
async fn a_revoked_tool_cannot_cross_the_scope_row_cap_when_regranted() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    for n in 0..960u64 {
        owner
            .grant_tool(tool_grant(7, &format!("tool-{n}"), n + 1))
            .await?;
    }
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        960
    );
    let revoked = owner.revoke_tool(tool_revoke(7, "tool-0", 961)).await?;
    assert_eq!(revoked.outcome, ToolTrustOutcome2::Revoked);
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        960
    );
    assert_eq!(
        owner.grant_tool(tool_grant(7, "tool-0", 962)).await.err(),
        Some(Error::Unavailable)
    );
    assert_eq!(
        fixture.rows.lock().map_err(|_| Error::Unavailable)?.len(),
        960
    );
    Ok(())
}
