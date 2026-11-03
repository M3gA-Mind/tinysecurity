use super::*;
use tinysecurity_bus::GrantToolRequest2;

const STREAM: &str = "5555555555555555555555555555555a";

fn id(n: u64) -> String {
    format!("{n:032x}")
}
fn subject(n: u64) -> SubjectScope {
    SubjectScope {
        user: format!("user-{n}"),
        workspace: "workspace".into(),
        agent: format!("agent-{n}"),
    }
}
fn scope(n: u64) -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: id(n),
        subject: subject(n),
        policy_ref: "runtime-policy-v1".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn register(n: u64) -> RegisterApprovalScopeRequest2 {
    RegisterApprovalScopeRequest2 {
        scope: scope(n),
        grants: ApprovalGrants2::default(),
        audit_stream_id: STREAM.into(),
        report_handle: false,
    }
}
fn begin_for(n: u64, tool: &str, flow: Option<&str>, origin: Origin) -> EvaluateApprovalRequest2 {
    let mut req = request();
    req.scope_id = id(n);
    req.request.caller.agent = format!("agent-{n}");
    req.request.caller.flow = flow.map(Into::into);
    req.request.caller.origin = origin;
    req.request.call.tool = tool.into();
    req
}
fn owner() -> Result<(Arc<Fixture>, Engine)> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = engine(fixture.clone(), clock)?;
    Ok((fixture, owner))
}
fn grants(tools: &[&str], flows: &[(&str, &str)]) -> ApprovalGrants2 {
    ApprovalGrants2 {
        tools: tools.iter().map(|t| (*t).into()).collect(),
        flows: flows
            .iter()
            .map(|(flow, tool)| FlowToolGrant2 {
                flow_id: (*flow).into(),
                tool: (*tool).into(),
            })
            .collect(),
    }
}
use tinysecurity_bus::FlowToolGrant2;

#[tokio::test]
async fn unregistered_scope_denies_until_registered_then_serves_its_own_subject() -> Result<()> {
    let (fixture, owner) = owner()?;
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    let receipt = owner.register_scope(register(7)).await?;
    assert_eq!(receipt.outcome, ApprovalScopeOutcome2::Created);
    assert_eq!(
        (
            receipt.scope_id.as_str(),
            receipt.generation,
            receipt.live_scopes
        ),
        (id(7).as_str(), 1, 2)
    );
    assert_eq!(
        *fixture.admitted.lock().map_err(|_| Error::Unavailable)?,
        vec![(id(7), STREAM.to_owned())]
    );
    let row = owner
        .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(row.binding.scope, binding::scope_handle(&subject(7))?);
    Ok(())
}

#[tokio::test]
async fn init_scope_keeps_working_beside_registered_ones() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let row = owner.begin(request()).await?;
    assert_eq!(
        row.binding.scope,
        binding::scope_handle(&config().scopes[0].subject)?
    );
    Ok(())
}

#[tokio::test]
async fn identical_registration_is_idempotent_and_any_other_reuse_conflicts() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let again = owner.register_scope(register(7)).await?;
    assert_eq!(again.outcome, ApprovalScopeOutcome2::Unchanged);
    // Only one admission reached the ports.
    assert_eq!(
        fixture
            .admitted
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len(),
        1
    );
    let mut changed = register(7);
    changed.scope.auto_approve_all = true;
    assert_eq!(
        owner.register_scope(changed).await.err(),
        Some(Error::Conflict)
    );
    let mut other_stream = register(7);
    other_stream.audit_stream_id = "6".repeat(32);
    assert_eq!(
        owner.register_scope(other_stream).await.err(),
        Some(Error::Conflict)
    );
    let mut same_subject = register(7);
    same_subject.scope.scope_id = id(8);
    assert_eq!(
        owner.register_scope(same_subject).await.err(),
        Some(Error::Conflict)
    );
    // Reusing the operator's init subject under a new identity conflicts as well.
    let mut operator = register(9);
    operator.scope.subject = config().scopes[0].subject.clone();
    assert_eq!(
        owner.register_scope(operator).await.err(),
        Some(Error::Conflict)
    );
    let mut init_id = register(9);
    init_id.scope.scope_id = "a".repeat(32);
    assert_eq!(
        owner.register_scope(init_id).await.err(),
        Some(Error::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn registration_validates_scope_generation_grants_stream_and_ports() -> Result<()> {
    let (fixture, owner) = owner()?;
    let mut bad_scope = register(7);
    bad_scope.scope.policy_ref.clear();
    assert_eq!(
        owner.register_scope(bad_scope).await.err(),
        Some(Error::Invalid)
    );
    let mut bad_stream = register(7);
    bad_stream.audit_stream_id = "short".into();
    assert_eq!(
        owner.register_scope(bad_stream).await.err(),
        Some(Error::Invalid)
    );
    let mut human_only = register(7);
    human_only.grants = grants(&["device_crypto"], &[]);
    assert_eq!(
        owner.register_scope(human_only).await.err(),
        Some(Error::Invalid)
    );
    let mut stale = register(7);
    stale.scope.generation = 2;
    assert_eq!(owner.register_scope(stale).await.err(), Some(Error::Denied));
    fixture.admit_fails.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.register_scope(register(7)).await.err(),
        Some(Error::Unavailable)
    );
    // A scope the ports refused never becomes usable.
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    fixture.admit_fails.store(0, Ordering::SeqCst);
    owner.register_scope(register(7)).await?;
    owner.advance_generation(2)?;
    let mut old = register(8);
    old.scope.generation = 1;
    assert_eq!(owner.register_scope(old).await.err(), Some(Error::Denied));
    // The engine owns the generation: an identical repeat after an advance is unchanged.
    let mut repeat = register(7);
    repeat.scope.generation = 2;
    assert_eq!(
        owner.register_scope(repeat).await?.outcome,
        ApprovalScopeOutcome2::Unchanged
    );
    Ok(())
}

#[tokio::test]
async fn scope_table_is_bounded() -> Result<()> {
    let (_, owner) = owner()?;
    for n in 1..MAX_APPROVAL_SCOPES2 as u64 {
        owner.register_scope(register(n + 100)).await?;
    }
    assert_eq!(
        owner.register_scope(register(1)).await.err(),
        Some(Error::Unavailable)
    );
    owner
        .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(101) })
        .await?;
    assert_eq!(
        owner.register_scope(register(1)).await?.outcome,
        ApprovalScopeOutcome2::Created
    );
    Ok(())
}

#[tokio::test]
async fn replace_changes_posture_atomically_and_keeps_subject_and_stream() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let pending = owner
        .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
        .await?;
    assert_eq!(pending.state, ApprovalLifecycle2::Pending);
    let mut auto = register(7);
    auto.scope.auto_approve_all = true;
    assert_eq!(
        owner.replace_scope(auto.clone()).await?.outcome,
        ApprovalScopeOutcome2::Replaced
    );
    assert_eq!(
        owner.replace_scope(auto).await?.outcome,
        ApprovalScopeOutcome2::Unchanged
    );
    let approved = owner
        .begin(begin_for(7, "other_tool", None, Origin::Operator))
        .await?;
    assert_eq!(approved.state, ApprovalLifecycle2::Approved);
    assert_eq!(approved.attribution.as_deref(), Some("auto:host-policy"));
    let mut moved = register(7);
    moved.scope.subject = subject(99);
    assert_eq!(owner.replace_scope(moved).await.err(), Some(Error::Denied));
    let mut other_stream = register(7);
    other_stream.audit_stream_id = "6".repeat(32);
    assert_eq!(
        owner.replace_scope(other_stream).await.err(),
        Some(Error::Denied)
    );
    assert_eq!(
        owner.replace_scope(register(40)).await.err(),
        Some(Error::Denied)
    );
    let mut invalid = register(7);
    invalid.grants = grants(&["policy_change"], &[]);
    assert_eq!(
        owner.replace_scope(invalid).await.err(),
        Some(Error::Invalid)
    );
    Ok(())
}

#[tokio::test]
async fn init_scope_can_be_replaced_and_keeps_the_base_stream() -> Result<()> {
    let (_, owner) = owner()?;
    let mut operator = config().scopes[0].clone();
    operator.auto_approve_all = true;
    let receipt = owner
        .replace_scope(RegisterApprovalScopeRequest2 {
            scope: operator,
            grants: ApprovalGrants2::default(),
            audit_stream_id: STREAM.into(),
            report_handle: false,
        })
        .await?;
    assert_eq!(receipt.outcome, ApprovalScopeOutcome2::Replaced);
    assert_eq!(
        owner.begin(request()).await?.state,
        ApprovalLifecycle2::Approved
    );
    Ok(())
}

#[tokio::test]
async fn retire_denies_later_calls_releases_the_subject_and_reports_once() -> Result<()> {
    let (fixture, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let receipt = owner
        .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
        .await?;
    assert_eq!(
        (receipt.outcome, receipt.generation, receipt.live_scopes),
        (ApprovalScopeOutcome2::Retired, 0, 1)
    );
    assert_eq!(
        *fixture.released.lock().map_err(|_| Error::Unavailable)?,
        vec![id(7)]
    );
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    assert_eq!(
        owner
            .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
            .await
            .err(),
        Some(Error::Denied)
    );
    // The identity and subject are free again.
    owner.register_scope(register(7)).await?;
    fixture.release_fails.store(1, Ordering::SeqCst);
    assert_eq!(
        owner
            .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
            .await
            .err(),
        Some(Error::Unavailable)
    );
    // A failed release keeps ownership: the subject cannot register again, and the
    // retirement can be retried until the ports complete it.
    let mut again = register(7);
    again.scope.scope_id = id(8);
    assert_eq!(
        owner.register_scope(again).await.err(),
        Some(Error::Conflict)
    );
    fixture.release_fails.store(0, Ordering::SeqCst);
    assert_eq!(
        owner
            .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
            .await?
            .outcome,
        ApprovalScopeOutcome2::Retired
    );
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn tool_grant_approves_only_that_tool_with_a_persisted_audited_row() -> Result<()> {
    let (fixture, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    let row = owner
        .begin(begin_for(7, "shell", None, Origin::Operator))
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(row.attribution, None);
    assert!(row.decision_ticket_sha256.is_none());
    assert!(
        fixture
            .audits
            .lock()
            .map_err(|_| Error::Unavailable)?
            .iter()
            .any(|a| a.request_id == row.request_id),
        "a granted row is audited"
    );
    // A configured allowlist cannot shortcut the required human decision.
    assert_eq!(
        owner
            .begin(begin_for(7, "shell", None, Origin::Operator))
            .await?
            .request_id,
        row.request_id
    );
    let other = owner
        .begin(begin_for(7, "http_request", None, Origin::Operator))
        .await?;
    assert_eq!(other.state, ApprovalLifecycle2::Pending);
    Ok(())
}

#[tokio::test]
async fn flow_grant_is_scoped_to_that_flow_and_tool() -> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&[], &[("flow-1", "shell")]);
    owner.register_scope(req).await?;
    let granted = owner
        .begin(begin_for(7, "shell", Some("flow-1"), Origin::Operator))
        .await?;
    assert_eq!(granted.state, ApprovalLifecycle2::Pending);
    assert_eq!(granted.attribution, None);
    for (tool, flow) in [
        ("shell", Some("flow-2")),
        ("shell", None),
        ("http_request", Some("flow-1")),
    ] {
        let row = owner
            .begin(begin_for(7, tool, flow, Origin::Operator))
            .await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{tool} {flow:?}");
    }
    Ok(())
}

#[tokio::test]
async fn grants_reach_saas_but_never_override_cron_external_denial_or_human_only_tools()
-> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&["shell", "local_diagnostic"], &[]);
    owner.register_scope(req).await?;
    let saas = owner
        .begin(begin_for(7, "shell", None, Origin::Saas))
        .await?;
    assert_eq!(saas.state, ApprovalLifecycle2::Pending);
    let mut cron = begin_for(7, "shell", None, Origin::Cron);
    cron.request.call.checks = vec![Check::Command {
        command: "x".into(),
    }];
    assert!(owner.begin(cron).await.is_err());
    // Even if a grant somehow named a human-only tool, the entry refuses to match it.
    let entry = ScopeEntry {
        scope: scope(7),
        tools: [
            "device_crypto",
            "native_secret_grant",
            "sandbox_host_network",
            "policy_change",
        ]
        .into_iter()
        .map(Into::into)
        .collect(),
        flows: [("f".to_owned(), "device_crypto".to_owned())].into(),
        audit_stream_id: None,
    };
    for tool in HUMAN_ONLY_TOOLS2 {
        assert_eq!(entry.grant(tool, Some("f")), None);
    }
    assert_eq!(entry.grant("native_x", None), None);
    Ok(())
}

#[tokio::test]
async fn default_ports_refuse_runtime_scopes_and_release_nothing() -> Result<()> {
    #[derive(Debug)]
    struct Bare;
    #[async_trait::async_trait]
    impl Ports for Bare {
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
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = Engine::new(
        config(),
        Arc::new(Bare),
        clock,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert_eq!(
        owner.register_scope(register(7)).await.err(),
        Some(Error::Denied)
    );
    assert!(Bare.release_scope(&scope(7)).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn host_tool_marker_is_an_external_effect_that_cron_cannot_reach() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let mut host_tool = begin_for(7, "gmail_send", None, Origin::Operator);
    host_tool.request.call.checks = vec![Check::HostTool {}];
    let row = owner.begin(host_tool.clone()).await?;
    assert!(row.external_effect);
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    host_tool.request.caller.origin = Origin::Cron;
    host_tool.request.caller.call_id = "cron-call".into();
    assert!(owner.begin(host_tool).await.is_err());
    Ok(())
}

#[tokio::test]
async fn skill_scan_warning_enters_human_approval() -> Result<()> {
    let (_, owner) = owner()?;
    let mut auto_approve = register(7);
    auto_approve.scope.auto_approve_all = true;
    auto_approve.grants = grants(&["run_workflow"], &[]);
    owner.register_scope(auto_approve).await?;

    let mut warning = begin_for(7, "run_workflow", None, Origin::Operator);
    warning.request.call.checks = vec![Check::SkillScan {
        verdict: tinysecurity_bus::SkillScanVerdict::Warn,
        bundle_sha256: "a".repeat(64),
    }];
    let pending = owner.begin(warning).await?;
    assert_eq!(pending.state, ApprovalLifecycle2::Pending);
    assert!(!pending.external_effect);

    let mut blocked = begin_for(7, "run_workflow", None, Origin::Operator);
    blocked.request.caller.call_id = "blocked-call".into();
    blocked.request.call.checks = vec![Check::SkillScan {
        verdict: tinysecurity_bus::SkillScanVerdict::Block,
        bundle_sha256: "b".repeat(64),
    }];
    assert_eq!(owner.begin(blocked).await.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn host_action_and_shell_checks_bind_with_their_own_external_effect() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(register(7)).await?;
    let bind = |tool: &'static str, call: &str, check: Check| {
        let mut begin = begin_for(7, tool, None, Origin::Operator);
        begin.request.caller.call_id = call.into();
        begin.request.call.checks = vec![check];
        begin
    };
    let action = |external_effect| Check::HostAction {
        permission: tinysecurity_bus::ToolPermission::Write,
        external_effect,
        spend: false,
        command_policy: None,
    };
    let shell = Check::HostShell {
        command: "touch f".into(),
        declared_class: None,
        spend: false,
        command_policy: None,
    };
    assert!(
        owner
            .begin(bind("gmail_send", "a", action(true)))
            .await?
            .external_effect
    );
    assert!(
        !owner
            .begin(bind("write_file", "b", action(false)))
            .await?
            .external_effect
    );
    assert!(
        owner
            .begin(bind("shell", "c", shell))
            .await?
            .external_effect
    );
    Ok(())
}

#[test]
fn init_rejects_duplicate_identities_and_duplicate_subjects() {
    let build = |cfg: ApprovalConfig2| {
        Engine::new(
            cfg,
            Arc::new(Fixture::default()),
            Arc::new(TestClock::default()),
            Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
        )
    };
    let mut same_identity = config();
    same_identity.scopes.push(same_identity.scopes[0].clone());
    assert_eq!(build(same_identity).err(), Some(Error::Invalid));
    let mut same_subject = config();
    let mut twin = same_subject.scopes[0].clone();
    twin.scope_id = id(9);
    same_subject.scopes.push(twin);
    assert_eq!(build(same_subject).err(), Some(Error::Invalid));
}

#[tokio::test]
async fn racing_registrations_of_one_subject_admit_exactly_one() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    fixture.admit_pause.store(1, Ordering::SeqCst);
    let first = tokio::spawn({
        let owner = owner.clone();
        async move { owner.register_scope(register(7)).await }
    });
    fixture.ports_entered.notified().await;
    // Same subject, another identity and stream, while the first is mid-admission.
    let mut rival = register(7);
    rival.scope.scope_id = id(8);
    rival.audit_stream_id = "6".repeat(32);
    let second = tokio::spawn({
        let owner = owner.clone();
        async move { owner.register_scope(rival).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "the rival waits for the first lifecycle"
    );
    fixture.ports_proceed.notify_one();
    assert_eq!(
        first.await.map_err(|_| Error::Unavailable)??.outcome,
        ApprovalScopeOutcome2::Created
    );
    assert_eq!(
        second.await.map_err(|_| Error::Unavailable)?.err(),
        Some(Error::Conflict)
    );
    // The ports only ever saw the winner, never the loser's stream.
    assert_eq!(
        *fixture.admitted.lock().map_err(|_| Error::Unavailable)?,
        vec![(id(7), STREAM.to_owned())]
    );
    assert!(
        fixture
            .released
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn failed_admission_is_undone_and_leaves_no_scope() -> Result<()> {
    let (fixture, owner) = owner()?;
    fixture.admit_fails.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.register_scope(register(7)).await.err(),
        Some(Error::Unavailable)
    );
    // The failed attempt asked the ports to forget the subject, and none is live.
    fixture.admit_fails.store(0, Ordering::SeqCst);
    assert_eq!(
        *fixture.released.lock().map_err(|_| Error::Unavailable)?,
        vec![id(7)]
    );
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    assert_eq!(
        owner.register_scope(register(7)).await?.outcome,
        ApprovalScopeOutcome2::Created
    );
    Ok(())
}

#[tokio::test]
async fn retirement_finishes_releasing_before_the_subject_can_register_again() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    owner.register_scope(register(7)).await?;
    fixture.release_pause.store(1, Ordering::SeqCst);
    let retire = tokio::spawn({
        let owner = owner.clone();
        async move {
            owner
                .retire_scope(RetireApprovalScopeRequest2 { scope_id: id(7) })
                .await
        }
    });
    fixture.ports_entered.notified().await;
    let mut again = register(7);
    again.scope.scope_id = id(8);
    let registered = tokio::spawn({
        let owner = owner.clone();
        async move { owner.register_scope(again).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !registered.is_finished(),
        "re-registration waits for the release"
    );
    fixture.ports_proceed.notify_one();
    assert_eq!(
        retire.await.map_err(|_| Error::Unavailable)??.outcome,
        ApprovalScopeOutcome2::Retired
    );
    assert_eq!(
        registered.await.map_err(|_| Error::Unavailable)??.outcome,
        ApprovalScopeOutcome2::Created
    );
    // Release happened first, then the replacement was admitted and stays live.
    assert_eq!(
        *fixture.released.lock().map_err(|_| Error::Unavailable)?,
        vec![id(7)]
    );
    assert_eq!(
        fixture
            .admitted
            .lock()
            .map_err(|_| Error::Unavailable)?
            .last()
            .map(|a| a.0.clone()),
        Some(id(8))
    );
    Ok(())
}

#[tokio::test]
async fn generation_advance_during_admission_never_publishes_the_stale_scope() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    fixture.admit_pause.store(1, Ordering::SeqCst);
    let racing = tokio::spawn({
        let owner = owner.clone();
        async move { owner.register_scope(register(7)).await }
    });
    fixture.ports_entered.notified().await;
    owner.advance_generation(2)?;
    fixture.ports_proceed.notify_one();
    assert_eq!(
        racing.await.map_err(|_| Error::Unavailable)?.err(),
        Some(Error::Denied)
    );
    // The admitted port state was undone and the scope is not usable.
    assert_eq!(
        *fixture.released.lock().map_err(|_| Error::Unavailable)?,
        vec![id(7)]
    );
    assert!(
        owner
            .begin(begin_for(7, "local_diagnostic", None, Origin::Operator))
            .await
            .is_err()
    );
    // A registration made against the new generation succeeds.
    let mut fresh = register(7);
    fresh.scope.generation = 2;
    assert_eq!(
        owner.register_scope(fresh).await?.outcome,
        ApprovalScopeOutcome2::Created
    );
    Ok(())
}

#[tokio::test]
async fn generation_advance_while_waiting_for_the_lifecycle_denies_the_registration() -> Result<()>
{
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    fixture.admit_pause.store(1, Ordering::SeqCst);
    let holder = tokio::spawn({
        let owner = owner.clone();
        async move { owner.register_scope(register(7)).await }
    });
    fixture.ports_entered.notified().await;
    let waiting = tokio::spawn({
        let owner = owner.clone();
        async move { owner.register_scope(register(8)).await }
    });
    tokio::task::yield_now().await;
    owner.advance_generation(2)?;
    fixture.ports_proceed.notify_one();
    let _ = holder.await.map_err(|_| Error::Unavailable)?;
    assert_eq!(
        waiting.await.map_err(|_| Error::Unavailable)?.err(),
        Some(Error::Denied)
    );
    assert_eq!(
        fixture
            .admitted
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn revoking_a_grant_blocks_consumption_of_its_unconsumed_approval() -> Result<()> {
    let (_, owner) = owner()?;
    let mut req = register(7);
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    let call = begin_for(7, "shell", None, Origin::Operator);
    let row = owner.begin(call.clone()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    // The grant is removed before the approved row is consumed.
    owner.replace_scope(register(7)).await?;
    let mut act = action(&row, 3);
    act.scope_id = id(7);
    act.request = call.request;
    assert_eq!(owner.consume(act).await.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn grant_revoked_while_the_ports_await_never_publishes_an_approval() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    let mut req = register(7);
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    fixture.pause_load.store(1, Ordering::SeqCst);
    let racing = tokio::spawn({
        let owner = owner.clone();
        async move {
            owner
                .begin(begin_for(7, "shell", None, Origin::Operator))
                .await
        }
    });
    fixture.loaded.notified().await;
    owner.replace_scope(register(7)).await?;
    fixture.release_load.notify_one();
    assert_eq!(
        racing.await.map_err(|_| Error::Unavailable)??.state,
        ApprovalLifecycle2::Pending
    );
    // The configured allowlist never bypasses the human decision.
    let again = owner
        .begin(begin_for(7, "shell", None, Origin::Operator))
        .await?;
    assert_eq!(again.state, ApprovalLifecycle2::Pending);
    Ok(())
}

fn automatic_scope(n: u64) -> RegisterApprovalScopeRequest2 {
    let mut req = register(n);
    req.scope.auto_approve_all = true;
    req
}

#[tokio::test]
async fn tightening_posture_blocks_consumption_of_an_unconsumed_automatic_approval() -> Result<()> {
    let (_, owner) = owner()?;
    owner.register_scope(automatic_scope(7)).await?;
    let call = begin_for(7, "shell", None, Origin::Operator);
    let row = owner.begin(call.clone()).await?;
    assert_eq!(row.attribution.as_deref(), Some("auto:host-policy"));
    owner.replace_scope(register(7)).await?;
    let mut act = action(&row, 3);
    act.scope_id = id(7);
    act.request = call.request;
    assert_eq!(owner.consume(act).await.err(), Some(Error::Denied));
    Ok(())
}

#[tokio::test]
async fn posture_tightened_while_the_ports_await_never_publishes_an_automatic_row() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    owner.register_scope(automatic_scope(7)).await?;
    fixture.pause_load.store(1, Ordering::SeqCst);
    let racing = tokio::spawn({
        let owner = owner.clone();
        async move {
            owner
                .begin(begin_for(7, "shell", None, Origin::Operator))
                .await
        }
    });
    fixture.loaded.notified().await;
    owner.replace_scope(register(7)).await?;
    fixture.release_load.notify_one();
    assert_eq!(
        racing.await.map_err(|_| Error::Unavailable)?.err(),
        Some(Error::Denied)
    );
    Ok(())
}

#[tokio::test]
async fn replacement_and_generation_advance_serialize_on_the_scope_table() -> Result<()> {
    let (_, owner) = owner()?;
    let owner = Arc::new(owner);
    owner.register_scope(register(7)).await?;
    let held = owner.scopes.write().map_err(|_| Error::Unavailable)?;
    let advancing = std::thread::spawn({
        let owner = owner.clone();
        move || owner.advance_generation(2)
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!advancing.is_finished(), "advance waits for the table lock");
    drop(held);
    advancing.join().map_err(|_| Error::Unavailable)??;
    // A replacement validated against the old generation is denied after the advance,
    // and the live scope is untouched.
    let mut stale = register(7);
    stale.scope.auto_approve_all = true;
    assert_eq!(
        owner.replace_scope(stale.clone()).await.err(),
        Some(Error::Denied)
    );
    let mut call = begin_for(7, "shell", None, Origin::Operator);
    call.audit.generation = 2;
    assert_eq!(owner.begin(call).await?.state, ApprovalLifecycle2::Pending);
    stale.scope.generation = 2;
    assert_eq!(
        owner.replace_scope(stale).await?.outcome,
        ApprovalScopeOutcome2::Replaced
    );
    Ok(())
}

#[tokio::test]
async fn policy_replaced_while_consume_awaits_never_reserves_the_old_approval() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    owner.register_scope(automatic_scope(7)).await?;
    let call = begin_for(7, "shell", None, Origin::Operator);
    let row = owner.begin(call.clone()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    fixture.pause_load.store(1, Ordering::SeqCst);
    let mut act = action(&row, 3);
    act.scope_id = id(7);
    act.request = call.request;
    let racing = tokio::spawn({
        let owner = owner.clone();
        async move { owner.consume(act).await }
    });
    fixture.loaded.notified().await;
    // Same posture and grants, new policy reference: the approval belongs to the old one.
    let mut next = automatic_scope(7);
    next.scope.policy_ref = "runtime-policy-v2".into();
    assert_eq!(
        owner.replace_scope(next).await?.outcome,
        ApprovalScopeOutcome2::Replaced
    );
    fixture.release_load.notify_one();
    assert_eq!(
        racing.await.map_err(|_| Error::Unavailable)?.err(),
        Some(Error::Denied)
    );
    Ok(())
}

#[tokio::test]
async fn scope_replacement_waits_for_a_trusted_reservation_to_commit() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    owner.register_scope(register(7)).await?;
    owner
        .grant_tool(GrantToolRequest2 {
            scope_id: id(7),
            tool: "shell".into(),
            audit: audit(1),
        })
        .await?;
    let call = begin_for(7, "shell", None, Origin::Operator);
    let row = owner.begin(call.clone()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    // The trusted grant disappears after checks but before the write commits.
    let before = fixture.cas_calls.load(Ordering::SeqCst);
    fixture
        .barrier
        .lock()
        .map_err(|_| Error::Unavailable)?
        .replace(Arc::new(tokio::sync::Barrier::new(2)));
    let mut act = action(&row, 3);
    act.scope_id = id(7);
    act.request = call.request;
    let racing = tokio::spawn({
        let owner = owner.clone();
        async move { owner.consume(act).await }
    });
    // The CAS is parked on the barrier; replacement must wait for the trusted
    // reservation to finish before changing the scope.
    while fixture.cas_calls.load(Ordering::SeqCst) == before {
        tokio::task::yield_now().await;
    }
    let replacing = tokio::spawn({
        let owner = owner.clone();
        async move {
            let mut next = register(7);
            next.scope.policy_ref = "replacement-policy".into();
            owner.replace_scope(next).await
        }
    });
    tokio::task::yield_now().await;
    assert!(!replacing.is_finished());
    let barrier = fixture
        .barrier
        .lock()
        .map_err(|_| Error::Unavailable)?
        .clone()
        .ok_or(Error::Unavailable)?;
    barrier.wait().await;
    assert_eq!(
        racing.await.map_err(|_| Error::Unavailable)??.state,
        ApprovalLifecycle2::Reserved
    );
    assert_eq!(
        replacing.await.map_err(|_| Error::Unavailable)??.outcome,
        ApprovalScopeOutcome2::Replaced
    );
    Ok(())
}

#[tokio::test]
async fn initialized_scopes_cannot_be_retired() -> Result<()> {
    let (fixture, owner) = owner()?;
    assert_eq!(
        owner
            .retire_scope(RetireApprovalScopeRequest2 {
                scope_id: "a".repeat(32)
            })
            .await
            .err(),
        Some(Error::Denied)
    );
    assert!(
        fixture
            .released
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    // It keeps serving.
    assert_eq!(
        owner.begin(request()).await?.state,
        ApprovalLifecycle2::Pending
    );
    Ok(())
}

#[tokio::test]
async fn grant_revoked_while_the_approval_is_published_is_not_returned() -> Result<()> {
    let (fixture, owner) = owner()?;
    let owner = Arc::new(owner);
    let mut req = register(7);
    req.grants = grants(&["shell"], &[]);
    owner.register_scope(req).await?;
    let before = fixture.cas_calls.load(Ordering::SeqCst);
    fixture
        .barrier
        .lock()
        .map_err(|_| Error::Unavailable)?
        .replace(Arc::new(tokio::sync::Barrier::new(2)));
    let racing = tokio::spawn({
        let owner = owner.clone();
        async move {
            owner
                .begin(begin_for(7, "shell", None, Origin::Operator))
                .await
        }
    });
    // The new row's write is parked while the configured allowlist is replaced.
    while fixture.cas_calls.load(Ordering::SeqCst) == before {
        tokio::task::yield_now().await;
    }
    owner.replace_scope(register(7)).await?;
    let barrier = fixture
        .barrier
        .lock()
        .map_err(|_| Error::Unavailable)?
        .clone()
        .ok_or(Error::Unavailable)?;
    barrier.wait().await;
    assert_eq!(
        racing.await.map_err(|_| Error::Unavailable)??.state,
        ApprovalLifecycle2::Pending
    );
    Ok(())
}

#[tokio::test]
async fn a_receipt_reports_the_subject_handle_only_when_asked() -> Result<()> {
    let (_fixture, owner) = owner()?;
    let handle = binding::scope_handle(&subject(21))?;
    let quiet = owner.register_scope(register(21)).await?;
    assert_eq!(quiet.outcome, ApprovalScopeOutcome2::Created);
    assert!(quiet.scope_handle.is_none(), "an older host never asked");

    let mut asking = register(21);
    asking.report_handle = true;
    let same = owner.register_scope(asking.clone()).await?;
    assert_eq!(same.outcome, ApprovalScopeOutcome2::Unchanged);
    assert_eq!(same.scope_handle, Some(handle.clone()));

    asking.grants.tools = vec!["shell".into()];
    let replaced = owner.replace_scope(asking).await?;
    assert_eq!(replaced.outcome, ApprovalScopeOutcome2::Replaced);
    assert_eq!(replaced.scope_handle, Some(handle));

    let retired = owner
        .retire_scope(RetireApprovalScopeRequest2 {
            scope_id: register(21).scope.scope_id,
        })
        .await?;
    assert_eq!(retired.outcome, ApprovalScopeOutcome2::Retired);
    assert!(retired.scope_handle.is_none(), "a retirement reports none");
    Ok(())
}

#[path = "engine_gaps_tests.rs"]
mod gaps_tests;
