use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tinybus::{broker::Broker, transport::memory::MemoryBus};
#[path = "../examples/approval_native_contract/callback.rs"]
pub(crate) mod callback;
#[path = "../examples/approval_native_contract/store.rs"]
pub(crate) mod store;
#[derive(Debug)]
struct TestClock(AtomicU64);
impl tinysecurity::approval::Clock for TestClock {
    fn wall_ms(&self) -> Option<u64> {
        Some(self.0.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
#[derive(Clone)]
struct Sink {
    fail: Arc<AtomicBool>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(tinybus::Error::failed("fixture audit unavailable"));
        }
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence,
            events: request
                .events
                .into_iter()
                .map(|e| AuditEventReceipt2 {
                    event_id: e.event_id,
                    sequence: e.sequence,
                })
                .collect(),
        }))
        .await
    }
}
fn begin(instance: u64, sequence: u64) -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: EvaluateRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: format!("execution-{instance}"),
                thread: Some("thread".into()),
                flow: Some("flow".into()),
                tier: AccessTier::Full,
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: r#"{"token":"private-secret"}"#.into(),
                checks: vec![Check::LocalDiagnostic {}],
            },
        },
        ttl_ms: None,
        summary: "bearer private-secret".into(),
        audit: audit(sequence),
    }
}
fn action(row: &ApprovalRow2, instance: u64, sequence: u64) -> ApprovalActionRequest2 {
    ApprovalActionRequest2 {
        scope_id: "a".repeat(32),
        request_id: row.request_id.clone(),
        request: begin(instance, sequence).request,
        audit: audit(sequence),
    }
}
fn record(row: &ApprovalRow2, sequence: u64) -> ApprovalRecordRequest2 {
    ApprovalRecordRequest2 {
        scope_id: "a".repeat(32),
        request_id: row.request_id.clone(),
        audit: audit(sequence),
    }
}
#[tokio::test]
async fn authenticated_module_routes_persistent_decisions_reservation_history_and_expiry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    serve_approvals(&host, &module, &clock, &store, &failure, None).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    execute_once(&proxy).await?;
    review_flow(&proxy, &store).await?;
    expire_history(&proxy, &clock).await?;
    failure.store(true, Ordering::SeqCst);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(4, 11),))
            .await
            .is_err()
    );
    assert!(!String::from_utf8_lossy(&std::fs::read(path)?).contains("private-secret"));
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn recent_decisions_session_purge_and_audit_error_use_the_approval_engine()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    serve_approvals(&host, &module, &clock, &store, &failure, None).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;

    let approved: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(1, 1),))
        .await?;
    let reserved: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (action(&approved.record, 1, 3),),
        )
        .await?;
    let terminal: ApprovalRow2 = proxy
        .call(
            names::methods::RECORD_EXECUTION2,
            (RecordExecutionRequest2 {
                action: action(&reserved, 1, 4),
                outcome: ExecutionOutcome::Succeeded,
            },),
        )
        .await?;
    let saved_error: ApprovalRow2 = proxy
        .call(
            names::methods::RECORD_AUDIT_ERROR2,
            (RecordAuditErrorRequest2 {
                scope_id: "a".repeat(32),
                request_id: terminal.request_id.clone(),
                audit_error: "sink unavailable".into(),
                audit: audit(5),
            },),
        )
        .await?;
    assert_eq!(saved_error.audit_error.as_deref(), Some("sink unavailable"));

    let recent: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::LIST_RECENT_DECISIONS2,
            (RecentApprovalDecisionsRequest2 { limit: 10 },),
        )
        .await?;
    assert!(
        recent
            .iter()
            .any(|row| row.request_id == approved.record.request_id)
    );

    let removed: usize = proxy
        .call(
            names::methods::PURGE_APPROVAL_SESSION2,
            (PurgeApprovalSessionRequest2 {
                session_id: "thread".into(),
            },),
        )
        .await?;
    assert_eq!(removed, 0);
    broker.abort();
    Ok(())
}
#[tokio::test]
async fn admission_questions_are_not_downgraded_by_configured_approvals()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    // Approvals configured, audit forwarded but not required: path, command and
    // admission members stay available, as the host configures production.
    let (config, mut audit_config) = settings();
    audit_config.required = false;
    serve_approvals_with(
        &host,
        &module,
        &clock,
        &store,
        &failure,
        None,
        (config, audit_config),
    )
    .await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    let caller = CallerContext {
        agent: "agent".into(),
        call_id: "call".into(),
        tier: AccessTier::Full,
        ..Default::default()
    };
    let call = |tool: &str, checks: Vec<Check>| EvaluateRequest {
        caller: caller.clone(),
        call: ToolCall {
            tool: tool.into(),
            arguments_json: "{}".into(),
            checks,
        },
    };
    let admission: Decision = proxy
        .call(
            names::methods::EVALUATE,
            (call(
                "read_file",
                vec![Check::HostAction {
                    permission: ToolPermission::ReadOnly,
                    external_effect: false,
                    spend: false,
                    command_policy: None,
                }],
            ),),
        )
        .await?;
    assert_eq!(admission.verdict, Verdict::Allow);
    // A mixed request is not an admission question: it is downgraded after the
    // evaluation, and the downgrade happens before any action is reserved.
    let scope: CommandPolicyId = proxy
        .call(
            names::methods::REGISTER_COMMAND_POLICY,
            (host_scope_policy(CommandAutonomy::Full, 1),),
        )
        .await?;
    let spending = |extra: Vec<Check>| {
        let mut checks = vec![Check::HostAction {
            permission: ToolPermission::Write,
            external_effect: false,
            spend: true,
            command_policy: Some(scope.clone()),
        }];
        checks.extend(extra);
        call("write_file", checks)
    };
    for _ in 0..3 {
        let mixed: Decision = proxy
            .call(
                names::methods::EVALUATE,
                (spending(vec![Check::LocalDiagnostic {}]),),
            )
            .await?;
        assert_ne!(mixed.verdict, Verdict::Allow);
    }
    let pure: Decision = proxy
        .call(names::methods::EVALUATE, (spending(vec![]),))
        .await?;
    assert_eq!(
        pure.verdict,
        Verdict::Allow,
        "the refused calls spent nothing"
    );
    // Any other permission still needs a bound audit event, so it is not allowed.
    let effect: Decision = proxy
        .call(
            names::methods::EVALUATE,
            (call("local_diagnostic", vec![Check::LocalDiagnostic {}]),),
        )
        .await?;
    assert_ne!(effect.verdict, Verdict::Allow);
    broker.abort();
    Ok(())
}
fn host_scope_policy(autonomy: CommandAutonomy, budget: u32) -> CommandPolicy {
    CommandPolicy {
        enabled: true,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        autonomy,
        allowed_commands: vec![],
        max_actions_per_hour: budget,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir().unwrap_or_default(),
        home_dir: None,
    }
}

fn external_action(instance: u64, scope: &CommandPolicyId) -> EvaluateApprovalRequest2 {
    let mut request = begin(instance, instance);
    request.request.call.tool = "gmail_send".into();
    request.request.call.checks = vec![Check::HostAction {
        permission: ToolPermission::Write,
        external_effect: true,
        spend: true,
        command_policy: Some(scope.clone()),
    }];
    request
}

/// A module with approvals served the way production serves them, and a proxy to it.
struct ApprovalFixture {
    _dir: tempfile::TempDir,
    _host: Connection,
    _module: Connection,
    broker: tokio::task::JoinHandle<tinybus::Result<()>>,
    proxy: tinybus::Proxy,
}

async fn approval_fixture() -> std::result::Result<ApprovalFixture, Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    serve_approvals(&host, &module, &clock, &store, &failure, None).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    Ok(ApprovalFixture {
        _dir: dir,
        _host: host,
        _module: module,
        broker,
        proxy,
    })
}

async fn register_scope(
    proxy: &tinybus::Proxy,
    autonomy: CommandAutonomy,
    budget: u32,
) -> std::result::Result<CommandPolicyId, Box<dyn std::error::Error>> {
    Ok(proxy
        .call(
            names::methods::REGISTER_COMMAND_POLICY,
            (host_scope_policy(autonomy, budget),),
        )
        .await?)
}

#[tokio::test]
async fn approval_cannot_override_a_command_scope_and_an_approved_action_spends_its_budget()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = approval_fixture().await?;
    let proxy = &fixture.proxy;
    // Read-only autonomy is a hard denial: a human cannot approve it away.
    let read_only = register_scope(proxy, CommandAutonomy::ReadOnly, 5).await?;
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(
                names::methods::EVALUATE_APPROVAL2,
                (external_action(1, &read_only),)
            )
            .await
            .is_err()
    );
    // A one-action budget: the approved call spends it when it is consumed, and the
    // next call is refused before a human is asked.
    let scope = register_scope(proxy, CommandAutonomy::Full, 1).await?;
    let approved: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (external_action(2, &scope),),
        )
        .await?;
    assert_eq!(approved.decision.verdict, Verdict::Allow);
    let mut consume = action(&approved.record, 2, 3);
    consume.request = external_action(2, &scope).request;
    let reserved: ApprovalRow2 = proxy
        .call(names::methods::CONSUME_APPROVAL2, (consume,))
        .await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(
                names::methods::EVALUATE_APPROVAL2,
                (external_action(3, &scope),)
            )
            .await
            .is_err(),
        "a spent budget cannot be approved"
    );
    fixture.broker.abort();
    Ok(())
}

#[tokio::test]
async fn a_run_refused_for_a_spent_budget_does_not_burn_its_once_only_approval()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = approval_fixture().await?;
    let proxy = &fixture.proxy;
    let scope = register_scope(proxy, CommandAutonomy::Full, 1).await?;
    let waiting: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (external_action(4, &scope),),
        )
        .await?;
    assert_eq!(waiting.decision.verdict, Verdict::Allow);
    // Another call spends the last action before the approved one runs.
    let spend = EvaluateRequest {
        caller: begin(0, 1).request.caller,
        call: ToolCall {
            tool: "write_file".into(),
            arguments_json: "{}".into(),
            checks: vec![Check::HostAction {
                permission: ToolPermission::Write,
                external_effect: false,
                spend: true,
                command_policy: Some(scope.clone()),
            }],
        },
    };
    let other_call: Decision = proxy.call(names::methods::EVALUATE, (spend,)).await?;
    assert_eq!(other_call.verdict, Verdict::Allow);
    let mut late = action(&waiting.record, 4, 8);
    late.request = external_action(4, &scope).request;
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::CONSUME_APPROVAL2, (late,))
            .await
            .is_err(),
        "the spent budget refuses the run"
    );
    let rows: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::LIST_APPROVALS2,
            (ApprovalRecordRequest2 {
                scope_id: "a".repeat(32),
                request_id: String::new(),
                audit: audit(9),
            },),
        )
        .await?;
    let row = rows
        .iter()
        .find(|row| row.request_id == waiting.record.request_id)
        .ok_or("approval row listed")?;
    assert_eq!(
        row.state,
        ApprovalLifecycle2::Approved,
        "a refused run leaves the approval unburned"
    );
    fixture.broker.abort();
    Ok(())
}

#[tokio::test]
async fn approval_initialization_requires_verified_audit_and_retains_immutable_registration()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await?).await?;
    let peer = connection.unique_name().ok_or("peer")?;
    let candidate = Policy::new(ModuleConfig::default())?;
    let (config, audit_config) = settings();
    let configure = |requested_host, approval, audit, current| {
        configured_approvals(
            &connection,
            requested_host,
            approval,
            audit,
            &candidate,
            current,
        )
    };
    assert!(configure(Some(peer.as_str()), Some(config.clone()), None, None).is_err());
    assert!(configure(None, Some(config.clone()), Some(&audit_config), None).is_err());
    let mut stale = config.clone();
    stale.scopes[0].generation = 2;
    assert!(configure(Some(peer.as_str()), Some(stale), Some(&audit_config), None).is_err());
    let active = configure(
        Some(peer.as_str()),
        Some(config.clone()),
        Some(&audit_config),
        None,
    )?;
    assert!(active.is_some());
    let retained = configure(
        Some(peer.as_str()),
        None,
        Some(&audit_config),
        Some(&active),
    )?;
    let (_, original) = active.as_ref().ok_or("engine")?;
    let (_, retained) = retained.as_ref().ok_or("retained")?;
    assert!(Arc::ptr_eq(original, retained));
    let same = configure(
        Some(peer.as_str()),
        Some(config.clone()),
        Some(&audit_config),
        Some(&active),
    )?;
    assert!(same.is_some());
    let mut changed = config.clone();
    changed.timeout_ms = 100;
    assert!(
        configure(
            Some(peer.as_str()),
            Some(changed),
            Some(&audit_config),
            Some(&active)
        )
        .is_err()
    );
    assert!(
        configure(
            Some(peer.as_str()),
            Some(config),
            Some(&audit_config),
            Some(&None)
        )
        .is_err()
    );
    assert!(configure(Some(peer.as_str()), None, None, Some(&None))?.is_none());
    broker.abort();
    Ok(())
}

async fn serve_approvals(
    host: &Connection,
    module: &Connection,
    clock: &Arc<TestClock>,
    store: &Arc<Mutex<store::DiskStore>>,
    failure: &Arc<AtomicBool>,
    automatic: Option<Arc<tinysecurity::auto::Engine>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    serve_approvals_with(host, module, clock, store, failure, automatic, settings()).await
}
async fn serve_approvals_with(
    host: &Connection,
    module: &Connection,
    clock: &Arc<TestClock>,
    store: &Arc<Mutex<store::DiskStore>>,
    failure: &Arc<AtomicBool>,
    automatic: Option<Arc<tinysecurity::auto::Engine>>,
    (config, audit_config): (ApprovalConfig2, AuditConfig2),
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let host_peer = host.unique_name().ok_or("host peer")?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let subject = audit_config.scope.clone();
    let redactor = tinysecurity::Redactor::new(&RedactorConfig {
        secrets: vec![Secret("fake-judge-key".into())],
    })?;
    let clients = crate::approval_callbacks::ApprovalClients::new_for_test(
        module,
        Some(host_peer.as_str()),
        &config,
        &audit_config,
        &redactor,
    )?;
    let engine = Arc::new(tinysecurity::approval::Engine::new(
        config,
        Arc::new(clients),
        clock.clone(),
        redactor,
    )?);
    engine.replace_automatic(automatic)?;
    let mut service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    );
    service.approvals = Some(engine);
    service.signals = Some(module.clone());
    module
        .serve_at(
            names::OBJECT_PATH.parse()?,
            crate::callbacks::Authenticated::new(
                service,
                crate::callbacks::PeerBinding::new(Some(host_peer.as_str()))?,
            ),
        )
        .await?;
    let reentrant = Arc::new(AtomicBool::new(true));
    let scope = tinysecurity::approval::scope_handle(&subject)?;
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        host.serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            callback::Callback {
                module: module_peer.clone(),
                host: host.clone(),
                interface: interface.parse()?,
                scope: scope.clone(),
                store: store.clone(),
                reentrant: reentrant.clone(),
                prompt_failure: failure.clone(),
            },
        )
        .await?;
    }
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Sink {
                fail: Arc::clone(failure),
            },
            crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
        ),
    )
    .await?;
    Ok(())
}
async fn execute_once(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let approved: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(1, 1),))
        .await?;
    assert_eq!(approved.decision.verdict, Verdict::Allow);
    let reserved: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (action(&approved.record, 1, 3),),
        )
        .await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    let terminal: ApprovalRow2 = proxy
        .call(
            names::methods::RECORD_EXECUTION2,
            (RecordExecutionRequest2 {
                action: action(&reserved, 1, 4),
                outcome: ExecutionOutcome::Succeeded,
            },),
        )
        .await?;
    assert_eq!(terminal.state, ApprovalLifecycle2::Executed);
    Ok(())
}
async fn review_flow(
    proxy: &tinybus::Proxy,
    store: &Arc<Mutex<store::DiskStore>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(2, 5),))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(pending.record.clone(), ApprovalChoice2::Flow)?;
    let flow: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: pending.record.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(6),
            },),
        )
        .await?;
    let reviewed: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::PREAUTHORIZE_FLOW2,
            (PreauthorizeFlowRequest2 {
                scope_id: "a".repeat(32),
                flow_id: "flow".into(),
                request_ids: vec![flow.request_id.clone()],
            },),
        )
        .await?;
    assert_eq!(reviewed, vec![flow.clone()]);
    let cancelled: ApprovalRow2 = proxy
        .call(names::methods::CANCEL_APPROVAL2, (record(&flow, 7),))
        .await?;
    assert_eq!(cancelled.state, ApprovalLifecycle2::Cancelled);
    Ok(())
}
async fn expire_history(
    proxy: &tinybus::Proxy,
    clock: &TestClock,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut short = begin(3, 8);
    short.ttl_ms = Some(1);
    let expiring: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (short,))
        .await?;
    clock.0.store(1001, Ordering::SeqCst);
    let expired: ApprovalRow2 = proxy
        .call(
            names::methods::EXPIRE_APPROVAL2,
            (record(&expiring.record, 9),),
        )
        .await?;
    assert_eq!(expired.state, ApprovalLifecycle2::Expired);
    let history: ApprovalRow2 = proxy
        .call(
            names::methods::IMPORT_APPROVAL_HISTORY2,
            (ApprovalHistoryImport2 {
                scope_id: "a".repeat(32),
                legacy: ApprovalRecord {
                    request_id: "legacy".into(),
                    fingerprint: "b".repeat(32),
                    caller: begin(99, 10).request.caller,
                    expires_at_ms: 999_999,
                    state: ApprovalState::Allowed,
                },
                audit: audit(10),
            },),
        )
        .await?;
    assert_eq!(history.state, ApprovalLifecycle2::Denied);
    let listed: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::LIST_APPROVALS2,
            (ApprovalRecordRequest2 {
                scope_id: "a".repeat(32),
                request_id: String::new(),
                audit: audit(11),
            },),
        )
        .await?;
    assert_eq!(listed.len(), 4);
    assert!(
        proxy
            .call::<Vec<ApprovalRow2>>(names::methods::LIST_APPROVALS2, (record(&history, 11),))
            .await
            .is_err()
    );
    Ok(())
}

fn settings() -> (ApprovalConfig2, AuditConfig2) {
    let subject = SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    };
    let config = ApprovalConfig2 {
        timeout_ms: 30_000,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: subject.clone(),
            policy_ref: "partial-policy".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        }],
    };
    let audit_config = AuditConfig2 {
        scope: subject.clone(),
        stream_id: "c".repeat(32),
        timeout_ms: 30_000,
        required: true,
        native_path: None,
        max_bytes: 100_000,
        max_archives: 3,
        journal_max_bytes: 1_000_000,
        journal_max_events: 10_000,
    };
    (config, audit_config)
}

fn judge_settings() -> JudgeConfig {
    JudgeConfig {
        credential: Secret("fake-judge-key".into()),
        endpoint: "http://127.0.0.1:1/jev".into(),
        provider: JudgeProvider::TypeSafe,
        threshold_millis: 900,
        exfiltrate_millis: 100,
        thresholds: vec![],
        timeout_ms: 1000,
        origins: vec![Origin::Operator],
        max_requests: 10,
        budget_window_ms: 60_000,
        cache_entries: 10,
        cache_ttl_ms: 1000,
    }
}
#[tokio::test]
async fn explicit_judge_initialization_activates_the_native_engine()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await?).await?;
    let peer = connection.unique_name().ok_or("peer")?;
    let judge = judge_settings();
    let candidate = Policy::new(ModuleConfig {
        judge: Some(judge.clone()),
        ..Default::default()
    })?;
    let (config, audit) = settings();
    let approvals = configured_approvals(
        &connection,
        Some(peer.as_str()),
        Some(config),
        Some(&audit),
        &candidate,
        None,
    )?;
    let (_, approvals) = approvals.as_ref().ok_or("approvals")?;
    let engine = configured_automatic(Some(judge.clone()), Some(approvals))?;
    assert!(engine.is_some());
    approvals.replace_automatic(engine)?;
    let mut invalid = judge.clone();
    invalid.endpoint = "http://not-loopback.invalid/jev".into();
    assert!(configured_automatic(Some(invalid), Some(approvals)).is_err());
    assert!(approvals.automatic()?.is_some());
    approvals.replace_automatic(None)?;
    assert!(approvals.automatic()?.is_none());
    assert!(approvals.previous_automatic()?.is_some());
    let restored = configured_automatic(Some(judge.clone()), Some(approvals))?;
    assert!(restored.is_some());
    approvals.replace_automatic(restored)?;
    assert!(configured_automatic(Some(judge), None).is_err());
    assert!(configured_automatic(None, None)?.is_none());
    assert!(!serde_json::to_string(&candidate.info())?.contains("fake-judge-key"));
    let redacted = candidate.redactor().redact(&RedactRequest {
        text: "fake-judge-key http://127.0.0.1:1/jev".into(),
        mode: RedactMode::Text,
    })?;
    assert!(!redacted.text.contains("fake-judge-key"));
    assert!(!redacted.text.contains("127.0.0.1"));
    broker.abort();
    Ok(())
}
#[path = "../examples/judge_native_contract/stub.rs"]
mod stub;
#[tokio::test]
async fn authenticated_judge_uses_sdk_http_before_audited_one_shot_and_real_human_fallback()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let stub = stub::Stub::start().await?;
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    let mut cfg = judge_settings();
    cfg.endpoint = stub.endpoint.clone();
    let automatic = Arc::new(tinysecurity::auto::Engine::new(
        cfg,
        Arc::new(tinysecurity::auto::SystemClock::default()),
    )?);
    serve_approvals(&host, &module, &clock, &store, &failure, Some(automatic)).await?;
    let peer = module.unique_name().ok_or("module")?;
    let proxy = host.proxy(peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    verify_judge_one_shot(&proxy).await?;
    *stub.response.lock().map_err(|_| "stub")? = (200, stub::response([0.5, 1.0, 0.0]));
    // Fixture's reentrant verified human callback approves this uncertain verdict.
    let human: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(21, 3),))
        .await?;
    assert_eq!(human.decision.verdict, Verdict::Allow);
    assert!(human.record.decision_ticket_sha256.is_some());
    assert_ne!(human.record.attribution.as_deref(), Some("auto:jev"));
    assert_eq!(
        human
            .record
            .judge
            .as_ref()
            .ok_or("uncertain evidence")?
            .outcome,
        JudgeOutcome2::Uncertain
    );
    let before = stub.requests.lock().map_err(|_| "stub")?.len();
    let mut forbidden = begin(22, 5);
    forbidden.request.call.checks = vec![Check::Unknown {
        description: "forbidden".into(),
    }];
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (forbidden,))
            .await
            .is_err()
    );
    assert_eq!(stub.requests.lock().map_err(|_| "stub")?.len(), before);
    *stub.response.lock().map_err(|_| "stub")? = (503, "unavailable".into());
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(23, 5),))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    assert_eq!(
        pending
            .record
            .judge
            .as_ref()
            .ok_or("failure evidence")?
            .outcome,
        JudgeOutcome2::Unavailable
    );
    assert_eq!(
        stub.requests.lock().map_err(|_| "stub")?.len(),
        before + 1,
        "SDK retries must be disabled"
    );
    *stub.response.lock().map_err(|_| "stub")? = (200, stub::response([1.0, 1.0, 0.0]));
    failure.store(true, Ordering::SeqCst);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(24, 6),))
            .await
            .is_err()
    );
    let requests = serde_json::to_string(&*stub.requests.lock().map_err(|_| "stub")?)?;
    assert!(!requests.contains("private-secret"));
    assert!(!requests.contains("fake-judge-key"));
    assert!(!String::from_utf8_lossy(&std::fs::read(path)?).contains("private-secret"));
    broker.abort();
    stub.shutdown().await?;
    Ok(())
}

async fn verify_judge_one_shot(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let qualified: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(20, 1),))
        .await?;
    assert_eq!(qualified.decision.verdict, Verdict::Allow);
    assert_eq!(qualified.record.attribution.as_deref(), Some("auto:jev"));
    assert!(qualified.record.decision_ticket_sha256.is_none());
    assert_eq!(
        qualified
            .record
            .judge
            .as_ref()
            .ok_or("judge evidence")?
            .outcome,
        JudgeOutcome2::Qualified
    );
    let reserved: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (action(&qualified.record, 20, 2),),
        )
        .await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    assert!(
        proxy
            .call::<ApprovalRow2>(
                names::methods::CONSUME_APPROVAL2,
                (action(&qualified.record, 20, 2),)
            )
            .await
            .is_err()
    );
    Ok(())
}

fn change_subject() -> SubjectScope {
    SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    }
}
fn change_caller() -> CallerContext {
    CallerContext {
        agent: "agent".into(),
        call_id: "change-1".into(),
        thread: Some("thread".into()),
        tier: AccessTier::Full,
        ..Default::default()
    }
}
async fn registered_policy(
    proxy: &tinybus::Proxy,
    root: &std::path::Path,
    judge: bool,
) -> std::result::Result<RegisteredPolicy, Box<dyn std::error::Error>> {
    let path_policy_id: PathPolicyId = proxy
        .call(
            names::methods::REGISTER_PATH_POLICY,
            (fixture_policy(root),),
        )
        .await?;
    let command_policy_id: CommandPolicyId = proxy
        .call(
            names::methods::REGISTER_COMMAND_POLICY,
            (CommandPolicy {
                action_dir: root.into(),
                ..command_fixture()?
            },),
        )
        .await?;
    Ok(RegisteredPolicy {
        path_policy_id,
        settings: PolicySettings {
            policy: PolicyConfig {
                enabled: true,
                action_dir: root.display().to_string(),
                workspace_dir: root.display().to_string(),
                allowed_commands: vec![],
                forbidden_paths: vec![],
            },
            privacy: PrivacyMode::Standard,
            egress_hosts: vec![],
            command_classes: vec![],
            auto_origins: vec![],
            judge_enabled: judge,
        },
        tool_rules: vec![],
        command_policy_id,
        subject_scope: change_subject(),
    })
}
async fn supersede(
    proxy: &tinybus::Proxy,
    previous: &PolicyId,
    next: &RegisteredPolicy,
    approval: Option<PolicyChangeApproval>,
) -> tinybus::Result<SupersedePolicyResponse> {
    proxy
        .call(
            names::methods::SUPERSEDE_POLICY,
            (SupersedePolicyRequest {
                caller: change_caller(),
                previous: previous.clone(),
                next: next.clone(),
                approval,
            },),
        )
        .await
}
#[tokio::test]
async fn widening_policy_change_needs_one_human_approval_under_the_old_policy()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let ledger = dir.path().join("ledger");
    std::fs::write(&ledger, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&ledger)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    serve_approvals(&host, &module, &clock, &store, &failure, None).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;

    let root = dir.path().join("root");
    std::fs::create_dir_all(&root)?;
    let base = registered_policy(&proxy, &root, false).await?;
    let old: PolicyId = proxy
        .call(names::methods::REGISTER_POLICY, (base.clone(),))
        .await?;
    let same: PolicyId = proxy
        .call(names::methods::REGISTER_POLICY, (base.clone(),))
        .await?;
    assert_eq!(old, same);

    // The review is only ever requested when the replacement widens.
    let wide = registered_policy(&proxy, &root, true).await?;
    let SupersedePolicyResponse::ReviewRequired { review, widenings } =
        supersede(&proxy, &old, &wide, None).await?
    else {
        return Err("widening change activated without review".into());
    };
    assert!(widenings.iter().any(|w| w.kind == WideningKind::Judge));
    let info: ScopedPolicyInfo = proxy
        .call(names::methods::SCOPED_POLICY_INFO, (old.clone(),))
        .await?;
    assert!(
        !info.superseded,
        "an unapproved widening must leave the old policy active"
    );

    // Unapproved or foreign approvals cannot activate it.
    let pending: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (EvaluateApprovalRequest2 {
                scope_id: "a".repeat(32),
                request: review.clone(),
                ttl_ms: None,
                summary: "policy change".into(),
                audit: audit(1),
            },),
        )
        .await?;
    // The fixture's reentrant human approves the first prompt; the policy change was
    // parked for that human rather than allowed by Evaluate.
    assert_eq!(pending.record.state, ApprovalLifecycle2::Approved);
    assert_eq!(pending.record.tool_name, POLICY_CHANGE_TOOL);
    assert!(pending.record.external_effect);
    let claim = |sequence| PolicyChangeApproval {
        scope_id: "a".repeat(32),
        request_id: pending.record.request_id.clone(),
        audit: audit(sequence),
    };
    let mut bogus = claim(3);
    bogus.request_id = "f".repeat(32);
    assert!(supersede(&proxy, &old, &wide, Some(bogus)).await.is_err());
    let still: ScopedPolicyInfo = proxy
        .call(names::methods::SCOPED_POLICY_INFO, (old.clone(),))
        .await?;
    assert!(
        !still.superseded,
        "a failed approval must leave the old policy active"
    );
    // The approval is bound to the exact replacement, not to any change.
    let other = registered_policy(&proxy, &root, true).await?;
    let mut other = other;
    other.settings.auto_origins.push(Origin::Cron);
    assert!(
        supersede(&proxy, &old, &other, Some(claim(3)))
            .await
            .is_err()
    );
    let SupersedePolicyResponse::Activated {
        policy_id,
        policy_generation,
    } = supersede(&proxy, &old, &wide, Some(claim(3))).await?
    else {
        return Err("approved change did not activate".into());
    };
    assert_eq!(policy_generation, 2);
    let old_info: ScopedPolicyInfo = proxy
        .call(names::methods::SCOPED_POLICY_INFO, (old.clone(),))
        .await?;
    assert!(old_info.superseded);
    let new_info: ScopedPolicyInfo = proxy
        .call(names::methods::SCOPED_POLICY_INFO, (policy_id,))
        .await?;
    assert!(new_info.settings.judge_enabled && !new_info.superseded);
    // Replaying the consumed approval cannot widen again.
    assert!(
        supersede(&proxy, &old, &wide, Some(claim(4)))
            .await
            .is_err()
    );
    broker.abort();
    Ok(())
}
#[tokio::test]
async fn narrowing_policy_change_activates_without_review_and_scoped_calls_follow_it()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let server = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let mut service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    );
    service.signals = Some(server.clone());
    server
        .serve_at(names::OBJECT_PATH.try_into()?, service)
        .await?;
    server.request_name(names::INTERFACE).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE)?;
    let mut base = registered_policy(&proxy, dir.path(), true).await?;
    base.subject_scope.agent = "agent-narrow".into();
    let old: PolicyId = proxy
        .call(names::methods::REGISTER_POLICY, (base.clone(),))
        .await?;
    let mut narrow = base.clone();
    narrow.settings.privacy = PrivacyMode::LocalOnly;
    let mut caller = change_caller();
    caller.agent = "agent-narrow".into();
    let request = |next: &RegisteredPolicy| SupersedePolicyRequest {
        caller: caller.clone(),
        previous: old.clone(),
        next: next.clone(),
        approval: None,
    };
    let SupersedePolicyResponse::Activated {
        policy_id,
        policy_generation,
    } = proxy
        .call(names::methods::SUPERSEDE_POLICY, (request(&narrow),))
        .await?
    else {
        return Err("narrowing change required review".into());
    };
    assert_eq!(policy_generation, 2);
    let scoped = |id: &PolicyId| ScopedEvaluateRequest {
        policy_id: id.clone(),
        caller: caller.clone(),
        call: ToolCall {
            tool: "local_diagnostic".into(),
            arguments_json: "{}".into(),
            checks: vec![Check::LocalDiagnostic {}],
        },
    };
    let now: ScopedDecision = proxy
        .call(names::methods::EVALUATE_SCOPED, (scoped(&policy_id),))
        .await?;
    assert_eq!(now.decision.verdict, Verdict::Allow);
    assert_eq!(now.policy_generation, 2);
    let retired: ScopedDecision = proxy
        .call(names::methods::EVALUATE_SCOPED, (scoped(&old),))
        .await?;
    assert_eq!(
        retired.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    let checked: ScopedCheckResponse = proxy
        .call(
            names::methods::CHECK_SCOPED,
            (ScopedCheckRequest {
                policy_id: policy_id.clone(),
                caller: caller.clone(),
                checks: vec![Check::LocalDiagnostic {}],
            },),
        )
        .await?;
    assert_eq!(checked.decisions[0].verdict, Verdict::Allow);
    assert_eq!(checked.fingerprint.len(), 64);
    // A different agent cannot use another subject's policy id.
    let mut foreign = scoped(&policy_id);
    foreign.caller.agent = "someone-else".into();
    let denied: ScopedDecision = proxy
        .call(names::methods::EVALUATE_SCOPED, (foreign,))
        .await?;
    assert_eq!(
        denied.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert!(info.scoped_policies >= 1);
    assert!(!info.callbacks.approvals && !info.callbacks.audit && !info.callbacks.judge);
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn automatic_approval_cannot_authorize_a_widening_policy_change()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let ledger = dir.path().join("ledger");
    std::fs::write(&ledger, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&ledger)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let failure = Arc::new(AtomicBool::new(false));
    let (mut config, audit_config) = settings();
    config.scopes[0].auto_approve_all = true;
    serve_approvals_with(
        &host,
        &module,
        &clock,
        &store,
        &failure,
        None,
        (config, audit_config),
    )
    .await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root)?;
    // The registry is process-wide, so this test owns a distinct subject.
    let mut base = registered_policy(&proxy, &root, false).await?;
    base.subject_scope.workspace = "workspace-auto".into();
    let old: PolicyId = proxy.call(names::methods::REGISTER_POLICY, (base,)).await?;
    let mut wide = registered_policy(&proxy, &root, true).await?;
    wide.subject_scope.workspace = "workspace-auto".into();
    let SupersedePolicyResponse::ReviewRequired { review, .. } =
        supersede(&proxy, &old, &wide, None).await?
    else {
        return Err("widening change activated without review".into());
    };
    let approved: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (EvaluateApprovalRequest2 {
                scope_id: "a".repeat(32),
                request: review,
                ttl_ms: None,
                summary: "policy change".into(),
                audit: audit(1),
            },),
        )
        .await?;
    // The configuration approves automatically, which is not a human decision.
    assert_eq!(approved.record.state, ApprovalLifecycle2::Approved);
    assert_eq!(
        approved.record.attribution.as_deref(),
        Some("auto:host-policy")
    );
    let claim = PolicyChangeApproval {
        scope_id: "a".repeat(32),
        request_id: approved.record.request_id,
        audit: audit(2),
    };
    assert!(supersede(&proxy, &old, &wide, Some(claim)).await.is_err());
    let info: ScopedPolicyInfo = proxy
        .call(names::methods::SCOPED_POLICY_INFO, (old,))
        .await?;
    assert!(!info.superseded);
    broker.abort();
    Ok(())
}
#[path = "adapter_scope_tests.rs"]
mod adapter_scope_tests;

#[path = "adapter_gaps_tests.rs"]
mod gaps_tests;
