//! Runtime approval scopes through the real bus, authenticated peer and store callbacks.
use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

const TENANT: &str = "7777777777777777777777777777777b";
const STREAM: &str = "8888888888888888888888888888888c";

fn tenant_subject() -> SubjectScope {
    SubjectScope {
        user: "tenant-user".into(),
        workspace: "tenant-workspace".into(),
        agent: "tenant-agent".into(),
    }
}
fn registration(grants: ApprovalGrants2) -> RegisterApprovalScopeRequest2 {
    RegisterApprovalScopeRequest2 {
        scope: ApprovalScope2 {
            scope_id: TENANT.into(),
            subject: tenant_subject(),
            policy_ref: "tenant-policy".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        },
        grants,
        audit_stream_id: STREAM.into(),
        report_handle: true,
    }
}
fn tenant_begin(instance: u64, sequence: u64, tool: &str) -> EvaluateApprovalRequest2 {
    let mut request = begin(instance, sequence);
    request.scope_id = TENANT.into();
    request.request.caller.agent = "tenant-agent".into();
    request.request.call.tool = tool.into();
    if tool != "local_diagnostic" {
        request.request.call.checks = vec![Check::HostTool {}];
    }
    request
}
fn tool_grants(tool: &str) -> ApprovalGrants2 {
    ApprovalGrants2 {
        tools: vec![tool.into()],
        flows: vec![],
    }
}

/// Serve the module and host callbacks for the tenant subject only; the init scope
/// exists but the fixture store refuses it, so every success below used the runtime scope.
async fn serve(
    host: &Connection,
    module: &Connection,
    store: &Arc<Mutex<store::DiskStore>>,
    sink: &Arc<AtomicBool>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (config, mut audit_config) = settings();
    audit_config.scope = tenant_subject();
    let host_peer = host.unique_name().ok_or("host peer")?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let redactor = tinysecurity::Redactor::new(&RedactorConfig { secrets: vec![] })?;
    let clients = crate::approval_callbacks::ApprovalClients::new_for_test(
        module,
        Some(host_peer.as_str()),
        &config,
        &audit_config,
        &redactor,
    )?;
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let engine = Arc::new(tinysecurity::approval::Engine::new(
        config,
        Arc::new(clients),
        clock,
        redactor,
    )?);
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
    let scope = tinysecurity::approval::scope_handle(&tenant_subject())?;
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
                reentrant: Arc::new(AtomicBool::new(false)),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            },
        )
        .await?;
    }
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Sink {
                fail: Arc::clone(sink),
            },
            crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
        ),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn runtime_scope_registers_grants_replaces_and_retires_through_the_authenticated_bus()
-> TestResult {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let stranger = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    serve(&host, &module, &store, &Arc::new(AtomicBool::new(false))).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;

    // Unregistered identity and any non-host peer deny.
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(
                names::methods::EVALUATE_APPROVAL2,
                (tenant_begin(1, 1, "local_diagnostic"),)
            )
            .await
            .is_err()
    );
    let outsider = stranger.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    assert!(
        outsider
            .call::<ApprovalScopeReceipt2>(
                names::methods::REGISTER_APPROVAL_SCOPE2,
                (registration(tool_grants("shell")),)
            )
            .await
            .is_err()
    );

    let created: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::REGISTER_APPROVAL_SCOPE2,
            (registration(tool_grants("shell")),),
        )
        .await?;
    assert_eq!(created.outcome, ApprovalScopeOutcome2::Created);
    assert_eq!(created.live_scopes, 2);
    // The receipt names the handle the host callbacks will carry for this subject,
    // so a host never has to reproduce the derivation.
    let handle = tinysecurity::approval::scope_handle(&tenant_subject())?;
    assert_eq!(created.scope_handle, Some(handle));

    // Required approval takes precedence over the registered tool allowlist.
    let granted: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (tenant_begin(2, 3, "shell"),),
        )
        .await?;
    assert!(matches!(
        granted.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(granted.record.clone(), ApprovalChoice2::Once)?;
    let granted = proxy
        .call::<ApprovalRow2>(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: TENANT.into(),
                request_id: granted.record.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(4),
            },),
        )
        .await?;
    assert_eq!(granted.state, ApprovalLifecycle2::Approved);
    // Other tools also require the tenant's own human.
    let pending: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (tenant_begin(3, 5, "local_diagnostic"),),
        )
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(pending.record.clone(), ApprovalChoice2::Once)?;
    let decided: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: TENANT.into(),
                request_id: pending.record.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(6),
            },),
        )
        .await?;
    assert_eq!(decided.state, ApprovalLifecycle2::Approved);

    replace_then_retire(&proxy).await?;
    assert!(!String::from_utf8_lossy(&std::fs::read(path)?).contains("private-secret"));
    broker.abort();
    Ok(())
}

async fn replace_then_retire(proxy: &tinybus::Proxy) -> TestResult {
    // Replacing the grants takes effect for the next call.
    let replaced: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::REPLACE_APPROVAL_SCOPE2,
            (registration(ApprovalGrants2::default()),),
        )
        .await?;
    assert_eq!(replaced.outcome, ApprovalScopeOutcome2::Replaced);
    assert_eq!(
        replaced.scope_handle,
        Some(tinysecurity::approval::scope_handle(&tenant_subject())?)
    );
    // A registration that does not ask (an older host) gets the 1.17 receipt.
    let mut quiet = registration(ApprovalGrants2::default());
    quiet.report_handle = false;
    let unchanged: ApprovalScopeReceipt2 = proxy
        .call(names::methods::REPLACE_APPROVAL_SCOPE2, (quiet,))
        .await?;
    assert_eq!(unchanged.outcome, ApprovalScopeOutcome2::Unchanged);
    assert!(unchanged.scope_handle.is_none());
    let after: EvaluateApprovalResponse2 = proxy
        .call(
            names::methods::EVALUATE_APPROVAL2,
            (tenant_begin(4, 8, "shell"),),
        )
        .await?;
    assert!(matches!(
        after.decision.verdict,
        Verdict::RequireApproval { .. }
    ));

    // Retiring closes the identity for good.
    let retired: ApprovalScopeReceipt2 = proxy
        .call(
            names::methods::RETIRE_APPROVAL_SCOPE2,
            (RetireApprovalScopeRequest2 {
                scope_id: TENANT.into(),
            },),
        )
        .await?;
    assert_eq!(retired.outcome, ApprovalScopeOutcome2::Retired);
    assert!(
        retired.scope_handle.is_none(),
        "a retirement reports no handle"
    );
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(
                names::methods::EVALUATE_APPROVAL2,
                (tenant_begin(5, 10, "shell"),)
            )
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<ApprovalScopeReceipt2>(
                names::methods::RETIRE_APPROVAL_SCOPE2,
                (RetireApprovalScopeRequest2 {
                    scope_id: TENANT.into(),
                },)
            )
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn approval_scope_members_fail_closed_without_an_approval_engine() -> TestResult {
    let service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    );
    assert!(
        service
            .register_approval_scope2(registration(ApprovalGrants2::default()))
            .await
            .is_err()
    );
    assert!(
        service
            .replace_approval_scope2(registration(ApprovalGrants2::default()))
            .await
            .is_err()
    );
    assert!(
        service
            .retire_approval_scope2(RetireApprovalScopeRequest2 {
                scope_id: TENANT.into()
            })
            .await
            .is_err()
    );
    Ok(())
}

/// Configuring approvals must not take the filesystem and command members away: they
/// are separate permissions that never ask a human, so only a required audit (which
/// needs a durable event per permission) refuses them.
#[tokio::test]
async fn configured_approvals_keep_path_and_command_members_available() -> TestResult {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    std::fs::write(&path, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&path)?));
    serve(&host, &module, &store, &Arc::new(AtomicBool::new(false))).await?;
    let module_peer = module.unique_name().ok_or("module peer")?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;

    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("file"), "x")?;
    let id: PathPolicyId = proxy
        .call(
            names::methods::REGISTER_PATH_POLICY,
            (super::super::fixture_policy(root.path()),),
        )
        .await?;
    let read: PathValidationResult = proxy
        .call(
            names::methods::VALIDATE_PATH,
            (PathValidationRequest {
                policy_id: id.clone(),
                path: "file".into(),
            },),
        )
        .await?;
    assert!(matches!(read, PathValidationResult::Allowed { .. }));
    let outside: PathValidationResult = proxy
        .call(
            names::methods::VALIDATE_PATH,
            (PathValidationRequest {
                policy_id: id.clone(),
                path: "../outside".into(),
            },),
        )
        .await?;
    assert!(matches!(outside, PathValidationResult::Denied { .. }));
    let parent: PathValidationResult = proxy
        .call(
            names::methods::VALIDATE_PARENT,
            (PathValidationRequest {
                policy_id: id.clone(),
                path: "new-file".into(),
            },),
        )
        .await?;
    assert!(matches!(parent, PathValidationResult::Allowed { .. }));
    let checked: bool = proxy
        .call(
            names::methods::CHECK_PATH,
            (PathCheckRequest {
                policy_id: id,
                path: root.path().join("file"),
                kind: PathCheckKind::Protected,
            },),
        )
        .await?;
    assert!(!checked);

    let command: CommandPolicyId = proxy
        .call(
            names::methods::REGISTER_COMMAND_POLICY,
            (super::super::command_fixture()?,),
        )
        .await?;
    let decision: CommandDecision = proxy
        .call(
            names::methods::CHECK_COMMAND,
            (CommandRequest {
                policy_id: command,
                command: "pwd".into(),
                declared_class: None,
            },),
        )
        .await?;
    assert_eq!(decision.gate, CommandGate::Allow);
    broker.abort();
    Ok(())
}
