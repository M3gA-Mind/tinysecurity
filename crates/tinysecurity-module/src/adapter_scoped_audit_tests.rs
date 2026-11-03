//! Audited registered-policy members: required audit gates scoped permission.
use super::*;

const AGENT: &str = "scoped-audit-agent";

fn caller(call_id: &str) -> CallerContext {
    CallerContext {
        agent: AGENT.into(),
        call_id: call_id.into(),
        thread: Some("thread".into()),
        tier: AccessTier::Full,
        ..Default::default()
    }
}

fn correlation(id: char, tail: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: id.to_string().repeat(32),
        expected_tail: tail,
        generation: 1,
    }
}

async fn register(
    service: &PolicyService,
    root: &std::path::Path,
    agent: &str,
) -> std::result::Result<PolicyId, Box<dyn std::error::Error>> {
    let path_policy_id = service
        .register_path_policy(PathPolicy {
            enabled: false,
            workspace_only: false,
            workspace_dir: root.into(),
            action_dir: root.into(),
            home_dir: None,
            forbidden_paths: vec![],
            trusted_roots: vec![],
            reserved_paths: vec![],
            reserved_prefixes: vec![],
            readonly_paths: vec![],
            reserved_names: vec![],
        })
        .await?;
    let command_policy_id = service
        .register_command_policy(CommandPolicy {
            action_dir: root.into(),
            ..command_fixture()?
        })
        .await?;
    let registered = RegisteredPolicy {
        path_policy_id,
        settings: PolicySettings {
            policy: PolicyConfig {
                enabled: false,
                action_dir: root.display().to_string(),
                workspace_dir: root.display().to_string(),
                allowed_commands: vec![],
                forbidden_paths: vec![],
            },
            privacy: PrivacyMode::Standard,
            egress_hosts: vec![],
            command_classes: vec![],
            auto_origins: vec![],
            judge_enabled: false,
        },
        tool_rules: vec![],
        command_policy_id,
        subject_scope: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: agent.into(),
        },
    };
    Ok(service.register_policy(registered).await?)
}

fn evaluate(id: &PolicyId, audit: AuditCorrelation2) -> EvaluateScopedAuditedRequest {
    AuditedRequest2 {
        request: ScopedEvaluateRequest {
            policy_id: id.clone(),
            caller: caller("call-1"),
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: "{\"token\":\"first-private-secret\"}".into(),
                checks: vec![Check::LocalDiagnostic {}],
            },
        },
        audit,
    }
}

fn check(id: &PolicyId, audit: AuditCorrelation2) -> CheckScopedAuditedRequest {
    AuditedRequest2 {
        request: ScopedCheckRequest {
            policy_id: id.clone(),
            caller: caller("call-2"),
            checks: vec![
                Check::LocalDiagnostic {},
                Check::Path {
                    path: "/etc/shadow".into(),
                    write: false,
                },
            ],
        },
        audit,
    }
}

type Rows = Arc<Mutex<std::collections::BTreeMap<String, AuditSinkRequest2>>>;

async fn verify_stale_privacy_and_unknown(
    required: &PolicyService,
    id: &PolicyId,
    rows: &Rows,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // A stale expected generation is denied before anything is appended.
    let mut stale = evaluate(id, correlation('e', 2));
    stale.audit.generation = 0;
    let stale = required.evaluate_scoped_audited(stale).await?;
    assert!(!stale.audit.permitted);
    assert!(matches!(
        stale.decision.decision.verdict,
        Verdict::Deny { .. }
    ));
    let mut stale = check(id, correlation('f', 2));
    stale.audit.generation = 0;
    assert!(!required.check_scoped_audited(stale).await?.audit.permitted);

    // The private policy id never reaches durable rows.
    let stored = serde_json::to_string(&*rows.lock().map_err(|_| "fixture rows")?)?;
    assert!(!stored.contains(&id.0) && !stored.contains("first-private-secret"));
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 2);

    // An unknown policy id is an error, not a permission.
    let unknown = PolicyId("unknown".into());
    assert!(
        required
            .evaluate_scoped_audited(evaluate(&unknown, correlation('1', 2)))
            .await
            .is_err()
    );
    assert!(
        required
            .check_scoped_audited(check(&unknown, correlation('2', 2)))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn required_audit_gates_scoped_permission_on_a_committed_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig {
        redactor: RedactorConfig {
            secrets: vec![Secret("first-private-secret".into())],
        },
        ..Default::default()
    })?));
    let dir = tempfile::tempdir()?;
    let required = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let id = register(&required, dir.path(), AGENT).await?;

    // The unbound scoped members still refuse permission under required audit.
    let unbound = required
        .evaluate_scoped(evaluate(&id, correlation('a', 0)).request)
        .await?;
    assert!(matches!(unbound.decision.verdict, Verdict::Deny { .. }));

    // No sink is reachable yet: audit is lost and the decision is denied.
    let lost = required
        .evaluate_scoped_audited(evaluate(&id, correlation('a', 0)))
        .await?;
    assert!(!lost.audit.permitted && !lost.audit.committed);
    assert!(matches!(
        lost.decision.decision.verdict,
        Verdict::Deny { .. }
    ));
    let lost = required
        .check_scoped_audited(check(&id, correlation('b', 0)))
        .await?;
    assert!(!lost.audit.permitted);
    assert!(
        lost.decision
            .decisions
            .iter()
            .all(|d| matches!(d.verdict, Verdict::Deny { .. }))
    );

    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy,
            change_generation: Arc::default(),
        },
    )
    .await?;
    let allowed = required
        .evaluate_scoped_audited(evaluate(&id, correlation('c', 0)))
        .await?;
    assert!(allowed.audit.committed && allowed.audit.permitted);
    assert_eq!(allowed.decision.decision.verdict, Verdict::Allow);
    assert!(
        !allowed.decision.decision.cacheable,
        "audited use is never reusable"
    );
    assert_eq!(allowed.decision.fingerprint.len(), 64);
    // Exact replay returns the committed evidence.
    assert_eq!(
        required
            .evaluate_scoped_audited(evaluate(&id, correlation('c', 0)))
            .await?,
        allowed
    );
    let checked = required
        .check_scoped_audited(check(&id, correlation('d', 1)))
        .await?;
    assert!(checked.audit.committed && checked.audit.permitted);
    assert_eq!(checked.decision.decisions[0].verdict, Verdict::Allow);
    assert!(matches!(
        checked.decision.decisions[1].verdict,
        Verdict::Deny { .. }
    ));
    assert!(checked.decision.decisions.iter().all(|d| !d.cacheable));

    verify_stale_privacy_and_unknown(&required, &id, &rows).await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn scoped_audited_members_need_a_configured_audit_client()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    );
    let dir = tempfile::tempdir()?;
    let id = register(&service, dir.path(), "scoped-audit-unconfigured").await?;
    assert!(
        service
            .evaluate_scoped_audited(evaluate(&id, correlation('a', 0)))
            .await
            .is_err()
    );
    assert!(
        service
            .check_scoped_audited(check(&id, correlation('b', 0)))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn required_audit_path_permission_exposes_a_result_only_after_a_durable_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let required = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let root = tempfile::tempdir()?;
    let path_policy = required
        .register_path_policy(PathPolicy {
            enabled: false,
            workspace_only: false,
            workspace_dir: root.path().into(),
            action_dir: root.path().into(),
            home_dir: None,
            forbidden_paths: vec![],
            trusted_roots: vec![],
            reserved_paths: vec![],
            reserved_prefixes: vec![],
            readonly_paths: vec![],
            reserved_names: vec![],
        })
        .await?;
    let path = PathValidationRequest {
        policy_id: path_policy,
        path: root.path().join("uploads/file").display().to_string(),
    };
    assert!(
        required.validate_parent(path.clone()).await.is_err(),
        "legacy unaudited permission must remain refused"
    );
    let request = |id, tail| AuditedRequest2 {
        request: PermissionRequest2::ValidateParent(path.clone()),
        audit: correlation(id, tail),
    };
    let lost = required.check_permission_audited2(request('a', 0)).await?;
    assert!(!lost.audit.permitted && lost.decision.is_none());
    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy,
            change_generation: Arc::default(),
        },
    )
    .await?;
    let allowed = required.check_permission_audited2(request('b', 0)).await?;
    assert!(allowed.audit.permitted && allowed.audit.committed);
    assert!(matches!(
        allowed.decision,
        Some(PermissionResult2::Path(
            PathValidationResult::Allowed { .. }
        ))
    ));
    verify_audited_native_queries(&required, root.path(), &path).await?;
    verify_audited_budget_queries(&required).await?;
    let mut stale = request('c', 8);
    stale.audit.generation = 0;
    let stale = required.check_permission_audited2(stale).await?;
    assert!(!stale.audit.permitted && stale.decision.is_none());
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 11);
    broker.abort();
    Ok(())
}

async fn verify_audited_native_queries(
    required: &PolicyService,
    root: &std::path::Path,
    path: &PathValidationRequest,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let read_path = root.join("read.txt");
    std::fs::write(&read_path, "fixture")?;
    let command_policy = required.register_command_policy(command_fixture()?).await?;
    let queries = [
        PermissionRequest2::ValidatePath(PathValidationRequest {
            policy_id: path.policy_id.clone(),
            path: read_path.display().to_string(),
        }),
        PermissionRequest2::CheckPath(PathCheckRequest {
            policy_id: path.policy_id.clone(),
            path: read_path.clone(),
            kind: PathCheckKind::ResolvedRead,
        }),
        PermissionRequest2::CheckPaths(PathBatchRequest2 {
            policy_id: path.policy_id.clone(),
            kind: PathCheckKind::ResolvedRead,
            paths: vec![read_path.clone(), root.join(".ssh/key")],
        }),
        PermissionRequest2::GateCommand(CommandRequest {
            policy_id: command_policy.clone(),
            command: "pwd".into(),
            declared_class: None,
        }),
        PermissionRequest2::PeekBudget(BudgetRequest2 { command_policy }),
        PermissionRequest2::PrivacyCheck(PrivacyCheckRequest2 {
            privacy: PrivacyMode::Standard,
            external: true,
            class: PrivacyDataClass2::Metadata,
            destination_label: "fixture".into(),
            risk: None,
        }),
        PermissionRequest2::ValidateParent(PathValidationRequest {
            policy_id: path.policy_id.clone(),
            path: root.join(".ssh/key").display().to_string(),
        }),
    ];
    for (index, query) in queries.into_iter().enumerate() {
        let tail = u64::try_from(index)? + 1;
        let result = required
            .check_permission_audited2(AuditedRequest2 {
                request: query,
                audit: AuditCorrelation2 {
                    event_id: format!("{:032x}", index + 16),
                    expected_tail: tail,
                    generation: 1,
                },
            })
            .await?;
        assert!(result.audit.permitted && result.audit.committed);
        match (index, result.decision) {
            (0, Some(PermissionResult2::Path(PathValidationResult::Allowed { .. })))
            | (1, Some(PermissionResult2::PathAllowed(true)))
            | (
                3,
                Some(PermissionResult2::Command(CommandDecision {
                    gate: CommandGate::Allow,
                    ..
                })),
            )
            | (4, Some(PermissionResult2::Budget(BudgetDecision2::Allow))) => {}
            (2, Some(PermissionResult2::Paths(result))) => {
                assert_eq!(result.allowed, [true, false]);
            }
            (5, Some(PermissionResult2::Privacy(result))) => {
                assert_eq!(result.decision.verdict, Verdict::Allow);
            }
            (6, Some(PermissionResult2::Path(PathValidationResult::Denied { category }))) => {
                assert_eq!(category, PathErrorCategory::Protected);
            }
            (_, result) => {
                return Err(format!("unexpected audited permission result: {result:?}").into());
            }
        }
    }
    Ok(())
}

async fn verify_audited_budget_queries(
    required: &PolicyService,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for (index, (enabled, autonomy, limit, expected)) in [
        (false, CommandAutonomy::Full, 1, BudgetDecision2::Allow),
        (
            true,
            CommandAutonomy::ReadOnly,
            1,
            BudgetDecision2::ReadOnlyMode,
        ),
        (
            true,
            CommandAutonomy::Full,
            0,
            BudgetDecision2::RateLimited { max_per_hour: 0 },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let command_policy = required
            .register_command_policy(CommandPolicy {
                enabled,
                autonomy,
                max_actions_per_hour: limit,
                ..command_fixture()?
            })
            .await?;
        let request = AuditedRequest2 {
            request: PermissionRequest2::PeekBudget(BudgetRequest2 { command_policy }),
            audit: AuditCorrelation2 {
                event_id: format!("{:032x}", index + 64),
                expected_tail: u64::try_from(index)? + 8,
                generation: 1,
            },
        };
        let response = required.check_permission_audited2(request.clone()).await?;
        assert!(response.audit.permitted && response.audit.committed);
        assert_eq!(response.decision, Some(PermissionResult2::Budget(expected)));
        assert_eq!(
            required.check_permission_audited2(request).await?,
            response,
            "an exact audited replay must not spend or change the budget"
        );
    }
    Ok(())
}
