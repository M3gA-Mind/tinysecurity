//! Contract 1.22 policy and egress gap members, through the service's real dispatch.
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn service() -> std::result::Result<PolicyService, Box<dyn std::error::Error>> {
    Ok(service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    ))
}

async fn call<A: serde::Serialize, R: serde::de::DeserializeOwned>(
    service: &PolicyService,
    method: &str,
    args: A,
) -> std::result::Result<R, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(
        service
            .call(&method.parse()?, serde_json::to_value((args,))?)
            .await?,
    )?)
}

fn scope(root: &std::path::Path) -> PathPolicy {
    PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: root.join("state"),
        action_dir: root.join("work"),
        home_dir: None,
        forbidden_paths: vec![],
        trusted_roots: vec![PathTrustedRoot {
            path: root.join("work"),
            access: PathAccess::ReadWrite,
        }],
        reserved_paths: vec![PathReservation {
            path: root.join("work/reserved"),
            children_only: false,
            exceptions: vec![],
        }],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    }
}

const KINDS: [PathCheckKind; 7] = [
    PathCheckKind::StringAllowed,
    PathCheckKind::ResolvedRead,
    PathCheckKind::ResolvedWrite,
    PathCheckKind::Internal,
    PathCheckKind::TrustedRead,
    PathCheckKind::TrustedWrite,
    PathCheckKind::Protected,
];

#[tokio::test]
async fn path_batch_equals_per_path_check_path_answers() -> TestResult {
    let service = service()?;
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    for sub in ["work/reserved", "state", "outside"] {
        std::fs::create_dir_all(root.join(sub))?;
    }
    std::fs::write(root.join("work/a.txt"), "x")?;
    std::fs::write(root.join("outside/secret.txt"), "x")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("outside"), root.join("work/escape"))?;
    let id: PathPolicyId =
        call(&service, names::methods::REGISTER_PATH_POLICY, scope(&root)).await?;
    let mut paths: Vec<PathBuf> = vec![
        root.join("work/a.txt"),
        root.join("work/new/file.txt"),
        root.join("work/reserved/inner"),
        root.join("work/escape/secret.txt"),
        root.join("outside/secret.txt"),
        root.join("work/../outside"),
        "/etc/passwd".into(),
        "/home/u/.ssh/id_rsa".into(),
        "relative.txt".into(),
        root.join("state/db"),
    ];
    paths.push(root.join("work/a.txt"));
    for kind in KINDS {
        let batch: PathBatchResponse2 = call(
            &service,
            names::methods::CHECK_PATHS2,
            PathBatchRequest2 {
                policy_id: id.clone(),
                kind,
                paths: paths.clone(),
            },
        )
        .await?;
        assert_eq!(batch.allowed.len(), paths.len());
        for (path, got) in paths.iter().zip(&batch.allowed) {
            let single: bool = call(
                &service,
                names::methods::CHECK_PATH,
                PathCheckRequest {
                    policy_id: id.clone(),
                    path: path.clone(),
                    kind,
                },
            )
            .await?;
            assert_eq!(*got, single, "{kind:?} {}", path.display());
        }
    }
    // Sanity: the fixture really separates allowed from refused answers.
    let trusted: PathBatchResponse2 = call(
        &service,
        names::methods::CHECK_PATHS2,
        PathBatchRequest2 {
            policy_id: id,
            kind: PathCheckKind::TrustedWrite,
            paths: vec![root.join("work/a.txt"), "/etc/passwd".into()],
        },
    )
    .await?;
    assert_eq!(trusted.allowed, vec![true, false]);
    Ok(())
}

#[tokio::test]
async fn path_batch_fails_closed_on_unknown_scope_and_oversize() -> TestResult {
    let service = service()?;
    let unknown = PathBatchRequest2 {
        policy_id: PathPolicyId("unknown".into()),
        kind: PathCheckKind::Protected,
        paths: vec!["/etc".into()],
    };
    assert!(
        call::<_, PathBatchResponse2>(&service, names::methods::CHECK_PATHS2, unknown)
            .await
            .is_err()
    );
    let dir = tempfile::tempdir()?;
    let id: PathPolicyId = call(
        &service,
        names::methods::REGISTER_PATH_POLICY,
        scope(dir.path()),
    )
    .await?;
    let too_many = PathBatchRequest2 {
        policy_id: id.clone(),
        kind: PathCheckKind::Protected,
        paths: vec!["/etc".into(); MAX_PATH_BATCH + 1],
    };
    assert!(
        call::<_, PathBatchResponse2>(&service, names::methods::CHECK_PATHS2, too_many)
            .await
            .is_err()
    );
    let empty: PathBatchResponse2 = call(
        &service,
        names::methods::CHECK_PATHS2,
        PathBatchRequest2 {
            policy_id: id,
            kind: PathCheckKind::Protected,
            paths: vec![],
        },
    )
    .await?;
    assert_eq!(empty.allowed, Vec::<bool>::new());
    Ok(())
}

#[tokio::test]
async fn protected_path_and_floor_need_no_scope_and_agree() -> TestResult {
    let service = service()?;
    let paths: Vec<PathBuf> = vec![
        "/home/u/.ssh/id_rsa".into(),
        "/etc/shadow".into(),
        "/usr/lib/x".into(),
        "/work/../x".into(),
        "C:\\Windows\\System32".into(),
        "/home/u/project/src/lib.rs".into(),
        "relative/ok".into(),
    ];
    let answer: ProtectedPathResponse2 = call(
        &service,
        names::methods::PROTECTED_PATH2,
        ProtectedPathRequest2 {
            paths: paths.clone(),
        },
    )
    .await?;
    assert_eq!(
        answer.protected,
        vec![true, true, true, true, true, false, false]
    );
    let oversize = ProtectedPathRequest2 {
        paths: vec!["/a".into(); MAX_PATH_BATCH + 1],
    };
    assert!(
        call::<_, ProtectedPathResponse2>(&service, names::methods::PROTECTED_PATH2, oversize)
            .await
            .is_err()
    );

    let floor: ProtectedFloor2 = serde_json::from_value(
        service
            .call(
                &names::methods::PROTECTED_FLOOR2.parse()?,
                serde_json::json!([]),
            )
            .await?,
    )?;
    assert!(floor.components.iter().any(|c| c == ".ssh"));
    assert!(floor.files.iter().any(|c| c == ".netrc"));
    assert!(floor.prefixes.iter().any(|c| c == "c:/windows"));
    let probes: Vec<PathBuf> = floor
        .components
        .iter()
        .chain(&floor.files)
        .map(|name| PathBuf::from(format!("/home/u/{name}/x")))
        .chain(
            floor
                .pairs
                .iter()
                .map(|[a, b]| PathBuf::from(format!("/home/u/{a}/{b}"))),
        )
        .chain(
            floor
                .prefixes
                .iter()
                .map(|p| PathBuf::from(format!("{p}/x"))),
        )
        .collect();
    let every: ProtectedPathResponse2 = call(
        &service,
        names::methods::PROTECTED_PATH2,
        ProtectedPathRequest2 {
            paths: probes.clone(),
        },
    )
    .await?;
    assert!(!probes.is_empty() && every.protected.iter().all(|p| *p));
    Ok(())
}

#[tokio::test]
async fn host_action_class_is_informational_and_matches_the_contract() -> TestResult {
    let service = service()?;
    for permission in [
        ToolPermission::None,
        ToolPermission::ReadOnly,
        ToolPermission::Write,
        ToolPermission::Execute,
        ToolPermission::Dangerous,
    ] {
        for external_effect in [false, true] {
            let request = HostActionClassRequest2 {
                permission,
                external_effect,
            };
            let want = request.class();
            let got: HostActionClassResponse2 =
                call(&service, names::methods::CLASSIFY_HOST_ACTION2, request).await?;
            assert_eq!(got.class, want);
        }
    }
    Ok(())
}

fn budget_policy(
    enabled: bool,
    autonomy: CommandAutonomy,
    per_hour: u32,
) -> std::result::Result<CommandPolicy, Box<dyn std::error::Error>> {
    Ok(CommandPolicy {
        enabled,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        autonomy,
        allowed_commands: vec!["echo".into()],
        max_actions_per_hour: per_hour,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir()?,
        home_dir: None,
    })
}

async fn register(
    service: &PolicyService,
    policy: CommandPolicy,
) -> std::result::Result<CommandPolicyId, Box<dyn std::error::Error>> {
    call(service, names::methods::REGISTER_COMMAND_POLICY, policy).await
}

async fn budget(
    service: &PolicyService,
    method: &str,
    id: &CommandPolicyId,
) -> std::result::Result<BudgetDecision2, Box<dyn std::error::Error>> {
    call(
        service,
        method,
        BudgetRequest2 {
            command_policy: id.clone(),
        },
    )
    .await
}

#[tokio::test]
async fn peek_never_spends_and_spend_exhausts_the_shared_ledger() -> TestResult {
    let service = service()?;
    let id = register(&service, budget_policy(true, CommandAutonomy::Full, 2)?).await?;
    for _ in 0..5 {
        assert_eq!(
            budget(&service, names::methods::PEEK_BUDGET2, &id).await?,
            BudgetDecision2::Allow
        );
    }
    assert_eq!(
        budget(&service, names::methods::SPEND_ACTION2, &id).await?,
        BudgetDecision2::Allow
    );
    // CheckCommand spends from the very same ledger.
    let shell: CommandDecision = call(
        &service,
        names::methods::CHECK_COMMAND,
        CommandRequest {
            policy_id: id.clone(),
            command: "echo hi".into(),
            declared_class: None,
        },
    )
    .await?;
    assert_eq!(shell.gate, CommandGate::Allow);
    let spent = BudgetDecision2::RateLimited { max_per_hour: 2 };
    assert_eq!(
        budget(&service, names::methods::PEEK_BUDGET2, &id).await?,
        spent
    );
    assert_eq!(
        budget(&service, names::methods::SPEND_ACTION2, &id).await?,
        spent
    );
    Ok(())
}

#[tokio::test]
async fn host_action_check_and_spend_action_share_one_ledger() -> TestResult {
    let service = service()?;
    let id = register(&service, budget_policy(true, CommandAutonomy::Full, 1)?).await?;
    let evaluate = EvaluateRequest {
        caller: CallerContext {
            agent: "a".into(),
            call_id: "c".into(),
            tier: AccessTier::Full,
            ..Default::default()
        },
        call: ToolCall {
            tool: "write_file".into(),
            arguments_json: "{}".into(),
            checks: vec![Check::HostAction {
                permission: ToolPermission::Write,
                external_effect: false,
                spend: true,
                command_policy: Some(id.clone()),
            }],
        },
    };
    let decision: Decision = call(&service, names::methods::EVALUATE, evaluate).await?;
    assert_eq!(decision.verdict, Verdict::Allow);
    assert_eq!(
        budget(&service, names::methods::SPEND_ACTION2, &id).await?,
        BudgetDecision2::RateLimited { max_per_hour: 1 }
    );
    Ok(())
}

#[tokio::test]
async fn read_only_tier_refuses_before_spending() -> TestResult {
    let service = service()?;
    let id = register(&service, budget_policy(true, CommandAutonomy::ReadOnly, 1)?).await?;
    for method in [
        names::methods::SPEND_ACTION2,
        names::methods::PEEK_BUDGET2,
        names::methods::SPEND_ACTION2,
    ] {
        assert_eq!(
            budget(&service, method, &id).await?,
            BudgetDecision2::ReadOnlyMode
        );
    }
    // Switching nothing else: the ledger is still empty, so a Full scope sharing
    // the budget would have allowed it. Prove nothing was reserved on this scope.
    let handle = service
        .commands
        .lock()
        .map_err(|_| "lock")?
        .get_owned(&id)?;
    assert!(!handle.exhausted());
    Ok(())
}

#[tokio::test]
async fn disabled_scope_is_inert_and_unknown_scope_is_an_error() -> TestResult {
    let service = service()?;
    let id = register(
        &service,
        budget_policy(false, CommandAutonomy::ReadOnly, 1)?,
    )
    .await?;
    for _ in 0..4 {
        assert_eq!(
            budget(&service, names::methods::SPEND_ACTION2, &id).await?,
            BudgetDecision2::Allow
        );
        assert_eq!(
            budget(&service, names::methods::PEEK_BUDGET2, &id).await?,
            BudgetDecision2::Allow
        );
    }
    let unknown = CommandPolicyId("unknown".into());
    assert!(
        budget(&service, names::methods::SPEND_ACTION2, &unknown)
            .await
            .is_err()
    );
    assert!(
        budget(&service, names::methods::PEEK_BUDGET2, &unknown)
            .await
            .is_err()
    );
    Ok(())
}

#[derive(Debug, Default)]
struct ManualClock(AtomicU64);
impl tinysecurity::CommandClock for ManualClock {
    fn now(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}

#[tokio::test]
async fn the_hour_window_releases_and_reinit_keeps_the_ledger() -> TestResult {
    let clock = Arc::new(ManualClock::default());
    let commands = Arc::new(Mutex::new(CommandPolicyRegistry::with_clock(clock.clone())));
    let first = PolicyService {
        commands: Arc::clone(&commands),
        ..service()?
    };
    let id = register(&first, budget_policy(true, CommandAutonomy::Full, 1)?).await?;
    assert_eq!(
        budget(&first, names::methods::SPEND_ACTION2, &id).await?,
        BudgetDecision2::Allow
    );
    // A re-initialised module keeps the scope registry and therefore the ledger.
    let reinit = PolicyService {
        commands,
        ..service()?
    };
    let limited = BudgetDecision2::RateLimited { max_per_hour: 1 };
    assert_eq!(
        budget(&reinit, names::methods::PEEK_BUDGET2, &id).await?,
        limited
    );
    clock.0.store(3599, Ordering::SeqCst);
    assert_eq!(
        budget(&reinit, names::methods::SPEND_ACTION2, &id).await?,
        limited
    );
    clock.0.store(3600, Ordering::SeqCst);
    assert_eq!(
        budget(&reinit, names::methods::PEEK_BUDGET2, &id).await?,
        BudgetDecision2::Allow
    );
    assert_eq!(
        budget(&reinit, names::methods::SPEND_ACTION2, &id).await?,
        BudgetDecision2::Allow
    );
    assert_eq!(
        budget(&reinit, names::methods::PEEK_BUDGET2, &id).await?,
        limited
    );
    Ok(())
}

fn privacy(
    mode: PrivacyMode,
    class: PrivacyDataClass2,
    risk: Option<PrivacyRisk2>,
) -> PrivacyCheckRequest2 {
    PrivacyCheckRequest2 {
        privacy: mode,
        external: true,
        class,
        destination_label: "inference".into(),
        risk,
    }
}

#[tokio::test]
async fn privacy_check_decides_and_reports_the_live_generation() -> TestResult {
    let service = service()?;
    let info: PolicyInfo = service
        .call(&names::methods::POLICY_INFO.parse()?, serde_json::json!([]))
        .await
        .map(serde_json::from_value)??;
    let denied: PrivacyCheckResponse2 = call(
        &service,
        names::methods::PRIVACY_CHECK2,
        privacy(PrivacyMode::LocalOnly, PrivacyDataClass2::UserContent, None),
    )
    .await?;
    assert_eq!(
        denied.decision,
        Decision {
            generation: info.generation,
            verdict: Verdict::Deny {
                reason: DenialReason::Privacy
            },
            cacheable: false,
        }
    );
    let allowed: PrivacyCheckResponse2 = call(
        &service,
        names::methods::PRIVACY_CHECK2,
        privacy(
            PrivacyMode::Sensitive,
            PrivacyDataClass2::ControlPlane,
            None,
        ),
    )
    .await?;
    assert_eq!(allowed.decision.verdict, Verdict::Allow);
    assert!(!allowed.decision.cacheable);
    let mut bad = privacy(PrivacyMode::Standard, PrivacyDataClass2::Metadata, None);
    bad.destination_label = "x".repeat(MAX_PRIVACY_LABEL_BYTES + 1);
    assert!(
        call::<_, PrivacyCheckResponse2>(&service, names::methods::PRIVACY_CHECK2, bad)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn provider_endpoint_classification_is_locality_only_not_lan_reachability() -> TestResult {
    let service = service()?;
    for (host, expected) in [
        (
            "localhost",
            tinysecurity_bus::ProviderEndpointLocality2::OnDevice,
        ),
        (
            "[::ffff:127.0.0.1]",
            tinysecurity_bus::ProviderEndpointLocality2::OnDevice,
        ),
        (
            "192.168.1.12",
            tinysecurity_bus::ProviderEndpointLocality2::External,
        ),
        (
            "[fd00::12]",
            tinysecurity_bus::ProviderEndpointLocality2::External,
        ),
    ] {
        let response: tinysecurity_bus::ProviderEndpointResponse2 = call(
            &service,
            names::methods::CLASSIFY_PROVIDER_ENDPOINT2,
            tinysecurity_bus::ProviderEndpointRequest2 { host: host.into() },
        )
        .await?;
        assert_eq!(response.locality, expected, "{host}");
        let mut privacy_request =
            privacy(PrivacyMode::LocalOnly, PrivacyDataClass2::UserContent, None);
        privacy_request.external =
            expected == tinysecurity_bus::ProviderEndpointLocality2::External;
        let privacy_response: PrivacyCheckResponse2 =
            call(&service, names::methods::PRIVACY_CHECK2, privacy_request).await?;
        let expected_verdict = if expected == tinysecurity_bus::ProviderEndpointLocality2::OnDevice
        {
            Verdict::Allow
        } else {
            Verdict::Deny {
                reason: DenialReason::Privacy,
            }
        };
        assert_eq!(
            privacy_response.decision.verdict, expected_verdict,
            "{host}"
        );
    }
    assert!(
        call::<_, tinysecurity_bus::ProviderEndpointResponse2>(
            &service,
            names::methods::CLASSIFY_PROVIDER_ENDPOINT2,
            tinysecurity_bus::ProviderEndpointRequest2 {
                host: "bad host".into(),
            },
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn host_action_class_does_not_depend_on_audit_configuration() -> TestResult {
    // Without a required audit configured the members answer; the informational
    // classification never depends on audit configuration.
    let service = service()?;
    assert!(!service.audit_required());
    let class: HostActionClassResponse2 = call(
        &service,
        names::methods::CLASSIFY_HOST_ACTION2,
        HostActionClassRequest2 {
            permission: ToolPermission::Write,
            external_effect: true,
        },
    )
    .await?;
    assert_eq!(class.class, CommandClass::Network);
    Ok(())
}

#[test]
fn all_seven_members_are_advertised_by_the_contract() {
    for name in [
        names::methods::CHECK_PATHS2,
        names::methods::PROTECTED_PATH2,
        names::methods::PROTECTED_FLOOR2,
        names::methods::SPEND_ACTION2,
        names::methods::PEEK_BUDGET2,
        names::methods::CLASSIFY_HOST_ACTION2,
        names::methods::PRIVACY_CHECK2,
    ] {
        assert!(names::METHODS.contains(&name), "{name}");
    }
}
