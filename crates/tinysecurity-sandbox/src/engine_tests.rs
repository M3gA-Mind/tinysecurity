use super::*;
use tinysecurity_bus::{
    AuditCorrelation2, ConstraintSupport2, PathAccess, PathGrant, PathPolicy, PathTrustedRoot,
    SandboxApprovalUse2, SandboxPlanOptions2, SandboxProxy2, SandboxSource2,
};
pub(crate) fn fixture() -> std::result::Result<
    (tempfile::TempDir, SandboxScope2, SandboxPlanRequest2),
    Box<dyn std::error::Error>,
> {
    let dir = tempfile::tempdir().required()?;
    let root = dir.path().canonicalize().required()?;
    let action = root.join("action");
    let state = root.join("state");
    let home = root.join("home");
    for path in [&action, &state, &home] {
        std::fs::create_dir(path).required()?;
    }
    let subject = SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    };
    let scope = SandboxScope2 {
        approval_scope_id: None,
        scope_id: "scope".into(),
        subject: subject.clone(),
        origin: Origin::Saas,
        tier: AccessTier::Full,
        deployment: SandboxDeployment2::Saas,
        environment: SandboxSetting2::Disabled,
        agent_mode: SandboxSetting2::Disabled,
        configured: SandboxSetting2::Disabled,
        paths: PathPolicy {
            enabled: true,
            workspace_only: false,
            workspace_dir: state,
            action_dir: action.clone(),
            home_dir: Some(home),
            forbidden_paths: vec![],
            trusted_roots: vec![PathTrustedRoot {
                path: action.clone(),
                access: PathAccess::ReadWrite,
            }],
            reserved_paths: vec![],
            reserved_prefixes: vec![],
            readonly_paths: vec![],
            reserved_names: vec![],
        },
        grant_ceiling: vec![PathGrant {
            path: action.to_str().required()?.into(),
            write: true,
        }],
        network_ceiling: NetworkPolicy::EgressProxy,
        operator_host_network: false,
        limits: ResourceLimits2::default(),
        sources: vec![SandboxSource2 {
            source_id: "source".into(),
            provenance: "digest".into(),
            trust: SourceTrust::UntrustedMcp,
        }],
        executors: vec![SandboxExecutor2 {
            executor_id: "executor".into(),
            capability_id: "revision".into(),
            backend: SandboxBackend::Namespace,
            available: true,
            isolation: IsolationLevel2::Kernel,
            constraints: vec![
                ConstraintSupport2 {
                    constraint: SandboxConstraint2::Filesystem,
                    enforcement: ConstraintEnforcement2::Enforced,
                },
                ConstraintSupport2 {
                    constraint: SandboxConstraint2::Network,
                    enforcement: ConstraintEnforcement2::Enforced,
                },
            ],
        }],
        proxy: None,
        max_ttl_ms: 1000,
    };
    let request = SandboxPlanRequest2 {
        host_approval: None,
        scope_id: scope.scope_id.clone(),
        subject,
        source_id: "source".into(),
        provenance: "digest".into(),
        call_id: "call".into(),
        operation_json: "{\"argv\":[\"python\",\"script.py\"]}".into(),
        grants: vec![PathGrant {
            path: action.to_str().required()?.into(),
            write: true,
        }],
        network: NetworkPolicy::None,
        limits: ResourceLimits2::default(),
        deny_subprocesses: false,
        accept_process_isolation: false,
        credential_denials: vec![],
        options: SandboxPlanOptions2::default(),
        generation: 1,
        ttl_ms: 1000,
        audit: AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    Ok((dir, scope, request))
}
fn plan(
    scope: SandboxScope2,
    request: &SandboxPlanRequest2,
) -> std::result::Result<SandboxPlanResponse2, Box<dyn std::error::Error>> {
    Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?
    .plan(request, 1, 100)
    .required()
}
#[test]
fn saas_overrides_environment_off_and_disabled_agent_modes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    assert_eq!(
        plan(scope.clone(), &request)?.decision.verdict,
        Verdict::Allow
    );
    for isolation in [IsolationLevel2::None, IsolationLevel2::Process] {
        let mut scope = scope.clone();
        scope.executors[0].isolation = isolation;
        assert_eq!(
            plan(scope, &request)?.denial,
            Some(SandboxDenial2::Unsupported)
        );
    }

    Ok(())
}
#[test]
fn untrusted_sources_never_use_noop_or_best_effort()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    for trust in [
        SourceTrust::UntrustedMcp,
        SourceTrust::UntrustedSkill,
        SourceTrust::Downloaded,
    ] {
        let mut scope = scope.clone();
        scope.deployment = SandboxDeployment2::Local;
        scope.origin = Origin::Operator;
        scope.sources[0].trust = trust;
        scope.executors[0].backend = SandboxBackend::Noop;
        assert_eq!(
            plan(scope, &request)?.denial,
            Some(SandboxDenial2::Unsupported)
        );
    }
    for enforcement in [
        ConstraintEnforcement2::BestEffort,
        ConstraintEnforcement2::Unsupported,
    ] {
        let mut scope = scope.clone();
        scope.executors[0].constraints[0].enforcement = enforcement;
        assert_eq!(
            plan(scope, &request)?.denial,
            Some(SandboxDenial2::Unsupported)
        );
    }

    Ok(())
}
#[test]
fn scope_and_provenance_claims_cannot_supply_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    for field in 0..5 {
        let mut request = request.clone();
        match field {
            0 => request.scope_id = "wrong".into(),
            1 => request.subject.user = "wrong".into(),
            2 => request.subject.agent = "wrong".into(),
            3 => request.source_id = "wrong".into(),
            _ => request.provenance = "wrong".into(),
        }
        assert_eq!(
            plan(scope.clone(), &request)?.denial,
            Some(SandboxDenial2::InvalidContext)
        );
    }

    Ok(())
}
#[test]
fn all_resource_units_and_subprocess_require_enforced_support()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    for (limits, constraint) in [
        (
            ResourceLimits2 {
                cpu_millicores: Some(1000),
                ..Default::default()
            },
            SandboxConstraint2::CpuMillicores,
        ),
        (
            ResourceLimits2 {
                memory_bytes: Some(1024),
                ..Default::default()
            },
            SandboxConstraint2::Memory,
        ),
        (
            ResourceLimits2 {
                pids_max: Some(4),
                ..Default::default()
            },
            SandboxConstraint2::Processes,
        ),
        (
            ResourceLimits2 {
                disk_bytes: Some(4096),
                ..Default::default()
            },
            SandboxConstraint2::Disk,
        ),
    ] {
        let mut request = request.clone();
        request.limits = limits;
        assert_eq!(
            plan(scope.clone(), &request)?.denial,
            Some(SandboxDenial2::Unsupported)
        );
        let mut supported = scope.clone();
        supported.executors[0].constraints.push(ConstraintSupport2 {
            constraint,
            enforcement: ConstraintEnforcement2::Enforced,
        });
        assert_eq!(plan(supported, &request)?.decision.verdict, Verdict::Allow);
    }
    let mut cpu = request.clone();
    cpu.limits.cpu_time_ms = Some(1);
    assert_eq!(
        plan(scope.clone(), &cpu)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    let mut subprocess = request.clone();
    subprocess.deny_subprocesses = true;
    assert_eq!(
        plan(scope, &subprocess)?.denial,
        Some(SandboxDenial2::Unsupported)
    );

    Ok(())
}
#[test]
fn mandatory_resource_and_network_ceilings_cannot_be_removed_or_widened()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, mut request) = fixture()?;
    scope.limits.memory_bytes = Some(1024);
    assert_eq!(
        plan(scope.clone(), &request)?.denial,
        Some(SandboxDenial2::Ceiling)
    );
    request.limits.memory_bytes = Some(2048);
    assert_eq!(
        plan(scope.clone(), &request)?.denial,
        Some(SandboxDenial2::Ceiling)
    );
    request.limits.memory_bytes = Some(512);
    scope.executors[0].constraints.push(ConstraintSupport2 {
        constraint: SandboxConstraint2::Memory,
        enforcement: ConstraintEnforcement2::Enforced,
    });
    assert_eq!(
        plan(scope.clone(), &request)?.decision.verdict,
        Verdict::Allow
    );
    scope.network_ceiling = NetworkPolicy::None;
    request.network = NetworkPolicy::EgressProxy;
    assert_eq!(plan(scope, &request)?.denial, Some(SandboxDenial2::Ceiling));

    Ok(())
}
#[test]
fn preferred_microvm_is_selected_only_if_every_constraint_is_enforced()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, mut request) = fixture()?;
    let mut microvm = scope.executors[0].clone();
    microvm.backend = SandboxBackend::MicroVm;
    microvm.executor_id = "microvm".into();
    microvm.isolation = IsolationLevel2::MicroVm;
    microvm.constraints.push(ConstraintSupport2 {
        constraint: SandboxConstraint2::Memory,
        enforcement: ConstraintEnforcement2::BestEffort,
    });
    scope.executors.insert(0, microvm);
    assert_eq!(
        plan(scope.clone(), &request)?.artifact.required()?.backend,
        SandboxBackend::MicroVm
    );
    request.limits.memory_bytes = Some(1024);
    scope.executors[1].constraints.push(ConstraintSupport2 {
        constraint: SandboxConstraint2::Memory,
        enforcement: ConstraintEnforcement2::Enforced,
    });
    assert_eq!(
        plan(scope, &request)?.artifact.required()?.backend,
        SandboxBackend::Namespace
    );

    Ok(())
}
#[test]
fn proxy_identity_must_bind_exclusive_pinned_egress_to_selected_executor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, mut request) = fixture()?;
    request.network = NetworkPolicy::EgressProxy;
    assert_eq!(
        plan(scope.clone(), &request)?.denial,
        Some(SandboxDenial2::Proxy)
    );
    scope.proxy = Some(SandboxProxy2 {
        proxy_id: "proxy".into(),
        executor_id: "executor".into(),
        capability_id: "revision".into(),
        pinned_destinations: true,
        exclusive_egress: true,
    });
    assert_eq!(
        plan(scope.clone(), &request)?.artifact.required()?.proxy_id,
        Some("proxy".into())
    );
    scope.proxy.as_mut().required()?.exclusive_egress = false;
    assert_eq!(plan(scope, &request)?.denial, Some(SandboxDenial2::Proxy));

    Ok(())
}
#[test]
fn host_network_never_uses_init_permission_as_human_approval()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, mut request) = fixture()?;
    scope.network_ceiling = NetworkPolicy::Host;
    request.network = NetworkPolicy::Host;
    assert_eq!(
        plan(scope, &request)?.denial,
        Some(SandboxDenial2::Approval)
    );

    Ok(())
}
#[test]
fn expiry_generation_and_live_capabilities_bind_exact_artifact()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    let executor = scope.executors[0].clone();
    let engine = Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?;
    let artifact = engine
        .stage(
            engine
                .plan(&request, 1, 100)
                .required()?
                .artifact
                .required()?,
            100,
        )
        .required()?;
    engine.activate(&artifact, 1, 100).required()?;
    assert!(
        engine
            .validate(&request, &artifact, 1, 100, &executor)
            .required()?
    );
    assert!(
        !engine
            .validate(&request, &artifact, 1, 1100, &executor)
            .required()?
    );
    assert!(
        !engine
            .validate(&request, &artifact, 2, 100, &executor)
            .required()?
    );
    assert!(
        !engine
            .validate(&request, &artifact, 1, 99, &executor)
            .required()?
    );
    let mut live = executor.clone();
    live.available = false;
    assert!(
        !engine
            .validate(&request, &artifact, 1, 100, &live)
            .required()?
    );
    live = executor.clone();
    live.capability_id = "changed".into();
    assert!(
        !engine
            .validate(&request, &artifact, 1, 100, &live)
            .required()?
    );
    live = executor.clone();
    live.constraints.clear();
    assert!(
        !engine
            .validate(&request, &artifact, 1, 100, &live)
            .required()?
    );
    let mut changed = request.clone();
    changed.operation_json = "{\"argv\":[\"different\"]}".into();
    assert!(
        !engine
            .validate(&changed, &artifact, 1, 100, &executor)
            .required()?
    );

    Ok(())
}
#[test]
fn malformed_requests_and_overflow_deny_without_artifacts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, request) = fixture()?;
    for mutation in 0..8 {
        let mut req = request.clone();
        match mutation {
            0 => req.call_id.clear(),
            1 => req.operation_json = "[]".into(),
            2 => req.operation_json = "bad".into(),
            3 => req.ttl_ms = 0,
            4 => req.ttl_ms = 1001,
            5 => req.limits.memory_bytes = Some(0),
            6 => req.operation_json = "x".repeat(65_537),
            _ => req.grants = vec![req.grants[0].clone(); 129],
        }
        assert_eq!(
            plan(scope.clone(), &req)?.denial,
            Some(SandboxDenial2::InvalidRequest)
        );
    }
    let engine = Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?;
    assert_eq!(
        engine.plan(&request, 2, 100).required()?.denial,
        Some(SandboxDenial2::Stale)
    );
    assert_eq!(
        engine.plan(&request, 1, u64::MAX).required()?.denial,
        Some(SandboxDenial2::InvalidRequest)
    );

    Ok(())
}
#[test]
fn init_rejects_duplicate_unbounded_and_unresolved_facts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, _request) = fixture()?;
    assert_eq!(
        Engine::new(SandboxConfig2 {
            scopes: vec![scope.clone(); 129]
        })
        .err()
        .required()?,
        Error::InvalidConfig
    );
    assert_eq!(
        Engine::new(SandboxConfig2 {
            scopes: vec![scope.clone(), scope.clone()]
        })
        .err()
        .required()?,
        Error::InvalidConfig
    );
    for mutation in 0..13 {
        let mut scope = scope.clone();
        match mutation {
            0 => scope.scope_id.clear(),
            1 => scope.subject.user.clear(),
            2 => scope.max_ttl_ms = 0,
            3 => scope.max_ttl_ms = 300_001,
            4 => scope.sources.clear(),
            5 => scope.sources.push(scope.sources[0].clone()),
            6 => scope.executors.push(scope.executors[0].clone()),
            7 => {
                let support = scope.executors[0].constraints[0].clone();
                scope.executors[0].constraints.push(support);
            }
            8 => scope.executors[0].capability_id.clear(),
            9 => scope.grant_ceiling[0].path = "relative".into(),
            10 => scope.paths.action_dir = "relative".into(),
            11 => scope.limits.pids_max = Some(0),
            _ => {
                scope.proxy = Some(SandboxProxy2 {
                    proxy_id: "proxy".into(),
                    executor_id: "wrong".into(),
                    capability_id: "wrong".into(),
                    pinned_destinations: true,
                    exclusive_egress: true,
                });
            }
        }
        assert_eq!(
            Engine::new(SandboxConfig2 {
                scopes: vec![scope]
            })
            .err()
            .required()?,
            Error::InvalidConfig
        );
    }

    Ok(())
}
#[test]
fn canonical_operation_key_order_and_redacted_debug()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, scope, mut request) = fixture()?;
    request.operation_json = "{\"b\":2,\"a\":1}".into();
    let first = plan(scope.clone(), &request)?;
    request.operation_json = "{ \"a\":1,\"b\":2 }".into();
    assert_eq!(first.artifact, plan(scope.clone(), &request)?.artifact);
    assert!(
        !format!(
            "{:?}",
            Engine::new(SandboxConfig2 {
                scopes: vec![scope]
            })
            .required()?
        )
        .contains("scope")
    );

    Ok(())
}
#[test]
fn host_network_candidate_binds_old_scope_source_executor_and_original_operation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut scope, mut request) = fixture()?;
    scope.network_ceiling = NetworkPolicy::Host;
    scope.approval_scope_id = Some("human".into());
    request.network = NetworkPolicy::Host;
    let engine = Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })
    .required()?;
    let (artifact, id, original) = engine.human_candidate(&request, 1, 100).required()?;
    assert_eq!(id, "human");
    assert_eq!(artifact.network, NetworkPolicy::Host);
    assert_eq!(original.call.tool, "sandbox_host_network");
    assert_eq!(original.caller.origin, Origin::Saas);
    let before = original.clone();
    request.audit.expected_tail = 99;
    request.host_approval = Some(SandboxApprovalUse2 {
        request_id: "human-row".into(),
        audit: request.audit.clone(),
    });
    assert_eq!(
        engine.human_candidate(&request, 1, 100).required()?.2,
        before
    );
    request.operation_json = "{\"argv\":[\"changed\"]}".into();
    assert_ne!(
        engine.human_candidate(&request, 1, 100).required()?.2,
        before
    );
    request.network = NetworkPolicy::None;
    assert_eq!(
        engine.human_candidate(&request, 1, 100).err().required()?,
        Error::InvalidOperation
    );

    Ok(())
}

trait Required {
    type Value;
    fn required(self) -> std::result::Result<Self::Value, Box<dyn std::error::Error>>;
}
impl<T, E: std::error::Error + 'static> Required for std::result::Result<T, E> {
    type Value = T;
    fn required(self) -> std::result::Result<T, Box<dyn std::error::Error>> {
        self.map_err(Into::into)
    }
}
impl<T> Required for Option<T> {
    type Value = T;
    fn required(self) -> std::result::Result<T, Box<dyn std::error::Error>> {
        self.ok_or_else(|| "missing test fixture".into())
    }
}
