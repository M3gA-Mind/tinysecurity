//! Operator host network and process-level isolation for ordinary tool commands
//! (contract 1.21): both are granted by explicit fields and never widen untrusted or
//! `SaaS` plans.
use super::*;
use crate::engine::tests::fixture;
use tinysecurity_bus::ConstraintSupport2;

type Res = std::result::Result<(), Box<dyn std::error::Error>>;

/// An operator's own trusted command on a local deployment, with the sandbox on.
fn operator() -> std::result::Result<
    (tempfile::TempDir, SandboxScope2, SandboxPlanRequest2),
    Box<dyn std::error::Error>,
> {
    let (dir, mut scope, request) = fixture()?;
    scope.deployment = SandboxDeployment2::Local;
    scope.origin = Origin::Operator;
    scope.environment = SandboxSetting2::Enabled;
    scope.agent_mode = SandboxSetting2::Enabled;
    scope.sources[0].trust = SourceTrust::TrustedHost;
    scope.network_ceiling = NetworkPolicy::Host;
    Ok((dir, scope, request))
}

fn engine(scope: SandboxScope2) -> std::result::Result<Engine, Box<dyn std::error::Error>> {
    Ok(Engine::new(SandboxConfig2 {
        scopes: vec![scope],
    })?)
}

fn seatbelt(isolation: IsolationLevel2) -> SandboxExecutor2 {
    SandboxExecutor2 {
        executor_id: "seatbelt".into(),
        capability_id: "seatbelt-revision".into(),
        backend: SandboxBackend::Jail,
        available: true,
        isolation,
        constraints: [SandboxConstraint2::Filesystem, SandboxConstraint2::Network]
            .into_iter()
            .map(|constraint| ConstraintSupport2 {
                constraint,
                enforcement: ConstraintEnforcement2::BestEffort,
            })
            .collect(),
    }
}

#[test]
fn host_network_needs_an_approval_unless_the_scope_grants_it() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    request.network = NetworkPolicy::Host;
    assert_eq!(
        engine(scope.clone())?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Approval)
    );
    scope.operator_host_network = true;
    let response = engine(scope)?.plan(&request, 1, 100)?;
    assert_eq!(response.denial, None);
    let artifact = response.artifact.ok_or("no artifact")?;
    assert_eq!(artifact.network, NetworkPolicy::Host);
    assert_eq!(artifact.approval_reservation_id, None);
    Ok(())
}

#[test]
fn operator_host_network_never_exceeds_the_ceiling() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.operator_host_network = true;
    scope.network_ceiling = NetworkPolicy::None;
    request.network = NetworkPolicy::Host;
    assert_eq!(
        engine(scope)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Ceiling)
    );
    Ok(())
}

#[test]
fn operator_host_network_is_ignored_under_saas() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.operator_host_network = true;
    request.network = NetworkPolicy::Host;
    for (deployment, origin) in [
        (SandboxDeployment2::Saas, Origin::Operator),
        (SandboxDeployment2::Local, Origin::Saas),
        // A caller the host could not label gets no operator privilege.
        (SandboxDeployment2::Local, Origin::Unlabelled),
    ] {
        let mut scope = scope.clone();
        scope.deployment = deployment;
        scope.origin = origin;
        assert_eq!(
            engine(scope)?.plan(&request, 1, 100)?.denial,
            Some(SandboxDenial2::Approval)
        );
    }
    Ok(())
}

#[test]
fn operator_host_network_grants_nothing_to_a_request_for_none() -> Res {
    let (_dir, mut scope, request) = operator()?;
    scope.operator_host_network = true;
    let artifact = engine(scope)?
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(artifact.network, NetworkPolicy::None);
    Ok(())
}

#[test]
fn process_level_jail_runs_an_operator_command_only_when_the_request_accepts_it() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.executors = vec![seatbelt(IsolationLevel2::Process)];
    assert_eq!(
        engine(scope.clone())?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    request.accept_process_isolation = true;
    let engine = engine(scope.clone())?;
    let planned = engine
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(planned.minimum_isolation, IsolationLevel2::Process);
    let artifact = engine.stage(planned, 100)?;
    engine.activate(&artifact, 1, 100)?;
    // The artifact is still bound to the request that accepted it.
    assert!(engine.validate(&request, &artifact, 1, 100, &scope.executors[0])?);
    let mut stricter = request.clone();
    stricter.accept_process_isolation = false;
    assert!(!engine.validate(&stricter, &artifact, 1, 100, &scope.executors[0])?);
    Ok(())
}

#[test]
fn trusted_folder_plan_carries_pre_admitted_grants_and_credential_denials() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.executors = vec![seatbelt(IsolationLevel2::Process)];
    request.accept_process_isolation = true;

    let ssh = scope
        .paths
        .home_dir
        .as_ref()
        .ok_or("home missing")?
        .join(".ssh");
    std::fs::create_dir(&ssh)?;
    let app_credential = scope.paths.workspace_dir.join("credential.json");
    std::fs::write(&app_credential, "secret")?;
    let mut wire_request = serde_json::to_value(&request)?;
    wire_request["credential_denials"] = serde_json::json!([app_credential]);
    let request: SandboxPlanRequest2 = serde_json::from_value(wire_request)?;

    let artifact = engine(scope.clone())?
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("trusted folder plan was denied")?;

    assert_eq!(artifact.minimum_isolation, IsolationLevel2::Process);
    assert_eq!(artifact.grants.len(), 1);
    assert!(std::path::Path::new(&artifact.grants[0].path).is_absolute());
    let wire_artifact = serde_json::to_value(artifact)?;
    let denied = wire_artifact["deny_read"]
        .as_array()
        .ok_or("folder plan did not return deny_read paths")?;
    assert!(denied.contains(&serde_json::json!(app_credential)));
    assert!(denied.contains(&serde_json::json!(ssh)));
    Ok(())
}

#[test]
fn credential_denial_paths_must_be_bounded_absolute_and_traversal_free() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.credential_denials = vec![std::path::PathBuf::from("relative/credential")];
    assert_eq!(
        engine(scope.clone())?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::InvalidRequest)
    );

    request.credential_denials = vec![std::path::PathBuf::from("/tmp/../secret")];
    assert_eq!(
        engine(scope.clone())?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::InvalidRequest)
    );

    request.credential_denials = vec![std::path::PathBuf::from(format!(
        "/tmp/{}",
        "x".repeat(4096)
    ))];
    assert_eq!(
        engine(scope)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::InvalidRequest)
    );
    Ok(())
}

#[test]
fn process_level_jail_never_runs_untrusted_or_saas_plans() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.accept_process_isolation = true;
    for trust in [
        SourceTrust::UntrustedMcp,
        SourceTrust::UntrustedSkill,
        SourceTrust::Downloaded,
    ] {
        let mut scope = scope.clone();
        scope.executors = vec![seatbelt(IsolationLevel2::Process)];
        scope.sources[0].trust = trust;
        assert_eq!(
            engine(scope)?.plan(&request, 1, 100)?.denial,
            Some(SandboxDenial2::Floor)
        );
    }
    for (deployment, origin) in [
        (SandboxDeployment2::Saas, Origin::Operator),
        (SandboxDeployment2::Local, Origin::Saas),
    ] {
        let mut scope = scope.clone();
        scope.executors = vec![seatbelt(IsolationLevel2::Process)];
        scope.deployment = deployment;
        scope.origin = origin;
        assert_eq!(
            engine(scope)?.plan(&request, 1, 100)?.denial,
            Some(SandboxDenial2::Floor)
        );
    }
    Ok(())
}

#[test]
fn process_level_jail_needs_a_real_jail_and_a_kernel_jail_still_wins() -> Res {
    let (_dir, scope, mut request) = operator()?;
    request.accept_process_isolation = true;
    let mut none = scope.clone();
    none.executors = vec![seatbelt(IsolationLevel2::None)];
    assert_eq!(
        engine(none)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    let mut noop = scope.clone();
    let mut executor = seatbelt(IsolationLevel2::Process);
    executor.backend = SandboxBackend::Noop;
    noop.executors = vec![executor];
    assert_eq!(
        engine(noop)?.plan(&request, 1, 100)?.denial,
        Some(SandboxDenial2::Unsupported)
    );
    let mut both = scope;
    both.executors.insert(0, seatbelt(IsolationLevel2::Process));
    let artifact = engine(both)?
        .plan(&request, 1, 100)?
        .artifact
        .ok_or("no artifact")?;
    assert_eq!(artifact.minimum_isolation, IsolationLevel2::Kernel);
    assert_eq!(artifact.executor_id, "executor");
    Ok(())
}

#[test]
fn an_unlabelled_origin_is_sandboxed_mandatorily_and_gets_no_unjailed_host_run() -> Res {
    let (_dir, mut scope, mut request) = operator()?;
    scope.origin = Origin::Unlabelled;
    scope.environment = SandboxSetting2::Disabled;
    request.options.host_run = true;
    let response = engine(scope)?.plan(&request, 1, 100)?;
    assert!(
        response.artifact.is_none() || response.denial.is_some(),
        "an unlabelled caller must not receive an unjailed host run"
    );
    Ok(())
}
