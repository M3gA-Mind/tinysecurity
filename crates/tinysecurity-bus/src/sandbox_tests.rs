use super::*;
#[test]
fn resources_preserve_cpu_time_and_throughput_as_distinct_units()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let limits = ResourceLimits2 {
        cpu_time_ms: Some(7),
        cpu_millicores: Some(500),
        memory_bytes: Some(1024),
        pids_max: Some(4),
        disk_bytes: Some(4096),
    };
    let value = serde_json::to_value(&limits).required()?;
    assert_eq!(value["cpu_time_ms"], 7);
    assert_eq!(value["cpu_millicores"], 500);
    assert_eq!(
        serde_json::from_value::<ResourceLimits2>(value).required()?,
        limits
    );
    assert!(serde_json::from_str::<ResourceLimits2>(r#"{"cpu_time_ms":null,"cpu_millicores":null,"memory_bytes":null,"pids_max":null,"disk_bytes":null,"cpu_millis":1}"#).is_err());
    assert_eq!(
        serde_json::to_value(crate::ResourceLimits {
            cpu_millis: 7,
            memory_bytes: 1,
            processes: 2
        })
        .required()?,
        serde_json::json!({"cpu_millis":7,"memory_bytes":1,"processes":2})
    );

    Ok(())
}
#[test]
fn sandbox_config_is_additive_and_unknown_init_facts_reject()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let legacy = serde_json::to_value(crate::ModuleConfig::default()).required()?;
    assert!(legacy.get("sandbox").is_none());
    let config = crate::ModuleConfig {
        sandbox: Some(SandboxConfig2 { scopes: vec![] }),
        ..Default::default()
    };
    let value = serde_json::to_value(&config).required()?;
    assert_eq!(value["sandbox"], serde_json::json!({"scopes":[]}));
    assert_eq!(
        serde_json::from_value::<crate::ModuleConfig>(value).required()?,
        config
    );
    assert!(
        serde_json::from_str::<SandboxConfig2>(r#"{"scopes":[],"caller_trusted":true}"#).is_err()
    );

    Ok(())
}
#[test]
fn typed_constraints_have_stable_wire_forms() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    for constraint in [
        SandboxConstraint2::Filesystem,
        SandboxConstraint2::Network,
        SandboxConstraint2::CpuMillicores,
        SandboxConstraint2::CpuTime,
        SandboxConstraint2::Memory,
        SandboxConstraint2::Processes,
        SandboxConstraint2::Disk,
        SandboxConstraint2::Subprocesses,
    ] {
        for enforcement in [
            ConstraintEnforcement2::Enforced,
            ConstraintEnforcement2::BestEffort,
            ConstraintEnforcement2::Unsupported,
        ] {
            let support = ConstraintSupport2 {
                constraint,
                enforcement,
            };
            assert_eq!(
                serde_json::from_value::<ConstraintSupport2>(
                    serde_json::to_value(&support).required()?
                )
                .required()?,
                support
            );
        }
    }
    for reason in [
        SandboxDenial2::InvalidContext,
        SandboxDenial2::InvalidRequest,
        SandboxDenial2::Stale,
        SandboxDenial2::Floor,
        SandboxDenial2::Path,
        SandboxDenial2::Ceiling,
        SandboxDenial2::Unsupported,
        SandboxDenial2::Proxy,
        SandboxDenial2::Approval,
        SandboxDenial2::Audit,
    ] {
        assert_eq!(
            serde_json::from_value::<SandboxDenial2>(serde_json::to_value(reason).required()?)
                .required()?,
            reason
        );
    }

    Ok(())
}
#[test]
fn empty_config_diagnostics_are_content_free() {
    assert_eq!(
        format!("{:?}", SandboxConfig2 { scopes: vec![] }),
        "SandboxConfig2([REDACTED])"
    );
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

#[test]
fn every_sensitive_sandbox_wire_diagnostic_is_redacted()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let subject = SubjectScope {
        user: "private".into(),
        workspace: "private".into(),
        agent: "private".into(),
    };
    let audit = AuditCorrelation2 {
        event_id: "private".into(),
        expected_tail: 0,
        generation: 1,
    };
    let (source, executor, proxy, scope) = diagnostic_scope(&subject);
    let claim = SandboxApprovalUse2 {
        request_id: "private".into(),
        audit: audit.clone(),
    };
    let (request, artifact) = diagnostic_operation(&subject, &audit, &claim);
    let response = SandboxPlanResponse2 {
        decision: Decision {
            generation: 1,
            verdict: crate::Verdict::Allow,
            cacheable: false,
        },
        denial: None,
        artifact: Some(artifact.clone()),
        audit: None,
    };
    let approval = EvaluateSandboxApprovalRequest2 {
        request: request.clone(),
        summary: "private".into(),
        audit: audit.clone(),
    };
    let consume = ConsumeSandboxPlanRequest2 {
        request: request.clone(),
        artifact: artifact.clone(),
        subject,
        audit,
    };
    let consumed = ConsumeSandboxPlanResponse2 {
        permitted: false,
        denial: Some(SandboxDenial2::Stale),
        audit: None,
    };
    for diagnostic in [
        format!("{source:?}"),
        format!("{executor:?}"),
        format!("{proxy:?}"),
        format!("{scope:?}"),
        format!("{claim:?}"),
        format!("{request:?}"),
        format!("{artifact:?}"),
        format!("{response:?}"),
        format!("{approval:?}"),
        format!("{consume:?}"),
        format!("{consumed:?}"),
    ] {
        assert!(diagnostic.ends_with("([REDACTED])"));
        assert!(!diagnostic.contains("private"));
    }
    assert_eq!(
        serde_json::from_value::<SandboxArtifact2>(serde_json::to_value(&artifact)?)?,
        artifact
    );
    assert_eq!(
        serde_json::from_value::<SandboxPlanRequest2>(serde_json::to_value(&request)?)?,
        request
    );
    assert_eq!(
        serde_json::from_value::<SandboxScope2>(serde_json::to_value(&scope)?)?,
        scope
    );
    Ok(())
}

fn diagnostic_scope(
    subject: &SubjectScope,
) -> (
    SandboxSource2,
    SandboxExecutor2,
    SandboxProxy2,
    SandboxScope2,
) {
    let source = SandboxSource2 {
        source_id: "private".into(),
        provenance: "private".into(),
        trust: SourceTrust::UntrustedMcp,
    };
    let executor = SandboxExecutor2 {
        executor_id: "private".into(),
        capability_id: "private".into(),
        backend: SandboxBackend::Docker,
        available: true,
        isolation: IsolationLevel2::Kernel,
        constraints: vec![],
    };
    let proxy = SandboxProxy2 {
        proxy_id: "private".into(),
        executor_id: "private".into(),
        capability_id: "private".into(),
        pinned_destinations: true,
        exclusive_egress: true,
    };
    let scope = SandboxScope2 {
        approval_scope_id: None,
        scope_id: "private".into(),
        subject: subject.clone(),
        origin: Origin::Saas,
        tier: AccessTier::Full,
        deployment: SandboxDeployment2::Saas,
        environment: SandboxSetting2::Disabled,
        agent_mode: SandboxSetting2::Disabled,
        configured: SandboxSetting2::Disabled,
        paths: PathPolicy {
            enabled: false,
            workspace_only: false,
            workspace_dir: "private".into(),
            action_dir: "private".into(),
            home_dir: None,
            forbidden_paths: vec![],
            trusted_roots: vec![],
            reserved_paths: vec![],
            reserved_prefixes: vec![],
            readonly_paths: vec![],
            reserved_names: vec![],
        },
        grant_ceiling: vec![],
        network_ceiling: NetworkPolicy::None,
        operator_host_network: false,
        limits: ResourceLimits2::default(),
        sources: vec![source.clone()],
        executors: vec![executor.clone()],
        proxy: Some(proxy.clone()),
        max_ttl_ms: 1,
    };
    (source, executor, proxy, scope)
}

fn diagnostic_operation(
    subject: &SubjectScope,
    audit: &AuditCorrelation2,
    claim: &SandboxApprovalUse2,
) -> (SandboxPlanRequest2, SandboxArtifact2) {
    let request = SandboxPlanRequest2 {
        host_approval: Some(claim.clone()),
        scope_id: "private".into(),
        subject: subject.clone(),
        source_id: "private".into(),
        provenance: "private".into(),
        call_id: "private".into(),
        operation_json: "private".into(),
        grants: vec![],
        network: NetworkPolicy::Host,
        limits: ResourceLimits2::default(),
        deny_subprocesses: true,
        accept_process_isolation: false,
        credential_denials: vec![],
        options: SandboxPlanOptions2::default(),
        generation: 1,
        ttl_ms: 1,
        audit: audit.clone(),
    };
    let artifact = SandboxArtifact2 {
        minimum_isolation: IsolationLevel2::Kernel,
        plan_id: "private".into(),
        approval_reservation_id: Some("private".into()),
        fingerprint: "private".into(),
        scope_id: "private".into(),
        subject: subject.clone(),
        source_id: "private".into(),
        provenance: "private".into(),
        call_id: "private".into(),
        generation: 1,
        expires_at_ms: 1,
        executor_id: "private".into(),
        capability_id: "private".into(),
        backend: SandboxBackend::Docker,
        grants: vec![],
        deny_read: vec![],
        network: NetworkPolicy::Host,
        proxy_id: Some("private".into()),
        limits: ResourceLimits2::default(),
        constraints: vec![],
        host_run: false,
        no_workspace: false,
    };
    (request, artifact)
}

fn private_pair() -> (SandboxPlanRequest2, SandboxArtifact2) {
    let subject = SubjectScope {
        user: "private".into(),
        workspace: "private".into(),
        agent: "private".into(),
    };
    let audit = AuditCorrelation2 {
        event_id: "private".into(),
        expected_tail: 0,
        generation: 1,
    };
    let claim = SandboxApprovalUse2 {
        request_id: "private".into(),
        audit: audit.clone(),
    };
    diagnostic_operation(&subject, &audit, &claim)
}

fn minimal_request() -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (request, _) = private_pair();
    serde_json::to_value(request).required()
}

#[test]
fn a_request_without_new_folder_fields_keeps_the_1_30_wire_shape()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let value = minimal_request()?;
    assert!(value.get("options").is_none(), "{value}");
    assert!(value.get("credential_denials").is_none(), "{value}");
    let mut with_unknown = value.clone();
    with_unknown["options"] = serde_json::json!({"unknown": true});
    assert!(serde_json::from_value::<SandboxPlanRequest2>(with_unknown).is_err());
    let back: SandboxPlanRequest2 = serde_json::from_value(value).required()?;
    assert!(back.options.is_default());
    assert_eq!(back.credential_denials, Vec::<std::path::PathBuf>::new());

    let mut with_credentials = serde_json::to_value(&back).required()?;
    with_credentials["credential_denials"] = serde_json::json!(["/home/user/.app/credentials"]);
    let back: SandboxPlanRequest2 = serde_json::from_value(with_credentials.clone()).required()?;
    assert_eq!(
        back.credential_denials,
        [std::path::PathBuf::from("/home/user/.app/credentials")]
    );
    assert_eq!(serde_json::to_value(back).required()?, with_credentials);
    Ok(())
}

#[test]
fn plan_options_have_a_pinned_wire_form() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let options = SandboxPlanOptions2 {
        preferred_backend: Some(SandboxBackend::Docker),
        require_preferred_backend: true,
        no_workspace: true,
        host_run: true,
    };
    assert_eq!(
        serde_json::to_value(&options).required()?,
        serde_json::json!({
            "preferred_backend": "docker",
            "require_preferred_backend": true,
            "no_workspace": true,
            "host_run": true,
        })
    );
    assert_eq!(
        serde_json::to_value(SandboxPlanOptions2::default()).required()?,
        serde_json::json!({})
    );
    assert!(!options.is_default());
    let back: SandboxPlanOptions2 =
        serde_json::from_value(serde_json::json!({"host_run": true})).required()?;
    assert!(back.host_run && back.preferred_backend.is_none());
    Ok(())
}

#[test]
fn an_artifact_marks_a_host_run_and_a_workspace_less_plan_only_when_set()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_, mut artifact) = private_pair();
    let value = serde_json::to_value(&artifact).required()?;
    assert!(value.get("host_run").is_none() && value.get("no_workspace").is_none());
    assert!(value.get("deny_read").is_none());
    artifact.host_run = true;
    artifact.no_workspace = true;
    artifact.deny_read = vec!["/home/user/.ssh".into()];
    let value = serde_json::to_value(&artifact).required()?;
    assert_eq!(value["host_run"], true);
    assert_eq!(value["no_workspace"], true);
    assert_eq!(value["deny_read"], serde_json::json!(["/home/user/.ssh"]));
    let back: SandboxArtifact2 = serde_json::from_value(value).required()?;
    assert!(back.host_run && back.no_workspace);
    Ok(())
}
