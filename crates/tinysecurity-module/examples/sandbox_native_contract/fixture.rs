//! Portable policy fixtures mirror executor declarations; they do not prove OS confinement.
use std::path::Path;
use tinysecurity_bus::{
    AccessTier, ApprovalConfig2, ApprovalScope2, AuditCorrelation2, ConstraintEnforcement2,
    ConstraintSupport2, IsolationLevel2, NetworkPolicy, Origin, PathAccess, PathGrant, PathPolicy,
    PathTrustedRoot, ResourceLimits2, SandboxBackend, SandboxConstraint2, SandboxDeployment2,
    SandboxExecutor2, SandboxPlanRequest2, SandboxScope2, SandboxSetting2, SandboxSource2,
    SourceTrust, SubjectScope,
};
pub(super) fn scope(root: &Path) -> std::result::Result<SandboxScope2, Box<dyn std::error::Error>> {
    let root = root.canonicalize()?;
    let action = root.join("action");
    let state = root.join("state");
    let home = root.join("home");
    for dir in [&action, &state, &home] {
        std::fs::create_dir_all(dir)?;
    }
    Ok(SandboxScope2 {
        approval_scope_id: Some("a".repeat(32)),
        scope_id: "sandbox".into(),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
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
            path: action.to_str().ok_or("fixture path encoding")?.into(),
            write: true,
        }],
        network_ceiling: NetworkPolicy::Host,
        operator_host_network: false,
        limits: ResourceLimits2::default(),
        sources: vec![SandboxSource2 {
            source_id: "source".into(),
            provenance: "immutable-source-digest".into(),
            trust: SourceTrust::UntrustedMcp,
        }],
        executors: vec![SandboxExecutor2 {
            executor_id: "verified-executor-fixture".into(),
            capability_id: "tinybox-0.1.17-kernel-fs-network-fixture".into(),
            backend: SandboxBackend::Docker,
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
        max_ttl_ms: 30_000,
    })
}
pub(super) fn request(scope: &SandboxScope2, sequence: u64) -> SandboxPlanRequest2 {
    SandboxPlanRequest2 {
        host_approval: None,
        scope_id: scope.scope_id.clone(),
        subject: scope.subject.clone(),
        source_id: scope.sources[0].source_id.clone(),
        provenance: scope.sources[0].provenance.clone(),
        call_id: format!("sandbox-call-{sequence}"),
        operation_json: r#"{"argv":["fixture-executable"],"input":"private-original-secret"}"#
            .into(),
        grants: scope.grant_ceiling.clone(),
        network: NetworkPolicy::None,
        limits: ResourceLimits2::default(),
        deny_subprocesses: false,
        accept_process_isolation: false,
        credential_denials: vec![],
        options: tinysecurity_bus::SandboxPlanOptions2::default(),
        generation: 1,
        ttl_ms: 30_000,
        audit: audit(sequence),
    }
}
pub(super) fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
pub(super) fn approval(scope: &SandboxScope2) -> ApprovalConfig2 {
    ApprovalConfig2 {
        timeout_ms: 30_000,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: scope.subject.clone(),
            policy_ref: "sandbox-old-immutable-policy".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: false,
            auto_approve_all: true,
        }],
    }
}
