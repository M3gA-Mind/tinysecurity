use super::*;

use super::super::{ModuleConfig, Policy, RwLock, service_for};
#[tokio::test]
async fn init_requires_authenticated_authority_and_immutable_reinit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = SandboxConfig2 { scopes: vec![] };
    assert!(
        sandbox_configured(Some(config.clone()), None, None, None, None)
            .await
            .is_err()
    );
    let active = sandbox_configured(Some(config.clone()), Some(":1.1"), None, None, None)
        .await
        .required()?;
    assert!(active.is_some());
    assert!(
        sandbox_configured(None, Some(":1.1"), None, None, Some(&active))
            .await
            .required()?
            .is_some()
    );
    assert!(
        sandbox_configured(
            Some(config.clone()),
            Some(":1.1"),
            None,
            None,
            Some(&active)
        )
        .await
        .required()?
        .is_some()
    );
    assert!(
        sandbox_configured(Some(config), Some(":1.1"), None, None, Some(&None))
            .await
            .is_err()
    );
    assert!(
        sandbox_configured(None, None, None, None, None)
            .await
            .required()?
            .is_none()
    );

    Ok(())
}
#[tokio::test]
async fn legacy_plan_and_missing_registered_scope_never_authorize()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let service = service_for(
        Arc::new(RwLock::new(
            Policy::new(ModuleConfig::default()).required()?,
        )),
        None,
    );
    let result = service
        .plan(tinysecurity_bus::SandboxPlanRequest {
            caller: tinysecurity_bus::CallerContext::default(),
            source: tinysecurity_bus::SourceTrust::TrustedHost,
            capabilities: vec![tinysecurity_bus::SandboxBackend::MicroVm],
            grants: vec![],
            network: tinysecurity_bus::NetworkPolicy::Host,
            limits: tinysecurity_bus::ResourceLimits {
                memory_bytes: 1,
                cpu_millis: 1,
                processes: 1,
            },
        })
        .await
        .required()?;
    assert!(result.backend.is_none());
    assert!(!matches!(
        result.decision.verdict,
        tinysecurity_bus::Verdict::Allow
    ));
    let request = SandboxPlanRequest2 {
        host_approval: None,
        scope_id: "scope".into(),
        subject: tinysecurity_bus::SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        source_id: "source".into(),
        provenance: "digest".into(),
        call_id: "call".into(),
        operation_json: "{}".into(),
        grants: vec![],
        network: tinysecurity_bus::NetworkPolicy::None,
        limits: tinysecurity_bus::ResourceLimits2::default(),
        deny_subprocesses: false,
        accept_process_isolation: false,
        credential_denials: vec![],
        options: tinysecurity_bus::SandboxPlanOptions2::default(),
        generation: 1,
        ttl_ms: 1000,
        audit: tinysecurity_bus::AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    assert_eq!(
        service.plan2(request.clone()).await.required()?.denial,
        Some(SandboxDenial2::InvalidContext)
    );
    let mut service = service;
    service.sandbox = Some(Arc::new(
        tinysecurity::sandbox::Engine::new(SandboxConfig2 { scopes: vec![] }).required()?,
    ));
    assert_eq!(
        service.plan2(request).await.required()?.denial,
        Some(SandboxDenial2::InvalidContext)
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

#[path = "../examples/sandbox_native_contract/fixture.rs"]
mod fixture;
use std::sync::{
    Mutex,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::{
    AuditConfig2, AuditEventReceipt2, AuditSinkRequest2, AuditSinkResponse2,
    ConsumeSandboxPlanRequest2, RedactorConfig, Secret, callback_names2,
};

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
#[derive(Clone)]
struct Sink {
    mode: Arc<AtomicU8>,
    clock: Arc<TestClock>,
    policy: Arc<RwLock<Policy>>,
    rows: Arc<Mutex<Vec<AuditSinkRequest2>>>,
    barrier: Arc<tokio::sync::Barrier>,
    entered: Arc<tokio::sync::Notify>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, batch: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        assert!(!serde_json::to_string(&batch)?.contains("private-original-secret"));
        // Reentrant acquisition proves the policy lock is absent during callbacks.
        assert!(self.policy.try_write().is_ok());
        self.rows
            .lock()
            .map_err(|_| tinybus::Error::failed("fixture"))?
            .push(batch.clone());
        match self.mode.load(Ordering::SeqCst) {
            1 => return Err(tinybus::Error::failed("fixture refusal")),
            2 => {
                self.clock.0.store(100_000, Ordering::SeqCst);
            }
            3 => {
                self.policy
                    .write()
                    .map_err(|_| tinybus::Error::failed("fixture"))?
                    .reinitialize(ModuleConfig::default())
                    .map_err(|_| tinybus::Error::failed("fixture"))?;
            }
            4 => {
                self.barrier.wait().await;
            }
            5 => {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            _ => {}
        }
        Ok(AuditSinkResponse2 {
            scope: batch.scope,
            stream_id: batch.stream_id,
            new_tail: batch.events[0].sequence,
            events: vec![AuditEventReceipt2 {
                event_id: batch.events[0].event_id.clone(),
                sequence: batch.events[0].sequence,
            }],
        })
    }
}
struct Harness {
    root: tempfile::TempDir,
    service: PolicyService,
    facts: tinysecurity_bus::SandboxScope2,
    sink: Sink,
    task: tokio::task::JoinHandle<tinybus::Result<()>>,
    host: Connection,
    module: Connection,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn harness() -> std::result::Result<Harness, Box<dyn std::error::Error>> {
    harness_with(|_| {}).await
}
async fn harness_with(
    adjust: impl FnOnce(&mut tinysecurity_bus::SandboxScope2),
) -> std::result::Result<Harness, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut facts = fixture::scope(root.path())?;
    adjust(&mut facts);
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let config = ModuleConfig {
        redactor: RedactorConfig {
            secrets: vec![Secret("private-original-secret".into())],
        },
        ..ModuleConfig::default()
    };
    let policy = Arc::new(RwLock::new(Policy::new(config)?));
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let sink = Sink {
        mode: Arc::new(AtomicU8::new(0)),
        clock: clock.clone(),
        policy: policy.clone(),
        rows: Arc::default(),
        barrier: Arc::new(tokio::sync::Barrier::new(2)),
        entered: Arc::default(),
    };
    host.serve_at(callback_names2::OBJECT_PATH.parse()?, sink.clone())
        .await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let audit = Arc::new(crate::callbacks::AuditClient::new_for_test(
        module.clone(),
        binding,
        AuditConfig2 {
            scope: facts.subject.clone(),
            stream_id: "c".repeat(32),
            timeout_ms: 30_000,
            required: true,
            native_path: None,
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        },
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?);
    let mut service = service_for(policy, Some(audit));
    service.sandbox = Some(Arc::new(tinysecurity::sandbox::Engine::new(
        SandboxConfig2 {
            scopes: vec![facts.clone()],
        },
    )?));
    service.sandbox_clock = clock;
    Ok(Harness {
        root,
        service,
        facts,
        sink,
        task,
        host,
        module,
    })
}
#[tokio::test]
async fn audited_artifact_admission_is_exact_once_even_during_concurrent_callbacks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let h = harness().await?;
    let plan = h.service.plan2(fixture::request(&h.facts, 1)).await?;
    assert_eq!(plan.decision.verdict, tinysecurity_bus::Verdict::Allow);
    assert!(plan.audit.required()?.committed);
    let artifact = plan.artifact.required()?;
    let request = ConsumeSandboxPlanRequest2 {
        request: fixture::request(&h.facts, 1),
        artifact,
        subject: h.facts.subject.clone(),
        audit: fixture::audit(2),
    };
    let mut forged = request.clone();
    forged.artifact.network = tinysecurity_bus::NetworkPolicy::Host;
    assert!(!h.service.consume_sandbox_plan2(forged).await?.permitted);
    let mut wrong_scope = request.clone();
    wrong_scope.subject.agent = "other".into();
    assert!(
        !h.service
            .consume_sandbox_plan2(wrong_scope)
            .await?
            .permitted
    );
    h.sink.mode.store(4, Ordering::SeqCst);
    let mut other = request.clone();
    other.audit = fixture::audit(3);
    let (a, b) = tokio::join!(
        h.service.consume_sandbox_plan2(request.clone()),
        h.service.consume_sandbox_plan2(other)
    );
    assert_eq!(u8::from(a?.permitted) + u8::from(b?.permitted), 1);
    h.sink.mode.store(0, Ordering::SeqCst);
    assert!(!h.service.consume_sandbox_plan2(request).await?.permitted);
    Ok(())
}
#[tokio::test]
async fn plan_callback_failure_expiry_and_generation_change_cannot_activate_pending_artifacts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for mode in [1, 2, 3] {
        let h = harness().await?;
        h.sink.mode.store(mode, Ordering::SeqCst);
        let result = h.service.plan2(fixture::request(&h.facts, 1)).await?;
        assert!(result.artifact.is_none());
        assert_ne!(result.decision.verdict, tinysecurity_bus::Verdict::Allow);
        assert_eq!(
            result.denial,
            Some(if mode == 1 {
                SandboxDenial2::Audit
            } else {
                SandboxDenial2::Stale
            })
        );
    }
    Ok(())
}
#[tokio::test]
async fn consume_callback_failure_expiry_and_generation_change_cannot_reserve_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for mode in [1, 2, 3] {
        let h = harness().await?;
        let artifact = h
            .service
            .plan2(fixture::request(&h.facts, 1))
            .await?
            .artifact
            .required()?;
        h.sink.mode.store(mode, Ordering::SeqCst);
        let result = h
            .service
            .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
                request: fixture::request(&h.facts, 1),
                artifact: artifact.clone(),
                subject: h.facts.subject.clone(),
                audit: fixture::audit(2),
            })
            .await?;
        assert!(!result.permitted);
        if mode == 1 {
            h.sink.mode.store(0, Ordering::SeqCst);
            assert!(
                h.service
                    .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
                        request: fixture::request(&h.facts, 1),
                        artifact,
                        subject: h.facts.subject.clone(),
                        audit: fixture::audit(3)
                    })
                    .await?
                    .permitted
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn initialization_requires_matching_audit_and_durable_approval_subjects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let h = harness().await?;
    let config = SandboxConfig2 {
        scopes: vec![h.facts.clone()],
    };
    let approvals = fixture::approval(&h.facts);
    assert!(
        sandbox_configured(Some(config.clone()), Some(":1.1"), None, None, None)
            .await
            .is_err()
    );
    assert!(
        sandbox_configured(
            Some(config.clone()),
            Some("ai.untrusted.Reusable"),
            None,
            Some(&approvals),
            None
        )
        .await
        .is_err()
    );
    let active = sandbox_configured(
        Some(config.clone()),
        Some(":1.1"),
        None,
        Some(&approvals),
        None,
    )
    .await?;
    assert!(active.is_some());
    let mut wrong = approvals;
    wrong.scopes[0].subject.agent = "other".into();
    assert!(
        sandbox_configured(Some(config), Some(":1.1"), None, Some(&wrong), None)
            .await
            .is_err()
    );
    Ok(())
}

use super::super::tests::approval_tests::{callback, store};
use fixture::audit;
use std::sync::atomic::AtomicBool;
use tinysecurity_bus::{
    ApprovalChoice2, DecideRequest2, EvaluateSandboxApprovalRequest2, NetworkPolicy,
    SandboxApprovalUse2,
};

async fn human_engine(
    h: &mut Harness,
) -> std::result::Result<Arc<Mutex<store::DiskStore>>, Box<dyn std::error::Error>> {
    std::fs::write(h.root.path().join("approvals.journal"), [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(
        &h.root.path().join("approvals.journal"),
    )?));
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        h.host
            .serve_at(
                callback_names2::OBJECT_PATH.parse()?,
                callback::Callback {
                    module: h.module.unique_name().required()?,
                    host: h.host.clone(),
                    interface: interface.parse()?,
                    scope: tinysecurity::approval::scope_handle(&h.facts.subject)?,
                    store: store.clone(),
                    reentrant: Arc::new(AtomicBool::new(false)),
                    prompt_failure: Arc::new(AtomicBool::new(false)),
                },
            )
            .await?;
    }
    let config = fixture::approval(&h.facts);
    let audit = AuditConfig2 {
        scope: h.facts.subject.clone(),
        stream_id: "c".repeat(32),
        timeout_ms: 30_000,
        required: true,
        native_path: None,
        max_bytes: 100_000,
        max_archives: 3,
        journal_max_bytes: 1_000_000,
        journal_max_events: 10_000,
    };
    let clients = crate::approval_callbacks::ApprovalClients::new_for_test(
        &h.module,
        h.host.unique_name().as_ref().map(tinybus::BusName::as_str),
        &config,
        &audit,
        &tinysecurity::Redactor::new(&RedactorConfig {
            secrets: vec![Secret("private-original-secret".into())],
        })?,
    )?;
    h.service.approvals = Some(Arc::new(tinysecurity::approval::Engine::new(
        config,
        Arc::new(clients),
        h.sink.clock.clone(),
        tinysecurity::Redactor::new(&RedactorConfig {
            secrets: vec![Secret("private-original-secret".into())],
        })?,
    )?));
    Ok(store)
}
#[tokio::test]
async fn host_network_plan_uses_exact_authenticated_human_once_and_rejects_cross_operation_and_replay()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut h = harness().await?;
    let store = human_engine(&mut h).await?;
    let mut request = fixture::request(&h.facts, 4);
    request.network = NetworkPolicy::Host;
    assert_eq!(
        h.service.plan2(request.clone()).await?.denial,
        Some(SandboxDenial2::Approval)
    );
    let pending = h
        .service
        .evaluate_sandbox_approval2(EvaluateSandboxApprovalRequest2 {
            request: request.clone(),
            summary: "exact operation".into(),
            audit: audit(1),
        })
        .await?;
    assert_eq!(pending.state, tinysecurity_bus::ApprovalLifecycle2::Pending);
    assert!(pending.judge.is_none());
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(pending.clone(), ApprovalChoice2::Once)?;
    let decided = h
        .service
        .approvals
        .as_ref()
        .required()?
        .decide(DecideRequest2 {
            scope_id: "a".repeat(32),
            request_id: pending.request_id.clone(),
            decision_ticket: ticket,
            audit: audit(2),
        })
        .await?;
    assert!(decided.decision_ticket_sha256.is_some());
    request.host_approval = Some(SandboxApprovalUse2 {
        request_id: pending.request_id,
        audit: audit(3),
    });
    let mut changed = request.clone();
    changed.call_id = "different".into();
    assert_ne!(
        h.service.plan2(changed).await?.decision.verdict,
        tinysecurity_bus::Verdict::Allow
    );
    let admitted = h.service.plan2(request.clone()).await?;
    assert_eq!(admitted.decision.verdict, tinysecurity_bus::Verdict::Allow);
    assert!(
        admitted
            .artifact
            .required()?
            .approval_reservation_id
            .is_some()
    );
    request.audit = audit(5);
    assert_ne!(
        h.service.plan2(request.clone()).await?.decision.verdict,
        tinysecurity_bus::Verdict::Allow
    );
    assert!(
        h.service
            .evaluate_sandbox_approval2(EvaluateSandboxApprovalRequest2 {
                request,
                summary: "claim".into(),
                audit: audit(6)
            })
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn sandbox_permission_requires_committed_evidence_even_without_generic_audit_requirement()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut h = harness().await?;
    h.service.audit = None;
    let result = h.service.plan2(fixture::request(&h.facts, 1)).await?;
    assert_ne!(result.decision.verdict, tinysecurity_bus::Verdict::Allow);
    assert_eq!(result.denial, Some(SandboxDenial2::Audit));
    assert!(result.artifact.is_none());
    Ok(())
}

#[tokio::test]
async fn copied_artifact_cannot_authorize_changed_concrete_spawn_operation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let h = harness().await?;
    let original = fixture::request(&h.facts, 1);
    let artifact = h
        .service
        .plan2(original.clone())
        .await?
        .artifact
        .required()?;
    let mut changed = original.clone();
    changed.operation_json = r#"{"argv":["other-executable"],"env":{"TOKEN":"different"},"cwd":"other","stdin":"different"}"#.into();
    let result = h
        .service
        .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
            request: changed,
            artifact: artifact.clone(),
            subject: h.facts.subject.clone(),
            audit: audit(2),
        })
        .await?;
    assert!(!result.permitted);
    assert!(
        h.service
            .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
                request: original,
                artifact,
                subject: h.facts.subject.clone(),
                audit: audit(3)
            })
            .await?
            .permitted
    );
    Ok(())
}

#[cfg(unix)]
#[path = "adapter_sandbox_review_tests.rs"]
mod review_tests;

#[tokio::test]
async fn cancellation_during_plan_audit_reclaims_pending_artifact_capacity()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let h = harness().await?;
    h.sink.mode.store(5, Ordering::SeqCst);
    let service = h.service.clone();
    let request = fixture::request(&h.facts, 1);
    let task = tokio::spawn(async move { service.plan2(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), h.sink.entered.notified()).await?;
    task.abort();
    assert!(task.await.is_err());
    let engine = h.service.sandbox.as_ref().required()?;
    let candidate = engine
        .plan(&fixture::request(&h.facts, 2), 1, 1000)?
        .artifact
        .required()?;
    for _ in 0..1024 {
        engine.stage(candidate.clone(), 1000)?;
    }
    assert!(engine.stage(candidate, 1000).is_err());
    Ok(())
}

#[path = "adapter_sandbox_scopes_tests.rs"]
mod scopes;

/// An operator's trusted source under a local deployment that disabled the sandbox.
fn operator_with_sandbox_off(facts: &mut tinysecurity_bus::SandboxScope2) {
    facts.approval_scope_id = None;
    facts.deployment = tinysecurity_bus::SandboxDeployment2::Local;
    facts.origin = tinysecurity_bus::Origin::Operator;
    facts.sources[0].trust = tinysecurity_bus::SourceTrust::TrustedHost;
}

fn host_run_request(facts: &tinysecurity_bus::SandboxScope2, sequence: u64) -> SandboxPlanRequest2 {
    let mut request = fixture::request(facts, sequence);
    request.grants.clear();
    request.options.host_run = true;
    request
}

#[tokio::test]
async fn a_planned_run_on_the_host_is_audited_and_admitted_once()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let h = harness_with(|facts| {
        operator_with_sandbox_off(facts);
        facts.environment = tinysecurity_bus::SandboxSetting2::Disabled;
    })
    .await?;
    let request = host_run_request(&h.facts, 1);
    let plan = h.service.plan2(request.clone()).await?;
    assert_eq!(plan.decision.verdict, tinysecurity_bus::Verdict::Allow);
    assert!(plan.audit.required()?.committed, "the plan must be audited");
    let artifact = plan.artifact.required()?;
    assert!(artifact.host_run);
    let consume = ConsumeSandboxPlanRequest2 {
        request,
        artifact,
        subject: h.facts.subject.clone(),
        audit: fixture::audit(2),
    };
    assert!(
        h.service
            .consume_sandbox_plan2(consume.clone())
            .await?
            .permitted
    );
    let mut replay = consume;
    replay.audit = fixture::audit(3);
    assert!(!h.service.consume_sandbox_plan2(replay).await?.permitted);
    Ok(())
}

#[tokio::test]
async fn a_run_on_the_host_is_refused_for_an_untrusted_source_or_saas()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for adjust in [
        (|facts: &mut tinysecurity_bus::SandboxScope2| {
            facts.sources[0].trust = tinysecurity_bus::SourceTrust::UntrustedSkill;
        }) as fn(&mut tinysecurity_bus::SandboxScope2),
        |facts| facts.deployment = tinysecurity_bus::SandboxDeployment2::Saas,
        |facts| facts.origin = tinysecurity_bus::Origin::Saas,
    ] {
        let h = harness_with(|facts| {
            operator_with_sandbox_off(facts);
            facts.environment = tinysecurity_bus::SandboxSetting2::Disabled;
            adjust(facts);
        })
        .await?;
        let plan = h.service.plan2(host_run_request(&h.facts, 1)).await?;
        assert_ne!(plan.decision.verdict, tinysecurity_bus::Verdict::Allow);
        assert_eq!(plan.denial, Some(SandboxDenial2::Floor));
        assert!(plan.artifact.is_none());
    }
    Ok(())
}
