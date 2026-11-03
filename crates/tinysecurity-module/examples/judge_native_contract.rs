//! Loaded native Jev scoring against a literal-loopback mock and durable callbacks.
#[path = "approval_native_contract/bound_callback.rs"]
mod bound_callback;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
#[path = "approval_native_contract/store.rs"]
mod store;
#[path = "judge_native_contract/stub.rs"]
mod stub;
use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tinybus::{
    Connection,
    broker::Broker,
    module::{HostCallbackEndpoint, HostCallbackProxy, ModuleHost},
    transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    AccessTier, ApprovalActionRequest2, ApprovalChoice2, ApprovalConfig2, ApprovalLifecycle2,
    ApprovalRow2, ApprovalScope2, AuditConfig2, AuditCorrelation2, AuditEventReceipt2,
    AuditSinkRequest2, AuditSinkResponse2, CallerContext, Check, DecideRequest2,
    EvaluateApprovalRequest2, EvaluateApprovalResponse2, EvaluateRequest, JudgeConfig,
    JudgeOutcome2, JudgeProvider, ModuleConfig, Origin, PolicyInfo, RedactorConfig, Secret,
    SubjectScope, ToolCall, Verdict, callback_names2, names,
};
#[derive(Clone)]
struct Sink;
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence,
            events: request
                .events
                .into_iter()
                .map(|event| AuditEventReceipt2 {
                    event_id: event.event_id,
                    sequence: event.sequence,
                })
                .collect(),
        }))
        .await
    }
}

async fn load_bound_module(
    lifecycle: &ModuleHost,
    library: &std::path::Path,
    host: &Connection,
    mut configuration: ModuleConfig,
    store: Arc<Mutex<store::DiskStore>>,
    prompt_failure: Arc<AtomicBool>,
) -> Result<
    (
        tinybus::module::HostCallbackBinding,
        HostCallbackProxy,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    let path: tinybus::ObjectPath = callback_names2::OBJECT_PATH.parse()?;
    let endpoint = |interface: &str, members: &[&str]| -> tinybus::Result<HostCallbackEndpoint> {
        Ok(HostCallbackEndpoint {
            path: path.clone(),
            interface: interface.parse()?,
            members: members
                .iter()
                .map(|member| (*member).parse())
                .collect::<tinybus::Result<_>>()?,
        })
    };
    let binding = lifecycle
        .prepare_host_callbacks(vec![
            endpoint(
                callback_names2::APPROVAL_STORE,
                &[callback_names2::LOAD, callback_names2::CAS],
            )?,
            endpoint(
                callback_names2::APPROVAL_PROMPT,
                &[callback_names2::PROMPT, callback_names2::VERIFY_HUMAN],
            )?,
            endpoint(callback_names2::AUDIT_SINK, &[callback_names2::APPEND])?,
        ])
        .await?;
    configuration.trusted_host = Some(binding.unique_name().to_string());
    let guard = binding.guard();
    let module_proxy = Arc::new(OnceLock::new());
    let scope = tinysecurity::approval::scope_handle(
        &configuration
            .approvals
            .as_ref()
            .ok_or("approval config")?
            .scopes[0]
            .subject,
    )?;
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        binding
            .serve_at(
                path.clone(),
                bound_callback::Callback {
                    guard: guard.clone(),
                    module_proxy: module_proxy.clone(),
                    interface: interface.parse()?,
                    scope: scope.clone(),
                    store: store.clone(),
                    reentrant: Arc::new(AtomicBool::new(false)),
                    prompt_failure: prompt_failure.clone(),
                },
            )
            .await?;
    }
    binding.serve_at(path, Sink).await?;
    let loaded = lifecycle
        .load_file_with_host_callbacks(library, serde_json::to_value(configuration)?, &binding)
        .await?;
    let module = module_peer(host).await?;
    let proxy = binding
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));
    module_proxy
        .set(proxy.clone())
        .map_err(|_| "fixture module proxy already initialized")?;
    assert!(proxy.attestation().await?.is_some());
    Ok((binding, proxy, loaded.name))
}

async fn module_peer(client: &Connection) -> tinybus::Result<tinybus::BusName> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = client.name_owner(names::INTERFACE).await? {
                return Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("native approval initialization unavailable"))?
}

static GENERATION: AtomicU64 = AtomicU64::new(1);
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: GENERATION.load(Ordering::SeqCst),
    }
}
fn begin(instance: u64, sequence: u64) -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: EvaluateRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: format!("call-{instance}"),
                tier: AccessTier::Full,
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: r#"{"token":"private-secret","ordinary":"fake-judge-key"}"#.into(),
                checks: vec![Check::LocalDiagnostic {}],
            },
        },
        ttl_ms: None,
        summary: "inspect bearer private-secret fake-judge-key".into(),
        audit: audit(sequence),
    }
}
fn judge(endpoint: String) -> JudgeConfig {
    JudgeConfig {
        credential: Secret("fake-judge-key".into()),
        endpoint,
        provider: JudgeProvider::TypeSafe,
        threshold_millis: 900,
        exfiltrate_millis: 100,
        thresholds: vec![],
        timeout_ms: 1000,
        origins: vec![Origin::Operator],
        max_requests: 6,
        budget_window_ms: 60_000,
        cache_entries: 10,
        cache_ttl_ms: 1000,
    }
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let library = admit_library()?;
    let (_directory, root) = namespace::create()?;
    let stub = stub::Stub::start().await?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let host = Connection::connect(bus.connect().await?).await?;
    let subject = SubjectScope {
        user: "user".into(),
        workspace: "workspace".into(),
        agent: "agent".into(),
    };
    let mut configuration = configuration(&host, &root, subject)?;
    configuration.judge = Some(judge(stub.endpoint.clone()));
    let store = Arc::new(Mutex::new(store::DiskStore::open(
        &root.join("approvals.journal"),
    )?));
    let prompt_failure = Arc::new(AtomicBool::new(false));
    let (_binding, proxy, loaded_name) = load_bound_module(
        &lifecycle,
        &library,
        &host,
        configuration.clone(),
        store.clone(),
        prompt_failure.clone(),
    )
    .await?;
    let mut non_opted = begin(1, 1);
    non_opted.request.caller.origin = Origin::Copilot;
    let off: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (non_opted,))
        .await?;
    assert!(matches!(
        off.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    assert!(stub.requests.lock().map_err(|_| "stub")?.is_empty());
    verify_scoring(&proxy, &stub).await?;
    verify_fallback(&proxy, &stub, &store).await?;
    verify_matrix(&proxy, &stub).await?;
    let mut invalid = configuration.clone();
    invalid.judge.as_mut().ok_or("judge")?.endpoint = "http://not-loopback.invalid/jev".into();
    invalid.judge.as_mut().ok_or("judge")?.credential = Secret("invalid-candidate-key".into());
    assert!(
        lifecycle
            .reinitialize(&loaded_name, serde_json::to_value(invalid)?)
            .await
            .is_err()
    );
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 1);
    verify_info(&info, &stub)?;
    verify_retained_scoring(&proxy, &stub).await?;
    prompt_failure.store(true, Ordering::SeqCst);
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(7, 14),))
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(8, 99),))
            .await
            .is_err(),
        "required ordered audit receipt gates all permissions"
    );
    let capture = serde_json::to_string(&*stub.requests.lock().map_err(|_| "stub")?)?;
    for secret in ["private-secret", "fake-judge-key"] {
        assert!(!capture.contains(secret));
    }
    let journal = String::from_utf8(std::fs::read(root.join("approvals.journal"))?)?;
    for secret in ["private-secret", "fake-judge-key"] {
        assert!(!journal.contains(secret));
    }
    assert!(journal.contains("auto:jev"));
    assert!(journal.contains("scores_millionths"));
    lifecycle.shutdown(Duration::from_secs(2)).await;
    task.abort();
    stub.shutdown().await?;
    println!(
        "native judge: off-default, explicit init, redacted SDK scores, durable one-shot, hard denial, budget, human fallback and audit verified"
    );
    Ok(())
}

fn verify_info(
    info: &PolicyInfo,
    stub: &stub::Stub,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    assert!(info.callbacks.judge && info.callbacks.approvals);
    let public = info.judge.as_ref().ok_or("judge info")?;
    assert_eq!(public.origins, vec![Origin::Operator]);
    assert_eq!(
        (public.threshold_millis, public.exfiltrate_millis),
        (900, 100)
    );
    let info_text = serde_json::to_string(info)?;
    assert!(!info_text.contains("fake-judge-key") && !info_text.contains(&stub.endpoint));
    Ok(())
}

async fn verify_retained_scoring(
    proxy: &HostCallbackProxy,
    stub: &stub::Stub,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    *stub.response.lock().map_err(|_| "stub")? = (200, stub::response([1.0, 1.0, 0.0]));
    let retained: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(9, 11),))
        .await?;
    assert_eq!(retained.decision.verdict, Verdict::Allow);
    assert_eq!(retained.record.attribution.as_deref(), Some("auto:jev"));
    assert!(retained.record.decision_ticket_sha256.is_none());
    let evidence = retained
        .record
        .judge
        .as_ref()
        .ok_or("retained scorer evidence")?;
    assert_eq!(evidence.outcome, JudgeOutcome2::Qualified);
    assert_eq!(evidence.scores_millionths, Some([1_000_000, 1_000_000, 0]));
    {
        let captured = stub.requests.lock().map_err(|_| "stub")?;
        assert_eq!(
            captured.len(),
            6,
            "fresh identity must use retained SDK endpoint and credential"
        );
        assert_eq!(
            captured.last().ok_or("retained SDK request")?["model"],
            "jev-latest"
        );
    }
    let consumed: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (ApprovalActionRequest2 {
                scope_id: "a".repeat(32),
                request_id: retained.record.request_id,
                request: begin(9, 12).request,
                audit: audit(12),
            },),
        )
        .await?;
    assert_eq!(consumed.state, ApprovalLifecycle2::Reserved);
    let budget: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(6, 13),))
        .await?;
    assert_eq!(
        budget
            .record
            .judge
            .as_ref()
            .ok_or("budget evidence")?
            .outcome,
        JudgeOutcome2::Budget
    );
    assert_eq!(stub.requests.lock().map_err(|_| "stub")?.len(), 6);
    Ok(())
}

/// Low confidence, malformed and timed-out (SDK reports both as unavailable) replies, and `SaaS` all reach a human, never Allow.
async fn verify_matrix(
    proxy: &HostCallbackProxy,
    stub: &stub::Stub,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (stub::response([0.1, 1.0, 0.0]), 0, JudgeOutcome2::Uncertain),
        (
            "{\"model\":\"jev-latest\",\"answers\":".to_owned(),
            0,
            JudgeOutcome2::Unavailable,
        ),
        (
            stub::response([1.0, 1.0, 0.0]),
            1500,
            JudgeOutcome2::Unavailable,
        ),
    ];
    for (offset, (body, delay, expected)) in cases.into_iter().enumerate() {
        *stub.response.lock().map_err(|_| "stub")? = (200, body);
        stub.delay_ms.store(delay, Ordering::SeqCst);
        let sequence = 7 + u64::try_from(offset)?;
        let row: EvaluateApprovalResponse2 = proxy
            .call(
                names::methods::EVALUATE_APPROVAL2,
                (begin(30 + sequence, sequence),),
            )
            .await?;
        assert!(matches!(
            row.decision.verdict,
            Verdict::RequireApproval { .. }
        ));
        assert_eq!(row.record.state, ApprovalLifecycle2::Pending);
        assert!(row.record.attribution.is_none());
        let evidence = row.record.judge.as_ref().ok_or("matrix evidence")?;
        // The SDK deadline and the judge deadline race; both are fail-to-human.
        assert!(
            evidence.outcome == expected
                || (delay > 0 && evidence.outcome == JudgeOutcome2::Timeout),
            "unexpected outcome {:?}",
            evidence.outcome
        );
        assert_eq!(
            evidence.question_ids,
            ["intent", "reversible", "exfiltrate"]
        );
        assert_eq!(evidence.thresholds.intent, 900);
        assert_eq!(evidence.thresholds.exfiltrate, 100);
    }
    stub.delay_ms.store(0, Ordering::SeqCst);
    // The SaaS origin is not opted in: it never reaches the judge and needs its own prompt.
    let before = stub.requests.lock().map_err(|_| "stub")?.len();
    let mut saas = begin(40, 10);
    saas.request.caller.origin = Origin::Saas;
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (saas,))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    assert!(pending.record.judge.is_none());
    assert_eq!(stub.requests.lock().map_err(|_| "stub")?.len(), before);
    Ok(())
}

fn configuration(
    host: &Connection,
    root: &std::path::Path,
    subject: SubjectScope,
) -> std::result::Result<ModuleConfig, Box<dyn std::error::Error>> {
    Ok(ModuleConfig {
        trusted_host: host.unique_name().map(|n| n.to_string()),
        approvals: Some(ApprovalConfig2 {
            timeout_ms: 30_000,
            scopes: vec![ApprovalScope2 {
                scope_id: "a".repeat(32),
                subject: subject.clone(),
                policy_ref: "native-judge".into(),
                generation: 1,
                ceiling: AccessTier::Full,
                require_approval: true,
                auto_approve_all: false,
            }],
        }),
        audit: Some(AuditConfig2 {
            scope: subject,
            stream_id: "c".repeat(32),
            timeout_ms: 30_000,
            required: true,
            native_path: Some(root.join("audit").to_str().ok_or("audit path")?.into()),
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        }),
        redactor: RedactorConfig {
            secrets: vec![Secret("fake-judge-key".into())],
        },
        ..Default::default()
    })
}

async fn verify_scoring(
    proxy: &HostCallbackProxy,
    stub: &stub::Stub,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let qualified: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(2, 2),))
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
            .scores_millionths,
        Some([1_000_000, 1_000_000, 0])
    );
    let consumed: ApprovalRow2 = proxy
        .call(
            names::methods::CONSUME_APPROVAL2,
            (ApprovalActionRequest2 {
                scope_id: "a".repeat(32),
                request_id: qualified.record.request_id.clone(),
                request: begin(2, 3).request,
                audit: audit(3),
            },),
        )
        .await?;
    assert_eq!(consumed.state, ApprovalLifecycle2::Reserved);
    let mut nonopted = begin(3, 4);
    nonopted.request.caller.origin = Origin::Copilot;
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (nonopted,))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    assert_eq!(stub.requests.lock().map_err(|_| "stub")?.len(), 1);
    let mut hard = begin(4, 5);
    hard.request.call.checks = vec![Check::Unknown {
        description: "unknown".into(),
    }];
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (hard,))
            .await
            .is_err()
    );
    assert_eq!(stub.requests.lock().map_err(|_| "stub")?.len(), 1);
    Ok(())
}

async fn verify_fallback(
    proxy: &HostCallbackProxy,
    stub: &stub::Stub,
    store: &Mutex<store::DiskStore>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    *stub.response.lock().map_err(|_| "stub")? = (503, "unavailable".into());
    let uncertain: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(5, 5),))
        .await?;
    assert!(matches!(
        uncertain.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    assert_eq!(
        uncertain
            .record
            .judge
            .as_ref()
            .ok_or("failure evidence")?
            .outcome,
        JudgeOutcome2::Unavailable
    );
    assert_eq!(
        stub.requests.lock().map_err(|_| "stub")?.len(),
        2,
        "no SDK retries"
    );
    let ticket = store
        .lock()
        .map_err(|_| "store")?
        .human_action(uncertain.record.clone(), ApprovalChoice2::Once)?;
    let human: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: uncertain.record.request_id,
                decision_ticket: ticket,
                audit: audit(6),
            },),
        )
        .await?;
    assert_eq!(human.state, ApprovalLifecycle2::Approved);
    assert!(human.decision_ticket_sha256.is_some());
    Ok(())
}

fn admit_library() -> std::result::Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let library = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: judge_native_contract <library>")?,
    )
    .canonicalize()?;
    let name = library
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("library encoding")?;
    std::fs::write(
        library
            .parent()
            .ok_or("library parent")?
            .join("modules.toml"),
        format!(
            "\"{name}\" = \"{}\"\n",
            tinybus::module::sha256_file(&library)?
        ),
    )?;
    Ok(library)
}
