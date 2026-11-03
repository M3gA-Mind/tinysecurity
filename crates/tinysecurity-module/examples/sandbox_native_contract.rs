//! Loaded scoped planning, exact human host-network reservation and once-only admission.
//! Executor snapshots are policy fixtures, not positive native OS-isolation evidence.
#[path = "approval_native_contract/bound_callback.rs"]
mod bound_callback;
#[path = "sandbox_native_contract/fixture.rs"]
mod fixture;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
#[path = "approval_native_contract/store.rs"]
mod store;
use fixture::audit;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, atomic::AtomicBool},
    time::Duration,
};
use tinybus::{
    Connection,
    broker::Broker,
    module::{HostCallbackEndpoint, HostCallbackProxy, ModuleHost},
    transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    ApprovalChoice2, ApprovalLifecycle2, ApprovalRow2, AuditConfig2, AuditEventReceipt2,
    AuditSinkRequest2, AuditSinkResponse2, ConsumeSandboxPlanRequest2, ConsumeSandboxPlanResponse2,
    DecideRequest2, EvaluateSandboxApprovalRequest2, ModuleConfig, NetworkPolicy, PolicyInfo,
    RedactorConfig, SandboxApprovalUse2, SandboxConfig2, SandboxPlanResponse2, Secret, SourceTrust,
    Verdict, callback_names2, names,
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
) -> std::result::Result<
    (
        tinybus::module::HostCallbackBinding,
        HostCallbackProxy,
        String,
        ModuleConfig,
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
    let guard = binding.guard();
    let module_proxy = Arc::new(OnceLock::new());
    let scope = tinysecurity::approval::scope_handle(
        &configuration.audit.as_ref().ok_or("audit config")?.scope,
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
                    prompt_failure: Arc::new(AtomicBool::new(false)),
                },
            )
            .await?;
    }
    binding.serve_at(path, Sink).await?;
    configuration.trusted_host = Some(binding.unique_name().to_string());
    let loaded = lifecycle
        .load_file_with_host_callbacks(library, serde_json::to_value(&configuration)?, &binding)
        .await?;
    let module = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = host.name_owner(names::INTERFACE).await? {
                return Ok::<_, tinybus::Error>(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("native sandbox initialization unavailable"))??;
    let proxy = binding
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));
    module_proxy
        .set(proxy.clone())
        .map_err(|_| "fixture module proxy already initialized")?;
    assert!(proxy.attestation().await?.is_some());
    Ok((binding, proxy, loaded.name, configuration))
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let library =
        PathBuf::from(std::env::args().nth(1).ok_or("native library required")?).canonicalize()?;
    let name = library
        .file_name()
        .and_then(|n| n.to_str())
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
    let (_directory, root) = namespace::create()?;
    let facts = fixture::scope(&root)?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let host = Connection::connect(bus.connect().await?).await?;
    let configuration = ModuleConfig {
        trusted_host: host.unique_name().map(|n| n.as_str().into()),
        sandbox: Some(SandboxConfig2 {
            scopes: vec![facts.clone()],
        }),
        approvals: Some(fixture::approval(&facts)),
        audit: Some(AuditConfig2 {
            scope: facts.subject.clone(),
            stream_id: "c".repeat(32),
            timeout_ms: 30_000,
            required: true,
            native_path: Some(
                root.join("audit")
                    .to_str()
                    .ok_or("fixture audit encoding")?
                    .into(),
            ),
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        }),
        redactor: RedactorConfig {
            secrets: vec![Secret("private-original-secret".into())],
        },
        ..Default::default()
    };
    let store = Arc::new(Mutex::new(store::DiskStore::open(
        &root.join("approvals.journal"),
    )?));
    let (_binding, proxy, loaded_name, configuration) = load_bound_module(
        &lifecycle,
        &library,
        &host,
        configuration.clone(),
        store.clone(),
    )
    .await?;
    opaque_admission(&proxy, &facts).await?;
    let (host_artifact, host_request) = human_admission(&proxy, &facts, &store).await?;
    generation_fence(
        &proxy,
        &lifecycle,
        &loaded_name,
        configuration,
        host_artifact,
        host_request,
        &root,
    )
    .await?;
    finish(&task);
    Ok(())
}
fn finish(task: &tokio::task::JoinHandle<tinybus::Result<()>>) {
    task.abort();
    println!(
        "native sandbox: scoped declarations, exact human Once, committed audit, opaque admission, tamper/replay/generation refusal passed; no OS-isolation claim"
    );
}

type ExampleResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
async fn opaque_admission(
    proxy: &HostCallbackProxy,
    facts: &tinysecurity_bus::SandboxScope2,
) -> ExampleResult<()> {
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert!(info.capabilities.iter().any(|m| m == names::methods::PLAN2));
    let request = fixture::request(facts, 1);
    let plan: SandboxPlanResponse2 = proxy
        .call(names::methods::PLAN2, (request.clone(),))
        .await?;
    assert_eq!(plan.decision.verdict, Verdict::Allow);
    assert!(plan.audit.ok_or("plan audit")?.committed);
    let artifact = plan.artifact.ok_or("artifact")?;
    assert_ne!(artifact.plan_id, "");
    let consume = ConsumeSandboxPlanRequest2 {
        request: request.clone(),
        artifact: artifact.clone(),
        subject: facts.subject.clone(),
        audit: audit(2),
    };
    let mut forged = consume.clone();
    forged.artifact.fingerprint = "recomputed-public-sha".into();
    assert!(
        !proxy
            .call::<ConsumeSandboxPlanResponse2>(names::methods::CONSUME_SANDBOX_PLAN2, (forged,))
            .await?
            .permitted
    );
    for changed_operation in [
        r#"{"argv":["other-executable"]}"#,
        r#"{"argv":["fixture-executable"],"env":{"NAME":"changed"}}"#,
        r#"{"argv":["fixture-executable"],"cwd":"changed"}"#,
        r#"{"argv":["fixture-executable"],"stdin":"changed"}"#,
    ] {
        let mut changed = consume.clone();
        changed.request.operation_json = changed_operation.into();
        assert!(
            !proxy
                .call::<ConsumeSandboxPlanResponse2>(
                    names::methods::CONSUME_SANDBOX_PLAN2,
                    (changed,)
                )
                .await?
                .permitted
        );
    }
    let mut revised = consume.clone();
    revised.artifact.capability_id = "stale-revision".into();
    assert!(
        !proxy
            .call::<ConsumeSandboxPlanResponse2>(names::methods::CONSUME_SANDBOX_PLAN2, (revised,))
            .await?
            .permitted
    );
    assert!(
        proxy
            .call::<ConsumeSandboxPlanResponse2>(
                names::methods::CONSUME_SANDBOX_PLAN2,
                (consume.clone(),)
            )
            .await?
            .permitted
    );
    assert!(
        !proxy
            .call::<ConsumeSandboxPlanResponse2>(names::methods::CONSUME_SANDBOX_PLAN2, (consume,))
            .await?
            .permitted
    );
    Ok(())
}
async fn human_admission(
    proxy: &HostCallbackProxy,
    facts: &tinysecurity_bus::SandboxScope2,
    store: &Arc<Mutex<store::DiskStore>>,
) -> ExampleResult<(
    tinysecurity_bus::SandboxArtifact2,
    tinysecurity_bus::SandboxPlanRequest2,
)> {
    let mut host_request = fixture::request(facts, 6);
    host_request.network = NetworkPolicy::Host;
    let pending: ApprovalRow2 = proxy
        .call(
            names::methods::EVALUATE_SANDBOX_APPROVAL2,
            (EvaluateSandboxApprovalRequest2 {
                request: host_request.clone(),
                summary: "permit exact host network operation".into(),
                audit: audit(3),
            },),
        )
        .await?;
    assert_eq!(pending.state, ApprovalLifecycle2::Pending);
    assert!(pending.judge.is_none());
    let ticket = store
        .lock()
        .map_err(|_| "fixture store")?
        .human_action(pending.clone(), ApprovalChoice2::Once)?;
    let human: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: pending.request_id.clone(),
                decision_ticket: ticket,
                audit: audit(4),
            },),
        )
        .await?;
    assert!(human.decision_ticket_sha256.is_some());
    host_request.host_approval = Some(SandboxApprovalUse2 {
        request_id: pending.request_id,
        audit: audit(5),
    });
    let plan: SandboxPlanResponse2 = proxy
        .call(names::methods::PLAN2, (host_request.clone(),))
        .await?;
    assert_eq!(plan.decision.verdict, Verdict::Allow);
    let host_artifact = plan.artifact.ok_or("human artifact")?;
    assert!(host_artifact.approval_reservation_id.is_some());
    let admitted: ConsumeSandboxPlanResponse2 = proxy
        .call(
            names::methods::CONSUME_SANDBOX_PLAN2,
            (ConsumeSandboxPlanRequest2 {
                request: host_request.clone(),
                artifact: host_artifact.clone(),
                subject: facts.subject.clone(),
                audit: audit(7),
            },),
        )
        .await?;
    assert!(admitted.permitted);
    let original = host_request.clone();
    host_request.audit = audit(8);
    let replay: SandboxPlanResponse2 = proxy.call(names::methods::PLAN2, (host_request,)).await?;
    assert_ne!(replay.decision.verdict, Verdict::Allow);
    Ok((host_artifact, original))
}
async fn generation_fence(
    proxy: &HostCallbackProxy,
    lifecycle: &ModuleHost,
    module_name: &str,
    configuration: ModuleConfig,
    host_artifact: tinysecurity_bus::SandboxArtifact2,
    host_request: tinysecurity_bus::SandboxPlanRequest2,
    root: &std::path::Path,
) -> ExampleResult<()> {
    let mut invalid = configuration.clone();
    invalid.sandbox.as_mut().ok_or("sandbox")?.scopes[0].sources[0].trust =
        SourceTrust::TrustedHost;
    assert!(
        lifecycle
            .reinitialize(module_name, serde_json::to_value(invalid)?)
            .await
            .is_err()
    );
    assert_eq!(
        proxy
            .call::<PolicyInfo>(names::methods::POLICY_INFO, ())
            .await?
            .generation,
        1
    );
    lifecycle
        .reinitialize(module_name, serde_json::to_value(&configuration)?)
        .await?;
    let stale: ConsumeSandboxPlanResponse2 = proxy
        .call(
            names::methods::CONSUME_SANDBOX_PLAN2,
            (ConsumeSandboxPlanRequest2 {
                request: host_request,
                artifact: host_artifact,
                subject: configuration.audit.as_ref().ok_or("audit")?.scope.clone(),
                audit: audit(9),
            },),
        )
        .await?;
    assert!(!stale.permitted);
    assert!(
        !String::from_utf8_lossy(&std::fs::read(root.join("audit.journal"))?)
            .contains("private-original-secret")
    );
    Ok(())
}
