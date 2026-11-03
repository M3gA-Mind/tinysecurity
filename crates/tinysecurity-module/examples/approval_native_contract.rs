//! Actual loaded cdylib approvals, disk mutation ledger and independent process restart.
#[path = "approval_native_contract/bound_callback.rs"]
mod bound_callback;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
#[path = "approval_native_contract/store.rs"]
mod store;
use std::{
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
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
    ApprovalRecordRequest2, ApprovalRow2, ApprovalScope2, AuditConfig2, AuditCorrelation2,
    CallerContext, Check, DecideRequest2, EvaluateApprovalRequest2, EvaluateApprovalResponse2,
    EvaluateRequest, ExecutionOutcome, ModuleConfig, Origin, RecordExecutionRequest2, SubjectScope,
    ToolCall, Verdict, callback_names2, names,
};

struct CallbackState {
    scope: SubjectScope,
    store: Arc<Mutex<store::DiskStore>>,
    reentrant: Arc<AtomicBool>,
    prompt_failure: Arc<AtomicBool>,
}

fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
fn registration() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "current-immutable-partial-scope".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn operation(instance: u64) -> EvaluateRequest {
    EvaluateRequest {
        caller: CallerContext {
            agent: "agent".into(),
            call_id: format!("execution-{instance}"),
            thread: Some("thread".into()),
            tier: AccessTier::Full,
            ..Default::default()
        },
        call: ToolCall {
            tool: "local_diagnostic".into(),
            arguments_json: r#"{"token":"private-secret","ordinary":1}"#.into(),
            checks: vec![Check::LocalDiagnostic {}],
        },
    }
}
fn begin(instance: u64, sequence: u64) -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: operation(instance),
        ttl_ms: None,
        summary: "bearer private-secret".into(),
        audit: audit(sequence),
    }
}
fn action(row: &ApprovalRow2, instance: u64, sequence: u64) -> ApprovalActionRequest2 {
    ApprovalActionRequest2 {
        scope_id: "a".repeat(32),
        request_id: row.request_id.clone(),
        request: operation(instance),
        audit: audit(sequence),
    }
}
async fn module_peer(client: &Connection) -> tinybus::Result<tinybus::BusName> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Some(peer)) = client.name_owner(names::INTERFACE).await {
                return Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("native approval initialization unavailable"))?
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let library = std::path::PathBuf::from(
        args.first()
            .ok_or("usage: approval_native_contract <library>")?,
    )
    .canonicalize()?;
    if let Some(phase) = args.get(1) {
        return verify(
            &library,
            Path::new(args.get(2).ok_or("fixture namespace required")?),
            phase == "first",
        )
        .await;
    }
    let (_directory, root) = namespace::create()?;
    let name = library
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("native library encoding")?;
    std::fs::write(
        library
            .parent()
            .ok_or("native library parent")?
            .join("modules.toml"),
        format!(
            "\"{name}\" = \"{}\"\n",
            tinybus::module::sha256_file(&library)?
        ),
    )?;
    let executable = std::env::current_exe()?;
    for phase in ["first", "restart"] {
        let status = std::process::Command::new(&executable)
            .arg(&library)
            .arg(phase)
            .arg(&root)
            .status()?;
        if !status.success() {
            return Err("native approval subprocess failed".into());
        }
    }
    let journal = std::fs::read(root.join("approvals.journal"))?;
    assert!(!String::from_utf8_lossy(&journal).contains("private-secret"));
    assert!(std::fs::metadata(root.join("audit.journal"))?.len() > 0);
    println!(
        "native approvals: authenticated callbacks, exact receipts, reentrant decision and persistent process restart passed"
    );
    Ok(())
}
async fn verify(
    library: &Path,
    root: &Path,
    first: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let client = Connection::connect(bus.connect().await?).await?;
    let reg = registration();
    let scope = tinysecurity::approval::scope_handle(&reg.subject)?;
    let configuration = ModuleConfig {
        trusted_host: client.unique_name().map(|n| n.as_str().to_owned()),
        approvals: Some(ApprovalConfig2 {
            timeout_ms: 30_000,
            scopes: vec![reg.clone()],
        }),
        audit: Some(AuditConfig2 {
            scope: reg.subject,
            stream_id: "c".repeat(32),
            timeout_ms: 30_000,
            required: true,
            native_path: Some(
                root.join("audit")
                    .to_str()
                    .ok_or("fixture path encoding")?
                    .into(),
            ),
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        }),
        ..Default::default()
    };
    let store = Arc::new(Mutex::new(store::DiskStore::open(
        &root.join("approvals.journal"),
    )?));
    let reentrant = Arc::new(AtomicBool::new(first));
    let prompt_failure = Arc::new(AtomicBool::new(false));
    let (_binding, module, proxy) = load_with_host_callbacks(
        &lifecycle,
        library,
        configuration,
        &client,
        CallbackState {
            scope: scope.clone(),
            store: store.clone(),
            reentrant,
            prompt_failure: prompt_failure.clone(),
        },
    )
    .await?;
    assert!(proxy.attestation().await?.is_some());
    let attacker = Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(1, 1),))
            .await
            .is_err()
    );
    if first {
        first_roundtrip(&proxy, &store).await?;
    } else {
        restart_roundtrip(&proxy, &store, &prompt_failure).await?;
    }
    let mut cron = begin(99, 99);
    cron.request.caller.origin = Origin::Cron;
    cron.request.call.tool = "command_check".into();
    cron.request.call.checks = vec![Check::Command {
        command: "pwd".into(),
    }];
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (cron,))
            .await
            .is_err()
    );
    lifecycle.shutdown(Duration::from_secs(2)).await;
    broker_task.abort();
    Ok(())
}

async fn load_with_host_callbacks(
    lifecycle: &ModuleHost,
    library: &Path,
    mut configuration: ModuleConfig,
    client: &Connection,
    callback: CallbackState,
) -> std::result::Result<
    (
        tinybus::module::HostCallbackBinding,
        tinybus::BusName,
        HostCallbackProxy,
    ),
    Box<dyn std::error::Error>,
> {
    let callback_path: tinybus::ObjectPath = callback_names2::OBJECT_PATH.parse()?;
    let endpoint = |interface: &str, members: &[&str]| -> tinybus::Result<HostCallbackEndpoint> {
        Ok(HostCallbackEndpoint {
            path: callback_path.clone(),
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
        ])
        .await?;
    configuration.trusted_host = Some(binding.unique_name().to_string());
    let guard = binding.guard();
    let module_proxy = Arc::new(OnceLock::new());
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        binding
            .serve_at(
                callback_path.clone(),
                bound_callback::Callback {
                    guard: guard.clone(),
                    module_proxy: module_proxy.clone(),
                    interface: interface.parse()?,
                    scope: callback.scope.clone(),
                    store: callback.store.clone(),
                    reentrant: callback.reentrant.clone(),
                    prompt_failure: callback.prompt_failure.clone(),
                },
            )
            .await?;
    }
    lifecycle
        .load_file_with_host_callbacks(library, serde_json::to_value(configuration)?, &binding)
        .await?;
    let module = module_peer(client).await?;
    let proxy = binding.proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    module_proxy
        .set(proxy.clone())
        .map_err(|_| "fixture module proxy already initialized")?;
    let proxy = proxy.with_timeout(Duration::from_secs(10));
    assert!(proxy.attestation().await?.is_some());
    Ok((binding, module, proxy))
}

async fn first_roundtrip(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<store::DiskStore>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let evaluated: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(1, 1),))
        .await?;
    assert_eq!(
        evaluated.decision.verdict,
        Verdict::Allow,
        "prompt callback must reenter Decide without a held module lock"
    );
    let row = evaluated.record;
    let mut altered = action(&row, 1, 3);
    altered.request.call.arguments_json = "{\"ordinary\":2}".into();
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::CONSUME_APPROVAL2, (altered,))
            .await
            .is_err()
    );
    let reserved: ApprovalRow2 = proxy
        .call(names::methods::CONSUME_APPROVAL2, (action(&row, 1, 3),))
        .await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::CONSUME_APPROVAL2, (action(&row, 1, 3),))
            .await
            .is_err()
    );
    let terminal = RecordExecutionRequest2 {
        action: action(&row, 1, 4),
        outcome: ExecutionOutcome::Succeeded,
    };
    let executed: ApprovalRow2 = proxy
        .call(names::methods::RECORD_EXECUTION2, (terminal.clone(),))
        .await?;
    assert_eq!(executed.state, ApprovalLifecycle2::Executed);
    assert_eq!(
        proxy
            .call::<ApprovalRow2>(names::methods::RECORD_EXECUTION2, (terminal,))
            .await?,
        executed
    );
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(2, 5),))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    approve_reusable(proxy, store).await?;
    // Receipt ledger must return the first committed receipt even now that
    // the row advanced through reservation and terminal versions.
    let original = store
        .lock()
        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
        .mutations
        .values()
        .find(|m| m.record_id == row.request_id && m.next_record.version == 1)
        .cloned()
        .ok_or("first mutation absent")?;
    let receipt = store
        .lock()
        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
        .cas(original.clone())?;
    assert_eq!(receipt.resulting_version, 1);
    original.verify_receipt(&receipt)?;
    Ok(())
}
async fn restart_roundtrip(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<store::DiskStore>>,
    prompt_failure: &AtomicBool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    restart_reusable(proxy, store).await?;
    let rows: Vec<ApprovalRow2> = proxy
        .call(
            names::methods::LIST_APPROVALS2,
            (ApprovalRecordRequest2 {
                scope_id: "a".repeat(32),
                request_id: String::new(),
                audit: audit(11),
            },),
        )
        .await?;
    assert!(rows.iter().any(|r| r.state == ApprovalLifecycle2::Executed));
    let orphan = rows
        .into_iter()
        .find(|r| r.state == ApprovalLifecycle2::Pending)
        .ok_or("durable orphan absent")?;
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (begin(2, 11),))
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::CONSUME_APPROVAL2, (action(&orphan, 2, 11),))
            .await
            .is_err()
    );
    let cancelled: ApprovalRow2 = proxy
        .call(
            names::methods::CANCEL_APPROVAL2,
            (ApprovalRecordRequest2 {
                scope_id: "a".repeat(32),
                request_id: orphan.request_id,
                audit: audit(11),
            },),
        )
        .await?;
    assert_eq!(cancelled.state, ApprovalLifecycle2::Cancelled);
    let evaluated: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (begin(3, 12),))
        .await?;
    assert!(matches!(
        evaluated.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let row = evaluated.record;
    let forged = DecideRequest2 {
        scope_id: "a".repeat(32),
        request_id: row.request_id.clone(),
        decision_ticket: "model-claimed-human".into(),
        audit: audit(13),
    };
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::DECIDE2, (forged.clone(),))
            .await
            .is_err()
    );
    let ticket = store
        .lock()
        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
        .human_action(row.clone(), ApprovalChoice2::Once)?;
    let approved: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                decision_ticket: ticket,
                ..forged
            },),
        )
        .await?;
    assert_eq!(approved.state, ApprovalLifecycle2::Approved);
    let _: ApprovalRow2 = proxy
        .call(names::methods::CONSUME_APPROVAL2, (action(&row, 3, 14),))
        .await?;
    let _: ApprovalRow2 = proxy
        .call(
            names::methods::RECORD_EXECUTION2,
            (RecordExecutionRequest2 {
                action: action(&row, 3, 15),
                outcome: ExecutionOutcome::Cancelled,
            },),
        )
        .await?;
    prompt_failure.store(true, Ordering::SeqCst);
    let mut saas = begin(4, 16);
    saas.request.caller.origin = Origin::Saas;
    assert!(
        proxy
            .call::<EvaluateApprovalResponse2>(names::methods::EVALUATE_APPROVAL2, (saas,))
            .await
            .is_err()
    );
    native_expiry(proxy, prompt_failure).await?;
    Ok(())
}

fn reviewed(instance: u64, sequence: u64) -> EvaluateApprovalRequest2 {
    let mut request = begin(instance, sequence);
    request.request.call.arguments_json = r#"{"token":"private-secret","ordinary":42}"#.into();
    request
}
async fn approve_reusable(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<store::DiskStore>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (reviewed(5, 6),))
        .await?;
    assert!(matches!(
        pending.decision.verdict,
        Verdict::RequireApproval { .. }
    ));
    let ticket = store
        .lock()
        .map_err(|_| "fixture lock")?
        .human_action(pending.record.clone(), ApprovalChoice2::Tool)?;
    let grant: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: pending.record.request_id,
                decision_ticket: ticket,
                audit: audit(7),
            },),
        )
        .await?;
    assert_eq!(grant.choice, Some(ApprovalChoice2::Tool));
    Ok(())
}
async fn restart_reusable(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<store::DiskStore>>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // The reopened disk ledger returns the original first receipt after later row versions.
    let original = {
        let saved = store.lock().map_err(|_| "fixture lock")?;
        saved
            .mutations
            .values()
            .find(|m| {
                m.next_record.version == 1
                    && saved.mutations.values().any(|later| {
                        later.record_id == m.record_id && later.next_record.version == 4
                    })
            })
            .cloned()
    };
    let original = original.ok_or("original persisted mutation")?;
    let receipt = store
        .lock()
        .map_err(|_| "fixture lock")?
        .cas(original.clone())?;
    original.verify_receipt(&receipt)?;
    assert_eq!(receipt.resulting_version, 1);
    let permitted: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (reviewed(6, 8),))
        .await?;
    assert_eq!(
        permitted.decision.verdict,
        Verdict::Allow,
        "exact reviewed grant survives a fresh process"
    );
    let mut exact = action(&permitted.record, 6, 9);
    exact.request = reviewed(6, 9).request;
    let consumed: ApprovalRow2 = proxy
        .call(names::methods::CONSUME_APPROVAL2, (exact.clone(),))
        .await?;
    assert_eq!(consumed.state, ApprovalLifecycle2::Reserved);
    exact.audit = audit(10);
    let executed: ApprovalRow2 = proxy
        .call(
            names::methods::RECORD_EXECUTION2,
            (RecordExecutionRequest2 {
                action: exact,
                outcome: ExecutionOutcome::Succeeded,
            },),
        )
        .await?;
    assert_eq!(executed.state, ApprovalLifecycle2::Executed);
    Ok(())
}
async fn native_expiry(
    proxy: &HostCallbackProxy,
    prompt_failure: &AtomicBool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    prompt_failure.store(false, Ordering::SeqCst);
    let mut short = begin(7, 17);
    short.ttl_ms = Some(1000);
    let pending: EvaluateApprovalResponse2 = proxy
        .call(names::methods::EVALUATE_APPROVAL2, (short,))
        .await?;
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        < u128::from(pending.record.expires_at_ms)
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let expired: ApprovalRow2 = proxy
        .call(
            names::methods::EXPIRE_APPROVAL2,
            (ApprovalRecordRequest2 {
                scope_id: "a".repeat(32),
                request_id: pending.record.request_id,
                audit: audit(18),
            },),
        )
        .await?;
    assert_eq!(expired.state, ApprovalLifecycle2::Expired);
    Ok(())
}
