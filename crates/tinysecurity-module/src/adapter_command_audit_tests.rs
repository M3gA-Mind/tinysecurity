//! Required audit gates actual command execution reservations.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct CancelAwareCommandAuditSink {
    calls: Arc<AtomicUsize>,
    first_call_started: Arc<tokio::sync::Notify>,
}

#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl CancelAwareCommandAuditSink {
    async fn append(&self, batch: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_call_started.notify_one();
            std::future::pending::<tinybus::Result<AuditSinkResponse2>>().await
        } else {
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
}

fn audited_command(
    policy_id: CommandPolicyId,
    command: &str,
    event: char,
    expected_tail: u64,
    generation: u64,
) -> CheckCommandAuditedRequest2 {
    AuditedRequest2 {
        request: CommandRequest {
            policy_id,
            command: command.into(),
            declared_class: None,
        },
        audit: AuditCorrelation2 {
            event_id: event.to_string().repeat(32),
            expected_tail,
            generation,
        },
    }
}

async fn service_with_command_policy(
    policy: CommandPolicy,
) -> std::result::Result<
    (
        tokio::task::JoinHandle<tinybus::Result<()>>,
        PolicyService,
        Connection,
        Arc<Mutex<std::collections::BTreeMap<String, AuditSinkRequest2>>>,
        CommandPolicyId,
    ),
    Box<dyn std::error::Error>,
> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let command_policy = service.register_command_policy(policy).await?;
    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    Ok((broker, service, host, rows, command_policy))
}

#[tokio::test]
async fn required_audit_gates_command_allow_and_exact_replay_reserves_once()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut policy = command_fixture()?;
    policy.autonomy = CommandAutonomy::ReadOnly;
    let (broker, service, host, rows, command_policy) = service_with_command_policy(policy).await?;

    let request = audited_command(command_policy.clone(), "pwd", 'a', 0, 1);
    // A read command is allowed in a read-only scope by the command policy;
    // a generic read-only budget denial would change CheckCommand semantics.
    let unavailable = service.check_command_audited2(request.clone()).await?;
    assert!(unavailable.decision.is_none());
    assert!(!unavailable.audit.permitted && !unavailable.audit.committed);

    // A failed audit must refund the command's pending hourly reservation.
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
            change_generation: Arc::default(),
        },
    )
    .await?;
    let allowed = service.check_command_audited2(request.clone()).await?;
    assert_eq!(
        allowed.decision.as_ref().map(|decision| decision.gate),
        Some(CommandGate::Allow)
    );
    assert!(allowed.audit.permitted && allowed.audit.committed);
    assert_eq!(
        service.check_command_audited2(request.clone()).await?,
        allowed
    );

    let conflict = audited_command(command_policy, "whoami", 'a', 0, 1);
    assert!(service.check_command_audited2(conflict).await.is_err());

    // A fresh audit identity reaches the already-consumed single action slot.
    let limited = service
        .check_command_audited2(audited_command(request.request.policy_id, "pwd", 'b', 1, 1))
        .await?;
    let decision = limited
        .decision
        .ok_or("audited rate-limit result missing")?;
    assert_eq!(decision.gate, CommandGate::Block);
    assert_eq!(decision.denial, Some(CommandDenial::RateLimit));
    assert!(limited.audit.permitted && limited.audit.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 2);
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn stale_generation_and_unowned_policy_never_replay_command_allow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (broker, service, host, rows, command_policy) =
        service_with_command_policy(command_fixture()?).await?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows,
            policy: Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
            change_generation: Arc::default(),
        },
    )
    .await?;

    let stale = audited_command(command_policy.clone(), "pwd", 'c', 0, 2);
    let refused = service.check_command_audited2(stale).await?;
    assert!(refused.decision.is_none());
    assert!(!refused.audit.permitted && !refused.audit.committed);

    let request = audited_command(command_policy, "pwd", 'd', 0, 1);
    let allowed = service.check_command_audited2(request.clone()).await?;
    assert_eq!(
        allowed.decision.as_ref().map(|decision| decision.gate),
        Some(CommandGate::Allow)
    );

    // Replays are scoped to the PolicyService that owns the registered policy.
    let isolated = PolicyService {
        commands: Arc::new(Mutex::new(CommandPolicyRegistry::default())),
        ..service.clone()
    };
    assert!(isolated.check_command_audited2(request).await.is_err());
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn cancellation_during_command_audit_refunds_the_pending_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (broker, service, host, _rows, command_policy) =
        service_with_command_policy(command_fixture()?).await?;
    let first_call_started = Arc::new(tokio::sync::Notify::new());
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        CancelAwareCommandAuditSink {
            calls: Arc::new(AtomicUsize::new(0)),
            first_call_started: first_call_started.clone(),
        },
    )
    .await?;

    let request = audited_command(command_policy, "pwd", 'e', 0, 1);
    let started = first_call_started.notified();
    let pending = tokio::spawn({
        let service = service.clone();
        let request = request.clone();
        async move { service.check_command_audited2(request).await }
    });
    started.await;
    pending.abort();
    let _ = pending.await;

    // The exact retry receives the durable decision, and cancellation did not
    // consume the one available action before that receipt could be committed.
    let retry = service.check_command_audited2(request).await?;
    assert_eq!(
        retry.decision.as_ref().map(|decision| decision.gate),
        Some(CommandGate::Allow)
    );
    assert!(retry.audit.permitted && retry.audit.committed);
    broker.abort();
    Ok(())
}
