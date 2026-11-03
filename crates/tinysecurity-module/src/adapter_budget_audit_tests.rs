//! Execution-side action reservations are audited and exactly replayable.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn reservation(
    command_policy: tinysecurity_bus::CommandPolicyId,
    id: char,
    tail: u64,
) -> tinysecurity_bus::ReserveActionBudgetAuditedRequest2 {
    tinysecurity_bus::AuditedRequest2 {
        request: tinysecurity_bus::BudgetRequest2 { command_policy },
        audit: AuditCorrelation2 {
            event_id: id.to_string().repeat(32),
            expected_tail: tail,
            generation: 1,
        },
    }
}

#[tokio::test]
async fn required_audit_reserves_once_and_replays_the_same_committed_result()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let audit_client = Arc::new(crate::callbacks::AuditClient::new_for_test(
        module,
        binding,
        permission_audit_config(true),
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?);
    let service = service_for(policy.clone(), Some(audit_client.clone()));
    let command_policy = service.register_command_policy(command_fixture()?).await?;
    let original = reservation(command_policy.clone(), 'a', 0);

    let mut stale = reservation(original.request.command_policy.clone(), 'z', 0);
    stale.audit.generation = 2;
    assert!(service.reserve_action_budget_audited2(stale).await.is_err());

    // A missing required sink must not leave a reservation in the hourly ledger.
    assert!(
        service
            .reserve_action_budget_audited2(original.clone())
            .await
            .is_err()
    );

    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        PermissionAuditSink {
            rows: rows.clone(),
            policy: policy.clone(),
            change_generation: Arc::default(),
        },
    )
    .await?;
    let allowed = service
        .reserve_action_budget_audited2(original.clone())
        .await?;
    assert_eq!(allowed.decision, BudgetDecision2::Allow);
    assert!(allowed.audit.permitted && allowed.audit.committed);

    // A lost response is reconciled by the exact operation and correlation.
    assert_eq!(
        service
            .reserve_action_budget_audited2(original.clone())
            .await?,
        allowed
    );

    // A distinct service instance cannot replay a result for a scope it does not own.
    let isolated = PolicyService {
        commands: Arc::new(Mutex::new(CommandPolicyRegistry::default())),
        ..service_for(policy, Some(audit_client))
    };
    assert!(
        isolated
            .reserve_action_budget_audited2(original.clone())
            .await
            .is_err()
    );

    // Reusing an operation id for another scope is a conflict, not a second spend.
    let other_policy = service.register_command_policy(command_fixture()?).await?;
    assert!(
        service
            .reserve_action_budget_audited2(reservation(other_policy, 'a', 0))
            .await
            .is_err()
    );

    // A distinct operation sees the consumed final slot and records that outcome.
    let limited = service
        .reserve_action_budget_audited2(reservation(command_policy, 'b', 1))
        .await?;
    assert_eq!(
        limited.decision,
        BudgetDecision2::RateLimited { max_per_hour: 1 }
    );
    assert!(limited.audit.permitted && limited.audit.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 2);
    broker.abort();
    Ok(())
}

#[derive(Clone)]
struct CancelAwareAuditSink {
    calls: Arc<AtomicUsize>,
    first_call_started: Arc<tokio::sync::Notify>,
}

#[derive(Clone)]
struct OrderedAuditSink {
    tail: Arc<Mutex<u64>>,
    rows: Arc<Mutex<std::collections::BTreeMap<String, AuditSinkRequest2>>>,
}

#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl OrderedAuditSink {
    async fn append(&self, batch: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        let response = {
            let mut tail = self
                .tail
                .lock()
                .map_err(|_| tinybus::Error::failed("fixture tail"))?;
            let event = batch
                .events
                .first()
                .ok_or_else(|| tinybus::Error::failed("fixture event"))?;
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| tinybus::Error::failed("fixture rows"))?;
            if let Some(previous) = rows.get(&event.event_id) {
                if previous != &batch {
                    return Err(tinybus::Error::failed("fixture conflict"));
                }
            } else {
                if batch.expected_tail != *tail || event.sequence != (*tail).saturating_add(1) {
                    return Err(tinybus::Error::failed("fixture tail conflict"));
                }
                *tail = event.sequence;
                rows.insert(event.event_id.clone(), batch.clone());
            }
            AuditSinkResponse2 {
                scope: batch.scope,
                stream_id: batch.stream_id,
                new_tail: event.sequence,
                events: vec![AuditEventReceipt2 {
                    event_id: event.event_id.clone(),
                    sequence: event.sequence,
                }],
            }
        };
        std::future::ready(Ok(response)).await
    }
}

#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl CancelAwareAuditSink {
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

#[tokio::test]
async fn cancellation_during_audit_refunds_the_pending_action()
-> std::result::Result<(), Box<dyn std::error::Error>> {
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
    let command_policy = service.register_command_policy(command_fixture()?).await?;
    let first_call_started = Arc::new(tokio::sync::Notify::new());
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        CancelAwareAuditSink {
            calls: Arc::new(AtomicUsize::new(0)),
            first_call_started: first_call_started.clone(),
        },
    )
    .await?;

    let request = reservation(command_policy, 'f', 0);
    let started = first_call_started.notified();
    let first = tokio::spawn({
        let service = service.clone();
        let request = request.clone();
        async move { service.reserve_action_budget_audited2(request).await }
    });
    started.await;
    first.abort();
    assert!(first.await.is_err());

    let retry = service.reserve_action_budget_audited2(request).await?;
    assert_eq!(retry.decision, BudgetDecision2::Allow);
    assert!(retry.audit.permitted && retry.audit.committed);
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn concurrent_exact_reservation_retries_return_one_allow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let service = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let command_policy = service.register_command_policy(command_fixture()?).await?;
    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        OrderedAuditSink {
            tail: Arc::new(Mutex::new(0)),
            rows: rows.clone(),
        },
    )
    .await?;

    let request = reservation(command_policy, 'c', 0);
    let (left, right) = tokio::join!(
        service.reserve_action_budget_audited2(request.clone()),
        service.reserve_action_budget_audited2(request),
    );
    let left = left?;
    let right = right?;
    assert_eq!(left.decision, BudgetDecision2::Allow);
    assert_eq!(right, left);
    assert!(left.audit.permitted && left.audit.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 1);
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn concurrent_distinct_reservations_cannot_both_take_the_last_slot()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    let service = service_for(
        policy.clone(),
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(true),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    let command_policy = service.register_command_policy(command_fixture()?).await?;
    let rows = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        OrderedAuditSink {
            tail: Arc::new(Mutex::new(0)),
            rows: rows.clone(),
        },
    )
    .await?;

    let (left, right) = tokio::join!(
        service.reserve_action_budget_audited2(reservation(command_policy.clone(), 'd', 0)),
        service.reserve_action_budget_audited2(reservation(command_policy, 'e', 1)),
    );
    let decisions = [left?, right?].map(|response| response.decision);
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| **decision == BudgetDecision2::Allow)
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, BudgetDecision2::RateLimited { .. }))
            .count(),
        1
    );
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 2);
    broker.abort();
    Ok(())
}
