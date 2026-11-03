//! `RecordAudit2`: the host appends to a registered subject's own stream.
use super::*;

fn subject(agent: &str) -> SubjectScope {
    SubjectScope {
        user: "recorded-user".into(),
        workspace: "recorded-workspace".into(),
        agent: agent.into(),
    }
}

fn record(
    agent: &str,
    stream: char,
    kind: AuditKind2,
    event: char,
    tail: u64,
) -> AuditRecordRequest2 {
    AuditRecordRequest2 {
        subject: subject(agent),
        stream_id: stream.to_string().repeat(32),
        kind,
        attribution: "tool:shell".into(),
        arguments_json:
            "{\"command\":\"echo private-secret\",\"policy_decision\":\"auto_approve_all\"}".into(),
        rule_ids: vec![],
        audit: AuditCorrelation2 {
            event_id: event.to_string().repeat(32),
            expected_tail: tail,
            generation: 1,
        },
    }
}

type Rows = Arc<Mutex<std::collections::BTreeMap<String, AuditSinkRequest2>>>;

/// Keeps the host connection alive and stops the broker when a test ends.
struct Fixture {
    _host: tinybus::Connection,
    broker: tokio::task::JoinHandle<tinybus::Result<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.broker.abort();
    }
}

async fn recording_service(
    required: bool,
    serve_sink: bool,
) -> std::result::Result<(PolicyService, Rows, Fixture), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let binding = crate::callbacks::PeerBinding::new(
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig {
        redactor: RedactorConfig {
            secrets: vec![Secret("private-secret".into())],
        },
        ..Default::default()
    })?));
    let rows: Rows = Arc::default();
    if serve_sink {
        host.serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            PermissionAuditSink {
                rows: rows.clone(),
                policy: policy.clone(),
                change_generation: Arc::default(),
            },
        )
        .await?;
    }
    let service = service_for(
        policy,
        Some(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module,
            binding,
            permission_audit_config(required),
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?)),
    );
    Ok((
        service,
        rows,
        Fixture {
            _host: host,
            broker,
        },
    ))
}

#[tokio::test]
async fn a_host_event_lands_in_the_named_subjects_stream_not_the_init_stream()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (service, rows, _host) = recording_service(true, true).await?;
    let first = service
        .record_audit2(record("alpha", 'b', AuditKind2::PolicyDecision, 'c', 0))
        .await?;
    assert!(first.permitted && first.committed);
    let second = service
        .record_audit2(record("alpha", 'b', AuditKind2::Execution, 'd', 1))
        .await?;
    assert!(second.permitted && second.committed);
    assert_eq!(second.receipt.map(|receipt| receipt.new_tail), Some(2));

    let rows = rows.lock().map_err(|_| "fixture rows")?;
    let stored = rows.get(&"c".repeat(32)).ok_or("first row")?;
    assert_eq!(stored.stream_id, "b".repeat(32));
    assert_ne!(stored.scope, permission_audit_config(true).scope);
    assert_eq!(stored.events[0].kind, AuditKind2::PolicyDecision);
    assert!(!serde_json::to_string(&*rows)?.contains("private-secret"));
    Ok(())
}

#[tokio::test]
async fn audit2_still_refuses_a_subject_other_than_the_init_one()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (service, rows, _host) = recording_service(true, true).await?;
    let batch = AuditSinkRequest2 {
        scope: subject("alpha"),
        stream_id: "b".repeat(32),
        expected_tail: 0,
        events: vec![AuditEvent2 {
            sequence: 1,
            event_id: "c".repeat(32),
            generation: 1,
            kind: AuditKind2::Execution,
            attribution: "tool:shell".into(),
            arguments_json: "{}".into(),
            rule_ids: vec![],
        }],
    };
    let refused = service.audit2(batch).await?;
    assert!(!refused.permitted && !refused.committed);
    assert!(rows.lock().map_err(|_| "fixture rows")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_host_record_cannot_impersonate_a_module_decision()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (service, rows, _host) = recording_service(true, true).await?;
    for (index, kind) in [
        AuditKind2::Approval,
        AuditKind2::Judge,
        AuditKind2::Sandbox,
        AuditKind2::Shell,
        AuditKind2::PolicyChanged,
        AuditKind2::NativeRoutine,
    ]
    .into_iter()
    .enumerate()
    {
        let event = char::from(b'1' + u8::try_from(index)?);
        let answer = service
            .record_audit2(record("alpha", 'b', kind, event, 0))
            .await?;
        assert!(!answer.permitted && !answer.committed);
    }
    assert!(rows.lock().map_err(|_| "fixture rows")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_subject_stays_on_its_first_stream_and_a_stale_generation_is_refused()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (service, rows, _host) = recording_service(true, true).await?;
    let kept = service
        .record_audit2(record("alpha", 'b', AuditKind2::Execution, 'c', 0))
        .await?;
    assert!(kept.committed);
    let moved = service
        .record_audit2(record("alpha", 'e', AuditKind2::Execution, 'd', 0))
        .await?;
    assert!(!moved.permitted && !moved.committed);
    let mut stale = record("beta", 'f', AuditKind2::Execution, 'a', 0);
    stale.audit.generation = 0;
    let stale = service.record_audit2(stale).await?;
    assert!(!stale.permitted && !stale.committed);
    let mut malformed = record("beta", 'f', AuditKind2::Execution, 'a', 0);
    malformed.stream_id = "short".into();
    assert!(!service.record_audit2(malformed).await?.committed);
    assert_eq!(rows.lock().map_err(|_| "fixture rows")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_unreachable_sink_is_reported_uncommitted_never_silently_dropped()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (required, _rows, _host) = recording_service(true, false).await?;
    let lost = required
        .record_audit2(record("alpha", 'b', AuditKind2::Execution, 'c', 0))
        .await?;
    assert!(!lost.committed && !lost.permitted);
    assert_eq!(lost.health, AuditHealth2::Denied);
    let (optional, _rows, _host) = recording_service(false, false).await?;
    let degraded = optional
        .record_audit2(record("alpha", 'b', AuditKind2::Execution, 'c', 0))
        .await?;
    assert!(!degraded.committed);
    assert_eq!(degraded.health, AuditHealth2::Degraded);
    Ok(())
}

#[tokio::test]
async fn recording_needs_a_configured_audit_client()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    );
    assert!(
        service
            .record_audit2(record("alpha", 'b', AuditKind2::Execution, 'c', 0))
            .await
            .is_err()
    );
    Ok(())
}
