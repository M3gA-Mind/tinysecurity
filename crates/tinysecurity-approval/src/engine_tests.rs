use super::*;
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use tinysecurity_bus::{
    AccessTier, ApprovalRecord, ApprovalRecord2, ApprovalState, AuditCorrelation2, CallerContext,
    Check, ExecutionOutcome, RedactorConfig, ToolCall,
};
#[derive(Debug, Default)]
struct TestClock {
    wall: AtomicU64,
    mono: AtomicU64,
    wall_failed: AtomicU64,
}
impl Clock for TestClock {
    fn wall_ms(&self) -> Option<u64> {
        (self.wall_failed.load(Ordering::SeqCst) == 0).then(|| self.wall.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}
#[derive(Debug, Default)]
struct Fixture {
    rows: Mutex<std::collections::BTreeMap<String, ApprovalRecord2>>,
    ledger: Mutex<std::collections::BTreeMap<String, (ApprovalCasRequest2, ApprovalCasResponse2)>>,
    order: Mutex<Vec<&'static str>>,
    fail: AtomicU64,
    load_fail: AtomicU64,
    pause_load: AtomicU64,
    pause_nth_load: AtomicU64,
    load_calls: AtomicU64,
    cas_calls: AtomicU64,
    expire_unavailable_cas: Mutex<Option<(Arc<TestClock>, u64)>>,
    loaded: tokio::sync::Notify,
    release_load: tokio::sync::Notify,
    choice: AtomicU64,
    reentrant: Mutex<Option<std::sync::Weak<Engine>>>,
    swallow_decision_audit_failure: AtomicU64,
    audits: Mutex<Vec<ApprovalRow2>>,
    advance_source_audit: Mutex<Option<(Arc<TestClock>, u64)>>,
    audit_receipts: Mutex<std::collections::BTreeMap<(String, u64), ApprovalRow2>>,
    barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    native_receipt_mode: AtomicU64,
    fail_cancelled_audit: AtomicU64,
    admitted: Mutex<Vec<(String, String)>>,
    released: Mutex<Vec<String>>,
    admit_fails: AtomicU64,
    release_fails: AtomicU64,
    admit_pause: AtomicU64,
    release_pause: AtomicU64,
    ports_entered: tokio::sync::Notify,
    ports_proceed: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl Ports for Fixture {
    async fn admit_scope(&self, scope: &ApprovalScope2, audit_stream_id: &str) -> Result<()> {
        if self.admit_pause.swap(0, Ordering::SeqCst) != 0 {
            self.ports_entered.notify_one();
            self.ports_proceed.notified().await;
        }
        if self.admit_fails.load(Ordering::SeqCst) != 0 {
            return Err(Error::Unavailable);
        }
        self.admitted
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push((scope.scope_id.clone(), audit_stream_id.into()));
        Ok(())
    }
    async fn release_scope(&self, scope: &ApprovalScope2) -> Result<()> {
        if self.release_pause.swap(0, Ordering::SeqCst) != 0 {
            self.ports_entered.notify_one();
            self.ports_proceed.notified().await;
        }
        if self.release_fails.load(Ordering::SeqCst) != 0 {
            return Err(Error::Unavailable);
        }
        self.released
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push(scope.scope_id.clone());
        Ok(())
    }
    async fn native_audit(&self, row: ApprovalRow2) -> Result<NativeAuditAcknowledgement> {
        self.audit(row.clone()).await?;
        let mode = self.native_receipt_mode.load(Ordering::SeqCst);
        if mode == 1 && row.state == ApprovalLifecycle2::Reserved {
            return Err(Error::Unavailable);
        }
        let tail = row.audit.expected_tail + 1;
        let expected_scope = row.binding.scope.clone();
        let receipt = tinysecurity_bus::AuditSinkResponse2 {
            scope: row.binding.scope.clone(),
            stream_id: "a".repeat(32),
            events: vec![tinysecurity_bus::AuditEventReceipt2 {
                sequence: tail,
                event_id: if mode == 2 && row.state == ApprovalLifecycle2::Reserved {
                    "f".repeat(32)
                } else {
                    row.audit.event_id.clone()
                },
            }],
            new_tail: tail,
        };
        NativeAuditAcknowledgement::from_verified_sink(row, expected_scope, receipt)
    }
    async fn purge_session(
        &self,
        request: tinysecurity_bus::ApprovalPurgeSessionRequest2,
    ) -> Result<tinysecurity_bus::ApprovalPurgeSessionResponse2> {
        let mut rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
        let remove = rows
            .iter()
            .filter_map(|(id, record)| {
                serde_json::from_str::<ApprovalRow2>(&record.record_json)
                    .ok()
                    .filter(|row| {
                        row.binding.scope == request.scope
                            && row.session_id.as_deref() == Some(&request.session_id)
                            && row.state == ApprovalLifecycle2::Pending
                    })
                    .map(|_| id.clone())
            })
            .collect::<Vec<_>>();
        for id in &remove {
            rows.remove(id);
        }
        Ok(tinysecurity_bus::ApprovalPurgeSessionResponse2 {
            scope: request.scope,
            session_id: request.session_id,
            removed: u32::try_from(remove.len()).map_err(|_| Error::Invalid)?,
        })
    }
    async fn load(&self, r: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        if self.load_fail.load(Ordering::SeqCst) != 0 {
            return Err(Error::Unavailable);
        }
        let requested_scope = r.scope.clone();
        let response = ApprovalLoadResponse2 {
            scope: requested_scope.clone(),
            records: self
                .rows
                .lock()
                .map_err(|_| Error::Unavailable)?
                .values()
                .filter(|record| {
                    serde_json::from_str::<ApprovalRow2>(&record.record_json)
                        .is_ok_and(|row| row.binding.scope == requested_scope)
                })
                .cloned()
                .collect(),
        };
        r.verify_response(&response).map_err(|_| Error::Invalid)?;
        let call = self.load_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.pause_nth_load.load(Ordering::SeqCst) == call
            || self
                .pause_load
                .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.loaded.notify_one();
            self.release_load.notified().await;
        }
        Ok(response)
    }
    async fn cas(&self, r: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.cas_calls.fetch_add(1, Ordering::SeqCst);
        if let Some((clock, deadline)) = self
            .expire_unavailable_cas
            .lock()
            .map_err(|_| Error::Unavailable)?
            .take()
        {
            clock.wall.store(deadline, Ordering::SeqCst);
            return Err(Error::Unavailable);
        }
        let barrier = self.barrier.lock().map_err(|_| Error::Unavailable)?.clone();
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        if self.fail.load(Ordering::SeqCst) == 1 {
            return Err(Error::Unavailable);
        }
        let mut ledger = self.ledger.lock().map_err(|_| Error::Unavailable)?;
        if let Some((prior, receipt)) = ledger.get(&r.mutation_id) {
            return if prior == &r {
                Ok(receipt.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        let mut rows = self.rows.lock().map_err(|_| Error::Unavailable)?;
        if rows.get(&r.record_id).map(|v| v.version) != r.expected_version {
            return Err(Error::Conflict);
        }
        let receipt = ApprovalCasResponse2 {
            scope: r.scope.clone(),
            record_id: r.record_id.clone(),
            mutation_id: r.mutation_id.clone(),
            resulting_version: r.next_record.version,
        };
        r.verify_receipt(&receipt).map_err(|_| Error::Invalid)?;
        rows.insert(r.record_id.clone(), r.next_record.clone());
        ledger.insert(r.mutation_id.clone(), (r, receipt.clone()));
        self.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push("cas");
        if self
            .fail
            .compare_exchange(13, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(Error::Unavailable);
        }
        Ok(receipt)
    }
    async fn prompt(&self, r: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push("prompt");
        if self.fail.load(Ordering::SeqCst) == 3 {
            return Err(Error::Unavailable);
        }
        let owner = self
            .reentrant
            .lock()
            .map_err(|_| Error::Unavailable)?
            .clone();
        if let Some(owner) = owner.and_then(|owner| owner.upgrade()) {
            let failure = self.swallow_decision_audit_failure.load(Ordering::SeqCst);
            if failure != 0 {
                self.fail
                    .store(if failure == 1 { 5 } else { 6 }, Ordering::SeqCst);
                assert!(owner.decide(decision(&r.row)).await.is_err());
            } else {
                owner.decide(decision(&r.row)).await?;
            }
        }
        Ok(ApprovalDeliveryResponse2 {
            request_id: r.row.request_id,
            nonce: r.row.nonce,
            delivered: true,
        })
    }
    async fn human(&self, r: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        if r.decision_ticket != "private-human-ticket" {
            return Err(Error::Denied);
        }
        Ok(HumanDecisionReceipt2 {
            row: r.row,
            ticket_sha256: format!("{:x}", Sha256::digest(r.decision_ticket.as_bytes())),
            actor: "human".into(),
            choice: match self.choice.load(Ordering::SeqCst) {
                1 => ApprovalChoice2::Tool,
                2 => ApprovalChoice2::Flow,
                3 => ApprovalChoice2::Deny,
                _ => ApprovalChoice2::Once,
            },
        })
    }
    async fn audit(&self, _r: ApprovalRow2) -> Result<()> {
        if _r.decision_ticket_sha256.is_some()
            && let Some((clock, now)) = self
                .advance_source_audit
                .lock()
                .map_err(|_| Error::Unavailable)?
                .take()
        {
            clock.wall.store(now, Ordering::SeqCst);
        }
        self.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push("audit");
        self.audits
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push(_r.clone());
        if _r.state == ApprovalLifecycle2::Cancelled
            && self.fail_cancelled_audit.swap(0, Ordering::SeqCst) != 0
        {
            return Err(Error::Unavailable);
        }
        let key = (_r.request_id.clone(), _r.version);
        let mut receipts = self.audit_receipts.lock().map_err(|_| Error::Unavailable)?;
        if let Some(prior) = receipts.get(&key) {
            return if prior == &_r {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if self.fail.load(Ordering::SeqCst) == 6 && _r.decision_ticket_sha256.is_some() {
            receipts.insert(key, _r);
            return Err(Error::Unavailable);
        }
        if self.fail.load(Ordering::SeqCst) == 5 && _r.decision_ticket_sha256.is_some() {
            return Err(Error::Unavailable);
        }
        if self.fail.load(Ordering::SeqCst) == 2
            || (self.fail.load(Ordering::SeqCst) == 4 && _r.state == ApprovalLifecycle2::Approved)
        {
            Err(Error::Unavailable)
        } else {
            receipts.insert(key, _r);
            Ok(())
        }
    }
}
#[derive(Debug)]
struct ForeignRowsPorts(Arc<Fixture>);
#[async_trait::async_trait]
impl Ports for ForeignRowsPorts {
    async fn load(&self, request: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        // Deliberately misbehaving store: echo the requested scope but return every row.
        Ok(ApprovalLoadResponse2 {
            scope: request.scope,
            records: self
                .0
                .rows
                .lock()
                .map_err(|_| Error::Unavailable)?
                .values()
                .cloned()
                .collect(),
        })
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.0.cas(request).await
    }
    async fn prompt(&self, request: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.0.prompt(request).await
    }
    async fn human(&self, request: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        self.0.human(request).await
    }
    async fn audit(&self, row: ApprovalRow2) -> Result<()> {
        self.0.audit(row).await
    }
}
fn config() -> ApprovalConfig2 {
    ApprovalConfig2 {
        timeout_ms: 100,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            policy_ref: "immutable-scope-v1".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        }],
    }
}
fn request() -> EvaluateApprovalRequest2 {
    EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: EvaluateRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: "execution-1".into(),
                thread: Some("thread".into()),
                tier: AccessTier::Full,
                ..Default::default()
            },
            call: ToolCall {
                tool: "local_diagnostic".into(),
                arguments_json: r#"{"token":"private-secret","b":2,"a":1}"#.into(),
                checks: vec![Check::LocalDiagnostic {}],
            },
        },
        ttl_ms: None,
        summary: "bearer private-summary".into(),
        audit: AuditCorrelation2 {
            event_id: "b".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    }
}
fn engine(f: Arc<Fixture>, c: Arc<TestClock>) -> Result<Engine> {
    Engine::new(
        config(),
        f,
        c,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )
}
#[tokio::test]
async fn pending_commit_and_audit_precede_prompt_and_returned_request_identity() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let owner = engine(fixture.clone(), clock)?;
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(
        *fixture.order.lock().map_err(|_| Error::Unavailable)?,
        vec!["cas", "audit", "prompt"]
    );
    assert_eq!(row.expires_at_ms, 601_000);
    let stored = serde_json::to_string(&*fixture.rows.lock().map_err(|_| Error::Unavailable)?)
        .map_err(|_| Error::Invalid)?;
    assert!(!stored.contains("private-secret") && !stored.contains("private-summary"));
    assert_eq!(row.binding.call_sha256.len(), 64);
    Ok(())
}

#[tokio::test]
async fn failed_store_or_audit_never_delivers_a_prompt_or_returns_permission() -> Result<()> {
    for mode in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.fail.store(mode, Ordering::SeqCst);
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        assert!(owner.begin(request()).await.is_err());
        assert!(
            !f.order
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contains(&"prompt")
        );
    }
    Ok(())
}

fn audit(version: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{version:032x}"),
        expected_tail: version - 1,
        generation: 1,
    }
}
fn decision(row: &ApprovalRow2) -> DecideRequest2 {
    DecideRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        decision_ticket: "private-human-ticket".into(),
        audit: audit(2),
    }
}
fn action(row: &ApprovalRow2, phase: u64) -> ApprovalActionRequest2 {
    ApprovalActionRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        request: request().request,
        audit: audit(phase),
    }
}
#[tokio::test]
async fn exact_human_ticket_first_winner_once_consumption_and_terminal_outcome() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    let mut forged = decision(&row);
    forged.decision_ticket = "model-says-yes".into();
    assert!(owner.decide(forged).await.is_err());
    assert!(owner.consume(action(&row, 3)).await.is_err());
    let approved = owner.decide(decision(&row)).await?;
    assert_eq!(approved.state, ApprovalLifecycle2::Approved);
    assert_eq!(owner.decide(decision(&row)).await?, approved);
    let mut altered = action(&row, 3);
    altered.request.call.arguments_json = "{\"a\":42}".into();
    assert!(owner.consume(altered).await.is_err());
    assert_eq!(
        owner.consume(action(&row, 3)).await?.state,
        ApprovalLifecycle2::Reserved
    );
    assert!(owner.consume(action(&row, 3)).await.is_err());
    let terminal = RecordExecutionRequest2 {
        action: action(&row, 4),
        outcome: ExecutionOutcome::Succeeded,
    };
    let finished = owner.record_execution(terminal.clone()).await?;
    assert_eq!(owner.record_execution(terminal.clone()).await?, finished);
    let mut conflicting = terminal;
    conflicting.outcome = ExecutionOutcome::Failed;
    assert!(owner.record_execution(conflicting).await.is_err());
    Ok(())
}

#[tokio::test]
async fn exact_ttl_boundaries_shortening_and_clock_rollback_deny_decisions() -> Result<()> {
    for (origin, ttl) in [
        (Origin::Operator, 600_000),
        (Origin::Copilot, 180_000),
        (Origin::SubAgent, 180_000),
    ] {
        let f = Arc::new(Fixture::default());
        let c = Arc::new(TestClock::default());
        c.wall.store(1000, Ordering::SeqCst);
        let owner = engine(f, c.clone())?;
        let mut input = request();
        input.request.caller.origin = origin;
        input.ttl_ms = Some(u64::MAX);
        let row = owner.begin(input).await?;
        assert_eq!(row.expires_at_ms, 1000 + ttl);
        c.wall.store(1000 + ttl, Ordering::SeqCst);
        assert!(owner.decide(decision(&row)).await.is_err());
    }
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    c.wall.store(1000, Ordering::SeqCst);
    let owner = engine(f, c.clone())?;
    let mut input = request();
    input.ttl_ms = Some(10);
    let row = owner.begin(input).await?;
    assert_eq!(row.expires_at_ms, 1010);
    c.wall.store(999, Ordering::SeqCst);
    assert!(owner.decide(decision(&row)).await.is_err());
    c.wall.store(1001, Ordering::SeqCst);
    assert!(
        owner.decide(decision(&row)).await.is_err(),
        "rollback fault stays latched"
    );
    Ok(())
}

#[tokio::test]
async fn restart_restores_rows_but_cannot_execute_orphaned_requests() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    let first = engine(f.clone(), c.clone())?;
    let row = first.begin(request()).await?;
    first.decide(decision(&row)).await?;
    let restarted = engine(f, c)?;
    assert!(restarted.consume(action(&row, 3)).await.is_err());
    assert!(restarted.begin(request()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn concurrent_consumers_cannot_both_reserve_one_execution() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    owner.decide(decision(&row)).await?;
    *f.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let (left, right) = tokio::join!(
        owner.consume(action(&row, 3)),
        owner.consume(action(&row, 3))
    );
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "durable CAS retry idempotence must not duplicate execution reservations"
    );
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_decision_audit_cannot_be_skipped_by_execution_consumption() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    f.fail.store(2, Ordering::SeqCst);
    assert!(owner.decide(decision(&row)).await.is_err());
    // A host cannot skip the missing decision audit by supplying the next phase.
    f.fail.store(4, Ordering::SeqCst);
    assert!(owner.consume(action(&row, 3)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn concurrent_retries_of_one_execution_share_one_random_pending_request() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    *f.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let (left, right) = tokio::join!(owner.begin(request()), owner.begin(request()));
    assert_eq!(left?.request_id, right?.request_id);
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn imported_legacy_allow_keeps_history_but_never_becomes_a_live_grant() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let legacy = ApprovalRecord {
        request_id: "old-request".into(),
        fingerprint: "broad-tool-name".into(),
        caller: request().request.caller,
        expires_at_ms: u64::MAX,
        state: ApprovalState::Allowed,
    };
    let row = owner
        .import_history(ApprovalHistoryImport2 {
            scope_id: request().scope_id,
            legacy,
            audit: audit(1),
        })
        .await?;
    assert!(
        row.legacy_history_json
            .as_ref()
            .ok_or(Error::Invalid)?
            .contains("allowed")
    );
    assert_eq!(row.state, ApprovalLifecycle2::Denied);
    assert!(owner.consume(action(&row, 2)).await.is_err());
    Ok(())
}
#[tokio::test]
async fn canonical_calls_keep_object_order_insignificant_and_secret_changes_distinct() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    let mut reordered = request();
    reordered.request.call.arguments_json = r#"{"a":1,"b":2,"token":"private-secret"}"#.into();
    assert_eq!(owner.begin(reordered).await?.request_id, row.request_id);
    let mut secret = request();
    secret.request.call.arguments_json = r#"{"a":1,"b":2,"token":"private-change"}"#.into();
    let other = owner.begin(secret).await?;
    assert_eq!(other.args_redacted, row.args_redacted);
    assert_ne!(other.binding.call_sha256, row.binding.call_sha256);
    let mut arrays = request();
    arrays.request.caller.call_id = "arrays".into();
    arrays.request.call.arguments_json = "{\"headers\":[\"first\",\"second\"]}".into();
    let first = owner.begin(arrays.clone()).await?;
    arrays.request.call.arguments_json = "{\"headers\":[\"second\",\"first\"]}".into();
    assert_ne!(
        owner.begin(arrays).await?.binding.call_sha256,
        first.binding.call_sha256
    );
    Ok(())
}
#[tokio::test]
async fn exact_tool_grants_survive_restart_without_argument_origin_or_generation_escalation()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    f.choice.store(1, Ordering::SeqCst);
    let c = Arc::new(TestClock::default());
    let owner = engine(f.clone(), c.clone())?;
    let row = owner.begin(request()).await?;
    owner.decide(decision(&row)).await?;
    let restart = engine(f.clone(), c)?;
    let mut next = request();
    next.request.caller.call_id = "execution-2".into();
    next.audit = audit(3);
    let reviewed = restart.begin(next.clone()).await?;
    assert_eq!(reviewed.state, ApprovalLifecycle2::Approved);
    let mut changed = next.clone();
    changed.request.caller.call_id = "execution-3".into();
    changed.request.call.arguments_json = "{\"a\":9}".into();
    changed.audit = audit(4);
    assert_eq!(
        restart.begin(changed).await?.state,
        ApprovalLifecycle2::Pending
    );
    next.request.caller.call_id = "execution-4".into();
    next.request.caller.origin = Origin::Copilot;
    next.audit = audit(5);
    assert_eq!(
        restart.begin(next.clone()).await?.state,
        ApprovalLifecycle2::Pending
    );
    restart.advance_generation(2)?;
    assert!(restart.consume(action(&reviewed, 6)).await.is_err());
    next.audit = AuditCorrelation2 {
        generation: 2,
        ..audit(6)
    };
    next.request.caller.origin = Origin::Operator;
    next.request.caller.call_id = "execution-5".into();
    assert_eq!(
        restart.begin(next).await?.state,
        ApprovalLifecycle2::Pending
    );
    assert!(restart.advance_generation(1).is_err());
    Ok(())
}
#[tokio::test]
async fn exact_flow_grants_are_bounded_idempotent_and_do_not_cover_another_flow() -> Result<()> {
    let f = Arc::new(Fixture::default());
    f.choice.store(2, Ordering::SeqCst);
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let mut input = request();
    input.request.caller.flow = Some("flow".into());
    let row = owner.begin(input.clone()).await?;
    owner.decide(decision(&row)).await?;
    let review = PreauthorizeFlowRequest2 {
        scope_id: input.scope_id.clone(),
        flow_id: "flow".into(),
        request_ids: vec![row.request_id.clone(), row.request_id.clone()],
    };
    assert_eq!(owner.preauthorize_flow(review.clone()).await?.len(), 1);
    assert_eq!(owner.preauthorize_flow(review.clone()).await?.len(), 1);
    let mut wrong = review.clone();
    wrong.flow_id = "other-flow".into();
    assert!(owner.preauthorize_flow(wrong).await.is_err());
    let mut oversized = review;
    oversized.request_ids = vec![row.request_id; 101];
    assert!(owner.preauthorize_flow(oversized).await.is_err());
    input.request.caller.call_id = "execution-2".into();
    input.audit = audit(3);
    assert_eq!(
        owner.begin(input.clone()).await?.state,
        ApprovalLifecycle2::Approved
    );
    input.request.caller.flow = Some("other-flow".into());
    input.request.caller.call_id = "execution-3".into();
    input.audit = audit(4);
    assert_eq!(owner.begin(input).await?.state, ApprovalLifecycle2::Pending);
    Ok(())
}
#[tokio::test]
async fn cron_external_effects_deny_before_auto_all_and_saas_still_requires_human_delivery()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    let mut config = config();
    config.scopes[0].auto_approve_all = true;
    let owner = Engine::new(
        config,
        f.clone(),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    let mut cron = request();
    cron.request.caller.origin = Origin::Cron;
    cron.request.call.checks = vec![Check::Command {
        command: "pwd".into(),
    }];
    assert!(owner.begin(cron).await.is_err());
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 0);
    let mut saas = request();
    saas.request.caller.origin = Origin::Saas;
    f.fail.store(3, Ordering::SeqCst);
    assert!(owner.begin(saas).await.is_err());
    let ordinary = owner.begin(request()).await?;
    assert_eq!(ordinary.state, ApprovalLifecycle2::Approved);
    Ok(())
}
#[tokio::test]
async fn expiry_cancellation_and_deny_keep_first_winner_and_captured_owner() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    let owner = engine(f, c.clone())?;
    let row = owner.begin(request()).await?;
    let expire = ApprovalRecordRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        audit: audit(2),
    };
    assert!(owner.expire(expire.clone()).await.is_err());
    c.wall.store(row.expires_at_ms, Ordering::SeqCst);
    let expired = owner.expire(expire.clone()).await?;
    assert_eq!(expired.state, ApprovalLifecycle2::Expired);
    assert_eq!(owner.expire(expire).await?, expired);
    assert!(owner.consume(action(&row, 3)).await.is_err());
    let mut second = request();
    second.request.caller.call_id = "second".into();
    second.audit = audit(3);
    let row = owner.begin(second).await?;
    let cancel = ApprovalRecordRequest2 {
        scope_id: request().scope_id,
        request_id: row.request_id.clone(),
        audit: audit(4),
    };
    let cancelled = owner.cancel(cancel.clone()).await?;
    assert_eq!(owner.cancel(cancel).await?, cancelled);
    assert!(owner.decide(decision(&row)).await.is_err());
    let f = Arc::new(Fixture::default());
    f.choice.store(3, Ordering::SeqCst);
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    assert_eq!(
        owner.decide(decision(&row)).await?.state,
        ApprovalLifecycle2::Denied
    );
    assert!(owner.consume(action(&row, 3)).await.is_err());
    assert!(
        owner
            .record_execution(RecordExecutionRequest2 {
                action: action(&row, 3),
                outcome: ExecutionOutcome::Succeeded
            })
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn commit_before_timeout_retries_the_same_mutation_and_original_receipt_survives_later_versions()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    f.fail.store(13, Ordering::SeqCst);
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    assert_eq!(f.ledger.lock().map_err(|_| Error::Unavailable)?.len(), 1);
    let initial = f
        .ledger
        .lock()
        .map_err(|_| Error::Unavailable)?
        .values()
        .next()
        .cloned()
        .ok_or(Error::Invalid)?;
    owner.decide(decision(&row)).await?;
    let receipt = f.cas(initial.0.clone()).await?;
    assert_eq!(receipt, initial.1);
    let mut conflict = initial.0;
    conflict.next_record.record_json = "{}".into();
    assert!(f.cas(conflict).await.is_err());
    Ok(())
}
#[tokio::test]
async fn wrong_registration_agent_access_ceiling_and_unverified_human_inputs_deny() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let mut wrong = request();
    wrong.scope_id = "f".repeat(32);
    assert!(owner.begin(wrong).await.is_err());
    let mut wrong = request();
    wrong.request.caller.agent = "another-agent".into();
    assert!(owner.begin(wrong).await.is_err());
    let row = owner.begin(request()).await?;
    let mut wrong = decision(&row);
    wrong.scope_id = "f".repeat(32);
    assert!(owner.decide(wrong).await.is_err());
    for ticket in [String::new(), "x".repeat(4097)] {
        let mut wrong = decision(&row);
        wrong.decision_ticket = ticket;
        assert!(owner.decide(wrong).await.is_err());
    }
    let mut other = config();
    other.scopes[0].subject.user = "other-user".into();
    let other = Engine::new(
        other,
        Arc::new(ForeignRowsPorts(f.clone())),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(other.list(&request().scope_id).await.is_err());
    let f = Arc::new(Fixture::default());
    let mut ceiling = config();
    ceiling.scopes[0].ceiling = AccessTier::Read;
    let read = Engine::new(
        ceiling,
        f,
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(read.begin(request()).await.is_err());
    Ok(())
}
#[tokio::test]
async fn corrupt_lifecycle_cannot_turn_a_deny_into_a_loaded_approval() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    let mut row = owner.begin(request()).await?;
    row.state = ApprovalLifecycle2::Approved;
    row.choice = Some(ApprovalChoice2::Deny);
    f.rows
        .lock()
        .map_err(|_| Error::Unavailable)?
        .insert(row.request_id.clone(), binding::envelope(&row)?);
    assert!(owner.consume(action(&row, 3)).await.is_err());
    Ok(())
}
#[tokio::test]
async fn simultaneous_decisions_and_conflicting_terminal_results_have_one_cas_winner() -> Result<()>
{
    let fixture = Arc::new(Fixture::default());
    let owner = engine(fixture.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin(request()).await?;
    *fixture.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let left = decision(&row);
    let mut right = left.clone();
    right.audit = audit(3);
    let (a, b) = tokio::join!(owner.decide(left.clone()), owner.decide(right.clone()));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    *fixture.barrier.lock().map_err(|_| Error::Unavailable)? = None;
    let winner = if a.is_ok() { left } else { right };
    assert_eq!(
        owner.decide(winner.clone()).await?,
        owner.decide(winner).await?
    );
    owner.consume(action(&row, 4)).await?;
    *fixture.barrier.lock().map_err(|_| Error::Unavailable)? =
        Some(Arc::new(tokio::sync::Barrier::new(2)));
    let left = RecordExecutionRequest2 {
        action: action(&row, 5),
        outcome: ExecutionOutcome::Succeeded,
    };
    let right = RecordExecutionRequest2 {
        action: action(&row, 6),
        outcome: ExecutionOutcome::Failed,
    };
    let (a, b) = tokio::join!(owner.record_execution(left), owner.record_execution(right));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    Ok(())
}

#[tokio::test]
async fn reusable_tool_and_flow_grants_reconcile_the_source_decision_audit_first() -> Result<()> {
    for choice in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.choice.store(choice, Ordering::SeqCst);
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        let mut input = request();
        input.request.caller.flow = Some("reviewed-flow".into());
        let pending = owner.begin(input.clone()).await?;
        f.fail.store(5, Ordering::SeqCst);
        assert!(owner.decide(decision(&pending)).await.is_err());
        input.request.caller.call_id = "new-execution".into();
        input.audit = audit(3);
        assert!(
            owner.begin(input.clone()).await.is_err(),
            "derived permission cannot skip the source decision audit"
        );
        assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 1);
        f.fail.store(0, Ordering::SeqCst);
        let derived = owner.begin(input).await?;
        assert_eq!(derived.state, ApprovalLifecycle2::Approved);
        let audits = f.audits.lock().map_err(|_| Error::Unavailable)?;
        let source = &audits[audits.len() - 2];
        assert_eq!(source.request_id, pending.request_id);
        assert_eq!(source.audit, audit(2));
        assert_eq!(source.state, ApprovalLifecycle2::Approved);
        assert_eq!(
            audits.last().ok_or(Error::Invalid)?.request_id,
            derived.request_id
        );
    }
    Ok(())
}

#[tokio::test]
async fn completed_executions_do_not_exhaust_the_creation_retry_window() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let mut config = config();
    config.scopes[0].auto_approve_all = true;
    let owner = Engine::new(
        config,
        f.clone(),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    for index in 0..1026 {
        let mut input = request();
        input.request.caller.call_id = format!("completed-{index}");
        let row = owner.begin(input.clone()).await?;
        let mut consume = action(&row, 3);
        consume.request = input.request;
        owner.consume(consume.clone()).await?;
        consume.audit = audit(4);
        owner
            .record_execution(RecordExecutionRequest2 {
                action: consume,
                outcome: ExecutionOutcome::Succeeded,
            })
            .await?;
        // Trusted storage retains bounded terminal history, independently of the
        // retry memo, preserving active rows and reusable human grants.
        let mut rows = f.rows.lock().map_err(|_| Error::Unavailable)?;
        if rows.len() > 8 {
            let oldest = rows
                .iter()
                .find(|(_, record)| {
                    serde_json::from_str::<ApprovalRow2>(&record.record_json).is_ok_and(|row| {
                        row.state == ApprovalLifecycle2::Executed
                            && row.choice == Some(ApprovalChoice2::Once)
                    })
                })
                .map(|(id, _)| id.clone())
                .ok_or(Error::Invalid)?;
            rows.remove(&oldest);
        }
    }
    assert!(owner.begin(request()).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn replayed_prompt_returns_the_reentrant_durable_decision() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
    f.fail.store(3, Ordering::SeqCst);
    assert!(owner.begin(request()).await.is_err());
    f.fail.store(0, Ordering::SeqCst);
    *f.reentrant.lock().map_err(|_| Error::Unavailable)? = Some(Arc::downgrade(&owner));
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.version, 2);
    Ok(())
}

#[tokio::test]
async fn late_source_audit_commit_is_reconciled_without_rolling_back_the_human_grant() -> Result<()>
{
    for choice in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.choice.store(choice, Ordering::SeqCst);
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        let mut input = request();
        input.request.caller.flow = Some("reviewed-flow".into());
        let source = owner.begin(input.clone()).await?;
        f.fail.store(6, Ordering::SeqCst);
        assert!(owner.decide(decision(&source)).await.is_err());
        // The sink committed the exact audit but its acknowledgement was lost.
        // Replaying that phase succeeds even while new human audits are denied.
        f.fail.store(5, Ordering::SeqCst);
        input.request.caller.call_id = "after-lost-ack".into();
        input.audit = audit(3);
        let derived = owner.begin(input.clone()).await?;
        assert_eq!(derived.state, ApprovalLifecycle2::Approved);
        let mut consume = action(&derived, 4);
        consume.request = input.request;
        assert_eq!(
            owner.consume(consume).await?.state,
            ApprovalLifecycle2::Reserved
        );
        assert_eq!(
            owner
                .list(&request().scope_id)
                .await?
                .iter()
                .find(|row| row.request_id == source.request_id)
                .ok_or(Error::Invalid)?
                .state,
            ApprovalLifecycle2::Approved
        );
    }
    Ok(())
}

#[tokio::test]
async fn indeterminate_creation_identities_survive_capacity_pressure_and_retry() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    f.fail.store(1, Ordering::SeqCst);
    for index in 0..1024 {
        let mut input = request();
        input.request.caller.call_id = format!("unacknowledged-{index}");
        assert!(owner.begin(input).await.is_err());
    }
    assert!(
        owner.begin(request()).await.is_err(),
        "the active retry window remains bounded"
    );
    let mut retry = request();
    retry.request.caller.call_id = "unacknowledged-0".into();
    // Pin the exact pending identity before recovery; no confirmed row exists.
    let (bound, _, _) = binding::original(&config().scopes[0], &retry.request, &owner.redactor()?)?;
    let pending = owner
        .creations
        .lock()
        .map_err(|_| Error::Unavailable)?
        .get(&bound.call_sha256)
        .cloned()
        .ok_or(Error::Invalid)?;
    f.fail.store(0, Ordering::SeqCst);
    let row = owner.begin(retry).await?;
    assert_eq!(row.request_id, pending.request_id);
    assert_eq!(row.nonce, pending.nonce);
    assert!(
        owner.begin(request()).await.is_ok(),
        "confirmed identity frees a retry slot"
    );
    Ok(())
}

#[tokio::test]
async fn a_stale_creation_snapshot_after_memo_reclamation_uses_the_durable_winner() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
    f.pause_load.store(1, Ordering::SeqCst);
    let concurrent_owner = owner.clone();
    let waiting = tokio::spawn(async move { concurrent_owner.begin(request()).await });
    f.loaded.notified().await;
    let winner = owner.begin(request()).await?;
    // This retry confirms the winning identity and retires its creation memo.
    assert_eq!(owner.begin(request()).await?.request_id, winner.request_id);
    f.release_load.notify_one();
    let resumed = waiting.await.map_err(|_| Error::Unavailable)??;
    assert_eq!(resumed.request_id, winner.request_id);
    assert_eq!(resumed.nonce, winner.nonce);
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 1);
    Ok(())
}

async fn swallowed_reentrant_audit_failure(resume: bool) -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
    if resume {
        f.fail.store(3, Ordering::SeqCst);
        assert!(owner.begin(request()).await.is_err());
        f.fail.store(0, Ordering::SeqCst);
    }
    *f.reentrant.lock().map_err(|_| Error::Unavailable)? = Some(Arc::downgrade(&owner));
    f.swallow_decision_audit_failure.store(1, Ordering::SeqCst);
    assert!(
        owner.begin(request()).await.is_err(),
        "prompt delivery cannot acknowledge an unaudited decision phase"
    );
    let stored = owner.list(&request().scope_id).await?;
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].state,
        ApprovalLifecycle2::Approved,
        "audit failure does not roll back the durable human winner"
    );
    assert!(owner.begin(request()).await.is_err());
    f.fail.store(0, Ordering::SeqCst);
    let reconciled = owner.begin(request()).await?;
    assert_eq!(reconciled, stored[0]);
    assert_eq!(reconciled.audit, audit(2));
    assert_eq!(
        owner.consume(action(&reconciled, 3)).await?.state,
        ApprovalLifecycle2::Reserved
    );
    Ok(())
}

#[tokio::test]
async fn fresh_prompt_cannot_return_a_swallowed_unaudited_human_decision() -> Result<()> {
    swallowed_reentrant_audit_failure(false).await
}

#[tokio::test]
async fn resumed_prompt_cannot_return_a_swallowed_unaudited_human_decision() -> Result<()> {
    swallowed_reentrant_audit_failure(true).await
}

#[tokio::test]
async fn fresh_and_resumed_prompt_reconcile_a_lost_decision_audit_acknowledgement() -> Result<()> {
    for resume in [false, true] {
        let f = Arc::new(Fixture::default());
        let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
        if resume {
            f.fail.store(3, Ordering::SeqCst);
            assert!(owner.begin(request()).await.is_err());
            f.fail.store(0, Ordering::SeqCst);
        }
        *f.reentrant.lock().map_err(|_| Error::Unavailable)? = Some(Arc::downgrade(&owner));
        f.swallow_decision_audit_failure.store(2, Ordering::SeqCst);
        let winner = owner.begin(request()).await?;
        assert_eq!(winner.state, ApprovalLifecycle2::Approved);
        assert_eq!(winner.version, 2);
        assert_eq!(winner.audit, audit(2));
        let approvals = f
            .audits
            .lock()
            .map_err(|_| Error::Unavailable)?
            .iter()
            .filter(|row| row.state == ApprovalLifecycle2::Approved)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(approvals, vec![winner.clone(), winner]);
        assert_eq!(
            f.audit_receipts
                .lock()
                .map_err(|_| Error::Unavailable)?
                .len(),
            2
        );
    }
    Ok(())
}

#[path = "automatic_tests.rs"]
mod automatic_tests;
#[path = "judge_matrix_tests.rs"]
mod judge_matrix_tests;

#[tokio::test]
async fn source_expiring_during_audit_never_poison_durable_subject_rows() -> Result<()> {
    for choice in [1, 2] {
        let f = Arc::new(Fixture::default());
        f.choice.store(choice, Ordering::SeqCst);
        let clock = Arc::new(TestClock::default());
        let owner = engine(f.clone(), clock.clone())?;
        let mut input = request();
        input.request.caller.flow = Some("reviewed-flow".into());
        let pending = owner.begin(input.clone()).await?;
        let source = owner.decide(decision(&pending)).await?;
        *f.advance_source_audit
            .lock()
            .map_err(|_| Error::Unavailable)? = Some((clock, source.expires_at_ms));
        input.request.caller.call_id = "expired-source-execution".into();
        input.audit = audit(3);
        assert!(owner.begin(input.clone()).await.is_err());
        assert_eq!(
            f.rows.lock().map_err(|_| Error::Unavailable)?.len(),
            1,
            "no invalid derived CAS"
        );
        input.request.caller.call_id = "future-independent-execution".into();
        input.request.call.tool = "independent_tool".into();
        let future = owner.begin(input).await?;
        assert_eq!(future.state, ApprovalLifecycle2::Pending);
        assert!(future.created_at_ms < future.expires_at_ms);
    }
    Ok(())
}
#[tokio::test]
async fn sandbox_host_network_requires_exact_authenticated_human_once_despite_auto_all()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let mut cfg = config();
    cfg.scopes[0].auto_approve_all = true;
    cfg.scopes[0].require_approval = false;
    let owner = Engine::new(
        cfg,
        f.clone(),
        clock,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    let mut begin = request();
    begin.request.call.tool = "sandbox_host_network".into();
    begin.request.call.checks = vec![Check::Unknown {
        description: "sandbox_host_network".into(),
    }];
    let row = owner.begin(begin.clone()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert!(row.judge.is_none());
    assert!(row.attribution.is_none());
    let approved = owner.decide(decision(&row)).await?;
    assert!(approved.decision_ticket_sha256.is_some());
    let mut consume = action(&row, 3);
    consume.request = begin.request.clone();
    let reserved = owner.consume(consume.clone()).await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    assert!(owner.consume(consume).await.is_err());
    let mut other = begin;
    other.request.caller.call_id = "different-plan".into();
    other.audit = audit(4);
    let row = owner.begin(other).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    f.choice.store(1, Ordering::SeqCst);
    owner
        .decide(DecideRequest2 {
            audit: audit(5),
            ..decision(&row)
        })
        .await?;
    let mut consume = action(&row, 6);
    consume.request.call.tool = "sandbox_host_network".into();
    consume.request.call.checks = vec![Check::Unknown {
        description: "sandbox_host_network".into(),
    }];
    consume.request.caller.call_id = "different-plan".into();
    assert!(owner.consume(consume).await.is_err());
    Ok(())
}

#[tokio::test]
async fn generic_native_label_cannot_bootstrap_authority_under_auto_all() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let mut cfg = config();
    cfg.scopes[0].auto_approve_all = true;
    let owner = Engine::new(
        cfg,
        fixture.clone(),
        clock,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    let mut req = request();
    req.request.call.tool = "native_secret_grant".into();
    assert!(
        owner.begin(req).await.is_err(),
        "generic label must not create native authority"
    );
    assert!(
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}

fn native_request() -> EvaluateApprovalRequest2 {
    let mut req = request();
    req.request.call.tool = "native_secret_grant".into();
    req.request.caller.call_id = format!("native-{}", "c".repeat(64));
    req.request.call.arguments_json =
        format!("{{\"native_authorization_v1\":\"{}\"}}", "c".repeat(64));
    req.request.call.checks = vec![Check::Unknown {
        description: "native-master-authority".into(),
    }];
    req.summary = "native master grant".into();
    req
}
fn native_action(row: &ApprovalRow2) -> ApprovalActionRequest2 {
    let mut req = action(row, 3);
    req.request = native_request().request;
    req
}
#[tokio::test]
async fn native_grants_require_real_once_decision_and_exact_consumption_receipt() -> Result<()> {
    for automatic in [true, false] {
        let f = Arc::new(Fixture::default());
        let c = Arc::new(TestClock::default());
        c.wall.store(1000, Ordering::SeqCst);
        let mut cfg = config();
        cfg.scopes[0].auto_approve_all = automatic;
        cfg.scopes[0].require_approval = false;
        let owner = Engine::new(
            cfg,
            f.clone(),
            c,
            Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
        )?;
        let row = owner.begin_native_grant(native_request(), 2000).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending);
        assert!(row.judge.is_none());
        assert_eq!(row.expires_at_ms, 2000);
        assert!(
            owner
                .consume_native_grant(native_action(&row))
                .await
                .is_err()
        );
        assert!(owner.consume(native_action(&row)).await.is_err());
        f.choice.store(1, Ordering::SeqCst);
        assert!(owner.decide(decision(&row)).await.is_err());
        f.choice.store(2, Ordering::SeqCst);
        assert!(owner.decide(decision(&row)).await.is_err());
        f.choice.store(0, Ordering::SeqCst);
        let mut wrong = decision(&row);
        wrong.decision_ticket.clear();
        assert!(owner.decide(wrong).await.is_err());
        let approved = owner.decide(decision(&row)).await?;
        assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
        let (reserved, receipt) = owner.consume_native_grant(native_action(&row)).await?;
        assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
        let receipt = receipt.into_receipt();
        assert_eq!(receipt.events[0].event_id, reserved.audit.event_id);
        assert_eq!(receipt.new_tail, 3);
        assert!(
            owner
                .consume_native_grant(native_action(&row))
                .await
                .is_err()
        );
        assert_eq!(
            *f.order.lock().map_err(|_| Error::Unavailable)?,
            vec![
                "cas", "audit", "prompt", "audit", "audit", "audit", "audit", "cas", "audit",
                "audit", "cas", "audit", "audit", "audit"
            ]
        );
    }
    Ok(())
}
#[tokio::test]
async fn native_expired_unavailable_cas_denies_before_retrying_durable_mutation() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    c.wall.store(1000, Ordering::SeqCst);
    let owner = engine(f.clone(), c.clone())?;
    *f.expire_unavailable_cas
        .lock()
        .map_err(|_| Error::Unavailable)? = Some((c, 1100));
    assert!(
        owner
            .begin_native_grant(native_request(), 1100)
            .await
            .is_err()
    );
    assert_eq!(f.cas_calls.load(Ordering::SeqCst), 1);
    assert!(f.rows.lock().map_err(|_| Error::Unavailable)?.is_empty());
    assert!(f.order.lock().map_err(|_| Error::Unavailable)?.is_empty());
    Ok(())
}
async fn native_second_load_invalidates_without_side_effects(fault: u8) -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    c.wall.store(1000, Ordering::SeqCst);
    c.mono.store(100, Ordering::SeqCst);
    let owner = Arc::new(engine(f.clone(), c.clone())?);
    f.pause_nth_load.store(2, Ordering::SeqCst);
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.begin_native_grant(native_request(), 1100).await })
    };
    f.loaded.notified().await;
    assert_eq!(f.load_calls.load(Ordering::SeqCst), 2);
    match fault {
        0 => c.wall.store(1100, Ordering::SeqCst),
        1 => c.wall.store(999, Ordering::SeqCst),
        2 => c.mono.store(99, Ordering::SeqCst),
        3 => c.wall_failed.store(1, Ordering::SeqCst),
        4 => c.mono.store(200, Ordering::SeqCst),
        _ => owner.advance_generation(4)?,
    }
    f.release_load.notify_one();
    assert!(task.await.map_err(|_| Error::Unavailable)?.is_err());
    assert_eq!(f.cas_calls.load(Ordering::SeqCst), 0);
    assert!(f.rows.lock().map_err(|_| Error::Unavailable)?.is_empty());
    assert!(f.order.lock().map_err(|_| Error::Unavailable)?.is_empty());
    assert!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}
#[tokio::test]
async fn native_second_load_exact_deadline_denies_before_any_durable_mutation() -> Result<()> {
    native_second_load_invalidates_without_side_effects(0).await
}
#[tokio::test]
async fn native_second_load_clock_faults_deny_before_any_durable_mutation() -> Result<()> {
    for fault in 1..=4 {
        native_second_load_invalidates_without_side_effects(fault).await?;
    }
    Ok(())
}
#[tokio::test]
async fn native_second_load_generation_change_denies_before_any_durable_mutation() -> Result<()> {
    native_second_load_invalidates_without_side_effects(5).await
}
#[tokio::test]
async fn native_fixed_deadline_survives_load_delay_and_retry_without_extension() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    c.wall.store(1000, Ordering::SeqCst);
    let owner = Arc::new(engine(f.clone(), c.clone())?);
    f.pause_load.store(1, Ordering::SeqCst);
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.begin_native_grant(native_request(), 2000).await })
    };
    f.loaded.notified().await;
    c.wall.store(1700, Ordering::SeqCst);
    f.release_load.notify_one();
    let row = task.await.map_err(|_| Error::Unavailable)??;
    assert_eq!(row.expires_at_ms, 2000);
    assert_eq!(owner.begin_native_grant(native_request(), 2000).await?, row);
    assert!(
        owner
            .begin_native_grant(native_request(), 2200)
            .await
            .is_err()
    );
    c.wall.store(2000, Ordering::SeqCst);
    assert!(
        owner
            .begin_native_grant(native_request(), 2000)
            .await
            .is_err()
    );
    assert!(owner.decide(decision(&row)).await.is_err());
    assert!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}
#[tokio::test]
async fn native_late_load_rollback_ceilings_and_cron_fail_closed() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    c.wall.store(1000, Ordering::SeqCst);
    let owner = Arc::new(engine(f.clone(), c.clone())?);
    assert!(
        owner
            .begin_native_grant(native_request(), 301_001)
            .await
            .is_err()
    );
    let mut cron = native_request();
    cron.request.caller.origin = Origin::Cron;
    assert!(owner.begin_native_grant(cron, 2000).await.is_err());
    let mut sub = native_request();
    sub.request.caller.origin = Origin::SubAgent;
    assert!(owner.begin_native_grant(sub, 181_001).await.is_err());
    f.pause_load.store(1, Ordering::SeqCst);
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.begin_native_grant(native_request(), 2000).await })
    };
    f.loaded.notified().await;
    c.wall.store(2000, Ordering::SeqCst);
    f.release_load.notify_one();
    assert!(task.await.map_err(|_| Error::Unavailable)?.is_err());
    assert!(f.rows.lock().map_err(|_| Error::Unavailable)?.is_empty());
    c.wall.store(1900, Ordering::SeqCst);
    assert!(
        owner
            .begin_native_grant(native_request(), 2100)
            .await
            .is_err()
    );
    c.wall.store(2200, Ordering::SeqCst);
    assert!(
        owner
            .begin_native_grant(native_request(), 2300)
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn native_store_label_and_forged_human_snapshot_cannot_replace_private_provenance()
-> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    let owner = engine(f.clone(), c.clone())?;
    let row = owner.begin_native_grant(native_request(), 1000).await?;
    let mut forged = row.clone();
    forged.version = 2;
    forged.state = ApprovalLifecycle2::Approved;
    forged.choice = Some(ApprovalChoice2::Once);
    forged.attribution = Some("human".into());
    forged.decision_ticket_sha256 = Some("e".repeat(64));
    f.rows
        .lock()
        .map_err(|_| Error::Unavailable)?
        .insert(row.request_id.clone(), binding::envelope(&forged)?);
    assert!(
        owner
            .consume_native_grant(native_action(&row))
            .await
            .is_err()
    );
    assert!(owner.decide(decision(&row)).await.is_err());
    assert!(
        owner
            .begin_native_grant(native_request(), 1000)
            .await
            .is_err()
    );
    let restarted = engine(f.clone(), c)?;
    assert!(
        restarted
            .begin_native_grant(native_request(), 1000)
            .await
            .is_err()
    );
    assert!(
        restarted
            .consume_native_grant(native_action(&row))
            .await
            .is_err()
    );
    // Metadata can still be read; orphan native rows cannot poison unrelated tool approvals.
    assert_eq!(restarted.list(&request().scope_id).await?.len(), 1);
    assert!(restarted.begin(request()).await.is_ok());
    Ok(())
}
#[tokio::test]
async fn native_receipt_failure_generation_change_and_substitution_never_ack_authority()
-> Result<()> {
    for mode in [1, 2] {
        let f = Arc::new(Fixture::default());
        let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
        let row = owner.begin_native_grant(native_request(), 1000).await?;
        owner.decide(decision(&row)).await?;
        f.native_receipt_mode.store(mode, Ordering::SeqCst);
        assert!(
            owner
                .consume_native_grant(native_action(&row))
                .await
                .is_err()
        );
        f.native_receipt_mode.store(0, Ordering::SeqCst);
        assert!(
            owner
                .consume_native_grant(native_action(&row))
                .await
                .is_err()
        );
    }
    let f = Arc::new(Fixture::default());
    let owner = engine(f, Arc::new(TestClock::default()))?;
    let row = owner.begin_native_grant(native_request(), 1000).await?;
    owner.decide(decision(&row)).await?;
    let mut changed = native_action(&row);
    changed.request.call.arguments_json = "{}".into();
    assert!(owner.consume_native_grant(changed).await.is_err());
    owner.advance_generation(2)?;
    assert!(
        owner
            .consume_native_grant(native_action(&row))
            .await
            .is_err()
    );
    assert!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn native_provenance_admission_bounds_rejected_creations_and_reclaims_expiry() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let c = Arc::new(TestClock::default());
    let owner = engine(f.clone(), c.clone())?;
    for index in 0..32 {
        let mut req = native_request();
        let commitment = format!("{:064x}", index + 1);
        req.request.caller.call_id = format!("native-{commitment}");
        req.request.call.arguments_json =
            format!("{{\"native_authorization_v1\":\"{commitment}\"}}");
        owner.begin_native_grant(req, 1000).await?;
    }
    for index in 32..96 {
        let mut req = native_request();
        let commitment = format!("{:064x}", index + 1);
        req.request.caller.call_id = format!("native-{commitment}");
        req.request.call.arguments_json =
            format!("{{\"native_authorization_v1\":\"{commitment}\"}}");
        assert!(owner.begin_native_grant(req, 1000).await.is_err());
    }
    assert_eq!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len(),
        32
    );
    assert_eq!(f.rows.lock().map_err(|_| Error::Unavailable)?.len(), 32);
    assert!(
        owner
            .creations
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len()
            <= 1
    );
    c.wall.store(1000, Ordering::SeqCst);
    let mut fresh = native_request();
    fresh.request.caller.call_id = format!("native-{}", "d".repeat(64));
    fresh.request.call.arguments_json =
        format!("{{\"native_authorization_v1\":\"{}\"}}", "d".repeat(64));
    assert!(owner.begin_native_grant(fresh, 2000).await.is_ok());
    assert_eq!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .len(),
        1
    );
    Ok(())
}
#[tokio::test]
async fn native_cancellation_before_admission_and_changed_nonce_scope_or_policy_deny() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let owner = Arc::new(engine(f.clone(), Arc::new(TestClock::default()))?);
    f.pause_load.store(1, Ordering::SeqCst);
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.begin_native_grant(native_request(), 1000).await })
    };
    f.loaded.notified().await;
    task.abort();
    assert!(task.await.is_err());
    assert!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    assert!(f.rows.lock().map_err(|_| Error::Unavailable)?.is_empty());
    let row = owner.begin_native_grant(native_request(), 1000).await?;
    for field in 0..3 {
        let mut changed = row.clone();
        match field {
            0 => changed.nonce = "e".repeat(32),
            1 => changed.binding.policy_ref = "e".repeat(64),
            _ => changed.binding.scope.user = "e".repeat(64),
        }
        f.rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .insert(row.request_id.clone(), binding::envelope(&changed)?);
        assert!(owner.decide(decision(&row)).await.is_err());
        assert!(
            owner
                .consume_native_grant(native_action(&row))
                .await
                .is_err()
        );
    }
    Ok(())
}

#[derive(Debug)]
struct GenericOnlyPorts(Arc<Fixture>);
#[async_trait::async_trait]
impl Ports for GenericOnlyPorts {
    async fn load(&self, r: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        self.0.load(r).await
    }
    async fn cas(&self, r: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.0.cas(r).await
    }
    async fn prompt(&self, r: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.0.prompt(r).await
    }
    async fn human(&self, r: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        self.0.human(r).await
    }
    async fn audit(&self, r: ApprovalRow2) -> Result<()> {
        self.0.audit(r).await
    }
}
#[tokio::test]
async fn generic_successful_audit_port_cannot_fabricate_native_acknowledgement() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let owner = Engine::new(
        config(),
        Arc::new(GenericOnlyPorts(f)),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(
        owner
            .begin_native_grant(native_request(), 1000)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn native_safe_correlation_origin_and_registered_subject_cannot_be_substituted() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let owner = engine(f.clone(), Arc::new(TestClock::default()))?;
    for field in 0..5 {
        let mut req = native_request();
        match field {
            0 => req.request.caller.call_id = "copied-public-label".into(),
            1 => req.request.call.arguments_json = "{}".into(),
            2 => req.scope_id = "f".repeat(32),
            3 => req.request.caller.agent = "other-agent".into(),
            _ => req.ttl_ms = Some(1000),
        }
        assert!(owner.begin_native_grant(req, 1000).await.is_err());
    }
    assert!(f.rows.lock().map_err(|_| Error::Unavailable)?.is_empty());
    assert!(f.order.lock().map_err(|_| Error::Unavailable)?.is_empty());
    Ok(())
}
#[derive(Debug)]
struct NativeFailingClock {
    failed: std::sync::atomic::AtomicBool,
}
impl Clock for NativeFailingClock {
    fn wall_ms(&self) -> Option<u64> {
        (!self.failed.load(Ordering::SeqCst)).then_some(1000)
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}
#[tokio::test]
async fn native_clock_failure_closes_existing_provenance_permanently() -> Result<()> {
    let clock = Arc::new(NativeFailingClock {
        failed: std::sync::atomic::AtomicBool::new(false),
    });
    let f = Arc::new(Fixture::default());
    let owner = Engine::new(
        config(),
        f,
        clock.clone(),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    let row = owner.begin_native_grant(native_request(), 2000).await?;
    clock.failed.store(true, Ordering::SeqCst);
    assert!(owner.decide(decision(&row)).await.is_err());
    clock.failed.store(false, Ordering::SeqCst);
    assert!(
        owner
            .begin_native_grant(native_request(), 2000)
            .await
            .is_err()
    );
    assert!(
        owner
            .native_intents
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}

#[derive(Debug)]
struct NativeAuditOnlyPorts(Arc<Fixture>);
#[async_trait::async_trait]
impl Ports for NativeAuditOnlyPorts {
    async fn load(&self, r: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        self.0.load(r).await
    }
    async fn cas(&self, r: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.0.cas(r).await
    }
    async fn prompt(&self, r: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.0.prompt(r).await
    }
    async fn human(&self, r: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        self.0.human(r).await
    }
    async fn audit(&self, _r: ApprovalRow2) -> Result<()> {
        std::future::ready(Err(Error::Denied)).await
    }
    async fn native_audit(&self, r: ApprovalRow2) -> Result<NativeAuditAcknowledgement> {
        self.0.native_audit(r).await
    }
}
#[tokio::test]
async fn redactor_matching_native_label_cannot_route_its_phases_to_generic_audit() -> Result<()> {
    let mut redactor = RedactorConfig::default();
    redactor
        .secrets
        .push(tinysecurity_bus::Secret("native_secret_grant".into()));
    let owner = Engine::new(
        config(),
        Arc::new(NativeAuditOnlyPorts(Arc::new(Fixture::default()))),
        Arc::new(TestClock::default()),
        Redactor::new(&redactor).map_err(|_| Error::Invalid)?,
    )?;
    let pending = owner.begin_native_grant(native_request(), 1000).await?;
    assert_eq!(pending.tool_name, "native_secret_grant");
    owner.decide(decision(&pending)).await?;
    assert!(
        owner
            .consume_native_grant(native_action(&pending))
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn expired_native_rows_resolve_terminally_without_restoring_authority() -> Result<()> {
    for approved in [false, true] {
        for cancel in [false, true] {
            let f = Arc::new(Fixture::default());
            let c = Arc::new(TestClock::default());
            let owner = engine(f.clone(), c.clone())?;
            let pending = owner.begin_native_grant(native_request(), 1000).await?;
            let row = if approved {
                owner.decide(decision(&pending)).await?
            } else {
                pending
            };
            c.wall.store(1000, Ordering::SeqCst);
            owner.prune_native(1000, row.binding.generation)?;
            let req = ApprovalRecordRequest2 {
                scope_id: native_request().scope_id,
                request_id: row.request_id.clone(),
                audit: audit(9),
            };
            let terminal = if cancel {
                owner.cancel(req.clone()).await?
            } else {
                owner.expire(req.clone()).await?
            };
            assert_eq!(
                terminal.state,
                if cancel {
                    ApprovalLifecycle2::Cancelled
                } else {
                    ApprovalLifecycle2::Expired
                }
            );
            assert_eq!(terminal.version, row.version + 1);
            assert!(owner.decide(decision(&row)).await.is_err());
            assert!(
                owner
                    .consume_native_grant(native_action(&row))
                    .await
                    .is_err()
            );
            let retry = if cancel {
                owner.cancel(req).await?
            } else {
                owner.expire(req).await?
            };
            assert_eq!(retry, terminal);
        }
    }
    Ok(())
}

async fn redacted_device_label_requires_once(choice: u64) -> Result<()> {
    {
        let fixture = Arc::new(Fixture::default());
        let redactor = RedactorConfig {
            secrets: vec![
                tinysecurity_bus::Secret("device_crypto".into()),
                tinysecurity_bus::Secret("private-tool-label".into()),
            ],
        };
        let owner = Engine::new(
            config(),
            fixture.clone(),
            Arc::new(TestClock::default()),
            Redactor::new(&redactor).map_err(|_| Error::Invalid)?,
        )?;
        let mut req = request();
        req.request.call.tool = "device_crypto".into();
        req.request.caller.flow = Some("registered-flow".into());
        let row = owner.begin(req.clone()).await?;
        fixture.choice.store(choice, Ordering::SeqCst);
        assert_eq!(owner.decide(decision(&row)).await, Err(Error::Denied));
        assert_eq!(row.tool_name, "device_crypto");
        fixture.choice.store(0, Ordering::SeqCst);
        let approved = owner.decide(decision(&row)).await?;
        assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
        assert!(approved.decision_ticket_sha256.is_some());
        let mut consume = action(&row, 3);
        consume.request = req.request;
        owner.consume(consume).await?;

        let mut generic = request();
        generic.request.call.tool = "private-tool-label".into();
        generic.request.caller.call_id = "generic-label".into();
        let generic_row = owner.begin(generic).await?;
        assert_ne!(generic_row.tool_name, "private-tool-label");
        assert!(
            !serde_json::to_string(&generic_row)
                .map_err(|_| Error::Invalid)?
                .contains("private-tool-label")
        );
    }
    Ok(())
}

#[tokio::test]
async fn redacted_device_labels_cannot_accept_tool_decisions() -> Result<()> {
    redacted_device_label_requires_once(1).await
}
#[tokio::test]
async fn redacted_device_labels_cannot_accept_flow_decisions() -> Result<()> {
    redacted_device_label_requires_once(2).await
}

fn app_io_request() -> EvaluateApprovalRequest2 {
    let mut req = native_request();
    req.request.call.tool = "native_app_io_grant".into();
    req.request.caller.call_id = format!("native-app-io-{}", "c".repeat(64));
    req.request.call.arguments_json = format!(
        "{{\"native_app_io_authorization_v1\":\"{}\"}}",
        "c".repeat(64)
    );
    req.request.call.checks = vec![Check::Unknown {
        description: "native-app-io-authority".into(),
    }];
    req.summary = "native app io grant".into();
    req
}

#[tokio::test]
async fn app_io_authority_cannot_begin_through_generic_auto_policy() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    clock.wall.store(1000, Ordering::SeqCst);
    let mut cfg = config();
    cfg.scopes[0].auto_approve_all = true;
    let owner = Engine::new(
        cfg,
        fixture.clone(),
        clock,
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(owner.begin(app_io_request()).await.is_err());
    assert!(
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}

fn app_io_action(row: &ApprovalRow2) -> ApprovalActionRequest2 {
    let mut req = action(row, 3);
    req.request = app_io_request().request;
    req
}

#[tokio::test]
async fn app_io_requires_native_human_once_despite_automatic_policy() -> Result<()> {
    for automatic in [false, true] {
        let fixture = Arc::new(Fixture::default());
        let clock = Arc::new(TestClock::default());
        let mut cfg = config();
        cfg.scopes[0].auto_approve_all = automatic;
        cfg.scopes[0].require_approval = false;
        let owner = Engine::new(
            cfg,
            fixture.clone(),
            clock,
            Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
        )?;
        let mut req = app_io_request();
        req.summary = "private-name /private/resource plaintext-value".into();
        let pending = owner.begin_native_app_io(req, 1000).await?;
        assert_eq!(pending.state, ApprovalLifecycle2::Pending);
        assert_eq!(pending.tool_name, "native_app_io_grant");
        assert_eq!(pending.summary, "native app io grant");
        assert_eq!(pending.expires_at_ms, 1000);
        assert!(pending.judge.is_none());
        assert!(
            owner
                .consume_native_app_io(app_io_action(&pending))
                .await
                .is_err()
        );
        assert!(
            owner
                .begin_native_grant(app_io_request(), 1000)
                .await
                .is_err()
        );
        assert!(
            owner
                .begin_native_app_io(native_request(), 1000)
                .await
                .is_err()
        );
        for choice in [1, 2] {
            fixture.choice.store(choice, Ordering::SeqCst);
            assert!(owner.decide(decision(&pending)).await.is_err());
        }
        fixture.choice.store(0, Ordering::SeqCst);
        owner.decide(decision(&pending)).await?;
        assert!(owner.consume(app_io_action(&pending)).await.is_err());
        assert!(
            owner
                .consume_native_grant(app_io_action(&pending))
                .await
                .is_err()
        );
        let grant = owner.consume_native_app_io(app_io_action(&pending)).await?;
        assert_eq!(format!("{grant:?}"), "NativeAppIoGrant([REDACTED])");
        let (reserved, acknowledgement) = grant.into_verified_consumption(
            &app_io_request().scope_id,
            &app_io_request().request,
            1,
            1000,
        )?;
        assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
        assert_eq!(reserved.choice, Some(ApprovalChoice2::Once));
        assert!(reserved.decision_ticket_sha256.is_some());
        let scope = acknowledgement.expected_scope().clone();
        let receipt = acknowledgement.into_receipt();
        assert_eq!(receipt.scope, scope);
        assert_eq!(receipt.events[0].event_id, reserved.audit.event_id);
        assert_eq!(receipt.new_tail, 3);
        assert!(
            owner
                .consume_native_app_io(app_io_action(&pending))
                .await
                .is_err()
        );
        assert!(
            owner
                .record_execution(RecordExecutionRequest2 {
                    action: app_io_action(&pending),
                    outcome: ExecutionOutcome::Succeeded
                })
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn app_io_consumed_authority_verifies_exact_original_owner_binding() -> Result<()> {
    for field in 0..12 {
        let owner = engine(Arc::new(Fixture::default()), Arc::new(TestClock::default()))?;
        let row = owner.begin_native_app_io(app_io_request(), 1000).await?;
        owner.decide(decision(&row)).await?;
        let grant = owner.consume_native_app_io(app_io_action(&row)).await?;
        let mut expected = app_io_request();
        let mut generation = 1;
        let mut deadline = 1000;
        match field {
            0 => expected.scope_id = "f".repeat(32),
            1 => generation = 2,
            2 => deadline = 1001,
            3 => expected.request.caller.call_id = "substituted-action".into(),
            4 => expected.request.caller.origin = Origin::Copilot,
            5 => {
                expected.request.call.arguments_json = format!(
                    "{{\"native_app_io_authorization_v1\":\"{}\"}}",
                    "d".repeat(64)
                );
                expected.request.caller.call_id = format!("native-app-io-{}", "d".repeat(64));
            }
            6 => expected.request = native_request().request,
            7 => expected.request.caller.agent = "different-agent".into(),
            8 => expected.request.caller.thread = Some("different-thread".into()),
            9 => expected.request.caller.flow = Some("different-flow".into()),
            10 => expected.request.caller.tier = AccessTier::Read,
            _ => expected.request.call.checks = vec![Check::LocalDiagnostic {}],
        }
        assert!(
            grant
                .into_verified_consumption(
                    &expected.scope_id,
                    &expected.request,
                    generation,
                    deadline
                )
                .is_err(),
            "changed field {field}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn app_io_safe_wrapper_rejects_substitutions_before_persistence() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let owner = engine(fixture.clone(), Arc::new(TestClock::default()))?;
    for field in 0..11 {
        let mut req = app_io_request();
        match field {
            0 => req.request.caller.call_id = "native-app-io-unkeyed".into(),
            1 => req.request.call.arguments_json = "{}".into(),
            2 => {
                req.request.call.arguments_json =
                    format!("{{\"native_authorization_v1\":\"{}\"}}", "c".repeat(64));
            }
            3 => {
                req.request.call.arguments_json = format!(
                    "{{\"native_app_io_authorization_v1\":\"{}\",\"name\":\"private\"}}",
                    "c".repeat(64)
                );
            }
            4 => {
                req.request.call.arguments_json = format!(
                    "{{\"native_app_io_authorization_v1\":\"{}\"}}",
                    "x".repeat(64)
                );
            }
            5 => req.scope_id = "f".repeat(32),
            6 => req.request.caller.agent = "other-agent".into(),
            7 => req.request.caller.origin = Origin::Cron,
            8 => req.ttl_ms = Some(1000),
            9 => {
                req.request.call.checks = vec![Check::Path {
                    path: "/private/name".into(),
                    write: true,
                }];
            }
            _ => req.request.call.tool = "arbitrary-native-grant".into(),
        }
        assert!(owner.begin_native_app_io(req, 1000).await.is_err());
    }
    assert!(
        owner
            .begin_native_app_io(app_io_request(), 0)
            .await
            .is_err()
    );
    assert!(
        owner
            .begin_native_app_io(app_io_request(), 300_001)
            .await
            .is_err()
    );
    assert!(
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    assert!(
        fixture
            .order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn app_io_native_deadline_cannot_renew_and_consumption_rechecks_context() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture.clone(), clock.clone())?;
    let row = owner.begin_native_app_io(app_io_request(), 1000).await?;
    assert_eq!(
        owner.begin_native_app_io(app_io_request(), 1000).await?,
        row
    );
    assert!(
        owner
            .begin_native_app_io(app_io_request(), 1001)
            .await
            .is_err()
    );
    owner.decide(decision(&row)).await?;
    for field in 0..6 {
        let mut req = app_io_action(&row);
        match field {
            0 => req.scope_id = "f".repeat(32),
            1 => req.request.caller.origin = Origin::Copilot,
            2 => req.request.caller.thread = Some("different-thread".into()),
            3 => {
                req.request.call.arguments_json = format!(
                    "{{\"native_app_io_authorization_v1\":\"{}\"}}",
                    "d".repeat(64)
                );
                req.request.caller.call_id = format!("native-app-io-{}", "d".repeat(64));
            }
            4 => req.request_id = "f".repeat(32),
            _ => req.audit.generation = 2,
        }
        assert!(owner.consume_native_app_io(req).await.is_err());
    }
    clock.mono.store(1000, Ordering::SeqCst);
    assert!(
        owner
            .consume_native_app_io(app_io_action(&row))
            .await
            .is_err()
    );
    assert!(
        owner
            .begin_native_app_io(app_io_request(), 2000)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn app_io_requires_actual_native_ack_and_retains_once_after_audit_failure() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let generic = Engine::new(
        config(),
        Arc::new(GenericOnlyPorts(fixture)),
        Arc::new(TestClock::default()),
        Redactor::new(&RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(
        generic
            .begin_native_app_io(app_io_request(), 1000)
            .await
            .is_err()
    );
    for mode in [1, 2] {
        let fixture = Arc::new(Fixture::default());
        let owner = engine(fixture.clone(), Arc::new(TestClock::default()))?;
        let row = owner.begin_native_app_io(app_io_request(), 1000).await?;
        owner.decide(decision(&row)).await?;
        fixture.native_receipt_mode.store(mode, Ordering::SeqCst);
        assert!(
            owner
                .consume_native_app_io(app_io_action(&row))
                .await
                .is_err()
        );
        fixture.native_receipt_mode.store(0, Ordering::SeqCst);
        assert!(
            owner
                .consume_native_app_io(app_io_action(&row))
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn app_io_provenance_is_not_recreated_by_restart_generation_or_serialized_rows() -> Result<()>
{
    for generation_change in [false, true] {
        let fixture = Arc::new(Fixture::default());
        let clock = Arc::new(TestClock::default());
        let owner = engine(fixture.clone(), clock.clone())?;
        let row = owner.begin_native_app_io(app_io_request(), 1000).await?;
        owner.decide(decision(&row)).await?;
        if generation_change {
            owner.advance_generation(2)?;
            assert!(
                owner
                    .consume_native_app_io(app_io_action(&row))
                    .await
                    .is_err()
            );
        } else {
            let restarted = engine(fixture, clock)?;
            assert!(
                restarted
                    .begin_native_app_io(app_io_request(), 1000)
                    .await
                    .is_err()
            );
            assert!(
                restarted
                    .consume_native_app_io(app_io_action(&row))
                    .await
                    .is_err()
            );
        }
    }
    let fixture = Arc::new(Fixture::default());
    let owner = engine(fixture.clone(), Arc::new(TestClock::default()))?;
    let row = owner.begin_native_app_io(app_io_request(), 1000).await?;
    let mut forged = row.clone();
    forged.state = ApprovalLifecycle2::Approved;
    forged.version += 1;
    forged.choice = Some(ApprovalChoice2::Once);
    forged.attribution = Some("auto:host-policy".into());
    fixture
        .rows
        .lock()
        .map_err(|_| Error::Unavailable)?
        .insert(forged.request_id.clone(), binding::envelope(&forged)?);
    assert!(
        owner
            .consume_native_app_io(app_io_action(&row))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn app_io_master_consent_cannot_supply_io_authority() -> Result<()> {
    let owner = engine(Arc::new(Fixture::default()), Arc::new(TestClock::default()))?;
    let master = owner.begin_native_grant(native_request(), 1000).await?;
    owner.decide(decision(&master)).await?;
    assert!(
        owner
            .consume_native_app_io(native_action(&master))
            .await
            .is_err()
    );
    assert!(
        owner
            .consume_native_app_io(app_io_action(&master))
            .await
            .is_err()
    );
    assert!(
        owner
            .consume_native_grant(native_action(&master))
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn app_io_rechecks_native_authority_after_actual_audit_await() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture.clone(), clock.clone())?;
    let row = owner.begin_native_app_io(app_io_request(), 1000).await?;
    owner.decide(decision(&row)).await?;
    *fixture
        .advance_source_audit
        .lock()
        .map_err(|_| Error::Unavailable)? = Some((clock, 1000));
    assert!(
        owner
            .consume_native_app_io(app_io_action(&row))
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get(&row.request_id)
            .ok_or(Error::Invalid)?
            .version,
        2,
        "audit expiry must prevent reservation CAS"
    );
    Ok(())
}

#[tokio::test]
async fn app_io_rows_cannot_supply_reusable_or_flow_authority() -> Result<()> {
    let owner = engine(Arc::new(Fixture::default()), Arc::new(TestClock::default()))?;
    let pending = owner.begin_native_app_io(app_io_request(), 1000).await?;
    let approved = owner.decide(decision(&pending)).await?;
    for choice in [ApprovalChoice2::Tool, ApprovalChoice2::Flow] {
        let mut row = approved.clone();
        row.choice = Some(choice);
        row.binding.caller.flow = Some("reviewed-flow".into());
        let bound = row.binding.clone();
        assert!(reusable_grant(&[row], &bound, 0).is_none());
    }
    assert!(
        owner
            .preauthorize_flow(PreauthorizeFlowRequest2 {
                scope_id: app_io_request().scope_id,
                flow_id: "reviewed-flow".into(),
                request_ids: vec![approved.request_id],
            })
            .await
            .is_err()
    );
    Ok(())
}
#[path = "engine_scopes_tests.rs"]
mod engine_scopes_tests;
