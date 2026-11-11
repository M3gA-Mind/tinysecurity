use super::*;
use tinyinference_decisions::{Answer, EvaluationRequest, EvaluationResponse, NoulAnswer, Usage};
use tinysecurity_bus::{JudgeConfig, JudgeOutcome2, JudgeProvider, Secret};
#[derive(Debug)]
struct Judge {
    qualified: AtomicU64,
    calls: AtomicU64,
    advance: Mutex<Option<std::sync::Weak<Engine>>>,
}
#[async_trait::async_trait]
impl tinysecurity_auto::JudgeClient for Judge {
    async fn evaluate(
        &self,
        _: &EvaluationRequest,
    ) -> tinysecurity_auto::Result<EvaluationResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(engine) = self
            .advance
            .lock()
            .map_err(|_| tinysecurity_auto::Error::Unavailable)?
            .take()
            .and_then(|engine| engine.upgrade())
        {
            engine
                .advance_generation(2)
                .map_err(|_| tinysecurity_auto::Error::Unavailable)?;
        }
        let intent = if self.qualified.load(Ordering::SeqCst) == 0 {
            0.1
        } else {
            1.0
        };
        Ok(EvaluationResponse {
            model: "jev-latest".into(),
            answers: [("intent", intent), ("reversible", 1.0), ("exfiltrate", 0.0)]
                .into_iter()
                .map(|(id, noul)| (id.into(), Answer::Noul(NoulAnswer { noul })))
                .collect(),
            usage: Usage::default(),
        })
    }
}
impl tinysecurity_auto::Clock for TestClock {
    fn milliseconds(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}
fn judge_config() -> JudgeConfig {
    JudgeConfig {
        credential: Some(Secret("fake-judge-key".into())),
        endpoint: "http://127.0.0.1:1/jev".into(),
        provider: JudgeProvider::TypeSafe,
        threshold_millis: 900,
        exfiltrate_millis: 100,
        thresholds: vec![],
        timeout_ms: 1000,
        origins: vec![Origin::Operator],
        max_requests: 10,
        budget_window_ms: 60_000,
        cache_entries: 0,
        cache_ttl_ms: 0,
    }
}
fn scorer(owner: &Engine, judge: Arc<Judge>, clock: Arc<TestClock>) -> Result<()> {
    let scorer = tinysecurity_auto::Engine::with_client(judge_config(), judge, clock)
        .map_err(|_| Error::Invalid)?;
    owner.replace_automatic(Some(Arc::new(scorer)))
}
fn judge(qualified: bool) -> Arc<Judge> {
    Arc::new(Judge {
        qualified: AtomicU64::new(u64::from(qualified)),
        calls: AtomicU64::new(0),
        advance: Mutex::new(None),
    })
}
#[tokio::test]
async fn retried_pending_creation_cannot_skip_human_delivery_when_new_scores_qualify() -> Result<()>
{
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture.clone(), clock.clone())?;
    let judge = judge(false);
    scorer(&owner, judge.clone(), clock)?;
    fixture.fail.store(1, Ordering::SeqCst);
    assert_eq!(owner.begin(request()).await, Err(Error::Unavailable));
    judge.qualified.store(1, Ordering::SeqCst);
    fixture.fail.store(3, Ordering::SeqCst);
    assert_eq!(
        owner.begin(request()).await,
        Err(Error::Unavailable),
        "original pending memo must still deliver a real prompt"
    );
    Ok(())
}
#[tokio::test]
async fn qualified_judge_requires_exact_durable_audit_before_one_shot_permission() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture.clone(), clock.clone())?;
    let judge = judge(true);
    scorer(&owner, judge.clone(), clock)?;
    fixture.fail.store(4, Ordering::SeqCst);
    assert_eq!(owner.begin(request()).await, Err(Error::Unavailable));
    assert!(
        !fixture
            .order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains(&"prompt")
    );
    fixture.fail.store(0, Ordering::SeqCst);
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:jev"));
    assert!(row.decision_ticket_sha256.is_none());
    assert_eq!(row.choice, Some(ApprovalChoice2::Once));
    let reserved = owner.consume(action(&row, 2)).await?;
    assert_eq!(reserved.state, ApprovalLifecycle2::Reserved);
    assert!(owner.consume(action(&row, 2)).await.is_err());
    assert_eq!(judge.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn generation_changes_during_judge_evaluation_never_persist_old_allow() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = Arc::new(engine(fixture.clone(), clock.clone())?);
    let judge = judge(true);
    *judge.advance.lock().map_err(|_| Error::Unavailable)? = Some(Arc::downgrade(&owner));
    scorer(&owner, judge, clock)?;
    assert_eq!(owner.begin(request()).await, Err(Error::Denied));
    assert!(
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
    );
    Ok(())
}
#[tokio::test]
async fn uncertain_judge_preserves_authenticated_human_and_unavailable_channel_denies() -> Result<()>
{
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = Arc::new(engine(fixture.clone(), clock.clone())?);
    scorer(&owner, judge(false), clock)?;
    fixture.fail.store(3, Ordering::SeqCst);
    assert_eq!(owner.begin(request()).await, Err(Error::Unavailable));
    fixture.fail.store(0, Ordering::SeqCst);
    *fixture.reentrant.lock().map_err(|_| Error::Unavailable)? = Some(Arc::downgrade(&owner));
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert!(row.decision_ticket_sha256.is_some());
    assert_eq!(
        row.judge.as_ref().ok_or(Error::Invalid)?.outcome,
        JudgeOutcome2::Uncertain
    );
    Ok(())
}
#[tokio::test]
async fn qualified_judge_is_never_invoked_for_sandbox_host_network_human_requirement() -> Result<()>
{
    let f = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(f, clock.clone())?;
    let judge = judge(true);
    scorer(&owner, judge.clone(), clock)?;
    let mut begin = request();
    begin.request.call.tool = "sandbox_host_network".into();
    begin.request.call.checks = vec![Check::Unknown {
        description: "sandbox_host_network".into(),
    }];
    let row = owner.begin(begin).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert!(row.judge.is_none());
    assert_eq!(judge.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn native_master_grant_never_calls_a_qualified_configured_judge() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture, clock.clone())?;
    let judge = judge(true);
    scorer(&owner, judge.clone(), clock)?;
    let row = owner.begin_native_grant(native_request(), 1000).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert!(row.judge.is_none());
    assert_eq!(judge.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn device_crypto_always_delivers_human_prompt_despite_qualified_judge() -> Result<()> {
    let f = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(f.clone(), clock.clone())?;
    let judge = judge(true);
    scorer(&owner, judge.clone(), clock)?;
    let mut req = request();
    req.request.call.tool = "device_crypto".into();
    let row = owner.begin(req).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert!(row.judge.is_none());
    assert_eq!(judge.calls.load(Ordering::SeqCst), 0);
    assert!(
        f.order
            .lock()
            .map_err(|_| Error::Unavailable)?
            .contains(&"prompt")
    );
    f.choice.store(1, Ordering::SeqCst);
    assert!(owner.decide(decision(&row)).await.is_err());
    f.choice.store(0, Ordering::SeqCst);
    let approved = owner.decide(decision(&row)).await?;
    assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
    assert!(approved.decision_ticket_sha256.is_some());
    let mut consume = action(&row, 3);
    consume.request.call.tool = "device_crypto".into();
    owner.consume(consume).await?;
    Ok(())
}

#[tokio::test]
async fn device_crypto_ignores_auto_approve_and_reusable_grants() -> Result<()> {
    for automatic in [false, true] {
        let fixture = Arc::new(Fixture::default());
        let clock = Arc::new(TestClock::default());
        let mut cfg = config();
        cfg.scopes[0].auto_approve_all = automatic;
        cfg.scopes[0].require_approval = !automatic;
        let owner = Engine::new(
            cfg,
            fixture.clone(),
            clock,
            Redactor::new(&tinysecurity_bus::RedactorConfig::default())
                .map_err(|_| Error::Invalid)?,
        )?;
        let mut req = request();
        req.request.call.tool = "device_crypto".into();
        let (bound, _, _) = binding::original(
            &owner.registration(&req.scope_id)?,
            &req.request,
            &owner.redactor()?,
        )?;
        let mut reusable = owner.begin(request()).await?;
        reusable.binding = bound;
        reusable.request_id = "f".repeat(32);
        reusable.state = ApprovalLifecycle2::Approved;
        reusable.choice = Some(ApprovalChoice2::Tool);
        reusable.attribution = Some("verified-human".into());
        reusable.decision_ticket_sha256 = Some("a".repeat(64));
        reusable.binding.call_sha256 = "e".repeat(64);
        fixture
            .rows
            .lock()
            .map_err(|_| Error::Unavailable)?
            .insert(reusable.request_id.clone(), binding::envelope(&reusable)?);
        let row = owner.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending);
        assert!(row.judge.is_none());
        assert!(row.decision_ticket_sha256.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn app_io_grant_never_uses_qualified_judge_or_reusable_reviewed_authority() -> Result<()> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture.clone(), clock.clone())?;
    let judge = judge(true);
    scorer(&owner, judge.clone(), clock)?;
    let mut generic = app_io_request();
    generic.request.call.tool = "generic_reviewed_action".into();
    generic.request.caller.call_id = "generic-action".into();
    let source = owner.begin(generic).await?;
    assert_eq!(source.state, ApprovalLifecycle2::Approved);
    assert_eq!(judge.calls.load(Ordering::SeqCst), 1);
    let io = owner.begin_native_app_io(app_io_request(), 1000).await?;
    assert_eq!(io.state, ApprovalLifecycle2::Pending);
    assert!(io.judge.is_none());
    assert_eq!(judge.calls.load(Ordering::SeqCst), 1);
    assert!(
        owner
            .consume_native_app_io(app_io_action(&io))
            .await
            .is_err()
    );
    let mut forged = io.clone();
    forged.version += 1;
    forged.state = ApprovalLifecycle2::Approved;
    forged.choice = Some(ApprovalChoice2::Once);
    forged.attribution = Some("auto:jev".into());
    forged.judge = source.judge;
    fixture
        .rows
        .lock()
        .map_err(|_| Error::Unavailable)?
        .insert(forged.request_id.clone(), binding::envelope(&forged)?);
    assert!(
        owner
            .consume_native_app_io(app_io_action(&io))
            .await
            .is_err()
    );
    Ok(())
}
