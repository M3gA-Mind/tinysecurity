use super::*;
use tinyinference_decisions::{Answer, EvaluationRequest, EvaluationResponse, NoulAnswer, Usage};
use tinysecurity_bus::{JudgeConfig, JudgeOutcome2, JudgeProvider, Secret};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Scores([f64; 3]),
    Fail,
    Malformed,
    Hang,
}
#[derive(Debug)]
struct Stub {
    mode: Mode,
    calls: AtomicU64,
}
#[async_trait::async_trait]
impl tinysecurity_auto::JudgeClient for Stub {
    async fn evaluate(
        &self,
        _: &EvaluationRequest,
    ) -> tinysecurity_auto::Result<EvaluationResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let scores = match self.mode {
            Mode::Scores(s) => s,
            Mode::Fail => return Err(tinysecurity_auto::Error::Unavailable),
            Mode::Malformed => [2.0, 1.0, 0.0],
            Mode::Hang => {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                [1.0, 1.0, 0.0]
            }
        };
        Ok(EvaluationResponse {
            model: "jev-latest".into(),
            answers: [
                ("intent", scores[0]),
                ("reversible", scores[1]),
                ("exfiltrate", scores[2]),
            ]
            .into_iter()
            .map(|(id, noul)| (id.into(), Answer::Noul(NoulAnswer { noul })))
            .collect(),
            usage: Usage::default(),
        })
    }
}
fn config(origins: Vec<Origin>, max_requests: u32) -> JudgeConfig {
    JudgeConfig {
        credential: Some(Secret("fake-judge-key".into())),
        endpoint: "http://127.0.0.1:1/jev".into(),
        provider: JudgeProvider::TypeSafe,
        threshold_millis: 900,
        exfiltrate_millis: 100,
        thresholds: vec![],
        timeout_ms: 50,
        origins,
        max_requests,
        budget_window_ms: 60_000,
        cache_entries: 0,
        cache_ttl_ms: 0,
    }
}
fn owner(
    mode: Mode,
    origins: Vec<Origin>,
    max_requests: u32,
) -> Result<(Engine, Arc<Fixture>, Arc<Stub>)> {
    let fixture = Arc::new(Fixture::default());
    let clock = Arc::new(TestClock::default());
    let owner = engine(fixture.clone(), clock.clone())?;
    let stub = Arc::new(Stub {
        mode,
        calls: AtomicU64::new(0),
    });
    let scorer =
        tinysecurity_auto::Engine::with_client(config(origins, max_requests), stub.clone(), clock)
            .map_err(|_| Error::Invalid)?;
    owner.replace_automatic(Some(Arc::new(scorer)))?;
    Ok((owner, fixture, stub))
}

#[tokio::test]
async fn every_non_qualifying_judge_outcome_falls_to_a_human_with_audited_evidence() -> Result<()> {
    let cases = [
        (Mode::Scores([0.5, 1.0, 0.0]), JudgeOutcome2::Uncertain),
        (Mode::Scores([1.0, 0.1, 0.0]), JudgeOutcome2::Uncertain),
        (Mode::Scores([1.0, 1.0, 0.5]), JudgeOutcome2::Uncertain),
        (Mode::Malformed, JudgeOutcome2::Invalid),
        (Mode::Fail, JudgeOutcome2::Unavailable),
        (Mode::Hang, JudgeOutcome2::Timeout),
    ];
    for (mode, expected) in cases {
        let (owner, fixture, stub) = owner(mode, vec![Origin::Operator], 10)?;
        let row = owner.begin(request()).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{mode:?}");
        assert!(
            row.attribution.is_none() && row.choice.is_none(),
            "{mode:?}"
        );
        assert!(row.decision_ticket_sha256.is_none());
        let evidence = row.judge.as_ref().ok_or(Error::Invalid)?;
        assert_eq!(evidence.outcome, expected, "{mode:?}");
        assert!(evidence.is_valid());
        assert_eq!(
            evidence.question_ids,
            ["intent", "reversible", "exfiltrate"]
        );
        assert_eq!(evidence.thresholds.intent, 900);
        assert_eq!(evidence.thresholds.reversible, 900);
        assert_eq!(evidence.thresholds.exfiltrate, 100);
        assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
        // The human prompt is delivered after the durable, audited pending row.
        assert_eq!(
            *fixture.order.lock().map_err(|_| Error::Unavailable)?,
            vec!["cas", "audit", "prompt"],
            "{mode:?}"
        );
        {
            let audited = fixture.audits.lock().map_err(|_| Error::Unavailable)?;
            assert_eq!(audited[0].judge.as_ref(), Some(evidence));
            assert_eq!(audited[0].attribution, None);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_missing_human_channel_denies_every_non_qualifying_judge_outcome() -> Result<()> {
    for mode in [
        Mode::Scores([0.1, 1.0, 0.0]),
        Mode::Malformed,
        Mode::Fail,
        Mode::Hang,
    ] {
        let (owner, fixture, _) = owner(mode, vec![Origin::Operator], 10)?;
        fixture.fail.store(3, Ordering::SeqCst);
        assert_eq!(owner.begin(request()).await, Err(Error::Unavailable));
    }
    Ok(())
}

#[tokio::test]
async fn budget_exhaustion_stops_requests_and_falls_to_a_human() -> Result<()> {
    let (owner, _, stub) = owner(Mode::Scores([1.0, 1.0, 0.0]), vec![Origin::Operator], 1)?;
    let first = owner.begin(request()).await?;
    assert_eq!(first.attribution.as_deref(), Some("auto:jev"));
    let mut second = request();
    second.request.caller.call_id = "execution-2".into();
    second.audit = audit(2);
    let row = owner.begin(second).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert_eq!(
        row.judge.as_ref().ok_or(Error::Invalid)?.outcome,
        JudgeOutcome2::Budget
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn judge_is_off_without_configuration_and_per_origin_opt_in_gates_requests() -> Result<()> {
    // No scorer installed: nothing is ever qualified and no evidence exists.
    let fixture = Arc::new(Fixture::default());
    let off = engine(fixture, Arc::new(TestClock::default()))?;
    let row = off.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending);
    assert!(row.judge.is_none());
    for origin in [Origin::Copilot, Origin::SubAgent, Origin::Saas] {
        let (owner, _, stub) = owner(Mode::Scores([1.0, 1.0, 0.0]), vec![Origin::Operator], 10)?;
        let mut req = request();
        req.request.caller.origin = origin.clone();
        let row = owner.begin(req).await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending, "{origin:?}");
        assert!(row.judge.is_none(), "{origin:?}");
        assert_eq!(stub.calls.load(Ordering::SeqCst), 0, "{origin:?}");
    }
    Ok(())
}

#[tokio::test]
async fn saas_needs_a_verified_prompt_even_when_a_qualified_judge_is_not_opted_in() -> Result<()> {
    let (owner, fixture, stub) = owner(Mode::Scores([1.0, 1.0, 0.0]), vec![Origin::Operator], 10)?;
    let mut saas = request();
    saas.request.caller.origin = Origin::Saas;
    fixture.fail.store(3, Ordering::SeqCst);
    assert_eq!(owner.begin(saas).await, Err(Error::Unavailable));
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn auto_approve_all_writes_an_audited_host_policy_row_before_permission() -> Result<()> {
    let mut cfg = config_with_auto_all();
    cfg.scopes[0].require_approval = false;
    let fixture = Arc::new(Fixture::default());
    let owner = Engine::new(
        cfg,
        fixture.clone(),
        Arc::new(TestClock::default()),
        Redactor::new(&tinysecurity_bus::RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    let row = owner.begin(request()).await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    assert_eq!(row.attribution.as_deref(), Some("auto:host-policy"));
    assert!(row.judge.is_none() && row.decision_ticket_sha256.is_none());
    assert_eq!(
        *fixture.order.lock().map_err(|_| Error::Unavailable)?,
        vec!["cas", "audit"],
        "no prompt, but the decision is durable and audited"
    );
    {
        let audited = fixture.audits.lock().map_err(|_| Error::Unavailable)?;
        assert_eq!(audited.len(), 1);
        assert_eq!(audited[0].attribution.as_deref(), Some("auto:host-policy"));
    }
    // A failed audit append means no permission is returned.
    let failing = Arc::new(Fixture::default());
    failing.fail.store(2, Ordering::SeqCst);
    let mut cfg = config_with_auto_all();
    cfg.scopes[0].require_approval = false;
    let denied = Engine::new(
        cfg,
        failing,
        Arc::new(TestClock::default()),
        Redactor::new(&tinysecurity_bus::RedactorConfig::default()).map_err(|_| Error::Invalid)?,
    )?;
    assert!(denied.begin(request()).await.is_err());
    Ok(())
}
fn config_with_auto_all() -> ApprovalConfig2 {
    let mut cfg = super::config();
    cfg.scopes[0].auto_approve_all = true;
    cfg
}
