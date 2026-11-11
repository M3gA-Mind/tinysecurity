use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tinyinference_decisions::{NoulAnswer, Usage};
use tinysecurity_bus::{AccessTier, CallerContext, Origin, RedactorConfig, Secret, SubjectScope};
#[derive(Debug, Default)]
struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn milliseconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
#[derive(Debug)]
struct Fake {
    calls: AtomicUsize,
    response: Mutex<Result<EvaluationResponse>>,
    requests: Mutex<Vec<EvaluationRequest>>,
    pending: bool,
}
#[async_trait::async_trait]
impl JudgeClient for Fake {
    async fn evaluate(&self, request: &EvaluationRequest) -> Result<EvaluationResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .map_err(|_| Error::Unavailable)?
            .push(request.clone());
        if self.pending {
            std::future::pending::<()>().await;
        }
        self.response
            .lock()
            .map_err(|_| Error::Unavailable)?
            .clone()
    }
}
fn config() -> JudgeConfig {
    JudgeConfig {
        credential: Some(Secret("fake-judge-key".into())),
        endpoint: "http://127.0.0.1:1/jev".into(),
        provider: JudgeProvider::TypeSafe,
        threshold_millis: 900,
        exfiltrate_millis: 100,
        thresholds: vec![],
        timeout_ms: 1000,
        origins: vec![Origin::Operator],
        max_requests: 2,
        budget_window_ms: 10_000,
        cache_entries: 10,
        cache_ttl_ms: 100,
    }
}
fn input() -> Input {
    Input {
        binding: ApprovalBinding2 {
            binding_version: 1,
            scope: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            policy_ref: "policy".into(),
            generation: 1,
            call_sha256: "a".repeat(64),
            content_sha256: "b".repeat(64),
            origin: Origin::Operator,
            caller: CallerContext {
                agent: "agent".into(),
                call_id: "call".into(),
                tier: AccessTier::Full,
                ..Default::default()
            },
        },
        external_effect: false,
        intent: "inspect bearer private-token and fake-judge-key".into(),
        context_json: r#"{"tool":"local_diagnostic"}"#.into(),
        arguments_json: r#"{"token":"private-token","ordinary":"fake-judge-key"}"#.into(),
    }
}
fn response(values: [f64; 3]) -> EvaluationResponse {
    EvaluationResponse {
        model: "jev-latest".into(),
        answers: QUESTIONS
            .into_iter()
            .zip(values)
            .map(|(id, noul)| (id.into(), Answer::Noul(NoulAnswer { noul })))
            .collect(),
        usage: Usage::default(),
    }
}
fn fake(values: [f64; 3]) -> Arc<Fake> {
    Arc::new(Fake {
        calls: AtomicUsize::new(0),
        response: Mutex::new(Ok(response(values))),
        requests: Mutex::new(vec![]),
        pending: false,
    })
}
fn registry() -> tinysecurity_bus::Result<Redactor> {
    Redactor::new(&RedactorConfig {
        secrets: vec![Secret("fake-judge-key".into())],
    })
}
#[tokio::test]
async fn qualified_boundaries_and_each_uncertain_score_compare_locally() -> Result<()> {
    let registry = registry().map_err(|_| Error::Invalid)?;
    for (scores, outcome) in [
        ([0.9, 0.9, 0.1], JudgeOutcome2::Qualified),
        ([0.899_999, 0.9, 0.1], JudgeOutcome2::Uncertain),
        ([0.9, 0.899_999, 0.1], JudgeOutcome2::Uncertain),
        ([0.9, 0.9, 0.100_001], JudgeOutcome2::Uncertain),
    ] {
        let engine = Engine::with_client(config(), fake(scores), Arc::new(TestClock::default()))?;
        let e = engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?;
        assert_eq!(e.outcome, outcome);
        assert_eq!(e.question_ids, QUESTIONS.map(str::to_owned));
    }
    Ok(())
}
#[tokio::test]
async fn non_opted_origin_and_failed_sanitation_send_no_request() -> Result<()> {
    let fake = fake([1.0, 1.0, 0.0]);
    let engine = Engine::with_client(config(), fake.clone(), Arc::new(TestClock::default()))?;
    let registry = registry().map_err(|_| Error::Invalid)?;
    let mut input = input();
    input.binding.origin = Origin::Saas;
    assert!(engine.evaluate(&input, &registry).await?.is_none());
    input.binding.origin = Origin::Operator;
    input.arguments_json = "malformed".into();
    assert_eq!(
        engine
            .evaluate(&input, &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Invalid
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn malformed_ids_types_nan_and_out_of_range_never_qualify() -> Result<()> {
    let registry = registry().map_err(|_| Error::Invalid)?;
    for value in [f64::NAN, f64::INFINITY, -0.001, 1.001] {
        let engine = Engine::with_client(
            config(),
            fake([value, 1.0, 0.0]),
            Arc::new(TestClock::default()),
        )?;
        assert_eq!(
            engine
                .evaluate(&input(), &registry)
                .await?
                .ok_or(Error::Response)?
                .outcome,
            JudgeOutcome2::Invalid
        );
    }
    for mutate in 0..3 {
        let fake = fake([1.0, 1.0, 0.0]);
        let mut r = response([1.0, 1.0, 0.0]);
        match mutate {
            0 => {
                r.answers.remove("intent");
            }
            1 => {
                r.answers
                    .insert("extra".into(), Answer::Noul(NoulAnswer { noul: 1.0 }));
            }
            _ => {
                r.model = "wrong-model".into();
            }
        }
        *fake.response.lock().map_err(|_| Error::Unavailable)? = Ok(r);
        let engine = Engine::with_client(config(), fake, Arc::new(TestClock::default()))?;
        assert_eq!(
            engine
                .evaluate(&input(), &registry)
                .await?
                .ok_or(Error::Response)?
                .outcome,
            JudgeOutcome2::Invalid
        );
    }
    Ok(())
}
#[tokio::test]
async fn failures_count_before_http_and_budget_rollbacks_latch_closed() -> Result<()> {
    let fake = fake([1.0, 1.0, 0.0]);
    *fake.response.lock().map_err(|_| Error::Unavailable)? = Err(Error::Unavailable);
    let clock = Arc::new(TestClock(AtomicU64::new(1)));
    let engine = Engine::with_client(config(), fake.clone(), clock.clone())?;
    let registry = registry().map_err(|_| Error::Invalid)?;
    for _ in 0..2 {
        assert_eq!(
            engine
                .evaluate(&input(), &registry)
                .await?
                .ok_or(Error::Response)?
                .outcome,
            JudgeOutcome2::Unavailable
        );
    }
    assert_eq!(
        engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Budget
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    clock.0.store(0, Ordering::SeqCst);
    assert_eq!(
        engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Budget
    );
    clock.0.store(20_000, Ordering::SeqCst);
    assert_eq!(
        engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Budget
    );
    Ok(())
}
#[tokio::test]
async fn exact_cache_binding_ttl_and_shared_configuration_budget_do_not_transfer_permission()
-> Result<()> {
    let fake = fake([1.0, 1.0, 0.0]);
    let clock = Arc::new(TestClock::default());
    let mut cfg = config();
    cfg.max_requests = 100;
    let engine = Engine::with_client(cfg, fake.clone(), clock.clone())?;
    let registry = registry().map_err(|_| Error::Invalid)?;
    let original = input();
    assert!(
        !engine
            .evaluate(&original, &registry)
            .await?
            .ok_or(Error::Response)?
            .cached
    );
    assert!(
        engine
            .evaluate(&original, &registry)
            .await?
            .ok_or(Error::Response)?
            .cached
    );
    let mut mutations = vec![];
    for n in 0..9 {
        let mut input = original.clone();
        match n {
            0 => input.binding.scope.user = "other".into(),
            1 => input.binding.scope.workspace = "other".into(),
            2 => input.binding.scope.agent = "other".into(),
            3 => input.binding.generation = 2,
            4 => input.binding.call_sha256 = "c".repeat(64),
            5 => input.binding.caller.call_id = "other".into(),
            6 => input.external_effect = true,
            7 => input.intent = "other intent".into(),
            _ => input.arguments_json = r#"{"ordinary":"changed"}"#.into(),
        }
        mutations.push(input);
    }
    for mutation in mutations {
        assert!(
            !engine
                .evaluate(&mutation, &registry)
                .await?
                .ok_or(Error::Response)?
                .cached
        );
    }
    clock.0.store(100, Ordering::SeqCst);
    assert!(
        !engine
            .evaluate(&original, &registry)
            .await?
            .ok_or(Error::Response)?
            .cached
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 11);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn total_deadline_ends_pending_evaluation_without_retry() -> Result<()> {
    let fake = Arc::new(Fake {
        pending: true,
        ..Fake {
            calls: AtomicUsize::new(0),
            response: Mutex::new(Ok(response([1.0, 1.0, 0.0]))),
            requests: Mutex::new(vec![]),
            pending: false,
        }
    });
    let engine = Engine::with_client(config(), fake.clone(), Arc::new(TestClock::default()))?;
    assert_eq!(
        engine
            .evaluate(&input(), &registry().map_err(|_| Error::Invalid)?)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Timeout
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn outbound_intent_context_and_arguments_contain_no_registered_or_bearer_secrets()
-> Result<()> {
    let fake = fake([1.0, 1.0, 0.0]);
    let engine = Engine::with_client(config(), fake.clone(), Arc::new(TestClock::default()))?;
    engine
        .evaluate(&input(), &registry().map_err(|_| Error::Invalid)?)
        .await?;
    let requests = fake.requests.lock().map_err(|_| Error::Unavailable)?;
    let json = serde_json::to_string(&*requests).map_err(|_| Error::Invalid)?;
    assert!(!json.contains("fake-judge-key"));
    assert!(!json.contains("private-token"));
    assert_eq!(requests[0].questions.len(), 3);
    Ok(())
}
#[tokio::test]
async fn typed_provider_models_and_primitives_are_validated_without_retry() -> Result<()> {
    let registry = registry().map_err(|_| Error::Invalid)?;
    for provider in [JudgeProvider::OpenRouter, JudgeProvider::OpenJev] {
        let mut cfg = config();
        cfg.provider = provider;
        let client = fake([1.0, 1.0, 0.0]);
        if provider == JudgeProvider::OpenRouter {
            let mut response = response([1.0, 1.0, 0.0]);
            response.model = "typesafe/jev-release".into();
            *client.response.lock().map_err(|_| Error::Unavailable)? = Ok(response);
        }
        let engine = Engine::with_client(cfg.clone(), client, Arc::new(TestClock::default()))?;
        assert_eq!(
            engine
                .evaluate(&input(), &registry)
                .await?
                .ok_or(Error::Response)?
                .outcome,
            JudgeOutcome2::Qualified
        );
        let sdk = SdkClient::new(&cfg)?;
        assert_eq!(format!("{sdk:?}"), "SdkClient([REDACTED])");
    }
    let client = fake([1.0, 1.0, 0.0]);
    let mut wrong = response([1.0, 1.0, 0.0]);
    wrong.answers.insert(
        "intent".into(),
        Answer::Choice(tinyinference_decisions::ChoiceAnswer {
            choice: "a".into(),
            probabilities: std::collections::BTreeMap::from([("a".into(), 1.0)]),
            confidence: 1.0,
        }),
    );
    *client.response.lock().map_err(|_| Error::Unavailable)? = Ok(wrong);
    let engine = Engine::with_client(config(), client, Arc::new(TestClock::default()))?;
    assert_eq!(
        engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Invalid
    );
    Ok(())
}
#[test]
fn explicit_sdk_configuration_and_debug_reject_secrets_and_invalid_endpoints() -> Result<()> {
    Engine::validate_config(&config())?;
    for endpoint in [
        "http://example.invalid/jev",
        "https://user:password@example.invalid/jev",
        "https://example.invalid/jev?key=secret",
        "https://example.invalid/jev#secret",
        "",
    ] {
        let mut cfg = config();
        cfg.endpoint = endpoint.into();
        assert_eq!(Engine::validate_config(&cfg), Err(Error::Invalid));
    }
    assert!(!format!("{:?}", config()).contains("fake-judge-key"));
    let engine = Engine::with_client(config(), fake([1.0; 3]), Arc::new(TestClock::default()))?;
    assert_eq!(format!("{engine:?}"), "Engine([REDACTED])");
    Ok(())
}
#[tokio::test]
async fn concurrent_attempts_share_one_atomic_request_limit() -> Result<()> {
    let client = fake([1.0, 1.0, 0.0]);
    let mut cfg = config();
    cfg.cache_entries = 0;
    let engine = Arc::new(Engine::with_client(
        cfg,
        client.clone(),
        Arc::new(TestClock::default()),
    )?);
    let registry = registry().map_err(|_| Error::Invalid)?;
    let mut tasks = vec![];
    for _ in 0..20 {
        let engine = Arc::clone(&engine);
        let registry = registry.clone();
        tasks.push(tokio::spawn(async move {
            engine.evaluate(&input(), &registry).await
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        let verdict = task
            .await
            .map_err(|_| Error::Unavailable)??
            .ok_or(Error::Response)?;
        if verdict.outcome == JudgeOutcome2::Qualified {
            allowed += 1;
        } else {
            assert_eq!(verdict.outcome, JudgeOutcome2::Budget);
        }
    }
    assert_eq!(allowed, 2);
    assert_eq!(client.calls.load(Ordering::SeqCst), 2);
    Ok(())
}
#[tokio::test]
async fn class_origin_thresholds_invalid_config_and_reconfiguration_cannot_reuse_scores()
-> Result<()> {
    use tinysecurity_bus::JudgeThresholdRule;
    let mut cfg = config();
    cfg.max_requests = 100;
    cfg.thresholds.push(JudgeThresholdRule {
        origin: Origin::Operator,
        external_effect: false,
        thresholds: JudgeThresholds {
            intent: 1000,
            reversible: 1000,
            exfiltrate: 0,
        },
    });
    let client = fake([0.9, 0.9, 0.1]);
    let engine = Engine::with_client(cfg.clone(), client.clone(), Arc::new(TestClock::default()))?;
    let registry = registry().map_err(|_| Error::Invalid)?;
    assert_eq!(
        engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Uncertain
    );
    let mut external = input();
    external.external_effect = true;
    assert_eq!(
        engine
            .evaluate(&external, &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Qualified
    );
    let candidate = engine.reconfigured(cfg.clone())?;
    assert!(Arc::ptr_eq(&engine.state, &candidate.state));
    assert_ne!(engine.configuration, candidate.configuration);
    let mut wrong = cfg.clone();
    wrong.endpoint = "http://invalid.invalid/".into();
    assert!(engine.reconfigured(wrong).is_err());
    for n in 0..15 {
        let mut invalid = cfg.clone();
        match n {
            0 => invalid.threshold_millis = 1001,
            1 => invalid.exfiltrate_millis = 1001,
            2 => invalid.timeout_ms = 0,
            3 => invalid.max_requests = 0,
            4 => invalid.budget_window_ms = 0,
            5 => invalid.cache_entries = 1025,
            6 => invalid.cache_ttl_ms = 600_001,
            7 => invalid.credential = Some(Secret("a".into())),
            8 => invalid.endpoint = "x".repeat(4097),
            9 => invalid.origins.push(Origin::Operator),
            10 => invalid.thresholds.push(invalid.thresholds[0].clone()),
            11 => invalid.thresholds[0].thresholds.intent = 1001,
            12 => invalid.thresholds[0].thresholds.reversible = 1001,
            13 => invalid.thresholds[0].thresholds.exfiltrate = 1001,
            _ => invalid.thresholds[0].origin = Origin::Saas,
        }
        assert!(
            Engine::with_client(invalid, client.clone(), Arc::new(TestClock::default())).is_err()
        );
    }
    let client = fake([1.0, 1.0, 0.0]);
    *client.response.lock().map_err(|_| Error::Unavailable)? = Err(Error::Response);
    let engine = Engine::with_client(config(), client, Arc::new(TestClock::default()))?;
    assert_eq!(
        engine
            .evaluate(&input(), &registry)
            .await?
            .ok_or(Error::Response)?
            .outcome,
        JudgeOutcome2::Invalid
    );
    Ok(())
}

#[tokio::test]
async fn legitimate_reconfiguration_shrinks_shared_cache_and_zero_clears_it() -> Result<()> {
    let mut cfg = config();
    cfg.max_requests = 10;
    let engine = Engine::with_client(
        cfg.clone(),
        fake([1.0, 1.0, 0.0]),
        Arc::new(TestClock::default()),
    )?;
    for call in ["a", "b", "c"] {
        let mut request = input();
        request.binding.caller.call_id = call.into();
        engine
            .evaluate(&request, &registry().map_err(|_| Error::Invalid)?)
            .await?;
    }
    assert_eq!(engine.state.lock().map_err(|_| Error::Budget)?.1.len(), 3);
    cfg.cache_entries = 1;
    let candidate = engine.reconfigured(cfg.clone())?;
    assert_eq!(
        candidate.state.lock().map_err(|_| Error::Budget)?.1.len(),
        1
    );
    cfg.cache_entries = 0;
    let disabled = candidate.reconfigured(cfg)?;
    assert_eq!(disabled.state.lock().map_err(|_| Error::Budget)?.1.len(), 0);
    Ok(())
}

#[derive(Debug, Default)]
struct Host {
    asks: Mutex<Vec<bool>>,
    credential: Mutex<Option<Secret>>,
}
#[async_trait::async_trait]
impl CredentialSource for Host {
    async fn credential(&self, rejected: bool) -> Option<Secret> {
        self.asks.lock().ok()?.push(rejected);
        self.credential.lock().ok()?.clone()
    }
}
fn host(credential: Option<&str>) -> Arc<Host> {
    Arc::new(Host {
        asks: Mutex::default(),
        credential: Mutex::new(credential.map(|c| Secret(c.into()))),
    })
}
fn asks(host: &Host) -> Result<Vec<bool>> {
    Ok(host.asks.lock().map_err(|_| Error::Unavailable)?.clone())
}
/// A judge with no configured credential, uncached and with room in its budget.
fn hosted(host: &Arc<Host>, client: &Arc<Fake>, clock: &Arc<TestClock>) -> Result<Engine> {
    let mut cfg = config();
    cfg.credential = None;
    cfg.cache_ttl_ms = 0;
    cfg.max_requests = 100;
    let client = Arc::clone(client);
    Engine::with_source(
        cfg,
        Some(Arc::clone(host) as Arc<dyn CredentialSource>),
        Arc::clone(clock) as Arc<dyn Clock>,
        Arc::new(move |_, _| Ok(Arc::clone(&client) as Arc<dyn JudgeClient>)),
    )
}
async fn outcome(engine: &Engine) -> Result<JudgeOutcome2> {
    let registry = registry().map_err(|_| Error::Invalid)?;
    Ok(engine
        .evaluate(&input(), &registry)
        .await?
        .ok_or(Error::Invalid)?
        .outcome)
}

#[tokio::test]
async fn a_hosted_judge_asks_on_first_use_and_reuses_the_credential_for_five_minutes() -> Result<()>
{
    let host = host(Some("host-held-key"));
    let clock = Arc::new(TestClock::default());
    let engine = hosted(&host, &fake([0.9, 0.9, 0.1]), &clock)?;
    // Construction asks nothing: the host is never called during load.
    assert_eq!(asks(&host)?, Vec::<bool>::new());
    assert_eq!(outcome(&engine).await?, JudgeOutcome2::Qualified);
    clock
        .0
        .store(host::HOST_CREDENTIAL_TTL_MS - 1, Ordering::SeqCst);
    assert_eq!(outcome(&engine).await?, JudgeOutcome2::Qualified);
    assert_eq!(asks(&host)?, [false]);
    clock
        .0
        .store(host::HOST_CREDENTIAL_TTL_MS, Ordering::SeqCst);
    assert_eq!(outcome(&engine).await?, JudgeOutcome2::Qualified);
    assert_eq!(asks(&host)?, [false, false]);
    Ok(())
}

#[tokio::test]
async fn no_usable_host_credential_sends_the_judgement_to_a_person() -> Result<()> {
    let clock = Arc::new(TestClock::default());
    for credential in [None, Some("abc")] {
        let host = host(credential);
        let engine = hosted(&host, &fake([0.9, 0.9, 0.1]), &clock)?;
        assert_eq!(outcome(&engine).await?, JudgeOutcome2::Unavailable);
        assert_eq!(asks(&host)?, [false]);
    }
    Ok(())
}

#[tokio::test]
async fn a_rejected_credential_is_dropped_and_the_next_ask_says_so() -> Result<()> {
    let host = host(Some("host-held-key"));
    let clock = Arc::new(TestClock::default());
    let client = fake([0.9, 0.9, 0.1]);
    *client.response.lock().map_err(|_| Error::Unavailable)? = Err(Error::Rejected);
    let engine = hosted(&host, &client, &clock)?;
    assert_eq!(outcome(&engine).await?, JudgeOutcome2::Unavailable);
    *client.response.lock().map_err(|_| Error::Unavailable)? = Ok(response([0.9, 0.9, 0.1]));
    assert_eq!(outcome(&engine).await?, JudgeOutcome2::Qualified);
    assert_eq!(outcome(&engine).await?, JudgeOutcome2::Qualified);
    // Asked again at once, flagged as a rejection, then reused.
    assert_eq!(asks(&host)?, [false, true]);
    Ok(())
}

#[tokio::test]
async fn a_reinit_drops_the_host_credential() -> Result<()> {
    let host = host(Some("host-held-key"));
    let clock = Arc::new(TestClock::default());
    let engine = hosted(&host, &fake([0.9, 0.9, 0.1]), &clock)?;
    outcome(&engine).await?;
    let mut cfg = config();
    cfg.credential = None;
    let reinit = engine.reconfigured(cfg)?;
    // The rebuilt engine talks to the unreachable fixture endpoint, but it has
    // to ask the host again first.
    outcome(&reinit).await?;
    assert_eq!(asks(&host)?, [false, false]);
    Ok(())
}

#[tokio::test]
async fn a_judge_without_credential_needs_a_host_source() -> Result<()> {
    let mut cfg = config();
    cfg.credential = None;
    Engine::validate_config(&cfg)?;
    assert_eq!(
        Engine::new(cfg.clone(), Arc::new(TestClock::default())).err(),
        Some(Error::Invalid)
    );
    let source: Arc<dyn CredentialSource> = host(Some("host-held-key"));
    assert!(
        Engine::with_credential_source(
            cfg.clone(),
            Arc::clone(&source),
            Arc::new(TestClock::default())
        )
        .is_ok()
    );
    // A configured credential is used as configured, whatever the source.
    assert!(
        Engine::with_credential_source(config(), source, Arc::new(TestClock::default())).is_ok()
    );
    let client = HostClient::new(
        cfg.clone(),
        host(None),
        Arc::new(TestClock::default()),
        host::sdk(),
    );
    assert_eq!(format!("{client:?}"), "HostClient([REDACTED])");
    cfg.endpoint = "x".repeat(4097);
    assert!(Engine::validate_config(&cfg).is_err());
    Ok(())
}

#[tokio::test]
async fn an_endpoint_refusing_the_credential_is_reported_as_rejected() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| Error::Unavailable)?;
    let port = listener
        .local_addr()
        .map_err(|_| Error::Unavailable)?
        .port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.ok()?;
        let mut buffer = vec![0; 65_536];
        let _ = stream.read(&mut buffer).await.ok()?;
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()
    });
    let mut cfg = config();
    cfg.endpoint = format!("http://127.0.0.1:{port}/jev");
    let client = SdkClient::new(&cfg)?;
    let registry = registry().map_err(|_| Error::Invalid)?;
    let request = request(&input(), &registry)?;
    assert_eq!(client.evaluate(&request).await.err(), Some(Error::Rejected));
    let _ = server.await;
    Ok(())
}
