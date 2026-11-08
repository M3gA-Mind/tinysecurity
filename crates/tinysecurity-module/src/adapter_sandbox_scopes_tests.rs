//! Runtime sandbox scopes through the real bus, authenticated peer and audit sink.
use super::super::super::sandbox_scopes::SandboxRuntime;
use super::*;
use tinysecurity_bus::{
    RegisterSandboxScopeRequest2, RetireSandboxScopeRequest2, SandboxScope2, SandboxScopeOutcome2,
    SubjectScope,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

const TENANT_STREAM: &str = "1111111111111111111111111111111d";
const OTHER_STREAM: &str = "2222222222222222222222222222222e";

fn tenant(name: &str, base: &SandboxScope2) -> SandboxScope2 {
    let mut scope = base.clone();
    scope.scope_id = format!("tenant-{name}");
    scope.approval_scope_id = None;
    scope.subject = SubjectScope {
        user: format!("user-{name}"),
        workspace: "tenant-workspace".into(),
        agent: "tenant-agent".into(),
    };
    scope
}
fn registration(scope: &SandboxScope2, stream: &str, report: bool) -> RegisterSandboxScopeRequest2 {
    RegisterSandboxScopeRequest2 {
        scope: scope.clone(),
        audit_stream_id: stream.into(),
        report_handle: report,
    }
}
async fn with_runtime() -> std::result::Result<Harness, Box<dyn std::error::Error>> {
    let mut h = harness().await?;
    h.service.sandbox_runtime = Some(Arc::new(runtime_for(&h)?));
    Ok(h)
}
fn runtime_for(h: &Harness) -> std::result::Result<SandboxRuntime, Box<dyn std::error::Error>> {
    runtime_with_timeout(h, 30_000)
}
fn runtime_with_timeout(
    h: &Harness,
    timeout_ms: u32,
) -> std::result::Result<SandboxRuntime, Box<dyn std::error::Error>> {
    let binding = crate::callbacks::PeerBinding::new(
        h.host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    Ok(SandboxRuntime::new(
        h.module.clone(),
        binding,
        AuditConfig2 {
            scope: h.facts.subject.clone(),
            stream_id: "c".repeat(32),
            timeout_ms,
            required: true,
            native_path: None,
            max_bytes: 100_000,
            max_archives: 3,
            journal_max_bytes: 1_000_000,
            journal_max_events: 10_000,
        },
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    ))
}
fn rows(h: &Harness) -> Vec<AuditSinkRequest2> {
    h.sink
        .rows
        .lock()
        .map(|rows| rows.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_registered_subject_plans_and_audits_on_its_own_stream() -> TestResult {
    let h = with_runtime().await?;
    let scope = tenant("a", &h.facts);
    let receipt = h
        .service
        .register_sandbox_scope2(registration(&scope, TENANT_STREAM, true))
        .await?;
    assert_eq!(receipt.outcome, SandboxScopeOutcome2::Created);
    assert_eq!(receipt.live_scopes, 2);
    let plan = h.service.plan2(fixture::request(&scope, 1)).await?;
    assert_eq!(plan.decision.verdict, tinysecurity_bus::Verdict::Allow);
    assert!(plan.audit.required()?.committed);
    let artifact = plan.artifact.required()?;
    let consumed = h
        .service
        .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
            request: fixture::request(&scope, 1),
            artifact,
            subject: scope.subject.clone(),
            audit: fixture::audit(2),
        })
        .await?;
    assert!(consumed.permitted);
    let sent = rows(&h);
    assert_eq!(sent.len(), 2);
    for row in &sent {
        assert_eq!(row.stream_id, TENANT_STREAM);
        // The receipt names the subject exactly as the sink received it.
        assert_eq!(Some(&row.scope), receipt.scope_handle.as_ref());
    }
    // The initialized scope keeps the base stream beside it.
    let init = h.service.plan2(fixture::request(&h.facts, 1)).await?;
    assert!(init.audit.required()?.committed);
    assert_eq!(
        rows(&h).last().map(|row| row.stream_id.clone()),
        Some("c".repeat(32))
    );
    Ok(())
}

#[tokio::test]
async fn the_handle_is_reported_only_to_a_registration_that_asks() -> TestResult {
    let h = with_runtime().await?;
    let quiet = tenant("quiet", &h.facts);
    let receipt = h
        .service
        .register_sandbox_scope2(registration(&quiet, TENANT_STREAM, false))
        .await?;
    assert_eq!(receipt.scope_handle, None);
    let again = h
        .service
        .register_sandbox_scope2(registration(&quiet, TENANT_STREAM, true))
        .await?;
    assert_eq!(again.outcome, SandboxScopeOutcome2::Unchanged);
    assert!(again.scope_handle.is_some());
    let retired = h
        .service
        .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
            scope_id: quiet.scope_id.clone(),
        })
        .await?;
    assert_eq!(retired.outcome, SandboxScopeOutcome2::Retired);
    assert_eq!(retired.scope_handle, None);
    assert_eq!(retired.live_scopes, 1);
    Ok(())
}

#[tokio::test]
async fn identity_stream_and_initialized_scopes_are_never_rebound() -> TestResult {
    let h = with_runtime().await?;
    let scope = tenant("a", &h.facts);
    h.service
        .register_sandbox_scope2(registration(&scope, TENANT_STREAM, false))
        .await?;
    // Another stream for a live identity.
    assert!(
        h.service
            .register_sandbox_scope2(registration(&scope, OTHER_STREAM, false))
            .await
            .is_err()
    );
    // Other facts for a live identity.
    let mut widened = scope.clone();
    widened.max_ttl_ms += 1;
    assert!(
        h.service
            .register_sandbox_scope2(registration(&widened, TENANT_STREAM, false))
            .await
            .is_err()
    );
    // The subject of a live scope keeps its stream for another identity too.
    let mut sibling = scope.clone();
    sibling.scope_id = "tenant-sibling".into();
    assert!(
        h.service
            .register_sandbox_scope2(registration(&sibling, OTHER_STREAM, false))
            .await
            .is_err()
    );
    // An initialized identity can be neither registered again nor retired.
    assert!(
        h.service
            .register_sandbox_scope2(registration(&h.facts, TENANT_STREAM, false))
            .await
            .is_err()
    );
    assert!(
        h.service
            .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
                scope_id: h.facts.scope_id.clone()
            })
            .await
            .is_err()
    );
    assert!(
        h.service
            .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
                scope_id: "missing".into()
            })
            .await
            .is_err()
    );
    // Malformed streams and facts never register.
    for stream in ["short", &"z".repeat(32)] {
        assert!(
            h.service
                .register_sandbox_scope2(registration(&tenant("b", &h.facts), stream, false))
                .await
                .is_err()
        );
    }
    let mut empty = tenant("c", &h.facts);
    empty.sources.clear();
    assert!(
        h.service
            .register_sandbox_scope2(registration(&empty, OTHER_STREAM, false))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn retirement_denies_new_plans_and_issued_artifacts_and_keeps_the_stream_pinned() -> TestResult
{
    let h = with_runtime().await?;
    let scope = tenant("a", &h.facts);
    h.service
        .register_sandbox_scope2(registration(&scope, TENANT_STREAM, false))
        .await?;
    let artifact = h
        .service
        .plan2(fixture::request(&scope, 1))
        .await?
        .artifact
        .required()?;
    h.service
        .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
            scope_id: scope.scope_id.clone(),
        })
        .await?;
    let denied = h.service.plan2(fixture::request(&scope, 2)).await?;
    assert_eq!(denied.denial, Some(SandboxDenial2::InvalidContext));
    let consumed = h
        .service
        .consume_sandbox_plan2(ConsumeSandboxPlanRequest2 {
            request: fixture::request(&scope, 1),
            artifact,
            subject: scope.subject.clone(),
            audit: fixture::audit(3),
        })
        .await?;
    assert!(!consumed.permitted);
    // Within the retention window the subject cannot move to another ledger.
    assert!(
        h.service
            .register_sandbox_scope2(registration(&scope, OTHER_STREAM, false))
            .await
            .is_err()
    );
    // The same stream registers again and plans.
    h.service
        .register_sandbox_scope2(registration(&scope, TENANT_STREAM, false))
        .await?;
    assert_eq!(
        h.service
            .plan2(fixture::request(&scope, 4))
            .await?
            .decision
            .verdict,
        tinysecurity_bus::Verdict::Allow
    );
    Ok(())
}

#[tokio::test]
async fn a_subject_is_released_for_another_stream_only_after_its_last_scope_retires() -> TestResult
{
    let mut h = harness().await?;
    let mut runtime = runtime_for(&h)?;
    runtime.pins.ttl = std::time::Duration::ZERO;
    h.service.sandbox_runtime = Some(Arc::new(runtime));
    let first = tenant("a", &h.facts);
    let mut second = first.clone();
    second.scope_id = "tenant-a-second".into();
    for scope in [&first, &second] {
        h.service
            .register_sandbox_scope2(registration(scope, TENANT_STREAM, false))
            .await?;
    }
    let retire = |id: &str| RetireSandboxScopeRequest2 {
        scope_id: id.into(),
    };
    h.service
        .retire_sandbox_scope2(retire(&first.scope_id))
        .await?;
    let mut elsewhere = first.clone();
    elsewhere.scope_id = "tenant-a-third".into();
    // The second scope still holds the subject, so its stream is still pinned.
    assert!(
        h.service
            .register_sandbox_scope2(registration(&elsewhere, OTHER_STREAM, false))
            .await
            .is_err()
    );
    h.service
        .retire_sandbox_scope2(retire(&second.scope_id))
        .await?;
    h.service
        .register_sandbox_scope2(registration(&elsewhere, OTHER_STREAM, false))
        .await?;
    Ok(())
}

#[tokio::test]
async fn a_refused_registration_releases_the_subject_it_pinned() -> TestResult {
    let mut h = harness().await?;
    let mut runtime = runtime_for(&h)?;
    runtime.pins.ttl = std::time::Duration::ZERO;
    h.service.sandbox_runtime = Some(Arc::new(runtime));
    let mut broken = tenant("a", &h.facts);
    broken.sources.clear();
    assert!(
        h.service
            .register_sandbox_scope2(registration(&broken, TENANT_STREAM, false))
            .await
            .is_err()
    );
    // Nothing was registered, so the subject is free to choose its stream.
    h.service
        .register_sandbox_scope2(registration(&tenant("a", &h.facts), OTHER_STREAM, false))
        .await?;
    Ok(())
}

#[tokio::test]
async fn registration_needs_the_runtime_audit_and_a_live_approval_link() -> TestResult {
    let mut h = harness().await?;
    let scope = tenant("a", &h.facts);
    // No runtime audit state (initialized without audit): nothing registers.
    assert!(
        h.service
            .register_sandbox_scope2(registration(&scope, TENANT_STREAM, false))
            .await
            .is_err()
    );
    assert!(
        h.service
            .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
                scope_id: scope.scope_id.clone()
            })
            .await
            .is_err()
    );
    h.service.sandbox_runtime = Some(Arc::new(runtime_for(&h)?));
    // An approval link with no approval engine can never be honoured.
    let mut linked = scope.clone();
    linked.approval_scope_id = Some("a".repeat(32));
    assert!(
        h.service
            .register_sandbox_scope2(registration(&linked, TENANT_STREAM, false))
            .await
            .is_err()
    );
    // Without a sandbox engine the whole surface is unavailable.
    h.service.sandbox = None;
    assert!(
        h.service
            .register_sandbox_scope2(registration(&scope, TENANT_STREAM, false))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn an_approval_link_must_name_a_live_approval_scope_of_the_same_subject() -> TestResult {
    let mut h = with_runtime().await?;
    let _store = human_engine(&mut h).await?;
    // The same subject as the approval scope, on a new identity: the link holds.
    let mut own = h.facts.clone();
    own.scope_id = "own-runtime".into();
    h.service
        .register_sandbox_scope2(registration(&own, "c".repeat(32).as_str(), false))
        .await?;
    // Another subject cannot ride this approval scope.
    let mut foreign = tenant("a", &h.facts);
    foreign.approval_scope_id = Some("a".repeat(32));
    assert!(
        h.service
            .register_sandbox_scope2(registration(&foreign, TENANT_STREAM, false))
            .await
            .is_err()
    );
    // A link to an approval scope that does not exist is refused too.
    let mut dangling = own.clone();
    dangling.scope_id = "dangling".into();
    dangling.approval_scope_id = Some("b".repeat(32));
    assert!(
        h.service
            .register_sandbox_scope2(registration(&dangling, "c".repeat(32).as_str(), false))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn attaching_a_sandbox_enables_runtime_scopes_only_with_an_audit() -> TestResult {
    let mut h = harness().await?;
    let engine = h.service.sandbox.clone().required()?;
    let binding = crate::callbacks::PeerBinding::new(
        h.host.unique_name().as_ref().map(tinybus::BusName::as_str),
    )?;
    let audit = AuditConfig2 {
        scope: h.facts.subject.clone(),
        stream_id: "c".repeat(32),
        timeout_ms: 30_000,
        required: true,
        native_path: None,
        max_bytes: 100_000,
        max_archives: 3,
        journal_max_bytes: 1_000_000,
        journal_max_events: 10_000,
    };
    h.service.sandbox_runtime = None;
    h.service
        .attach_sandbox(Some(&engine), None, (&h.module, &binding))?;
    assert!(h.service.sandbox.is_some() && h.service.sandbox_runtime.is_none());
    h.service
        .attach_sandbox(Some(&engine), Some(audit.clone()), (&h.module, &binding))?;
    assert!(h.service.sandbox_runtime.is_some());
    h.service
        .attach_sandbox(None, Some(audit), (&h.module, &binding))?;
    assert!(h.service.sandbox.is_none() && h.service.sandbox_runtime.is_none());
    Ok(())
}

#[tokio::test]
async fn an_unusable_audit_base_refuses_registration_and_releases_the_pin() -> TestResult {
    let mut h = harness().await?;
    let mut runtime = runtime_for(&h)?;
    runtime.pins.ttl = std::time::Duration::ZERO;
    h.service.sandbox_runtime = Some(Arc::new(runtime));
    let scope = tenant("a", &h.facts);
    h.service
        .register_sandbox_scope2(registration(&scope, TENANT_STREAM, false))
        .await?;
    // A runtime whose base audit is invalid (zero timeout) never admits a scope.
    let mut broken = runtime_with_timeout(&h, 0)?;
    broken.pins.ttl = std::time::Duration::ZERO;
    h.service.sandbox_runtime = Some(Arc::new(broken));
    let second = tenant("b", &h.facts);
    assert!(
        h.service
            .register_sandbox_scope2(registration(&second, TENANT_STREAM, false))
            .await
            .is_err()
    );
    assert_eq!(
        h.service.sandbox.as_ref().required()?.live_scopes()?,
        2,
        "the refused scope is not live"
    );
    Ok(())
}

#[tokio::test]
async fn a_retired_runtime_identity_never_audits_on_the_base_stream() -> TestResult {
    let h = with_runtime().await?;
    // A runtime scope for the very subject the base audit client serves.
    let mut own = h.facts.clone();
    own.scope_id = "own-runtime".into();
    own.approval_scope_id = None;
    h.service
        .register_sandbox_scope2(registration(&own, TENANT_STREAM, false))
        .await?;
    h.service
        .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
            scope_id: own.scope_id.clone(),
        })
        .await?;
    let before = rows(&h).len();
    let denied = h.service.plan2(fixture::request(&own, 1)).await?;
    assert_eq!(denied.denial, Some(SandboxDenial2::InvalidContext));
    assert!(denied.audit.is_none_or(|audit| !audit.committed));
    assert_eq!(rows(&h).len(), before, "nothing reached any ledger");
    Ok(())
}

#[tokio::test]
async fn a_plan_in_flight_when_its_scope_retires_keeps_its_own_stream_and_never_activates()
-> TestResult {
    let h = with_runtime().await?;
    let mut own = h.facts.clone();
    own.scope_id = "own-runtime".into();
    own.approval_scope_id = None;
    h.service
        .register_sandbox_scope2(registration(&own, TENANT_STREAM, false))
        .await?;
    h.sink.mode.store(4, Ordering::SeqCst);
    let plan = h.service.plan2(fixture::request(&own, 1));
    let retire = async {
        while rows(&h).is_empty() {
            tokio::task::yield_now().await;
        }
        let retired = h
            .service
            .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
                scope_id: own.scope_id.clone(),
            })
            .await;
        h.sink.barrier.wait().await;
        retired
    };
    let (plan, retired) = tokio::join!(plan, retire);
    retired?;
    let plan = plan?;
    assert!(plan.artifact.is_none());
    assert_ne!(plan.decision.verdict, tinysecurity_bus::Verdict::Allow);
    let sent = rows(&h);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].stream_id, TENANT_STREAM);
    assert!(sent.iter().all(|row| row.stream_id != "c".repeat(32)));
    Ok(())
}

#[tokio::test]
async fn a_plan_in_flight_never_activates_under_a_scope_registered_again_meanwhile() -> TestResult {
    let h = with_runtime().await?;
    let mut own = h.facts.clone();
    own.scope_id = "own-runtime".into();
    own.approval_scope_id = None;
    h.service
        .register_sandbox_scope2(registration(&own, TENANT_STREAM, false))
        .await?;
    h.sink.mode.store(4, Ordering::SeqCst);
    let plan = h.service.plan2(fixture::request(&own, 1));
    let reregister = async {
        while rows(&h).is_empty() {
            tokio::task::yield_now().await;
        }
        h.service
            .retire_sandbox_scope2(RetireSandboxScopeRequest2 {
                scope_id: own.scope_id.clone(),
            })
            .await?;
        h.service
            .register_sandbox_scope2(registration(&own, TENANT_STREAM, false))
            .await?;
        h.sink.barrier.wait().await;
        Ok::<_, tinybus::Error>(())
    };
    let (plan, reregistered) = tokio::join!(plan, reregister);
    reregistered?;
    let plan = plan?;
    // The identity, subject and facts are the same, but the candidate was planned for
    // the previous registration: it neither activates nor survives to be consumed.
    assert!(plan.artifact.is_none());
    assert_ne!(plan.decision.verdict, tinysecurity_bus::Verdict::Allow);
    Ok(())
}
