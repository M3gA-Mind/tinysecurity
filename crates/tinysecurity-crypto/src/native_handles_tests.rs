use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
struct Clock(AtomicU64);
impl NativeClock for Clock {
    fn now(&self) -> Result<Time> {
        let n = self.0.load(Ordering::SeqCst);
        Ok(Time {
            wall: 1000 + n,
            monotonic: n,
        })
    }
}
fn registration(id: &str) -> Registration {
    Registration {
        id: id.into(),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: id.into(),
        },
        durable_subject: SubjectScope {
            user: "durable-user".into(),
            workspace: "durable-workspace".into(),
            agent: id.into(),
        },
        policy_ref: "policy".into(),
        purposes: vec![
            Purpose::ConfigUserMaster,
            Purpose::AppEncryptionMaster,
            Purpose::PasswordEncryption,
        ],
    }
}
fn registry(limits: Limits) -> Result<(Registry, Arc<Clock>)> {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    Ok((
        Registry::new(
            vec![registration("a"), registration("b")],
            ":1.1",
            1,
            limits,
            clock.clone(),
        )?,
        clock,
    ))
}

#[test]
fn a_live_registry_accepts_an_immutable_additional_subject_scope() -> TestResult {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let registry = Registry::new(
        vec![registration("first")],
        ":1.1",
        1,
        Limits::default(),
        clock,
    )?;
    let mut second = registration("second");
    second.subject.user = "another-user".into();
    second.durable_subject.user = "another-durable-user".into();

    registry.register_scope(second.clone(), 1)?;
    registry.register_scope(second, 1)?;

    let first = registry.reserve(Request {
        registration: "first",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::RetainPlaintext,
        call_id: "first-call",
        input: Zeroizing::new(b"first".to_vec()),
        ttl_ms: 100,
        generation: 1,
    })?;
    let second = registry.reserve(Request {
        registration: "second",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::RetainPlaintext,
        call_id: "second-call",
        input: Zeroizing::new(b"second".to_vec()),
        ttl_ms: 100,
        generation: 1,
    })?;
    assert_eq!(first.binding().subject().user, "user");
    assert_eq!(second.binding().subject().user, "another-user");

    let mut conflicting = registration("second");
    conflicting.subject.user = "attacker-user".into();
    assert!(registry.register_scope(conflicting, 1).is_err());
    assert!(registry.register_scope(registration("stale"), 2).is_err());
    assert!(
        registry
            .reserve(Request {
                registration: "unknown",
                authenticated_peer: ":1.1",
                purpose: Purpose::ConfigUserMaster,
                kind: OperationKind::RetainPlaintext,
                call_id: "unknown-call",
                input: Zeroizing::new(b"unknown".to_vec()),
                ttl_ms: 100,
                generation: 1,
            })
            .is_err()
    );
    Ok(())
}

#[test]
fn replacing_a_live_scope_updates_policy_and_fences_old_reservations() -> TestResult {
    let (registry, _) = registry(Limits::default())?;
    let old = reserve(
        &registry,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"old",
    )?;
    let mut updated = registration("a");
    updated.policy_ref = "policy-next".into();
    registry.replace_scope(&updated, 1)?;
    assert!(old.validate().is_err());

    let next = reserve(
        &registry,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"new",
    )?;
    assert_eq!(next.binding().policy_ref, "policy-next");
    Ok(())
}

#[test]
fn a_revoked_scope_id_cannot_be_registered_again_but_can_be_replaced() -> TestResult {
    let (registry, _) = registry(Limits::default())?;
    registry.revoke_scope("a")?;

    assert!(registry.register_scope(registration("a"), 1).is_err());
    assert!(
        registry
            .reserve(Request {
                registration: "a",
                authenticated_peer: ":1.1",
                purpose: Purpose::ConfigUserMaster,
                kind: OperationKind::RetainPlaintext,
                call_id: "revoked-call",
                input: Zeroizing::new(b"revoked".to_vec()),
                ttl_ms: 100,
                generation: 1,
            })
            .is_err()
    );

    // The trusted approval-scope replacement path reactivates a configured
    // native scope only after fencing the previous generation.
    let replacement = registration("a");
    registry.replace_scope(&replacement, 1)?;
    let next = reserve(
        &registry,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"next-generation",
    )?;
    assert_eq!(next.binding().policy_ref, "policy");
    Ok(())
}

fn reserve(
    reg: &Registry,
    purpose: Purpose,
    kind: OperationKind,
    input: &[u8],
) -> Result<Reservation> {
    reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose,
        kind,
        call_id: "call",
        input: Zeroizing::new(input.to_vec()),
        ttl_ms: 100,
        generation: 1,
    })
}
struct Routine;
impl NativeRoutineVerifier for Routine {
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
        Box::pin(async move {
            RoutineReceipt::from_consumed_pending(binding, "pending", "native-consumer")
        })
    }
}
#[tokio::test]
async fn retained_plaintext_is_opaque_and_scope_purpose_peer_and_registry_bound() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"private fixture",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    let handle = reg.retain_plaintext(auth, Zeroizing::new(b"private fixture".to_vec()))?;
    reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)?;
    for (scope, purpose, peer) in [
        ("b", Purpose::ConfigUserMaster, ":1.1"),
        ("a", Purpose::AppEncryptionMaster, ":1.1"),
        ("a", Purpose::ConfigUserMaster, ":2.2"),
    ] {
        assert!(
            reg.validate_handle(&handle, scope, purpose, peer, 1)
                .is_err()
        );
    }
    let (other, _) = registry(Limits::default())?;
    assert!(
        other
            .validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    assert!(!format!("{handle:?} {reg:?}").contains("private fixture"));
    Ok(())
}
#[tokio::test]
async fn routine_cannot_issue_master_and_changed_input_cannot_publish() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"backend:fixed",
    )?;
    assert!(reg.authorize_routine(work, &Routine).await.is_err());
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"original",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert!(
        reg.retain_plaintext(auth, Zeroizing::new(b"substituted".to_vec()))
            .is_err()
    );
    assert_eq!(reg.lock()?.retained_bytes, 0);
    Ok(())
}
#[test]
fn private_challenge_and_generation_change_safe_commitments_without_raw_hashes() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let first = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"guessable",
    )?;
    let second = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"guessable",
    )?;
    assert_ne!(first.binding.commitment, second.binding.commitment);
    let arguments = first.binding.safe_arguments();
    assert!(!arguments.contains("guessable"));
    assert!(!arguments.contains(&hex(&first.binding.challenge)));
    assert!(!arguments.contains(&hex(&reg.lock()?.authorization_key)));
    let old = first.binding.commitment;
    drop(first);
    drop(second);
    reg.advance_generation(2)?;
    let next = reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::RetainPlaintext,
        call_id: "call",
        input: Zeroizing::new(b"guessable".to_vec()),
        ttl_ms: 100,
        generation: 2,
    })?;
    assert_ne!(old, next.binding.commitment);
    Ok(())
}
#[tokio::test]
async fn callback_close_and_generation_change_fence_late_publication() -> TestResult {
    struct Closing(Registry);
    impl NativeRoutineVerifier for Closing {
        fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
            Box::pin(async move {
                let reply = RoutineReceipt::from_consumed_pending(binding, "pending", "consumer")?;
                self.0.close();
                Ok(reply)
            })
        }
    }
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(
        reg.authorize_routine(work, &Closing(reg.clone()))
            .await
            .is_err()
    );
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    reg.advance_generation(2)?;
    assert!(
        reg.retain_plaintext(auth, Zeroizing::new(vec![b'x']))
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn expiry_and_rollback_revoke_retained_owners_permanently() -> TestResult {
    let (reg, clock) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    let handle = reg.retain_plaintext(
        reg.authorize_routine(work, &Routine).await?,
        Zeroizing::new(vec![b'x']),
    )?;
    clock.0.store(100, Ordering::SeqCst);
    assert!(
        reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    assert_eq!(reg.lock()?.retained_bytes, 0);
    clock.0.store(99, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        )
        .is_err()
    );
    clock.0.store(101, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn cancellation_releases_capacity_without_refunding_rate() -> TestResult {
    let (reg, clock) = registry(Limits {
        max_in_flight: 1,
        operations_per_minute: 1,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(matches!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        ),
        Err(Error::NativeCapacity)
    ));
    drop(work);
    assert!(matches!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        ),
        Err(Error::NativeRate)
    ));
    clock.0.store(60_000, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        )
        .is_ok()
    );
    Ok(())
}
#[tokio::test]
async fn handle_and_retained_byte_limits_release_on_revoke_and_close() -> TestResult {
    let (reg, _) = registry(Limits {
        max_handles: 1,
        max_retained_bytes: 2,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"ab",
    )?;
    let handle = reg.retain_plaintext(
        reg.authorize_routine(work, &Routine).await?,
        Zeroizing::new(b"ab".to_vec()),
    )?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"a",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert!(matches!(
        reg.retain_plaintext(auth, Zeroizing::new(vec![b'a'])),
        Err(Error::NativeCapacity)
    ));
    reg.revoke_scope("a")?;
    assert!(
        reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    assert_eq!(reg.lock()?.retained_bytes, 0);
    reg.close();
    assert!(reg.lock()?.authorization_key.iter().all(|b| *b == 0));
    Ok(())
}
#[tokio::test]
async fn substituted_receipt_is_rejected_before_retention() -> TestResult {
    struct Wrong;
    impl NativeRoutineVerifier for Wrong {
        fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
            Box::pin(async move {
                let mut reply =
                    RoutineReceipt::from_consumed_pending(binding, "pending", "consumer")?;
                reply.echo.commitment[0] ^= 1;
                Ok(reply)
            })
        }
    }
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(reg.authorize_routine(work, &Wrong).await.is_err());
    Ok(())
}
#[test]
fn malformed_registration_and_purpose_operation_pairs_deny() -> TestResult {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let mut duplicate = registration("a");
    duplicate.purposes.push(Purpose::ConfigUserMaster);
    assert!(Registry::new(vec![duplicate], ":1.1", 1, Limits::default(), clock.clone()).is_err());
    assert!(
        Registry::new(
            vec![registration("a"), registration("a")],
            ":1.1",
            1,
            Limits::default(),
            clock.clone()
        )
        .is_err()
    );
    assert!(
        Registry::new(
            vec![registration("a")],
            "claimed-peer",
            1,
            Limits::default(),
            clock
        )
        .is_err()
    );
    let (reg, _) = registry(Limits::default())?;
    assert!(
        reserve(
            &reg,
            Purpose::PasswordEncryption,
            OperationKind::NativeMasterGrant,
            b"x"
        )
        .is_err()
    );
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPassword,
            b"x"
        )
        .is_err()
    );
    Ok(())
}

pub(super) fn human_receipt(binding: &Binding) -> Result<HumanGrantReceipt> {
    use tinysecurity_bus::{
        AccessTier, ApprovalBinding2, AuditCorrelation2, AuditEventReceipt2, CallerContext, Origin,
    };
    let row = ApprovalRow2 {
        request_id: "1".repeat(32),
        version: 3,
        binding: ApprovalBinding2 {
            binding_version: 1,
            scope: binding.durable_subject.clone(),
            policy_ref: binding.policy_ref.clone(),
            generation: binding.generation,
            call_sha256: "2".repeat(64),
            content_sha256: "3".repeat(64),
            origin: Origin::Operator,
            caller: CallerContext {
                call_id: binding.safe_call_id(),
                agent: binding.subject.agent.clone(),
                tier: AccessTier::Full,
                origin: Origin::Operator,
                ..Default::default()
            },
        },
        host_instance: "4".repeat(32),
        nonce: "5".repeat(32),
        tool_name: "native_secret_grant".into(),
        session_id: None,
        audit_error: None,
        external_effect: false,
        args_redacted: binding.safe_arguments(),
        summary: "native key authority".into(),
        created_at_ms: 1000,
        expires_at_ms: binding.expires_at_ms(),
        state: ApprovalLifecycle2::Reserved,
        choice: Some(ApprovalChoice2::Once),
        attribution: Some("human".into()),
        decision_ticket_sha256: Some("6".repeat(64)),
        outcome: None,
        reservation_id: Some("7".repeat(32)),
        legacy_history_json: None,
        judge: None,
        audit: AuditCorrelation2 {
            event_id: "8".repeat(32),
            expected_tail: 2,
            generation: binding.generation,
        },
    };
    let audit = AuditSinkResponse2 {
        scope: binding.durable_subject.clone(),
        stream_id: "9".repeat(32),
        events: vec![AuditEventReceipt2 {
            sequence: 3,
            event_id: "8".repeat(32),
        }],
        new_tail: 3,
    };
    HumanGrantReceipt::from_durable_consumption(binding, row, audit)
}
struct Human;
impl HumanGrantVerifier for Human {
    fn consume<'a>(&'a self, binding: &'a Binding) -> Verification<'a, HumanGrantReceipt> {
        Box::pin(async move { human_receipt(binding) })
    }
}
#[tokio::test]
async fn trusted_human_consumption_retains_master_without_returning_key_bytes() -> TestResult {
    use crate::keyring::{DriverMint, MasterResolver, MasterSlot};
    use tinystoragedrivers::secrets::MemorySecrets;
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"fixed-native-source",
    )?;
    let grant = reg.authorize_human(work, &Human).await?;
    let resolver = MasterResolver::new(
        Arc::new(MemorySecrets::new()),
        vec![],
        &MasterSlot::User("fixture".into()),
        Arc::new(DriverMint),
    )?;
    let key = resolver.resolve().await?;
    let handle = reg.retain_master(grant, key)?;
    reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)?;
    assert_eq!(reg.lock()?.retained_bytes, 32);
    Ok(())
}
#[tokio::test]
async fn trusted_caller_password_retention_is_distinct_from_native_master() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::PasswordEncryption,
        OperationKind::RetainPassword,
        b"caller-owned binding",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    let key = PasswordKey::derive("fixture", &[1; 16])?;
    let handle = reg.retain_password(auth, key)?;
    reg.validate_handle(&handle, "a", Purpose::PasswordEncryption, ":1.1", 1)?;
    assert!(
        reg.validate_handle(&handle, "a", Purpose::AppEncryptionMaster, ":1.1", 1)
            .is_err()
    );
    Ok(())
}
#[test]
fn human_receipt_rejects_reusable_grants_missing_nonce_and_mismatched_audit() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"source",
    )?;
    let mut receipt = human_receipt(&work.binding)?;
    receipt.row.choice = Some(ApprovalChoice2::Tool);
    assert!(receipt.verify(&work.binding).is_err());
    receipt.row.choice = Some(ApprovalChoice2::Once);
    receipt.row.nonce.clear();
    assert!(receipt.verify(&work.binding).is_err());
    receipt.row.nonce = "5".repeat(32);
    receipt.row.audit.event_id = "a".repeat(32);
    assert!(receipt.verify(&work.binding).is_err());
    Ok(())
}
#[tokio::test]
async fn aborted_pending_callback_releases_charged_input_only_when_future_drops() -> TestResult {
    struct Pending;
    impl NativeRoutineVerifier for Pending {
        fn consume<'a>(&'a self, _binding: &'a Binding) -> Verification<'a, RoutineReceipt> {
            Box::pin(std::future::pending())
        }
    }
    let (reg, _) = registry(Limits {
        max_in_flight: 1,
        max_pending_bytes: 33,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    let mut future = Box::pin(reg.authorize_routine(work, &Pending));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert_eq!(reg.lock()?.pending_bytes, 33);
    reg.advance_generation(2)?;
    assert_eq!(reg.lock()?.pending_bytes, 33);
    drop(future);
    assert_eq!(reg.lock()?.pending_bytes, 0);
    Ok(())
}
#[test]
fn pending_and_combined_resident_bounds_do_not_rely_on_handle_count() -> TestResult {
    let (reg, _) = registry(Limits {
        max_pending_bytes: 33,
        max_resident_bytes: 65,
        ..Limits::default()
    })?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"x",
    )?;
    assert!(matches!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"x"
        ),
        Err(Error::NativeCapacity)
    ));
    drop(work);
    assert_eq!(reg.lock()?.pending_bytes, 0);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"xx"
        )
        .is_err()
    );
    Ok(())
}

thread_local! {
    static WIPES: std::cell::RefCell<(usize, bool)> = const { std::cell::RefCell::new((0, true)) };
}
thread_local! {
    static REFUND_PROBE: std::cell::RefCell<Option<Arc<Mutex<State>>>> = const { std::cell::RefCell::new(None) };
    static REFUND_SAMPLES: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}
pub(super) fn observe_wiped(bytes: &[u8]) {
    REFUND_PROBE.with(|probe| {
        if let Some(state) = probe.borrow().as_ref().filter(|_| !bytes.is_empty()) {
            let pending = state.lock().map_or(usize::MAX, |state| state.pending_bytes);
            REFUND_SAMPLES.with(|samples| samples.borrow_mut().push(pending));
        }
    });
    WIPES.with(|observed| {
        let mut observed = observed.borrow_mut();
        observed.0 += 1;
        observed.1 &= bytes.iter().all(|byte| *byte == 0);
    });
}
#[tokio::test]
async fn denied_publication_and_close_wipe_owned_buffers_before_releasing_allocations() -> TestResult
{
    WIPES.with(|observed| *observed.borrow_mut() = (0, true));
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"original",
    )?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert!(
        reg.retain_plaintext(auth, Zeroizing::new(b"changed".to_vec()))
            .is_err()
    );
    reg.close();
    drop(reg);
    WIPES.with(|observed| {
        let observed = observed.borrow();
        assert!(observed.0 >= 5);
        assert!(
            observed.1,
            "owned buffers must be wiped before their allocation is released"
        );
    });
    Ok(())
}

fn backed_input(capacity: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![b'x'; capacity]);
    bytes.truncate(1);
    bytes
}
fn reserve_backed(reg: &Registry, capacity: usize) -> Result<Reservation> {
    reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::RetainPlaintext,
        call_id: "call",
        input: backed_input(capacity),
        ttl_ms: 100,
        generation: 1,
    })
}
#[test]
fn pending_backing_capacity_cannot_bypass_logical_input_and_resident_limits() -> TestResult {
    for limits in [
        Limits {
            max_input_bytes: 1,
            max_pending_bytes: 33,
            ..Limits::default()
        },
        Limits {
            max_input_bytes: 1,
            max_resident_bytes: 66,
            ..Limits::default()
        },
    ] {
        let (reg, _) = registry(limits)?;
        assert!(matches!(
            reserve_backed(&reg, 1_048_576),
            Err(Error::NativeCapacity)
        ));
        assert_eq!(reg.lock()?.pending_bytes, 0);
    }
    Ok(())
}
#[tokio::test]
async fn retained_backing_capacity_cannot_bypass_retained_or_resident_limits() -> TestResult {
    for limits in [
        Limits {
            max_input_bytes: 1,
            max_retained_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_input_bytes: 1,
            max_resident_bytes: 66,
            ..Limits::default()
        },
    ] {
        let (reg, _) = registry(limits)?;
        let auth = reg
            .authorize_routine(reserve_backed(&reg, 1)?, &Routine)
            .await?;
        assert!(matches!(
            reg.retain_plaintext(auth, backed_input(1_048_576)),
            Err(Error::NativeCapacity)
        ));
        assert_eq!(reg.lock()?.retained_bytes, 0);
        assert_eq!(reg.lock()?.pending_bytes, 0);
    }
    Ok(())
}
#[tokio::test]
async fn admitted_backing_capacity_stays_charged_until_cancel_publication_and_revoke() -> TestResult
{
    let (reg, _) = registry(Limits {
        max_input_bytes: 1,
        ..Limits::default()
    })?;
    let work = reserve_backed(&reg, 128)?;
    assert_eq!(reg.lock()?.pending_bytes, 160);
    reg.advance_generation(2)?;
    assert_eq!(reg.lock()?.pending_bytes, 160);
    drop(work);
    assert_eq!(reg.lock()?.pending_bytes, 0);
    let work = reg.reserve(Request {
        registration: "a",
        authenticated_peer: ":1.1",
        purpose: Purpose::ConfigUserMaster,
        kind: OperationKind::RetainPlaintext,
        call_id: "call",
        input: backed_input(128),
        ttl_ms: 100,
        generation: 2,
    })?;
    let auth = reg.authorize_routine(work, &Routine).await?;
    assert_eq!(reg.lock()?.pending_bytes, 160);
    let handle = reg.retain_plaintext(auth, backed_input(256))?;
    assert_eq!(reg.lock()?.pending_bytes, 0);
    assert_eq!(reg.lock()?.retained_bytes, 256);
    reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 2)?;
    assert_eq!(reg.lock()?.retained_bytes, 256);
    reg.revoke_scope("b")?;
    assert_eq!(reg.lock()?.retained_bytes, 256);
    reg.revoke_scope("a")?;
    assert_eq!(reg.lock()?.retained_bytes, 0);
    Ok(())
}

#[tokio::test]
async fn borrowed_native_deadline_and_live_grant_validation_preserve_original_authority()
-> TestResult {
    let (reg, clock) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"fixed backend",
    )?;
    let safe = work.binding().safe_arguments();
    assert_eq!(work.binding().expires_at_ms(), 1100);
    clock.0.store(50, Ordering::SeqCst);
    assert_eq!(work.binding().expires_at_ms(), 1100);
    assert_eq!(work.binding().safe_arguments(), safe);
    let grant = reg.authorize_human(work, &Human).await?;
    reg.validate_grant(&grant)?;
    let (other, _) = registry(Limits::default())?;
    assert!(other.validate_grant(&grant).is_err());
    clock.0.store(100, Ordering::SeqCst);
    assert!(reg.validate_grant(&grant).is_err());
    Ok(())
}
#[tokio::test]
async fn native_grant_validation_fences_revocation_generation_and_closed_owner() -> TestResult {
    for mode in 0..3 {
        let (reg, _) = registry(Limits::default())?;
        let work = reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::NativeMasterGrant,
            b"fixed backend",
        )?;
        let grant = reg.authorize_human(work, &Human).await?;
        match mode {
            0 => reg.revoke_scope("a")?,
            1 => reg.advance_generation(2)?,
            _ => reg.close(),
        }
        assert!(reg.validate_grant(&grant).is_err());
    }
    Ok(())
}

#[test]
fn native_consumption_preserves_independently_verified_distinct_audit_scope() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::NativeMasterGrant,
        b"fixed backend",
    )?;
    let original = human_receipt(work.binding())?;
    let mut actual = original.audit.clone();
    actual.scope.user = "actual-audit-user".into();
    let expected = actual.scope.clone();
    let receipt = HumanGrantReceipt::from_verified_native_consumption(
        work.binding(),
        original.row.clone(),
        actual.clone(),
        expected.clone(),
    )?;
    receipt.verify(work.binding())?;
    assert_eq!(receipt.audit, actual);
    assert!(
        HumanGrantReceipt::from_durable_consumption(
            work.binding(),
            original.row.clone(),
            actual.clone()
        )
        .is_err()
    );
    let mut wrong = expected;
    wrong.user = "other-audit-subject".into();
    assert!(
        HumanGrantReceipt::from_verified_native_consumption(
            work.binding(),
            original.row,
            actual,
            wrong
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn rejected_prepared_generation_preserves_live_handles_and_reservations() -> TestResult {
    let (reg, _) = registry(Limits::default())?;
    let work = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"live",
    )?;
    let handle = reg.retain_plaintext(
        reg.authorize_routine(work, &Routine).await?,
        Zeroizing::new(b"live".to_vec()),
    )?;
    let pending = reserve(
        &reg,
        Purpose::ConfigUserMaster,
        OperationKind::RetainPlaintext,
        b"pending",
    )?;
    let key = reg.lock()?.authorization_key.to_vec();
    drop(reg.prepare_generation(2)?);
    assert_eq!(&*reg.lock()?.authorization_key, key.as_slice());
    pending.validate()?;
    reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)?;
    reg.prepare_generation(2)?.commit();
    assert!(pending.validate().is_err());
    drop(pending);
    assert!(
        reg.validate_handle(&handle, "a", Purpose::ConfigUserMaster, ":1.1", 1)
            .is_err()
    );
    Ok(())
}
#[test]
fn prepared_generation_clock_rollback_permanently_closes_authority() -> TestResult {
    let (reg, clock) = registry(Limits::default())?;
    clock.0.store(1, Ordering::SeqCst);
    drop(reg.prepare_generation(2)?);
    clock.0.store(0, Ordering::SeqCst);
    assert!(reg.prepare_generation(2).is_err());
    clock.0.store(2, Ordering::SeqCst);
    assert!(reg.prepare_generation(2).is_err());
    assert!(reg.lock()?.closed);
    Ok(())
}

#[test]
fn reservation_keeps_capacity_charged_until_confidential_buffer_teardown() -> TestResult {
    let (registry, _) = registry(Limits::default())?;
    let work = reserve(
        &registry,
        Purpose::AppEncryptionMaster,
        OperationKind::NativeMasterGrant,
        b"synthetic",
    )?;
    REFUND_SAMPLES.with(|samples| samples.borrow_mut().clear());
    REFUND_PROBE.with(|probe| *probe.borrow_mut() = Some(registry.state.clone()));
    drop(work);
    REFUND_PROBE.with(|probe| *probe.borrow_mut() = None);
    REFUND_SAMPLES.with(|samples| {
        let samples = samples.borrow();
        assert!(samples.len() >= 2, "P01");
        assert!(samples.iter().all(|pending| *pending > 0), "P02");
    });
    assert_eq!(
        registry
            .state
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .pending_bytes,
        0,
        "P03"
    );
    Ok(())
}

#[test]
fn app_store_cannot_enter_generic_routine_or_master_admission() -> TestResult {
    let (registry, _) = registry(Limits::default())?;
    assert!(
        reserve(
            &registry,
            Purpose::AppEncryptionMaster,
            OperationKind::AppStore,
            b"synthetic"
        )
        .is_err(),
        "P01"
    );
    Ok(())
}

struct AdvancingGatedClock {
    registry: Mutex<Option<Registry>>,
    armed: std::sync::atomic::AtomicBool,
}
impl NativeClock for AdvancingGatedClock {
    fn now(&self) -> Result<Time> {
        let initial = Time {
            wall: 1_000,
            monotonic: 0,
        };
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(initial);
        }
        let registry = self
            .registry
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .clone()
            .ok_or(Error::NativeDenied)?;
        let advanced = Time {
            wall: 1_002,
            monotonic: 2,
        };
        if let Ok(_gate) = registry.physical_gate.try_lock() {
            // Deterministically advance healthy authority after this sample,
            // before the caller obtains its physical gate (the reported race).
            registry
                .state
                .lock()
                .map_err(|_| Error::NativeDenied)?
                .check(advanced)?;
            return Ok(initial);
        }
        // Gate-owned sampling sees current time, never the earlier sample.
        Ok(advanced)
    }
}
#[test]
fn ordinary_authority_samples_current_clock_only_inside_physical_gate() -> TestResult {
    let clock = Arc::new(AdvancingGatedClock {
        registry: Mutex::new(None),
        armed: std::sync::atomic::AtomicBool::new(false),
    });
    let reg = Registry::new(
        vec![registration("a")],
        ":1.1",
        1,
        Limits::default(),
        clock.clone(),
    )?;
    *clock.registry.lock().map_err(|_| "P01")? = Some(reg.clone());
    clock.armed.store(true, Ordering::SeqCst);
    assert!(
        reserve(
            &reg,
            Purpose::ConfigUserMaster,
            OperationKind::RetainPlaintext,
            b"synthetic"
        )
        .is_ok(),
        "P02"
    );
    assert!(!reg.state.lock().map_err(|_| "P03")?.closed, "P04");
    Ok(())
}
