use super::super::SECRET_SCOPE_LIFECYCLE;
use super::*;
use std::result::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The module's confidential authorities are process-owned and intentionally
/// survive service-tree replacement. Run actual bus fixtures in a child test
/// process so Windows' linked module loader cannot share those owners between
/// independent broker instances in the same libtest process.
fn isolate_process_owned_fixture(
    test_filter: &str,
    marker: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    const CHILD_MARKER: &str = "TINYSECURITY_PROCESS_OWNED_FIXTURE";
    if std::env::var(CHILD_MARKER).is_ok_and(|value| value == marker) {
        return Ok(false);
    }
    let status = std::process::Command::new(std::env::current_exe()?)
        .arg(test_filter)
        .arg("--nocapture")
        .env(CHILD_MARKER, marker)
        .status()?;
    if !status.success() {
        return Err(format!("isolated fixture process exited with {status}").into());
    }
    Ok(true)
}
#[derive(Debug)]
struct FixedClock(std::sync::atomic::AtomicU64);
impl tinysecurity::approval::Clock for FixedClock {
    fn wall_ms(&self) -> Option<u64> {
        Some(self.0.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}
fn scope() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "registered-user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "registered-policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: false,
        auto_approve_all: true,
    }
}
fn config() -> SecretConfig2 {
    SecretConfig2 {
        registrations: vec![SecretRegistration2 {
            registration_id: "b".repeat(32),
            approval_scope_id: "a".repeat(32),
            origin: Origin::Operator,
            purpose: MasterPurpose2::ConfigUserMaster,
            target: SecretBinding2 {
                backend_id: "c".repeat(32),
                slot: MasterSlotKind2::User,
            },
            legacy: vec![
                SecretBinding2 {
                    backend_id: "d".repeat(32),
                    slot: MasterSlotKind2::File,
                },
                SecretBinding2 {
                    backend_id: "e".repeat(32),
                    slot: MasterSlotKind2::User,
                },
            ],
        }],
        limits: SecretLimits2::default(),
        // This fixture also runs under llvm-cov on Windows; 50 ms can turn
        // an otherwise valid backend callback into a spurious authority deny.
        callback_timeout_ms: 1000,
    }
}
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
fn request(call: u32) -> SecretRequest2 {
    SecretRequest2 {
        registration_id: "b".repeat(32),
        call_id: format!("original-private-{call}"),
        ttl_ms: 30000,
        operation: SecretOperation2::ResolveConfigMaster,
    }
}

#[test]
fn pairing_master_lookup_requires_one_config_user_registration_for_the_scope() -> TestResult {
    let descriptor = config().registrations.remove(0);
    let scope_id = "a".repeat(32);
    let selected = unique_config_master_for_scope(std::iter::once(&descriptor), &scope_id)?;
    assert_eq!(selected.registration_id, "b".repeat(32));
    ensure_scope_id_matches(&scope_id, &scope())?;
    assert!(ensure_scope_id_matches(&"c".repeat(32), &scope()).is_err());

    assert!(unique_config_master_for_scope(std::iter::empty(), &"a".repeat(32)).is_err());
    assert!(
        unique_config_master_for_scope(
            std::iter::once(&descriptor).chain(std::iter::once(&descriptor)),
            &"a".repeat(32),
        )
        .is_err()
    );
    let mut app = descriptor.clone();
    app.purpose = MasterPurpose2::AppEncryptionMaster;
    assert!(unique_config_master_for_scope(std::iter::once(&app), &"a".repeat(32)).is_err());
    Ok(())
}
struct Backend {
    mode: u32,
    loads: AtomicU32,
    sets: AtomicU32,
    rows: Mutex<BTreeMap<String, ApprovalRecord2>>,
    batches: Mutex<Vec<AuditSinkRequest2>>,
    target: Mutex<Option<Zeroizing<Vec<u8>>>>,
    registry: Mutex<Option<handles::Registry>>,
    mutation_pending: std::sync::atomic::AtomicBool,
    release: tokio::sync::Notify,
    cipher_slots: Mutex<BTreeMap<u16, cipher_tests::Slot>>,
    cipher_clock: Mutex<Option<Arc<FixedClock>>>,
}
impl Backend {
    fn new(mode: u32) -> Self {
        Self {
            mode,
            loads: AtomicU32::new(0),
            sets: AtomicU32::new(0),
            rows: Mutex::new(BTreeMap::new()),
            batches: Mutex::new(Vec::new()),
            target: Mutex::new(
                (mode >= 20 || matches!(mode, 0 | 17))
                    .then(|| Zeroizing::new("AA".repeat(32).into_bytes())),
            ),
            registry: Mutex::new(None),
            mutation_pending: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
            cipher_slots: Mutex::new(BTreeMap::new()),
            cipher_clock: Mutex::new(None),
        }
    }
}
#[derive(Clone)]
struct Store(Arc<Backend>);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl Store {
    async fn load(&self, request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        let records = self
            .0
            .rows
            .lock()
            .map_err(|_| denied())?
            .values()
            .cloned()
            .collect();
        std::future::ready(Ok(ApprovalLoadResponse2 {
            scope: request.scope,
            records,
        }))
        .await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> tinybus::Result<ApprovalCasResponse2> {
        let receipt = {
            let mut rows = self.0.rows.lock().map_err(|_| denied())?;
            if rows.get(&request.record_id).map(|r| r.version) != request.expected_version {
                return Err(denied());
            }
            let receipt = ApprovalCasResponse2 {
                scope: request.scope.clone(),
                record_id: request.record_id.clone(),
                mutation_id: request.mutation_id.clone(),
                resulting_version: request.next_record.version,
            };
            rows.insert(request.record_id, request.next_record);
            receipt
        };
        std::future::ready(Ok(receipt)).await
    }
}
#[derive(Clone)]
struct Sink(Arc<Backend>);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    #[tinybus(confidential)]
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        {
            let mut batches = self.0.batches.lock().map_err(|_| denied())?;
            if let Some(prior) = batches
                .iter()
                .find(|b| b.events[0].event_id == request.events[0].event_id)
            {
                if prior != &request {
                    return Err(denied());
                }
            } else {
                batches.push(request.clone());
            }
        }
        cipher_tests::audit_boundary(&self.0, &request)?;
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.expected_tail + 1,
            events: request
                .events
                .into_iter()
                .map(|e| AuditEventReceipt2 {
                    event_id: e.event_id,
                    sequence: e.sequence,
                })
                .collect(),
        }))
        .await
    }
}
#[derive(Clone)]
struct Prompt(Arc<Backend>);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalPrompt2")]
impl Prompt {
    #[tinybus(confidential)]
    async fn prompt(
        &self,
        request: ApprovalDeliveryRequest2,
    ) -> tinybus::Result<ApprovalDeliveryResponse2> {
        if self.0.mode == 18 {
            std::future::pending::<()>().await;
        }
        std::future::ready(Ok(ApprovalDeliveryResponse2 {
            request_id: request.row.request_id,
            nonce: request.row.nonce,
            delivered: true,
        }))
        .await
    }
    #[tinybus(confidential)]
    async fn verify_human(
        &self,
        request: VerifyHumanRequest2,
    ) -> tinybus::Result<HumanDecisionReceipt2> {
        use sha2::{Digest, Sha256};
        if request.decision_ticket != "actual-fixture-human-ticket"
            || request.row.state != ApprovalLifecycle2::Pending
        {
            return Err(denied());
        }
        std::future::ready(Ok(HumanDecisionReceipt2 {
            row: request.row,
            choice: ApprovalChoice2::Once,
            actor: "authenticated-fixture-human".into(),
            ticket_sha256: format!("{:x}", Sha256::digest(request.decision_ticket.as_bytes())),
        }))
        .await
    }
}
#[derive(Clone)]
struct Secrets(Arc<Backend>);
impl Secrets {
    fn verify_inventory(&self, identity: &SecretBackendIdentity2) -> tinybus::Result<()> {
        let config = config();
        let descriptor = &config.registrations[0];
        let app = self.0.mode == 17;
        if identity.registration_id != descriptor.registration_id
            || identity.generation != 1
            || identity.operation_id.len() != 64
            || !identity.operation_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(denied());
        }
        let registered = if identity.phase == SecretPhase2::LegacyRead {
            descriptor.legacy.iter().any(|binding| {
                identity.backend_id == binding.backend_id
                    && identity.slot
                        == if app {
                            MasterSlotKind2::App
                        } else {
                            binding.slot
                        }
            })
        } else {
            identity.backend_id == descriptor.target.backend_id
                && identity.slot
                    == if app {
                        MasterSlotKind2::App
                    } else {
                        descriptor.target.slot
                    }
        };
        if registered { Ok(()) } else { Err(denied()) }
    }
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.SecretBackend2")]
impl Secrets {
    #[tinybus(confidential)]
    async fn load(&self, request: SecretBackendLoadRequest2) -> tinybus::Result<serde_json::Value> {
        self.verify_inventory(&request.identity)?;
        if self.0.mutation_pending.load(Ordering::SeqCst)
            && request.identity.phase != SecretPhase2::TargetReadback
        {
            return Err(denied());
        }
        self.0.loads.fetch_add(1, Ordering::SeqCst);
        // Real Human verification, CAS and exact Reserved audit already happened.
        assert!(self.0.rows.lock().map_err(|_| denied())?.values().any(|r| {
            serde_json::from_str::<ApprovalRow2>(&r.record_json).is_ok_and(|r| {
                r.state == ApprovalLifecycle2::Reserved && r.choice == Some(ApprovalChoice2::Once)
            })
        }));
        assert!(self.0.batches.lock().map_err(|_| denied())?.len() >= 3);
        let mut identity = request.identity;
        let status = match identity.phase {
            SecretPhase2::TargetRead => {
                if self.0.mode == 9 {
                    self.0
                        .registry
                        .lock()
                        .map_err(|_| denied())?
                        .as_ref()
                        .ok_or_else(denied)?
                        .advance_generation(2)
                        .map_err(|_| denied())?;
                }
                match self.0.mode {
                    7 => identity.operation_id.push('x'),
                    11 => identity.backend_id.push('x'),
                    12 => identity.registration_id.push('x'),
                    13 => identity.generation += 1,
                    14 => identity.phase = SecretPhase2::LegacyRead,
                    15 => identity.slot = MasterSlotKind2::File,
                    16 => return Ok(serde_json::json!({"status":{"kind":"absent"}})),
                    _ => {}
                }
                if self.0.mode == 8 {
                    SecretBackendLoadStatus2::Present {
                        encoded: vec![b' '; 4097],
                    }
                } else {
                    self.0.target.lock().map_err(|_| denied())?.as_ref().map_or(
                        SecretBackendLoadStatus2::Absent,
                        |v| SecretBackendLoadStatus2::Present {
                            encoded: v.to_vec(),
                        },
                    )
                }
            }
            SecretPhase2::LegacyRead
                if matches!(self.0.mode, 4 | 5) && identity.slot == MasterSlotKind2::File =>
            {
                SecretBackendLoadStatus2::Present {
                    encoded: "AB".repeat(32).into_bytes(),
                }
            }
            SecretPhase2::LegacyRead if self.0.mode == 4 => SecretBackendLoadStatus2::Denied,
            SecretPhase2::LegacyRead if self.0.mode == 5 => SecretBackendLoadStatus2::Present {
                encoded: b"malformed".to_vec(),
            },
            SecretPhase2::LegacyRead if self.0.mode == 1 => SecretBackendLoadStatus2::Present {
                encoded: format!(" \n{}\n", "AB".repeat(32)).into_bytes(),
            },
            SecretPhase2::LegacyRead if self.0.mode == 3 => SecretBackendLoadStatus2::Present {
                encoded: if identity.slot == MasterSlotKind2::File {
                    "AB".repeat(32).into_bytes()
                } else {
                    "CD".repeat(32).into_bytes()
                },
            },
            SecretPhase2::LegacyRead => SecretBackendLoadStatus2::Absent,
            SecretPhase2::TargetReadback if self.0.mode == 6 => SecretBackendLoadStatus2::Present {
                encoded: "FF".repeat(32).into_bytes(),
            },
            SecretPhase2::TargetReadback => SecretBackendLoadStatus2::Present {
                encoded: self
                    .0
                    .target
                    .lock()
                    .map_err(|_| denied())?
                    .as_ref()
                    .ok_or_else(denied)?
                    .to_vec(),
            },
            SecretPhase2::TargetSet => return Err(denied()),
        };
        std::future::ready(Ok(serde_json::to_value(SecretBackendLoadResponse2 {
            identity,
            status,
        })?))
        .await
    }
    #[tinybus(confidential)]
    async fn set(
        &self,
        request: SecretBackendSetRequest2,
    ) -> tinybus::Result<SecretBackendSetResponse2> {
        self.verify_inventory(&request.identity)?;
        if self.0.mutation_pending.swap(true, Ordering::SeqCst) {
            return Err(denied());
        }
        self.0.sets.fetch_add(1, Ordering::SeqCst);
        if self.0.mode == 10 {
            // Actual detached provider future survives callback cancellation/timeout.
            let state = self.0.clone();
            let encoded = Zeroizing::new(request.encoded.clone());
            tokio::spawn(async move {
                state.release.notified().await;
                if let Ok(mut target) = state.target.lock() {
                    *target = Some(encoded);
                }
            });
            std::future::pending::<()>().await;
        }
        *self.0.target.lock().map_err(|_| denied())? = Some(Zeroizing::new(request.encoded));
        // Keep the host slot fence until exact readback; test mode10 never clears it.
        std::future::ready(Ok(SecretBackendSetResponse2 {
            identity: request.identity,
            status: SecretBackendSetStatus2::Stored,
        }))
        .await
    }
}
struct Control {
    connection: Connection,
    service: PolicyService,
    state: Arc<Backend>,
    clock: Arc<FixedClock>,
}
impl Control {
    async fn rollback_pending(&self) -> tinybus::Result<serde_json::Value> {
        let evaluate = EvaluateSecretRequest2 {
            request: request(1),
            audit: audit(1),
        };
        let pending = self.service.secret_approval(evaluate.clone()).await?;
        assert_eq!(pending.state, ApprovalLifecycle2::Pending);
        self.clock.0.store(999, Ordering::SeqCst);
        assert!(self.service.secret_approval(evaluate).await.is_err());
        assert_eq!(self.state.loads.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.sets.load(Ordering::SeqCst), 0);
        Ok(serde_json::json!({"loads":0,"sets":0}))
    }
    async fn verify_reinit_transition(&self) -> tinybus::Result<()> {
        if !matches!(self.state.mode, 0 | 1 | 2 | 6 | 10 | 17) {
            return Ok(());
        }
        let secret = self.service.secret.as_ref().ok_or_else(denied)?;
        let prior_aliases = secret.aliases.lock().map_err(|_| denied())?.len();
        let brokers: Vec<_> = secret
            .registered
            .values()
            .map(|reg| Arc::as_ptr(&reg.broker) as usize)
            .collect();
        // Dropping a valid preparation simulates rejected event publication.
        let policy_before = self.service.read()?.info();
        assert!(
            super::super::activate_authorities(None, None, Some(secret), 2, || Err(denied()))
                .is_err()
        );
        assert_eq!(self.service.read()?.info(), policy_before);
        assert_eq!(
            secret.aliases.lock().map_err(|_| denied())?.len(),
            prior_aliases
        );
        for alias in secret.aliases.lock().map_err(|_| denied())?.values() {
            secret
                .registry
                .validate_handle(
                    &alias.handle,
                    &alias.registration,
                    alias.purpose,
                    &secret.peer,
                    alias.generation,
                )
                .map_err(|_| denied())?;
        }
        // Include a pending Reservation: its Drop must not deadlock on native commit.
        let mut req = request(77);
        if self.state.mode == 17 {
            req.operation = SecretOperation2::ResolveAppMaster;
        }
        let work = secret
            .registry
            .reserve(handles::Request {
                registration: &req.registration_id,
                authenticated_peer: &secret.peer,
                purpose: if self.state.mode == 17 {
                    handles::Purpose::AppEncryptionMaster
                } else {
                    handles::Purpose::ConfigUserMaster
                },
                kind: handles::OperationKind::NativeMasterGrant,
                call_id: &req.call_id,
                input: Zeroizing::new(vec![]),
                ttl_ms: 100,
                generation: 1,
            })
            .map_err(|_| denied())?;
        secret.pending.lock().map_err(|_| denied())?.insert(
            (req.registration_id.clone(), req.call_id.clone()),
            Pending {
                request: req,
                audit: audit(77),
                work,
                row: None,
            },
        );
        {
            let mut policy = self.service.policy.write().map_err(|_| denied())?;
            super::super::activate_authorities(None, None, Some(secret), 2, || {
                self.service
                    .approvals
                    .as_ref()
                    .ok_or_else(denied)?
                    .advance_generation(2)
                    .map_err(approval_failure)?;
                policy
                    .reinitialize(ModuleConfig::default())
                    .map_err(|_| denied())?;
                Ok(())
            })?;
            assert_eq!(policy.info().generation, 2);
        }
        assert!(secret.pending.lock().map_err(|_| denied())?.is_empty());
        assert!(secret.aliases.lock().map_err(|_| denied())?.is_empty());
        assert_eq!(
            brokers,
            secret
                .registered
                .values()
                .map(|reg| Arc::as_ptr(&reg.broker) as usize)
                .collect::<Vec<_>>()
        );
        assert!(prepare_generation(Some(secret), 2).is_err());
        if matches!(self.state.mode, 6 | 10) {
            let prior = self.state.loads.load(Ordering::SeqCst);
            for reg in secret.registered.values() {
                assert!(reg.resolver.resolve().await.is_err());
            }
            assert_eq!(self.state.loads.load(Ordering::SeqCst), prior);
            assert_eq!(self.state.sets.load(Ordering::SeqCst), 1);
        }
        Ok(())
    }
    async fn canceled_evaluation(
        &self,
        _proxy: &tinybus::Proxy,
    ) -> tinybus::Result<serde_json::Value> {
        let evaluation = EvaluateSecretRequest2 {
            request: request(1),
            audit: audit(1),
        };
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                self.service.secret_approval(evaluation.clone())
            )
            .await
            .is_err()
        );
        let state = self.service.secret.as_ref().ok_or_else(denied)?;
        assert_eq!(state.pending.lock().map_err(|_| denied())?.len(), 1);
        assert!(self.service.secret_approval(evaluation).await.is_err());
        for call in 2..=4 {
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(20),
                    self.service.secret_approval(EvaluateSecretRequest2 {
                        request: request(call),
                        audit: audit(u64::from(call))
                    })
                )
                .await
                .is_err()
            );
        }
        assert_eq!(state.pending.lock().map_err(|_| denied())?.len(), 4);
        assert!(
            self.service
                .secret_approval(EvaluateSecretRequest2 {
                    request: request(5),
                    audit: audit(5)
                })
                .await
                .is_err()
        );
        assert_eq!(self.state.loads.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.sets.load(Ordering::SeqCst), 0);
        state.close();
        assert!(state.pending.lock().map_err(|_| denied())?.is_empty());
        Ok(serde_json::json!({"loads":0,"sets":0}))
    }
    async fn verify_close(&self) -> tinybus::Result<()> {
        let state = self.service.secret.as_ref().ok_or_else(denied)?;
        let mut request = request(99);
        if self.state.mode == 17 {
            request.operation = SecretOperation2::ResolveAppMaster;
        }
        if matches!(self.state.mode, 0 | 1 | 2 | 17) {
            state
                .registry
                .revoke_scope(&request.registration_id)
                .map_err(|_| denied())?;
            state.prune()?;
            assert!(state.aliases.lock().map_err(|_| denied())?.is_empty());
        }
        state.close();
        assert!(state.pending.lock().map_err(|_| denied())?.is_empty());
        assert!(state.aliases.lock().map_err(|_| denied())?.is_empty());
        assert!(
            self.service
                .secret_approval(EvaluateSecretRequest2 {
                    request,
                    audit: audit(99)
                })
                .await
                .is_err()
        );
        Ok(())
    }
    async fn review(
        &self,
        proxy: &tinybus::Proxy,
        req: SecretRequest2,
    ) -> tinybus::Result<ExecuteSecretRequest2> {
        assert!(
            proxy
                .call::<ApprovalRow2>(
                    names::methods::EVALUATE_SECRET2,
                    (EvaluateSecretRequest2 {
                        request: req.clone(),
                        audit: audit(1)
                    },)
                )
                .await
                .is_err()
        );
        let pending: ApprovalRow2 = proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET2,
                (EvaluateSecretRequest2 {
                    request: req.clone(),
                    audit: audit(1),
                },),
            )
            .await?;
        assert_eq!(pending.state, ApprovalLifecycle2::Pending);
        let retry: ApprovalRow2 = proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET2,
                (EvaluateSecretRequest2 {
                    request: req.clone(),
                    audit: audit(1),
                },),
            )
            .await?;
        assert_eq!(retry.request_id, pending.request_id);
        assert_eq!(retry.args_redacted, pending.args_redacted);
        assert!(!serde_json::to_string(&pending)?.contains("original-private"));
        let changed = SecretRequest2 {
            ttl_ms: 29999,
            ..req.clone()
        };
        assert!(
            self.service
                .secret_approval(EvaluateSecretRequest2 {
                    request: changed,
                    audit: audit(1)
                })
                .await
                .is_err()
        );
        let execute = ExecuteSecretRequest2 {
            request: req,
            request_id: pending.request_id.clone(),
            audit: audit(3),
        };
        let wrong = ExecuteSecretRequest2 {
            request_id: "f".repeat(32),
            ..execute.clone()
        };
        assert!(self.service.secret_execute(wrong).await.is_err());
        assert_eq!(self.state.loads.load(Ordering::SeqCst), 0);
        let approved: ApprovalRow2 = proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: "a".repeat(32),
                    request_id: pending.request_id.clone(),
                    decision_ticket: "actual-fixture-human-ticket".into(),
                    audit: audit(2),
                },),
            )
            .await?;
        assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
        Ok(execute)
    }
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.SecretFixture")]
impl Control {
    #[allow(clippy::too_many_lines)] // One fixture exercises the full secret lifecycle over TinyBus.
    async fn exercise(&self) -> tinybus::Result<serde_json::Value> {
        let peer = self.connection.unique_name().ok_or_else(denied)?;
        let proxy = self
            .connection
            .proxy(peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
        if self.state.mode == 19 {
            return self.rollback_pending().await;
        }
        if self.state.mode == 18 {
            return self.canceled_evaluation(&proxy).await;
        }
        if self.state.mode == 22 {
            let approval_request = RegisterApprovalScopeRequest2 {
                scope: ApprovalScope2 {
                    scope_id: "f".repeat(32),
                    subject: SubjectScope {
                        user: "runtime-user".into(),
                        workspace: "runtime-workspace".into(),
                        agent: "runtime-agent".into(),
                    },
                    policy_ref: "runtime-policy".into(),
                    generation: 1,
                    ceiling: AccessTier::Full,
                    require_approval: true,
                    auto_approve_all: false,
                },
                grants: ApprovalGrants2::default(),
                audit_stream_id: "9".repeat(32),
                report_handle: false,
            };
            let _: ApprovalScopeReceipt2 = proxy
                .call(
                    names::methods::REGISTER_APPROVAL_SCOPE2,
                    (&approval_request,),
                )
                .await?;
            let registration = SecretRegistration2 {
                registration_id: "1".repeat(32),
                approval_scope_id: "f".repeat(32),
                origin: Origin::Operator,
                purpose: MasterPurpose2::ConfigUserMaster,
                target: SecretBinding2 {
                    backend_id: "2".repeat(32),
                    slot: MasterSlotKind2::User,
                },
                legacy: vec![SecretBinding2 {
                    backend_id: "7".repeat(32),
                    slot: MasterSlotKind2::File,
                }],
            };
            let register_request = RegisterSecretScopeRequest2 {
                registration: registration.clone(),
            };
            let unknown = RegisterSecretScopeRequest2 {
                registration: SecretRegistration2 {
                    registration_id: "4".repeat(32),
                    approval_scope_id: "5".repeat(32),
                    origin: Origin::Operator,
                    purpose: MasterPurpose2::ConfigUserMaster,
                    target: SecretBinding2 {
                        backend_id: "6".repeat(32),
                        slot: MasterSlotKind2::User,
                    },
                    legacy: vec![],
                },
            };
            assert!(
                proxy
                    .call_confidential::<SecretScopeReceipt2>(
                        names::methods::REGISTER_SECRET_SCOPE2,
                        (&unknown,),
                    )
                    .await
                    .is_err()
            );
            let receipt: SecretScopeReceipt2 = proxy
                .call_confidential(names::methods::REGISTER_SECRET_SCOPE2, (&register_request,))
                .await?;
            assert!(receipt.active);
            assert_eq!(receipt.registration_id, registration.registration_id);
            let pairing_request = RegisterDevicePairingScopeRequest2 {
                approval_scope_id: "f".repeat(32),
            };
            let pairing_receipt: DevicePairingScopeReceipt2 = proxy
                .call(
                    names::methods::REGISTER_DEVICE_PAIRING_SCOPE2,
                    (&pairing_request,),
                )
                .await?;
            assert_eq!(pairing_receipt.scope_id, registration.approval_scope_id);
            assert!(pairing_receipt.active);
            let duplicate_pairing_receipt: DevicePairingScopeReceipt2 = proxy
                .call(
                    names::methods::REGISTER_DEVICE_PAIRING_SCOPE2,
                    (&pairing_request,),
                )
                .await?;
            assert_eq!(duplicate_pairing_receipt, pairing_receipt);
            let secret = self.service.secret.as_ref().ok_or_else(denied)?;
            let static_registration = config().registrations[0].clone();
            let static_request = RegisterSecretScopeRequest2 {
                registration: static_registration.clone(),
            };
            let static_receipt: SecretScopeReceipt2 = proxy
                .call_confidential(names::methods::REGISTER_SECRET_SCOPE2, (&static_request,))
                .await?;
            assert!(static_receipt.active);
            assert_eq!(
                static_receipt.registration_id,
                static_registration.registration_id
            );
            let mut conflicting_static = static_request;
            conflicting_static.registration.target.backend_id = "f".repeat(32);
            assert!(
                proxy
                    .call_confidential::<SecretScopeReceipt2>(
                        names::methods::REGISTER_SECRET_SCOPE2,
                        (&conflicting_static,),
                    )
                    .await
                    .is_err()
            );
            let mut invalid_replacement = approval_request.clone();
            invalid_replacement.scope.subject.user = "different-user".into();
            assert!(
                self.service
                    .replace_approval_scope2(invalid_replacement)
                    .await
                    .is_err()
            );
            assert!(
                secret
                    .dynamic
                    .lock()
                    .map_err(|_| denied())?
                    .contains_key(&registration.registration_id)
            );
            let prior = Arc::as_ptr(
                secret
                    .dynamic
                    .lock()
                    .map_err(|_| denied())?
                    .get(&registration.registration_id)
                    .ok_or_else(denied)?,
            ) as usize;
            assert_eq!(
                proxy
                    .call_confidential::<SecretScopeReceipt2>(
                        names::methods::REGISTER_SECRET_SCOPE2,
                        (&register_request,),
                    )
                    .await?,
                receipt
            );
            assert_eq!(
                Arc::as_ptr(
                    secret
                        .dynamic
                        .lock()
                        .map_err(|_| denied())?
                        .get(&registration.registration_id)
                        .ok_or_else(denied)?,
                ) as usize,
                prior
            );
            let mut conflicting = register_request;
            conflicting.registration.target.backend_id = "3".repeat(32);
            assert!(
                proxy
                    .call_confidential::<SecretScopeReceipt2>(
                        names::methods::REGISTER_SECRET_SCOPE2,
                        (&conflicting,),
                    )
                    .await
                    .is_err()
            );
            let base_scope = scope();
            assert!(
                self.service
                    .retire_approval_scope2(RetireApprovalScopeRequest2 {
                        scope_id: base_scope.scope_id.clone(),
                    })
                    .await
                    .is_err()
            );
            // A stale pending call can outlive a registration only across a
            // service-tree replacement. Replacing the scope must prune it
            // before any caller can resume work under the new generation.
            let reservation_request = request(88);
            let reservation = secret
                .registry
                .reserve(handles::Request {
                    registration: &reservation_request.registration_id,
                    authenticated_peer: &secret.peer,
                    purpose: handles::Purpose::ConfigUserMaster,
                    kind: handles::OperationKind::NativeMasterGrant,
                    call_id: &reservation_request.call_id,
                    input: Zeroizing::new(vec![]),
                    ttl_ms: reservation_request.ttl_ms,
                    generation: 1,
                })
                .map_err(|_| denied())?;
            let stale_request = SecretRequest2 {
                registration_id: "6".repeat(32),
                call_id: "orphaned-pending-call".into(),
                ttl_ms: 30_000,
                operation: SecretOperation2::ResolveConfigMaster,
            };
            secret.pending.lock().map_err(|_| denied())?.insert(
                (
                    stale_request.registration_id.clone(),
                    stale_request.call_id.clone(),
                ),
                Pending {
                    request: stale_request,
                    audit: audit(88),
                    work: reservation,
                    row: None,
                },
            );
            let _: ApprovalScopeReceipt2 = self
                .service
                .replace_approval_scope2(RegisterApprovalScopeRequest2 {
                    scope: ApprovalScope2 {
                        policy_ref: "registered-policy-next".into(),
                        ..base_scope
                    },
                    grants: ApprovalGrants2::default(),
                    audit_stream_id: "a".repeat(32),
                    report_handle: false,
                })
                .await?;
            assert!(
                secret.pending.lock().map_err(|_| denied())?.is_empty(),
                "scope replacement prunes pending calls for unknown registrations"
            );
            let cipher = self.service.secret_cipher.as_ref().ok_or_else(denied)?;
            let approvals = self.service.approvals.as_ref().ok_or_else(denied)?;
            assert_eq!(
                cipher.audit_policy_ref()?,
                approvals
                    .durable_policy_ref(&"a".repeat(32))
                    .map_err(|_| denied())?,
                "cipher audit policy follows the replaced approval scope",
            );
            let replacement = RegisterApprovalScopeRequest2 {
                scope: ApprovalScope2 {
                    scope_id: "f".repeat(32),
                    subject: SubjectScope {
                        user: "runtime-user".into(),
                        workspace: "runtime-workspace".into(),
                        agent: "runtime-agent".into(),
                    },
                    // Reusing the same policy reference still advances the
                    // approval generation. A retired dynamic secret ID must
                    // not become live again just because its descriptor is
                    // byte-for-byte identical.
                    policy_ref: "runtime-policy".into(),
                    generation: 1,
                    ceiling: AccessTier::Full,
                    require_approval: true,
                    auto_approve_all: false,
                },
                grants: ApprovalGrants2::default(),
                audit_stream_id: "9".repeat(32),
                report_handle: false,
            };
            let _: ApprovalScopeReceipt2 = proxy
                .call(names::methods::REPLACE_APPROVAL_SCOPE2, (&replacement,))
                .await?;
            assert!(
                proxy
                    .call::<DevicePairingScopeReceipt2>(
                        names::methods::REGISTER_DEVICE_PAIRING_SCOPE2,
                        (&pairing_request,),
                    )
                    .await
                    .is_err(),
                "retired approval scopes cannot regain pairing authority"
            );
            assert!(
                secret
                    .registration_id(&registration.registration_id)
                    .is_err()
            );
            assert!(
                proxy
                    .call_confidential::<SecretScopeReceipt2>(
                        names::methods::REGISTER_SECRET_SCOPE2,
                        (&RegisterSecretScopeRequest2 {
                            registration: registration.clone(),
                        },),
                    )
                    .await
                    .is_err(),
                "replacing the approval generation must require a new immutable secret ID"
            );
            let race_registration = SecretRegistration2 {
                registration_id: "6".repeat(32),
                target: SecretBinding2 {
                    backend_id: "5".repeat(32),
                    slot: MasterSlotKind2::User,
                },
                ..registration.clone()
            };
            let race_request = RegisterSecretScopeRequest2 {
                registration: race_registration.clone(),
            };
            self.service
                .register_secret_scope2(race_request.clone())
                .await?;
            let lifecycle = SECRET_SCOPE_LIFECYCLE.get_or_init(|| tokio::sync::Mutex::new(()));
            let held = lifecycle.lock().await;
            let replacing_service = self.service.clone();
            let replacing_request = replacement.clone();
            let (replace_started, replace_started_rx) = tokio::sync::oneshot::channel();
            let mut replacing = tokio::spawn(async move {
                let _ = replace_started.send(());
                replacing_service
                    .replace_approval_scope2(replacing_request)
                    .await
            });
            replace_started_rx.await.map_err(|_| denied())?;
            let registering_service = self.service.clone();
            let (register_started, register_started_rx) = tokio::sync::oneshot::channel();
            let mut registering = tokio::spawn(async move {
                let _ = register_started.send(());
                registering_service
                    .register_secret_scope2(race_request)
                    .await
            });
            register_started_rx.await.map_err(|_| denied())?;
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), &mut replacing)
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), &mut registering)
                    .await
                    .is_err()
            );
            drop(held);
            replacing.await.map_err(|_| denied())??;
            assert!(registering.await.map_err(|_| denied())?.is_err());
            assert!(
                secret
                    .dynamic
                    .lock()
                    .map_err(|_| denied())?
                    .get(&race_registration.registration_id)
                    .is_none()
            );
            let replacement_registration = SecretRegistration2 {
                registration_id: "7".repeat(32),
                target: SecretBinding2 {
                    backend_id: "8".repeat(32),
                    slot: MasterSlotKind2::User,
                },
                ..registration.clone()
            };
            let _: SecretScopeReceipt2 = proxy
                .call_confidential(
                    names::methods::REGISTER_SECRET_SCOPE2,
                    (&RegisterSecretScopeRequest2 {
                        registration: replacement_registration.clone(),
                    },),
                )
                .await?;
            let _: ApprovalScopeReceipt2 = proxy
                .call(
                    names::methods::RETIRE_APPROVAL_SCOPE2,
                    (RetireApprovalScopeRequest2 {
                        scope_id: "f".repeat(32),
                    },),
                )
                .await?;
            assert!(
                self.service
                    .secret
                    .as_ref()
                    .ok_or_else(denied)?
                    .registration_id(&replacement_registration.registration_id)
                    .is_err()
            );
        }
        let mut req = request(1);
        if self.state.mode == 17 {
            req.operation = SecretOperation2::ResolveAppMaster;
        }
        let mut execute = self.review(&proxy, req).await?;
        let result = proxy
            .call_confidential::<SecretResponse2>(names::methods::EXECUTE_SECRET2, (&execute,))
            .await;
        if self.state.mode >= 20 {
            let response = result?;
            return self.exercise_cipher(&proxy, response).await;
        }
        if self.state.mode <= 2 || self.state.mode == 17 {
            let response = result?;
            let encoded = serde_json::to_string(&response)?;
            assert!(!encoded.contains(&"AA".repeat(32)) && !encoded.contains(&"AB".repeat(32)));
            assert_eq!(
                self.service
                    .secret
                    .as_ref()
                    .ok_or_else(denied)?
                    .aliases
                    .lock()
                    .map_err(|_| denied())?
                    .len(),
                1
            );
            assert!(self.service.secret_execute(execute.clone()).await.is_err());
        } else {
            assert!(result.is_err());
            assert!(
                self.service
                    .secret
                    .as_ref()
                    .ok_or_else(denied)?
                    .aliases
                    .lock()
                    .map_err(|_| denied())?
                    .is_empty()
            );
        }
        // Failed readback/timeout is permanent in the exact persistent resolver.
        if matches!(self.state.mode, 6 | 10) {
            let prior = self.state.loads.load(Ordering::SeqCst);
            let req = request(2);
            let row = self
                .service
                .secret_approval(EvaluateSecretRequest2 {
                    request: req.clone(),
                    audit: audit(4),
                })
                .await?;
            let _: ApprovalRow2 = proxy
                .call(
                    names::methods::DECIDE2,
                    (DecideRequest2 {
                        scope_id: "a".repeat(32),
                        request_id: row.request_id.clone(),
                        decision_ticket: "actual-fixture-human-ticket".into(),
                        audit: audit(5),
                    },),
                )
                .await?;
            execute.request = req;
            execute.request_id = row.request_id;
            execute.audit = audit(6);
            assert!(self.service.secret_execute(execute).await.is_err());
            assert_eq!(self.state.loads.load(Ordering::SeqCst), prior);
            assert_eq!(self.state.sets.load(Ordering::SeqCst), 1);
            self.state.release.notify_one();
        }
        self.verify_reinit_transition().await?;
        let target = self
            .state
            .target
            .lock()
            .map_err(|_| denied())?
            .as_ref()
            .map(|v| v.to_vec());
        if self.state.mode == 1 {
            assert_eq!(
                target,
                Some(format!(" \n{}\n", "AB".repeat(32)).into_bytes())
            );
        }
        self.verify_close().await?;
        std::future::ready(Ok(serde_json::json!({"loads":self.state.loads.load(Ordering::SeqCst),"sets":self.state.sets.load(Ordering::SeqCst)}))).await
    }
}
async fn serve_callbacks(
    connection: &Connection,
    state: &Arc<Backend>,
    binding: &crate::callbacks::PeerBinding,
) -> tinybus::Result<()> {
    let path = callback_names2::OBJECT_PATH.parse::<tinybus::ObjectPath>()?;
    connection
        .serve_at(
            path.clone(),
            crate::callbacks::Authenticated::new(Store(state.clone()), binding.clone()),
        )
        .await?;
    connection
        .serve_at(
            path.clone(),
            crate::callbacks::Authenticated::new(Sink(state.clone()), binding.clone()),
        )
        .await?;
    connection
        .serve_at(
            path.clone(),
            crate::callbacks::Authenticated::new(Prompt(state.clone()), binding.clone()),
        )
        .await?;
    connection
        .serve_at(
            path.clone(),
            crate::callbacks::Authenticated::new(Secrets(state.clone()), binding.clone()),
        )
        .await?;
    connection
        .serve_at(
            path,
            crate::callbacks::Authenticated::new(
                cipher_tests::Consumer(state.clone()),
                binding.clone(),
            ),
        )
        .await?;
    Ok(())
}
mod linked_fixture {
    use super::*;

    fn approval_and_audit() -> (ApprovalConfig2, AuditConfig2) {
        (
            ApprovalConfig2 {
                timeout_ms: 1000,
                scopes: vec![scope()],
            },
            AuditConfig2 {
                scope: scope().subject,
                stream_id: "a".repeat(32),
                timeout_ms: 1000,
                required: true,
                native_path: None,
                max_bytes: 10000,
                max_archives: 3,
                journal_max_bytes: 100_000,
                journal_max_events: 1000,
            },
        )
    }
    fn activate_runtime_pairing(
        connection: &Connection,
        peer: &str,
        approvals: &ApprovalConfig2,
        audit: &AuditConfig2,
        secret: &Arc<SecretState>,
        clock: &Arc<FixedClock>,
    ) -> tinybus::Result<()> {
        let config = DeviceConfig2 {
            scopes: vec![],
            max_handles: 16,
            max_in_flight: 4,
            operations_per_minute: 4096,
            frames_per_minute: 12_000,
            max_ttl_ms: 300_000,
            max_message_bytes: 1024,
            max_bootstrap_nonces: 64,
        };
        let (device_registry, _) = super::super::super::device::configured(
            Some(config),
            Some(peer),
            Some(approvals),
            Some(audit),
            1,
            clock.as_ref(),
        )?;
        let pair_config = DevicePairingConfig2 {
            scopes: vec![],
            runtime_scope: Some(DevicePairingRuntimeScope2 {
                persistence_backend_id: "runtime-pairing-state".into(),
                legacy_device_backend_id: Some("8".repeat(32)),
                allowed_origins: vec![Origin::Operator],
            }),
            max_pairings: 32,
            max_pending: 8,
            max_pending_ttl_ms: 30_000,
            max_session_ttl_ms: 3_600_000,
            max_state_bytes: 65_536,
            callback_timeout_ms: 1_000,
        };
        let pairing_state = super::super::super::device_pairing::configured(
            Some(pair_config),
            connection,
            Some(peer),
            Some(secret),
            device_registry.as_ref(),
            Arc::clone(clock) as Arc<dyn tinysecurity::approval::Clock>,
            1,
        )?;
        super::super::super::device::activate(device_registry.as_ref())?;
        super::super::super::device_pairing::activate(pairing_state)
    }
    #[allow(clippy::too_many_lines)] // The linked fixture wires all authority owners in one setup.
    async fn setup(
        connection: tinybus::Connection,
        fixture_config: serde_json::Value,
    ) -> tinybus::Result<()> {
        let mode = u32::try_from(fixture_config["mode"].as_u64().ok_or_else(denied)?)
            .map_err(|_| denied())?;
        let peer = connection.unique_name().ok_or_else(denied)?;
        let binding = crate::callbacks::PeerBinding::new(Some(peer.as_str()))?;
        let state = Arc::new(Backend::new(mode));
        serve_callbacks(&connection, &state, &binding).await?;
        let (approvals, audit) = approval_and_audit();
        let redactor =
            tinysecurity::Redactor::new(&RedactorConfig::default()).map_err(|_| denied())?;
        let clock = Arc::new(FixedClock(std::sync::atomic::AtomicU64::new(1000)));
        let engine = Arc::new(
            tinysecurity::approval::Engine::new(
                approvals.clone(),
                Arc::new(crate::approval_callbacks::ApprovalClients::new(
                    &connection,
                    Some(peer.as_str()),
                    &approvals,
                    &audit,
                    &redactor,
                )?),
                clock.clone(),
                redactor,
            )
            .map_err(|_| denied())?,
        );
        let mut facade_config = super::config();
        if mode == 17 {
            facade_config.registrations[0].purpose = MasterPurpose2::AppEncryptionMaster;
            facade_config.registrations[0].target.slot = MasterSlotKind2::App;
            for source in &mut facade_config.registrations[0].legacy {
                source.slot = MasterSlotKind2::App;
            }
        }
        let secret = Arc::new(SecretState::new(
            facade_config,
            &connection,
            peer.as_str(),
            &approvals,
            &engine,
            1,
            clock.clone(),
        )?);
        // The pairing persistence cipher is bound to the registration's signed
        // scope. A caller cannot redirect it to another tenant's state slot.
        assert!(
            secret
                .pairing_state_cipher(
                    &"b".repeat(32),
                    "untrusted-alias",
                    1,
                    &"f".repeat(32),
                    &"c".repeat(32),
                )
                .is_err()
        );
        *state.registry.lock().map_err(|_| denied())? = Some(secret.registry.clone());
        if mode == 22 {
            activate_runtime_pairing(
                &connection,
                peer.as_str(),
                &approvals,
                &audit,
                &secret,
                &clock,
            )?;
        }
        let (cipher, audit_client) = cipher_tests::configured_fixture(
            &connection,
            &binding,
            &audit,
            &clock,
            &state,
            &secret,
            &engine,
        )?;
        let mut service = super::super::super::service_for(
            Arc::new(std::sync::RwLock::new(
                tinysecurity::Policy::new(ModuleConfig::default()).map_err(|_| denied())?,
            )),
            None,
        );
        service.secret = Some(secret);
        service.secret_cipher = cipher;
        service.audit = Some(audit_client);
        service.approvals = Some(engine);
        connection
            .serve_at(
                names::OBJECT_PATH.parse()?,
                crate::callbacks::Authenticated::new(service.clone(), binding),
            )
            .await?;
        connection
            .serve_at(
                "/fixture".parse()?,
                Control {
                    connection: connection.clone(),
                    service,
                    state,
                    clock,
                },
            )
            .await
    }
    tinybus_module::module_export_static! { setup = setup, config = serde_json::Value, worker_threads = 1, provides = ["ai.tinyhumans.tinysecurity.SecretFixture"], methods = ["Exercise"], signals = [], requires = [], optional = [], lazy = false, }
}
#[tokio::test]
async fn actual_sdk_confidential_master_resolution_is_human_only_exact_and_fail_closed()
-> TestResult {
    if isolate_process_owned_fixture(
        "actual_sdk_confidential_master_resolution_is_human_only_exact_and_fail_closed",
        "master",
    )? {
        return Ok(());
    }
    for mode in 0..=19 {
        let bus = MemoryBus::new();
        let owner = Broker::new();
        let broker = owner.spawn(bus.clone());
        let client = Connection::connect(bus.connect().await?).await?;
        let host = tinybus::module::ModuleHost::new(owner);
        let info = host.attach_linked_with_config(
            linked_fixture::linked_module()?,
            serde_json::json!({"mode":mode}),
        )?;
        let peer = client
            .name_owner(info.manifest.bus_name.as_str())
            .await?
            .ok_or("fixture peer")?;
        let proxy = client.proxy(
            peer.as_str(),
            "/fixture",
            "ai.tinyhumans.tinysecurity.SecretFixture",
        )?;
        let result: serde_json::Value = proxy
            .with_timeout(std::time::Duration::from_secs(10))
            .call("Exercise", ())
            .await
            .map_err(|e| format!("mode {mode}: {e}"))?;
        assert_eq!(result["sets"], u32::from(matches!(mode, 1 | 2 | 6 | 10)));
        if matches!(mode, 0 | 17) {
            assert_eq!(result["loads"], 1);
        }
        // A different actual peer cannot invoke even a confidential facade member.
        let proxy = client.proxy(peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
        assert!(
            proxy
                .call_confidential::<ApprovalRow2>(
                    names::methods::EVALUATE_SECRET2,
                    (EvaluateSecretRequest2 {
                        request: request(99),
                        audit: audit(1)
                    },)
                )
                .await
                .is_err()
        );
        broker.abort();
    }
    Ok(())
}

#[tokio::test]
async fn runtime_secret_registration_is_bound_to_approval_scope_and_retirement() -> TestResult {
    if isolate_process_owned_fixture(
        "runtime_secret_registration_is_bound_to_approval_scope_and_retirement",
        "runtime-pairing",
    )? {
        return Ok(());
    }
    let bus = MemoryBus::new();
    let owner = Broker::new();
    let broker = owner.spawn(bus.clone());
    let client = Connection::connect(bus.connect().await?).await?;
    let host = tinybus::module::ModuleHost::new(owner);
    let info = host.attach_linked_with_config(
        linked_fixture::linked_module()?,
        serde_json::json!({"mode":22}),
    )?;
    let peer = client
        .name_owner(info.manifest.bus_name.as_str())
        .await?
        .ok_or("fixture peer")?;
    let proxy = client.proxy(
        peer.as_str(),
        "/fixture",
        "ai.tinyhumans.tinysecurity.SecretFixture",
    )?;
    let result: serde_json::Value = proxy
        .with_timeout(std::time::Duration::from_secs(10))
        .call("Exercise", ())
        .await?;
    assert_eq!(result["denied"], true);
    broker.abort();
    Ok(())
}

#[path = "adapter_secret_cipher_fixture_tests.rs"]
mod cipher_tests;
