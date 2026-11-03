use super::*;
#[tokio::test]
async fn unconfigured_device_service_denies_before_creating_native_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            tinysecurity_bus::ModuleConfig::default(),
        )?)),
        None,
    );
    let request = tinysecurity_bus::DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: "call".into(),
        ttl_ms: 1,
        operation: tinysecurity_bus::DeviceOperation2::Cancel,
    };
    assert!(
        service
            .device_approval(EvaluateDeviceRequest2 {
                request: request.clone(),
                audit: tinysecurity_bus::AuditCorrelation2 {
                    event_id: "a".repeat(32),
                    expected_tail: 0,
                    generation: 1
                }
            })
            .await
            .is_err()
    );
    assert!(
        service
            .device_execute(ExecuteDeviceRequest2 {
                request,
                request_id: "b".repeat(32),
                audit: tinysecurity_bus::AuditCorrelation2 {
                    event_id: "a".repeat(32),
                    expected_tail: 0,
                    generation: 1
                }
            })
            .await
            .is_err()
    );
    assert!(
        service
            .device_frame(tinysecurity_bus::DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: "missing-tunnel".into(),
                call_id: "frame-call".into(),
                operation: tinysecurity_bus::DeviceFrameOperation2::Seal {
                    plaintext: b"private frame".to_vec(),
                },
            })
            .await
            .is_err()
    );
    assert!(time(&FailedClock).is_err());
    Ok(())
}

#[test]
fn module_frame_crypto_does_not_block_the_async_worker()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (service, request) = module_frame_fixture()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()?;
    runtime.block_on(async move {
        let (blocker_started_tx, blocker_started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = blocker_started_tx.send(());
            let _ = release_rx.recv();
        });
        blocker_started_rx.await?;

        let (frame_started_tx, frame_started_rx) = tokio::sync::oneshot::channel();
        let frame = tokio::spawn(async move {
            let _ = frame_started_tx.send(());
            service.device_frame(request).await
        });
        frame_started_rx.await?;

        // The blocking pool is occupied, so offloaded frame work must remain pending while
        // the single async worker continues to run unrelated tasks.
        let (tick_tx, tick_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tick_tx.send(());
        });
        tick_rx.await?;
        let finished_before_release = frame.is_finished();
        release_tx
            .send(())
            .map_err(|_| "blocking worker exited early")?;
        blocker.await?;
        let response = frame.await??;
        assert_eq!(response.bytes.first(), Some(&2));
        assert_eq!(format!("{response:?}"), "DeviceFrameResponse2([REDACTED])");
        assert!(
            !finished_before_release,
            "frame AEAD must be queued off the async worker"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

fn module_frame_fixture() -> std::result::Result<
    (PolicyService, tinysecurity_bus::DeviceFrameRequest2),
    Box<dyn std::error::Error>,
> {
    use tinysecurity_bus::*;
    let scope_id = "c".repeat(32);
    let registered = ApprovalScope2 {
        scope_id: scope_id.clone(),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let registry = Arc::new(Registry::new(
        DeviceConfig2 {
            scopes: vec![DeviceScope2 {
                scope_id: scope_id.clone(),
                origin: Origin::Operator,
                static_secret: Some([11; 32]),
            }],
            max_handles: 8,
            max_in_flight: 2,
            operations_per_minute: 100,
            frames_per_minute: 12_000,
            max_ttl_ms: 100,
            max_message_bytes: 1024,
            max_bootstrap_nonces: 8,
        },
        &[registered],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let execute = |operation| -> std::result::Result<DeviceResponse2, tinysecurity::crypto::Error> {
        let request = DeviceRequest2 {
            scope_id: scope_id.clone(),
            call_id: "approved-tunnel-setup".into(),
            ttl_ms: 100,
            operation,
        };
        let now = Time {
            wall: 1000,
            monotonic: 0,
        };
        let work = registry.reserve(&request, 1, now)?;
        registry.execute(&work, &request.operation, 1, now)
    };
    let static_handle = execute(DeviceOperation2::Key {
        purpose: DeviceKeyPurpose2::Static,
    })?
    .handle
    .ok_or("missing static handle")?;
    let ephemeral = execute(DeviceOperation2::Key {
        purpose: DeviceKeyPurpose2::Ephemeral,
    })?;
    let remote_static =
        tinysecurity::crypto::device::KeyPair::from_secret(zeroize::Zeroizing::new([12; 32]))?;
    let remote_ephemeral =
        tinysecurity::crypto::device::KeyPair::from_secret(zeroize::Zeroizing::new([13; 32]))?;
    let tunnel = execute(DeviceOperation2::Tunnel {
        key: static_handle,
        ephemeral: ephemeral.handle.ok_or("missing ephemeral handle")?,
        peer_static: remote_static.public_key().encode(),
        peer_ephemeral: remote_ephemeral.public_key().encode(),
        role: DeviceRole2::Client,
    })?
    .handle
    .ok_or("missing tunnel handle")?;
    let mut service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            ModuleConfig::default(),
        )?)),
        None,
    );
    service.device = Some(registry);
    service.sandbox_clock = Arc::new(ToggleClock(std::sync::atomic::AtomicBool::new(false)));
    assert_eq!(service.read()?.info().generation, 1);
    assert_eq!(time(service.sandbox_clock.as_ref())?.wall, 1000);
    Ok((
        service,
        DeviceFrameRequest2 {
            scope_id,
            handle: tunnel,
            call_id: "socket-send".into(),
            operation: DeviceFrameOperation2::Seal {
                plaintext: b"socket frame".to_vec(),
            },
        },
    ))
}

#[derive(Debug)]
struct FailedClock;
impl tinysecurity::approval::Clock for FailedClock {
    fn wall_ms(&self) -> Option<u64> {
        None
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}

#[derive(Debug)]
struct ToggleClock(std::sync::atomic::AtomicBool);
impl tinysecurity::approval::Clock for ToggleClock {
    fn wall_ms(&self) -> Option<u64> {
        (!self.0.load(std::sync::atomic::Ordering::SeqCst)).then_some(1000)
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}
#[test]
fn clock_failure_invalidates_existing_device_authority_permanently()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::*;
    let clock = Arc::new(ToggleClock(std::sync::atomic::AtomicBool::new(true)));
    let reg = ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "immutable".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let config = DeviceConfig2 {
        scopes: vec![DeviceScope2 {
            scope_id: reg.scope_id.clone(),
            origin: tinysecurity_bus::Origin::Operator,
            static_secret: None,
        }],
        max_handles: 10,
        max_in_flight: 2,
        operations_per_minute: 100,
        frames_per_minute: 12_000,
        max_ttl_ms: 100,
        max_message_bytes: 100,
        max_bootstrap_nonces: 10,
    };
    let registry = Arc::new(Registry::new(
        config,
        &[reg],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let mut service = super::super::service_for(
        Arc::new(std::sync::RwLock::new(tinysecurity::Policy::new(
            ModuleConfig::default(),
        )?)),
        None,
    );
    service.device = Some(registry.clone());
    service.sandbox_clock = clock.clone();
    assert!(service.device_time().is_err());
    clock.0.store(false, std::sync::atomic::Ordering::SeqCst);
    let operation_request = DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: "call".into(),
        ttl_ms: 1,
        operation: DeviceOperation2::Cancel,
    };
    assert!(
        registry
            .reserve(&operation_request, 1, service.device_time()?)
            .is_err()
    );
    Ok(())
}

#[test]
fn runtime_shutdown_closes_credentials_even_when_object_tree_observer_remains()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let cfg = device_configuration();
    let registry = Arc::new(Registry::new(
        cfg,
        &[device_registration()],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let observer = registry.clone();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        retain_lifetime(&registry);
        tokio::task::yield_now().await;
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    let request = device_request(1, tinysecurity_bus::DeviceOperation2::Cancel);
    assert!(
        observer
            .reserve(
                &request,
                1,
                Time {
                    wall: 1000,
                    monotonic: 0
                }
            )
            .is_err()
    );
    Ok(())
}
fn device_registration() -> tinysecurity_bus::ApprovalScope2 {
    tinysecurity_bus::ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: tinysecurity_bus::SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "immutable-device".into(),
        generation: 1,
        ceiling: tinysecurity_bus::AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn device_configuration() -> DeviceConfig2 {
    DeviceConfig2 {
        scopes: vec![tinysecurity_bus::DeviceScope2 {
            scope_id: "a".repeat(32),
            origin: tinysecurity_bus::Origin::Operator,
            static_secret: Some([7; 32]),
        }],
        max_handles: 16,
        max_in_flight: 4,
        operations_per_minute: 4096,
        frames_per_minute: 12_000,
        max_ttl_ms: 300_000,
        max_message_bytes: 1024,
        max_bootstrap_nonces: 64,
    }
}
fn device_request(
    instance: u64,
    operation: tinysecurity_bus::DeviceOperation2,
) -> tinysecurity_bus::DeviceRequest2 {
    tinysecurity_bus::DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: format!("call-{instance}"),
        ttl_ms: 300_000,
        operation,
    }
}

use super::super::tests::approval_tests::{callback, store};
use std::sync::{
    Mutex, RwLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
struct Harness {
    service: PolicyService,
    proxy: tinybus::Proxy,
    host: Connection,
    module: Connection,
    store: Arc<Mutex<store::DiskStore>>,
    fault: Arc<AtomicU8>,
    broker: tokio::task::JoinHandle<tinybus::Result<()>>,
    directory: tempfile::TempDir,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.broker.abort();
    }
}
#[derive(Clone)]
struct Sink {
    fault: Arc<AtomicU8>,
    registry: Arc<Registry>,
    policy: Arc<RwLock<tinysecurity::Policy>>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        assert!(!serde_json::to_string(&request)?.contains("private-secret"));
        let fault = self.fault.load(Ordering::SeqCst);
        if fault == 1 {
            return Err(tinybus::Error::failed("fixture sink unavailable"));
        }
        if fault == 3 {
            self.registry
                .reconfigure(self.registry.configuration().map_err(|_| denied())?, 2)
                .map_err(|_| denied())?;
            self.policy
                .write()
                .map_err(|_| denied())?
                .reinitialize(ModuleConfig::default())
                .map_err(|_| denied())?;
            self.fault.store(0, Ordering::SeqCst);
        }
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence + u64::from(fault == 2),
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
async fn serve_approval_callbacks(
    host: &Connection,
    module: &tinybus::BusName,
    store: &Arc<Mutex<store::DiskStore>>,
) -> tinybus::Result<()> {
    let scope = tinysecurity::approval::scope_handle(&device_registration().subject)
        .map_err(|_| denied())?;
    for interface in [
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
    ] {
        host.serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            callback::Callback {
                module: module.clone(),
                host: host.clone(),
                interface: interface.parse()?,
                scope: scope.clone(),
                store: store.clone(),
                reentrant: Arc::new(AtomicBool::new(false)),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            },
        )
        .await?;
    }
    Ok(())
}
async fn harness() -> std::result::Result<Harness, Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let peer = host.unique_name().ok_or("fixture host")?;
    let module_peer = module.unique_name().ok_or("fixture module")?;
    let config = ApprovalConfig2 {
        timeout_ms: 1000,
        scopes: vec![device_registration()],
    };
    let audit_config = AuditConfig2 {
        scope: device_registration().subject,
        stream_id: "c".repeat(32),
        timeout_ms: 1000,
        required: true,
        native_path: None,
        max_bytes: 10_000,
        max_archives: 3,
        journal_max_bytes: 10_0000,
        journal_max_events: 1000,
    };
    let clock = Arc::new(ToggleClock(AtomicBool::new(false)));
    let redactor = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    let registry = Arc::new(Registry::new(
        device_configuration(),
        &config.scopes,
        peer.as_str(),
        1,
        time(clock.as_ref())?,
    )?);
    let clients = crate::approval_callbacks::ApprovalClients::new_for_test(
        &module,
        Some(peer.as_str()),
        &config,
        &audit_config,
        &redactor,
    )?;
    let approvals = Arc::new(tinysecurity::approval::Engine::new(
        config,
        Arc::new(clients),
        clock.clone(),
        redactor,
    )?);
    let mut service = super::super::service_for(
        Arc::new(RwLock::new(tinysecurity::Policy::new(
            ModuleConfig::default(),
        )?)),
        None,
    );
    service.device = Some(registry.clone());
    service.approvals = Some(approvals);
    service.sandbox_clock = clock;
    module
        .serve_at(
            names::OBJECT_PATH.parse()?,
            crate::callbacks::Authenticated::new(
                service.clone(),
                crate::callbacks::PeerBinding::new(Some(peer.as_str()))?,
            ),
        )
        .await?;
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("ledger");
    std::fs::write(&file, [])?;
    let store = Arc::new(Mutex::new(store::DiskStore::open(&file)?));
    serve_approval_callbacks(&host, &module_peer, &store).await?;
    let fault = Arc::new(AtomicU8::new(0));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Sink {
                fault: fault.clone(),
                registry,
                policy: service.policy.clone(),
            },
            crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
        ),
    )
    .await?;
    let proxy = host.proxy(module_peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    Ok(Harness {
        service,
        proxy,
        host,
        module,
        store,
        fault,
        broker,
        directory,
    })
}
impl Harness {
    async fn review(
        &self,
        request: DeviceRequest2,
        sequence: u64,
        choice: ApprovalChoice2,
    ) -> tinybus::Result<ApprovalRow2> {
        let row = self
            .service
            .evaluate_device2(EvaluateDeviceRequest2 {
                request,
                audit: audit(sequence),
            })
            .await?;
        let ticket = self
            .store
            .lock()
            .map_err(|_| denied())?
            .human_action(row.clone(), choice)?;
        self.proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: "a".repeat(32),
                    request_id: row.request_id,
                    decision_ticket: ticket,
                    audit: audit(sequence + 1),
                },),
            )
            .await
    }
    async fn execute(
        &self,
        request: DeviceRequest2,
        row: &ApprovalRow2,
        sequence: u64,
    ) -> tinybus::Result<DeviceResponse2> {
        self.service
            .execute_device2(ExecuteDeviceRequest2 {
                request,
                request_id: row.request_id.clone(),
                audit: audit(sequence),
            })
            .await
    }
}
#[tokio::test]
async fn native_device_work_requires_exact_human_receipts_and_durable_audit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = harness().await?;
    let request = device_request(
        1,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let row = fixture
        .review(request.clone(), 1, ApprovalChoice2::Once)
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Approved);
    let key = fixture.execute(request.clone(), &row, 3).await?;
    assert!(key.handle.is_some());
    assert!(fixture.execute(request, &row, 4).await.is_err());
    for (instance, choice) in [(2, ApprovalChoice2::Deny), (3, ApprovalChoice2::Tool)] {
        let request = device_request(
            instance,
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Ephemeral,
            },
        );
        let reviewed = fixture.review(request.clone(), instance * 10, choice).await;
        let row = if choice == ApprovalChoice2::Tool {
            assert!(
                reviewed.is_err(),
                "device decisions only accept Human Once or Deny"
            );
            let row = fixture
                .service
                .evaluate_device2(EvaluateDeviceRequest2 {
                    request: request.clone(),
                    audit: audit(instance * 10),
                })
                .await?;
            assert_eq!(row.state, ApprovalLifecycle2::Pending);
            row
        } else {
            reviewed?
        };
        assert!(
            fixture
                .execute(request, &row, instance * 10 + 2)
                .await
                .is_err()
        );
    }
    let mut request = device_request(
        4,
        DeviceOperation2::Seal {
            handle: "f".repeat(64),
            plaintext: b"private-secret".to_vec(),
        },
    );
    let row = fixture
        .review(request.clone(), 40, ApprovalChoice2::Once)
        .await?;
    if let DeviceOperation2::Seal { plaintext, .. } = &mut request.operation {
        plaintext.push(1);
    }
    assert!(fixture.execute(request, &row, 42).await.is_err());
    let serialized = std::fs::read(fixture.directory.path().join("ledger"))?;
    assert!(!String::from_utf8_lossy(&serialized).contains("private-secret"));
    Ok(())
}
#[tokio::test]
async fn audit_failure_malformed_receipt_and_generation_race_never_issue_handles()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for fault in [1, 2] {
        let fixture = harness().await?;
        fixture.fault.store(fault, Ordering::SeqCst);
        let request = device_request(
            u64::from(fault),
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Static,
            },
        );
        assert!(
            fixture
                .service
                .device_approval(EvaluateDeviceRequest2 {
                    request,
                    audit: audit(1)
                })
                .await
                .is_err()
        );
    }
    let fixture = harness().await?;
    let request = device_request(
        3,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let row = fixture
        .review(request.clone(), 1, ApprovalChoice2::Once)
        .await?;
    fixture.fault.store(3, Ordering::SeqCst);
    assert!(fixture.execute(request, &row, 3).await.is_err());
    Ok(())
}
#[tokio::test]
async fn missing_callback_and_public_identity_claims_cannot_create_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinybus::Interface;
    let fixture = harness().await?;
    let member: tinybus::MemberName = names::methods::EXECUTE_DEVICE2.parse()?;
    assert!(fixture.service.requires_confidential(&member));
    assert!(
        fixture
            .proxy
            .call::<ApprovalRow2>(
                names::methods::EVALUATE_DEVICE2,
                (EvaluateDeviceRequest2 {
                    request: device_request(1, DeviceOperation2::Cancel),
                    audit: audit(1)
                },)
            )
            .await
            .is_err()
    );
    let host_peer = fixture.host.unique_name().ok_or("host peer unavailable")?;
    let authenticated = crate::callbacks::Authenticated::new(
        fixture.service.clone(),
        crate::callbacks::PeerBinding::new(Some(host_peer.as_str()))?,
    );
    assert!(
        authenticated
            .call(&member, serde_json::json!(["private-secret"]))
            .await
            .is_err()
    );
    let mut absent = fixture.service.clone();
    absent.approvals = None;
    assert!(
        absent
            .device_approval(EvaluateDeviceRequest2 {
                request: device_request(1, DeviceOperation2::Cancel),
                audit: audit(1)
            })
            .await
            .is_err()
    );
    assert!(
        absent
            .device_execute(ExecuteDeviceRequest2 {
                request: device_request(1, DeviceOperation2::Cancel),
                request_id: "a".repeat(32),
                audit: audit(1)
            })
            .await
            .is_err()
    );
    fixture.host.close().await?;
    assert!(
        fixture
            .service
            .device_approval(EvaluateDeviceRequest2 {
                request: device_request(2, DeviceOperation2::Cancel),
                audit: audit(1)
            })
            .await
            .is_err()
    );
    assert!(fixture.module.unique_name().is_some());
    Ok(())
}
#[test]
fn device_configuration_preserves_immutable_subjects_and_weak_shutdown_lookup()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let approvals = ApprovalConfig2 {
        timeout_ms: 1000,
        scopes: vec![device_registration()],
    };
    let audit = AuditConfig2 {
        scope: device_registration().subject,
        stream_id: "a".repeat(32),
        timeout_ms: 1000,
        required: true,
        native_path: None,
        max_bytes: 10_000,
        max_archives: 1,
        journal_max_bytes: 10_0000,
        journal_max_events: 1000,
    };
    let clock = ToggleClock(AtomicBool::new(false));
    let init = Initialization {
        peer: Some(":1.1"),
        registrations: Some(&approvals),
        audit: Some(&audit),
        generation: 1,
        clock: &clock,
    };
    assert!(configure(None, None, &init)?.0.is_none());
    assert!(
        configure(
            Some(device_configuration()),
            None,
            &Initialization {
                audit: None,
                ..init
            }
        )
        .is_err()
    );
    assert!(
        configure(
            Some(device_configuration()),
            None,
            &Initialization {
                registrations: None,
                ..init
            }
        )
        .is_err()
    );
    assert!(
        configure(
            Some(device_configuration()),
            None,
            &Initialization { peer: None, ..init }
        )
        .is_err()
    );
    let (registry, limits) = configure(Some(device_configuration()), None, &init)?;
    let registry = registry.ok_or("registry")?;
    let current = Some(Arc::downgrade(&registry));
    let next = Initialization {
        generation: 2,
        ..init
    };
    assert!(configure(Some(device_configuration()), Some(&current), &next).is_err());
    let retained = configure(None, Some(&current), &next)?
        .0
        .ok_or("retained")?;
    assert!(Arc::ptr_eq(&registry, &retained));
    verify_generation_handles(&registry, limits)?;
    assert!(configure(Some(device_configuration()), Some(&None), &next).is_err());
    assert!(configure(None, Some(&None), &next)?.0.is_none());
    transition(None, None, 2, || Ok(()))?;
    drop(registry);
    drop(retained);
    assert!(configure(None, Some(&current), &next).is_err());
    Ok(())
}

// Instrumented runtime evidence inspects still-live owned bytes before deallocation.
// No freed allocation is read, and the synthetic fixture contains no credentials.
const CLEANUP_PAYLOAD: &[u8] = b"device-cleanup-probe-unique-plaintext";
struct CleanupProbe {
    created: tokio::sync::Notify,
    dropped: tokio::sync::Notify,
    resume: std::sync::Barrier,
    wiped: AtomicBool,
}
static CLEANUP_PROBE: Mutex<Option<Arc<CleanupProbe>>> = Mutex::new(None);
pub(super) fn observe_created(response: &DeviceResponse2) {
    if response.bytes == CLEANUP_PAYLOAD {
        let probe = CLEANUP_PROBE.lock().ok().and_then(|p| p.clone());
        if let Some(probe) = probe {
            probe.created.notify_one();
            probe.resume.wait();
        }
    }
}
pub(super) fn observe_dropped(response: &DeviceResponse2) {
    if response.bytes.len() == CLEANUP_PAYLOAD.len() {
        let probe = CLEANUP_PROBE.lock().ok().and_then(|p| p.clone());
        if let Some(probe) = probe {
            probe
                .wiped
                .store(response.bytes.iter().all(|b| *b == 0), Ordering::SeqCst);
            probe.dropped.notify_one();
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpublished_worker_plaintext_is_wiped_on_clock_read_failure_and_join_abort()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity::crypto::device::{KeyPair, PublicKey};
    let mut outcomes = Vec::new();
    for fault in 0..4 {
        let mut fixture = harness().await?;
        let clock = Arc::new(ToggleClock(AtomicBool::new(false)));
        fixture.service.sandbox_clock = clock.clone();
        let request = device_request(
            1,
            DeviceOperation2::Key {
                purpose: DeviceKeyPurpose2::Static,
            },
        );
        let row = fixture
            .review(request.clone(), 1, ApprovalChoice2::Once)
            .await?;
        let key = fixture.execute(request, &row, 3).await?;
        let peer = KeyPair::generate()?;
        let frame = peer.seal_handshake(
            PublicKey::decode(&key.public_key.ok_or("fixture public")?)?,
            CLEANUP_PAYLOAD,
        )?;
        let request = device_request(
            2,
            DeviceOperation2::OpenHandshake {
                handle: key.handle.ok_or("fixture key")?,
                frame,
            },
        );
        let row = fixture
            .review(request.clone(), 4, ApprovalChoice2::Once)
            .await?;
        let probe = Arc::new(CleanupProbe {
            created: tokio::sync::Notify::new(),
            dropped: tokio::sync::Notify::new(),
            resume: std::sync::Barrier::new(2),
            wiped: AtomicBool::new(false),
        });
        *CLEANUP_PROBE.lock().map_err(|_| "probe lock")? = Some(probe.clone());
        let service = fixture.service.clone();
        let execution = tokio::spawn(async move {
            service
                .device_execute(ExecuteDeviceRequest2 {
                    request,
                    request_id: row.request_id,
                    audit: audit(6),
                })
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), probe.created.notified()).await?;
        if fault == 1 {
            execution.abort();
        } else if fault == 0 {
            clock.0.store(true, Ordering::SeqCst);
        } else if fault == 3 {
            let registry = fixture.service.device.as_ref().ok_or("registry")?;
            transition(Some(registry), None, 2, || Ok(()))?;
            fixture
                .service
                .policy
                .write()
                .map_err(|_| "policy lock")?
                .reinitialize(ModuleConfig::default())?;
        } else {
            let policy = fixture.service.policy.clone();
            assert!(
                std::panic::catch_unwind(move || {
                    let _guard = policy
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    std::panic::resume_unwind(Box::new("synthetic publication read poison"));
                })
                .is_err()
            );
        }
        probe.resume.wait();
        if fault == 1 {
            assert!(execution.await.is_err());
        } else {
            assert!(execution.await?.is_err());
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), probe.dropped.notified()).await?;
        *CLEANUP_PROBE.lock().map_err(|_| "probe lock")? = None;
        outcomes.push((fault, probe.wiped.load(Ordering::SeqCst)));
    }
    assert!(
        outcomes.iter().all(|(_, wiped)| *wiped),
        "unpublished cleanup outcomes: {outcomes:?}"
    );
    Ok(())
}

fn verify_generation_handles(
    registry: &Arc<Registry>,
    limits: Option<DeviceConfig2>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let now = Time {
        wall: 1000,
        monotonic: 0,
    };
    let request = device_request(
        1,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let work = registry.reserve(&request, 1, now)?;
    let old = registry
        .execute(&work, &request.operation, 1, now)?
        .handle
        .ok_or("key handle")?;
    transition(Some(registry), limits, 2, || Ok(()))?;
    assert!(registry.validate(&work, 2, now).is_err());
    assert!(registry.reserve(&request, 1, now).is_err());
    let fresh = registry.reserve(&request, 2, now)?;
    assert!(
        registry
            .execute(
                &fresh,
                &DeviceOperation2::Revoke {
                    handle: old.clone()
                },
                2,
                now
            )
            .is_err()
    );
    let replacement = registry
        .execute(&fresh, &request.operation, 2, now)?
        .handle
        .ok_or("new key handle")?;
    assert_ne!(replacement, old);
    drop(work);
    drop(fresh);

    Ok(())
}

#[test]
fn bootstrap_after_prevalidation_rejects_before_generation_publication()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity::crypto::device::{KeyPair, PublicKey};
    let reg = Arc::new(Registry::new(
        device_configuration(),
        &[device_registration()],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let now = Time {
        wall: 1000,
        monotonic: 0,
    };
    let key_request = device_request(
        1,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let work = reg.reserve(&key_request, 1, now)?;
    let key = reg.execute(&work, &key_request.operation, 1, now)?;
    drop(work);
    let handle = key.handle.ok_or_else(denied)?;
    let public = PublicKey::decode(&key.public_key.ok_or_else(denied)?)?;
    let mut cfg = reg.configuration()?;
    cfg.max_bootstrap_nonces = 1;
    reg.validate_configuration(&cfg, 2)?;
    let client = KeyPair::from_secret(zeroize::Zeroizing::new([3; 32]))?;
    for call in 2..4 {
        let operation_request = device_request(
            call,
            DeviceOperation2::OpenHandshake {
                handle: handle.clone(),
                frame: client.seal_handshake(public, b"fixture-private")?,
            },
        );
        let work = reg.reserve(&operation_request, 1, now)?;
        reg.execute(&work, &operation_request.operation, 1, now)?;
    }
    let published = AtomicBool::new(false);
    assert!(
        transition(Some(&reg), Some(cfg), 2, || {
            published.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err()
    );
    assert!(
        !published.load(Ordering::SeqCst),
        "rejected capacity must not publish or advance other components"
    );
    let operation_request = device_request(4, DeviceOperation2::Revoke { handle });
    let work = reg.reserve(&operation_request, 1, now)?;
    reg.validate(&work, 1, now)?;
    Ok(())
}

#[test]
fn rejected_generation_publication_preserves_device_handles_and_replay()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let reg = Arc::new(Registry::new(
        device_configuration(),
        &[device_registration()],
        ":1.1",
        1,
        Time {
            wall: 1000,
            monotonic: 0,
        },
    )?);
    let now = Time {
        wall: 1000,
        monotonic: 0,
    };
    let operation_request = device_request(
        1,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let work = reg.reserve(&operation_request, 1, now)?;
    let key = reg.execute(&work, &operation_request.operation, 1, now)?;
    assert!(transition(Some(&reg), None, 2, || Err(denied())).is_err());
    reg.validate(&work, 1, now)?;
    drop(work);
    let operation_request = device_request(
        2,
        DeviceOperation2::Revoke {
            handle: key.handle.ok_or_else(denied)?,
        },
    );
    let work = reg.reserve(&operation_request, 1, now)?;
    reg.execute(&work, &operation_request.operation, 1, now)?;
    Ok(())
}
