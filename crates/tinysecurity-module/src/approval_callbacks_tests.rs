use super::*;
use tinybus::{broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::{AccessTier, ApprovalRecord2, ApprovalScope2};
#[derive(Clone)]
struct Store {
    scope: SubjectScope,
    wrong: bool,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl Store {
    async fn load(&self, request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        std::future::ready(Ok(ApprovalLoadResponse2 {
            scope: if self.wrong {
                self.scope.clone()
            } else {
                request.scope
            },
            records: vec![],
        }))
        .await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> tinybus::Result<ApprovalCasResponse2> {
        std::future::ready(Ok(ApprovalCasResponse2 {
            scope: request.scope,
            record_id: request.record_id,
            mutation_id: if self.wrong {
                "f".repeat(32)
            } else {
                request.mutation_id
            },
            resulting_version: request.next_record.version,
        }))
        .await
    }

    async fn purge_session(
        &self,
        request: ApprovalPurgeSessionRequest2,
    ) -> tinybus::Result<ApprovalPurgeSessionResponse2> {
        std::future::ready(Ok(ApprovalPurgeSessionResponse2 {
            scope: if self.wrong {
                self.scope.clone()
            } else {
                request.scope
            },
            session_id: if self.wrong {
                "wrong-session".into()
            } else {
                request.session_id
            },
            removed: 1,
        }))
        .await
    }
}
fn config() -> ApprovalConfig2 {
    ApprovalConfig2 {
        timeout_ms: 30_000,
        scopes: vec![ApprovalScope2 {
            scope_id: "a".repeat(32),
            subject: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            policy_ref: "scope".into(),
            generation: 1,
            ceiling: AccessTier::Full,
            require_approval: true,
            auto_approve_all: false,
        }],
    }
}
#[tokio::test]
async fn real_store_clients_validate_exact_scope_receipt_and_fixed_unique_peer()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let config = config();
    let scope = tinysecurity::approval::scope_handle(&config.scopes[0].subject)?;
    let peer = host.unique_name().ok_or("host peer")?;
    let client = ApprovalStoreClient::new_for_test(module.clone(), Some(peer.as_str()), &config)?;
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await
            .is_err()
    );
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            Store {
                scope: scope.clone(),
                wrong: false,
            },
            PeerBinding::new(module.unique_name().as_ref().map(tinybus::BusName::as_str))?,
        ),
    )
    .await?;
    assert_eq!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await?
            .records
            .len(),
        0
    );
    let request = ApprovalCasRequest2 {
        scope: scope.clone(),
        record_id: "b".repeat(32),
        expected_version: None,
        next_record: ApprovalRecord2 {
            record_id: "b".repeat(32),
            version: 1,
            policy_id: "scope".into(),
            generation: 1,
            fingerprint: "c".repeat(32),
            record_json: "{}".into(),
        },
        mutation_id: "d".repeat(32),
    };
    request.verify_receipt(&client.cas(request.clone()).await?)?;
    let mut other = scope.clone();
    other.user = "other".into();
    assert!(
        client
            .load(ApprovalLoadRequest2 { scope: other })
            .await
            .is_err()
    );
    assert!(ApprovalStoreClient::new(module.clone(), Some("ai.unverified.Host"), &config).is_err());
    for deadline in [0, 30001] {
        let mut invalid = config.clone();
        invalid.timeout_ms = deadline;
        assert!(ApprovalStoreClient::new(module.clone(), Some(peer.as_str()), &invalid).is_err());
    }
    let attacker = tinybus::Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(
                peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::APPROVAL_STORE
            )?
            .call::<ApprovalLoadResponse2>(
                callback_names2::LOAD,
                (ApprovalLoadRequest2 {
                    scope: scope.clone()
                },)
            )
            .await
            .is_err()
    );
    host.close().await?;
    let replacement = tinybus::Connection::connect(bus.connect().await?).await?;
    replacement
        .serve_at(
            callback_names2::OBJECT_PATH.parse()?,
            Store {
                scope: scope.clone(),
                wrong: false,
            },
        )
        .await?;
    assert!(client.load(ApprovalLoadRequest2 { scope }).await.is_err());
    assert!(!format!("{client:?}").contains("user"));
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn approval_store_client_does_not_send_to_an_unattested_host()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let config = config();
    let scope = tinysecurity::approval::scope_handle(&config.scopes[0].subject)?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        Store {
            scope: scope.clone(),
            wrong: false,
        },
    )
    .await?;
    let client = ApprovalStoreClient::new(
        module,
        Some(host.unique_name().ok_or("host peer")?.as_str()),
        &config,
    )?;

    // Confidential calls to an unattested peer are rejected before its ordinary
    // callback can receive approval rows. An ordinary call would succeed here.
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await
            .is_err()
    );
    let request = ApprovalCasRequest2 {
        scope,
        record_id: "b".repeat(32),
        expected_version: None,
        next_record: ApprovalRecord2 {
            record_id: "b".repeat(32),
            version: 1,
            policy_id: "scope".into(),
            generation: 1,
            fingerprint: "c".repeat(32),
            record_json: "{}".into(),
        },
        mutation_id: "d".repeat(32),
    };
    assert!(client.cas(request).await.is_err());
    host.close().await?;
    drop(broker);
    Ok(())
}

#[tokio::test]
async fn store_client_rejects_empty_init_scope_list()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let mut config = config();
    config.scopes.clear();

    assert!(
        ApprovalStoreClient::new(
            module,
            host.unique_name().as_ref().map(tinybus::BusName::as_str),
            &config,
        )
        .is_err()
    );
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn store_client_purges_session_only_through_registered_scope()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let config = config();
    let scope = tinysecurity::approval::scope_handle(&config.scopes[0].subject)?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        Store {
            scope: scope.clone(),
            wrong: false,
        },
    )
    .await?;
    let client = ApprovalStoreClient::new_for_test(
        module,
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
        &config,
    )?;
    let request = ApprovalPurgeSessionRequest2 {
        scope: scope.clone(),
        session_id: "session-private".into(),
    };
    assert_eq!(client.purge_session(request.clone()).await?.removed, 1);
    let mut outside_scope = request;
    outside_scope.scope.user = "other".into();
    assert!(client.purge_session(outside_scope).await.is_err());
    broker.abort();
    Ok(())
}
#[tokio::test]
async fn unrelated_receipts_do_not_confirm_store_commits()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let scope = tinysecurity::approval::scope_handle(&config().scopes[0].subject)?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        Store {
            scope: SubjectScope {
                user: "wrong".into(),
                workspace: "wrong".into(),
                agent: "wrong".into(),
            },
            wrong: true,
        },
    )
    .await?;
    let client = ApprovalStoreClient::new_for_test(
        module,
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
        &config(),
    )?;
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: scope.clone()
            })
            .await
            .is_err()
    );
    assert!(
        client
            .cas(ApprovalCasRequest2 {
                scope: scope.clone(),
                record_id: "b".repeat(32),
                expected_version: None,
                next_record: ApprovalRecord2 {
                    record_id: "b".repeat(32),
                    version: 1,
                    policy_id: "scope".into(),
                    generation: 1,
                    fingerprint: "c".repeat(32),
                    record_json: "{}".into()
                },
                mutation_id: "d".repeat(32)
            })
            .await
            .is_err()
    );
    assert!(
        client
            .purge_session(ApprovalPurgeSessionRequest2 {
                scope,
                session_id: "session-private".into(),
            })
            .await
            .is_err()
    );
    broker.abort();
    Ok(())
}
#[derive(Clone)]
struct StalledStore(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl StalledStore {
    async fn load(&self, _request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        std::future::pending().await
    }
}
#[tokio::test(start_paused = true)]
async fn registered_store_that_never_replies_is_bounded_by_the_captured_deadline()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        crate::callbacks::Authenticated::new(
            StalledStore(entered.clone()),
            PeerBinding::new(module.unique_name().as_ref().map(tinybus::BusName::as_str))?,
        ),
    )
    .await?;
    let mut config = config();
    config.timeout_ms = 1;
    let client = ApprovalStoreClient::new_for_test(
        module,
        host.unique_name().as_ref().map(tinybus::BusName::as_str),
        &config,
    )?;
    let started = tokio::time::Instant::now();
    assert!(
        client
            .load(ApprovalLoadRequest2 {
                scope: tinysecurity::approval::scope_handle(&config.scopes[0].subject)?
            })
            .await
            .is_err()
    );
    assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(1));
    broker.abort();
    Ok(())
}

#[derive(Clone)]
struct NativeSink {
    batches: Arc<std::sync::Mutex<Vec<AuditSinkRequest2>>>,
    wrong: bool,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl NativeSink {
    async fn read(&self) -> tinybus::Result<serde_json::Value> {
        let metadata = {
            let batches = self
                .batches
                .lock()
                .map_err(|_| tinybus::Error::failed("sink unavailable"))?;
            serde_json::json!({
                "writes": batches.len(),
                "tails": batches.iter().map(|b| b.expected_tail).collect::<Vec<_>>(),
                "scope": batches.first().map(|b| &b.scope),
            })
        };
        std::future::ready(Ok(metadata)).await
    }
    #[tinybus(confidential)]
    async fn append(&self, batch: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        let receipt = {
            let serialized = serde_json::to_string(&batch)?;
            assert!(!serialized.contains("private-fixture-ticket"));
            assert!(!serialized.contains("fixed-native-binding-fixture"));
            assert!(!serialized.contains("original-private-native-operation"));
            let mut batches = self
                .batches
                .lock()
                .map_err(|_| tinybus::Error::failed("sink unavailable"))?;
            if let Some(prior) = batches
                .iter()
                .find(|b| b.events[0].event_id == batch.events[0].event_id)
            {
                if prior != &batch {
                    return Err(tinybus::Error::failed("conflicting event"));
                }
            } else {
                batches.push(batch.clone());
            }
            let mut receipt = AuditSinkResponse2 {
                scope: batch.scope,
                stream_id: batch.stream_id,
                events: batch
                    .events
                    .iter()
                    .map(|e| tinysecurity_bus::AuditEventReceipt2 {
                        sequence: e.sequence,
                        event_id: e.event_id.clone(),
                    })
                    .collect(),
                new_tail: batch.expected_tail + 1,
            };
            if self.wrong {
                receipt.scope.user = "wrong-subject".into();
            }
            receipt
        };
        std::future::ready(Ok(receipt)).await
    }
}

#[derive(Clone)]
struct NativeStore {
    rows: Arc<
        std::sync::Mutex<std::collections::BTreeMap<String, tinysecurity_bus::ApprovalRecord2>>,
    >,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalStore2")]
impl NativeStore {
    async fn load(&self, request: ApprovalLoadRequest2) -> tinybus::Result<ApprovalLoadResponse2> {
        let records = {
            let rows = self
                .rows
                .lock()
                .map_err(|_| tinybus::Error::failed("store unavailable"))?;
            rows.values().cloned().collect()
        };
        std::future::ready(Ok(ApprovalLoadResponse2 {
            scope: request.scope,
            records,
        }))
        .await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> tinybus::Result<ApprovalCasResponse2> {
        let receipt = {
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| tinybus::Error::failed("store unavailable"))?;
            if rows.get(&request.record_id).map(|r| r.version) != request.expected_version {
                return Err(tinybus::Error::failed("conflicting version"));
            }
            let receipt = ApprovalCasResponse2 {
                scope: request.scope.clone(),
                record_id: request.record_id.clone(),
                mutation_id: request.mutation_id.clone(),
                resulting_version: request.next_record.version,
            };
            request
                .verify_receipt(&receipt)
                .map_err(|_| tinybus::Error::failed("invalid receipt"))?;
            rows.insert(request.record_id, request.next_record);
            receipt
        };
        std::future::ready(Ok(receipt)).await
    }
}
#[derive(Clone)]
struct NativePrompt;
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.ApprovalPrompt2")]
impl NativePrompt {
    #[tinybus(confidential)]
    async fn prompt(
        &self,
        request: ApprovalDeliveryRequest2,
    ) -> tinybus::Result<ApprovalDeliveryResponse2> {
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
        if request.decision_ticket != "private-fixture-ticket"
            || request.row.state != tinysecurity_bus::ApprovalLifecycle2::Pending
        {
            return Err(tinybus::Error::failed("invalid human ticket"));
        }
        std::future::ready(Ok(HumanDecisionReceipt2 {
            ticket_sha256: format!("{:x}", Sha256::digest(request.decision_ticket.as_bytes())),
            row: request.row,
            actor: "fixture-human".into(),
            choice: tinysecurity_bus::ApprovalChoice2::Once,
        }))
        .await
    }
}
mod linked_native_sink {
    async fn setup(
        connection: tinybus::Connection,
        config: serde_json::Value,
    ) -> tinybus::Result<()> {
        let peer = config
            .get("peer")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| tinybus::Error::failed("fixture peer unavailable"))?;
        let binding = crate::callbacks::PeerBinding::new(Some(peer))?;
        connection
            .serve_at(
                tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?,
                crate::callbacks::Authenticated::new(
                    super::NativeSink {
                        batches: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                        wrong: config
                            .get("wrong")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false),
                    },
                    binding.clone(),
                ),
            )
            .await?;
        connection
            .serve_at(
                tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?,
                crate::callbacks::Authenticated::new(
                    super::NativeStore {
                        rows: std::sync::Arc::new(std::sync::Mutex::new(
                            std::collections::BTreeMap::new(),
                        )),
                    },
                    binding.clone(),
                ),
            )
            .await?;
        connection
            .serve_at(
                tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?,
                crate::callbacks::Authenticated::new(super::NativePrompt, binding),
            )
            .await
    }
    tinybus_module::module_export_static! {
        setup = setup, config = serde_json::Value, worker_threads = 1,
        provides = ["ai.tinyhumans.tinysecurity.AuditSink2", "ai.tinyhumans.tinysecurity.ApprovalStore2", "ai.tinyhumans.tinysecurity.ApprovalPrompt2"],
        methods = ["Append", "Read", "Load", "Cas", "Prompt", "VerifyHuman"], signals = [], requires = [], optional = [], lazy = false,
    }
}
fn native_audit_config(scope: SubjectScope, required: bool) -> AuditConfig2 {
    AuditConfig2 {
        scope,
        stream_id: "a".repeat(32),
        timeout_ms: 30_000,
        required,
        native_path: None,
        max_bytes: 10_000,
        max_archives: 3,
        journal_max_bytes: 100_000,
        journal_max_events: 1000,
    }
}
fn audit_row(scope: SubjectScope) -> ApprovalRow2 {
    use tinysecurity_bus::*;
    ApprovalRow2 {
        request_id: "b".repeat(32),
        version: 3,
        binding: ApprovalBinding2 {
            binding_version: 1,
            scope,
            policy_ref: "c".repeat(64),
            generation: 1,
            call_sha256: "d".repeat(64),
            content_sha256: "e".repeat(64),
            origin: Origin::Operator,
            caller: CallerContext {
                call_id: "native-safe-binding".into(),
                ..Default::default()
            },
        },
        host_instance: "f".repeat(32),
        nonce: "1".repeat(32),
        tool_name: "native_secret_grant".into(),
        session_id: None,
        audit_error: None,
        external_effect: true,
        args_redacted: "{}".into(),
        summary: "native grant".into(),
        created_at_ms: 1,
        expires_at_ms: 1000,
        state: ApprovalLifecycle2::Reserved,
        choice: Some(ApprovalChoice2::Once),
        attribution: Some("human".into()),
        decision_ticket_sha256: Some("2".repeat(64)),
        outcome: None,
        reservation_id: Some("3".repeat(32)),
        legacy_history_json: None,
        judge: None,
        audit: AuditCorrelation2 {
            event_id: "4".repeat(32),
            expected_tail: 2,
            generation: 1,
        },
    }
}
#[tokio::test]
async fn native_audit_uses_required_confidential_sink_and_returns_original_distinct_scope()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::*;
    for wrong in [false, true] {
        let bus = MemoryBus::new();
        let broker_owner = Broker::new();
        let broker = broker_owner.spawn(bus.clone());
        let unattested = tinybus::Connection::connect(bus.connect().await?).await?;
        let module = tinybus::Connection::connect(bus.connect().await?).await?;
        let module_host = tinybus::module::ModuleHost::new(broker_owner);
        let info = module_host.attach_linked_with_config(linked_native_sink::linked_module()?,
            serde_json::json!({"peer": module.unique_name().ok_or("module peer")?.as_str(), "wrong": wrong}))?;
        let peer = module
            .name_owner(info.manifest.bus_name.as_str())
            .await?
            .ok_or("linked peer")?;
        let cfg = config();
        let redactor = tinysecurity::Redactor::new(&RedactorConfig::default())?;
        let scope = tinysecurity::approval::scope_handle(&cfg.scopes[0].subject)?;
        let row = audit_row(scope.clone());
        let mut audit = native_audit_config(cfg.scopes[0].subject.clone(), false);
        let optional = ApprovalClients::new(&module, Some(peer.as_str()), &cfg, &audit, &redactor)?;
        assert!(optional.native_audit(row.clone()).await.is_err());
        let read_batches = module.proxy(
            peer.as_str(),
            callback_names2::OBJECT_PATH,
            callback_names2::AUDIT_SINK,
        )?;
        assert_eq!(
            read_batches.call::<serde_json::Value>("Read", ()).await?["writes"],
            0
        );
        audit.required = true;
        let untrusted_client = ApprovalClients::new(
            &module,
            unattested
                .unique_name()
                .as_ref()
                .map(tinybus::BusName::as_str),
            &cfg,
            &audit,
            &redactor,
        )?;
        assert!(untrusted_client.native_audit(row.clone()).await.is_err());
        let client = ApprovalClients::new(&module, Some(peer.as_str()), &cfg, &audit, &redactor)?;
        let first = client.native_audit(row.clone()).await;
        if wrong {
            assert!(first.is_err());
        } else {
            let ack = first?;
            assert_ne!(ack.expected_scope(), &scope);
            let expected = ack.expected_scope().clone();
            let first_receipt = ack.into_receipt();
            assert_eq!(first_receipt.scope, expected);
            assert_eq!(
                client.native_audit(row.clone()).await?.into_receipt(),
                first_receipt
            );
            let persisted = read_batches.call::<serde_json::Value>("Read", ()).await?;
            assert_eq!(persisted["writes"], 1);
            assert_eq!(
                persisted["scope"],
                serde_json::to_value(&first_receipt.scope)?
            );
            let unconfidential = AuditSinkRequest2 {
                scope: first_receipt.scope.clone(),
                stream_id: first_receipt.stream_id.clone(),
                expected_tail: 2,
                events: vec![AuditEvent2 {
                    sequence: 3,
                    event_id: row.audit.event_id.clone(),
                    generation: 1,
                    kind: AuditKind2::Approval,
                    attribution: "human".into(),
                    arguments_json: "{}".into(),
                    rule_ids: vec![],
                }],
            };
            assert!(
                module
                    .proxy(
                        peer.as_str(),
                        callback_names2::OBJECT_PATH,
                        callback_names2::AUDIT_SINK
                    )?
                    .call::<AuditSinkResponse2>(callback_names2::APPEND, (unconfidential,))
                    .await
                    .is_err()
            );
            let mut foreign = row.clone();
            foreign.binding.scope.user = "foreign".into();
            assert!(client.native_audit(foreign).await.is_err());
        }
        broker.abort();
    }
    Ok(())
}

#[derive(Debug)]
struct ComposedClock;
impl tinysecurity::approval::Clock for ComposedClock {
    fn wall_ms(&self) -> Option<u64> {
        Some(1000)
    }
    fn monotonic_ms(&self) -> u64 {
        0
    }
}
impl tinysecurity::crypto::native_handles::NativeClock for ComposedClock {
    fn now(&self) -> tinysecurity::crypto::Result<tinysecurity::crypto::native_handles::Time> {
        Ok(tinysecurity::crypto::native_handles::Time {
            wall: 1000,
            monotonic: 0,
        })
    }
}
fn composed_request(
    binding: &tinysecurity::crypto::native_handles::Binding,
) -> tinysecurity_bus::EvaluateRequest {
    use tinysecurity_bus::*;
    EvaluateRequest {
        caller: CallerContext {
            agent: "agent".into(),
            call_id: binding.safe_call_id(),
            tier: AccessTier::Full,
            origin: Origin::Operator,
            ..Default::default()
        },
        call: ToolCall {
            tool: "native_secret_grant".into(),
            arguments_json: binding.safe_arguments(),
            checks: vec![Check::Unknown {
                description: "native-master-authority".into(),
            }],
        },
    }
}
struct ComposedVerifier {
    engine: Arc<tinysecurity::approval::Engine>,
    request_id: String,
}
impl tinysecurity::crypto::native_handles::HumanGrantVerifier for ComposedVerifier {
    fn consume<'a>(
        &'a self,
        binding: &'a tinysecurity::crypto::native_handles::Binding,
    ) -> tinysecurity::crypto::native_handles::Verification<
        'a,
        tinysecurity::crypto::native_handles::HumanGrantReceipt,
    > {
        Box::pin(async move {
            let (row, ack) = self
                .engine
                .consume_native_grant(tinysecurity_bus::ApprovalActionRequest2 {
                    scope_id: "a".repeat(32),
                    request_id: self.request_id.clone(),
                    request: composed_request(binding),
                    audit: tinysecurity_bus::AuditCorrelation2 {
                        event_id: "3".repeat(32),
                        expected_tail: 2,
                        generation: 1,
                    },
                })
                .await
                .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?;
            let scope = ack.expected_scope().clone();
            tinysecurity::crypto::native_handles::HumanGrantReceipt::from_verified_native_consumption(
                binding, row, ack.into_receipt(), scope)
        })
    }
}
fn composed_registry(
    engine: &tinysecurity::approval::Engine,
    subject: SubjectScope,
    peer: &str,
) -> tinysecurity::crypto::Result<tinysecurity::crypto::native_handles::Registry> {
    use tinysecurity::crypto::native_handles as handles;
    let scope = engine
        .durable_scope(&"a".repeat(32))
        .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?;
    let policy = engine
        .durable_policy_ref(&"a".repeat(32))
        .map_err(|_| tinysecurity::crypto::Error::NativeDenied)?;
    handles::Registry::new(
        vec![handles::Registration {
            id: "a".repeat(32),
            subject,
            durable_subject: scope,
            policy_ref: policy,
            purposes: vec![handles::Purpose::ConfigUserMaster],
        }],
        peer,
        1,
        handles::Limits::default(),
        Arc::new(ComposedClock),
    )
}
#[tokio::test]
async fn actual_registry_engine_and_linked_callbacks_compose_exact_human_once_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity::crypto::native_handles as handles;
    use tinysecurity_bus::*;
    let bus = MemoryBus::new();
    let broker_owner = Broker::new();
    let broker = broker_owner.spawn(bus.clone());
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let module_host = tinybus::module::ModuleHost::new(broker_owner);
    let info = module_host.attach_linked_with_config(linked_native_sink::linked_module()?,
        serde_json::json!({"peer": module.unique_name().ok_or("module peer")?.as_str(), "wrong": false}))?;
    let peer = module
        .name_owner(info.manifest.bus_name.as_str())
        .await?
        .ok_or("host peer")?;
    let cfg = config();
    let subject = cfg.scopes[0].subject.clone();
    let redactor = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    let audit = native_audit_config(subject.clone(), true);
    let ports = Arc::new(ApprovalClients::new(
        &module,
        Some(peer.as_str()),
        &cfg,
        &audit,
        &redactor,
    )?);
    let engine = Arc::new(tinysecurity::approval::Engine::new(
        cfg,
        ports,
        Arc::new(ComposedClock),
        redactor,
    )?);
    let registry = composed_registry(&engine, subject, peer.as_str())?;
    let work = registry.reserve(handles::Request {
        registration: &"a".repeat(32),
        authenticated_peer: peer.as_str(),
        purpose: handles::Purpose::ConfigUserMaster,
        kind: handles::OperationKind::NativeMasterGrant,
        call_id: "original-private-native-operation",
        input: zeroize::Zeroizing::new(b"fixed-native-binding-fixture".to_vec()),
        ttl_ms: 100,
        generation: 1,
    })?;
    let request = EvaluateApprovalRequest2 {
        scope_id: "a".repeat(32),
        request: composed_request(work.binding()),
        ttl_ms: None,
        summary: "native master grant".into(),
        audit: AuditCorrelation2 {
            event_id: "1".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    let pending = engine
        .begin_native_grant(request, work.binding().expires_at_ms())
        .await
        .map_err(|_| "native begin phase failed")?;
    assert_eq!(pending.state, ApprovalLifecycle2::Pending);
    assert_eq!(
        pending.binding.caller.call_id,
        work.binding().safe_call_id()
    );
    let approved = engine
        .decide(DecideRequest2 {
            scope_id: "a".repeat(32),
            request_id: pending.request_id.clone(),
            decision_ticket: "private-fixture-ticket".into(),
            audit: AuditCorrelation2 {
                event_id: "2".repeat(32),
                expected_tail: 1,
                generation: 1,
            },
        })
        .await
        .map_err(|_| "native decision phase failed")?;
    assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
    let grant = registry
        .authorize_human(
            work,
            &ComposedVerifier {
                engine,
                request_id: pending.request_id,
            },
        )
        .await?;
    registry.validate_grant(&grant)?;
    let batches = module
        .proxy(
            peer.as_str(),
            callback_names2::OBJECT_PATH,
            callback_names2::AUDIT_SINK,
        )?
        .call::<serde_json::Value>("Read", ())
        .await?;
    assert_eq!(batches["writes"], 3);
    assert_eq!(batches["tails"], serde_json::json!([0, 1, 2]));
    broker.abort();
    Ok(())
}

fn runtime_scope(n: u64) -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: format!("{n:032x}"),
        subject: SubjectScope {
            user: format!("user-{n}"),
            workspace: "workspace".into(),
            agent: format!("agent-{n}"),
        },
        policy_ref: "runtime".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}

#[tokio::test]
async fn store_client_admits_releases_and_bounds_runtime_subjects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let peer = host.unique_name().ok_or("host peer")?;
    let client = ApprovalStoreClient::new(module, Some(peer.as_str()), &config())?;
    let handle = tinysecurity::approval::scope_handle(&runtime_scope(1).subject)?;
    assert!(client.scope(&handle).is_err());
    client.admit(handle.clone())?;
    client.admit(handle.clone())?;
    assert!(client.scope(&handle).is_ok());
    assert_eq!(client.scopes.read().map_err(|_| "lock")?.len(), 2);
    client.release(&handle)?;
    assert!(client.scope(&handle).is_err());
    // Filling to the cap refuses the next new subject, and re-admitting a held one stays fine.
    for n in 0..(tinysecurity_bus::MAX_APPROVAL_SCOPES2 - 1) {
        client.admit(tinysecurity::approval::scope_handle(&SubjectScope {
            user: format!("u{n}"),
            workspace: "w".into(),
            agent: "a".into(),
        })?)?;
    }
    assert!(client.admit(handle).is_err());
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn clients_admit_a_runtime_subject_with_its_own_stream_and_release_it()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let peer = host.unique_name().ok_or("host peer")?;
    let base = config();
    let redactor =
        tinysecurity::Redactor::new(&tinysecurity_bus::RedactorConfig { secrets: vec![] })?;
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        Store {
            scope: base.scopes[0].subject.clone(),
            wrong: false,
        },
    )
    .await?;
    let clients = ApprovalClients::new(
        &module,
        Some(peer.as_str()),
        &base,
        &native_audit_config(base.scopes[0].subject.clone(), false),
        &redactor,
    )?;
    assert_eq!(format!("{clients:?}"), "ApprovalClients([REDACTED])");
    let mut invalid_audit = native_audit_config(base.scopes[0].subject.clone(), false);
    invalid_audit.stream_id = "short".into();
    assert!(
        ApprovalClients::new(
            &module,
            Some(peer.as_str()),
            &base,
            &invalid_audit,
            &redactor,
        )
        .is_err()
    );
    let scope = runtime_scope(2);
    let handle = tinysecurity::approval::scope_handle(&scope.subject)?;
    // A malformed stream never admits the subject.
    assert!(clients.admit_scope(&scope, "short").await.is_err());
    assert!(clients.store.scope(&handle).is_err());
    clients.admit_scope(&scope, &"d".repeat(32)).await?;
    // A subject keeps its stream: no other one is accepted, released or not, so an
    // in-flight call of a retired scope cannot reach another ledger.
    assert!(clients.admit_scope(&scope, &"e".repeat(32)).await.is_err());
    clients.admit_scope(&scope, &"d".repeat(32)).await?;
    assert!(clients.store.scope(&handle).is_ok());
    let purge = ApprovalPurgeSessionRequest2 {
        scope: handle.clone(),
        session_id: "session-private".into(),
    };
    assert_eq!(
        clients.purge_session(purge).await?,
        ApprovalPurgeSessionResponse2 {
            scope: handle.clone(),
            session_id: "session-private".into(),
            removed: 1,
        }
    );
    {
        let held = clients.audit.read().map_err(|_| "lock")?;
        assert_eq!(held.iter().filter(|(s, _)| s == &handle).count(), 1);
        let (_, client) = held.iter().find(|(s, _)| s == &handle).ok_or("client")?;
        assert_eq!(client.stream_id(), "d".repeat(32));
    }
    clients.release_scope(&scope).await?;
    assert!(clients.admit_scope(&scope, &"e".repeat(32)).await.is_err());
    assert!(clients.store.scope(&handle).is_err());
    assert!(
        clients
            .audit
            .read()
            .map_err(|_| "lock")?
            .iter()
            .all(|(s, _)| s != &handle)
    );
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn released_subjects_keep_their_stream_only_for_the_retention_window_and_pins_are_bounded()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let peer = host.unique_name().ok_or("host peer")?;
    let base = config();
    let redactor =
        tinysecurity::Redactor::new(&tinysecurity_bus::RedactorConfig { secrets: vec![] })?;
    let mut clients = ApprovalClients::new(
        &module,
        Some(peer.as_str()),
        &base,
        &native_audit_config(base.scopes[0].subject.clone(), false),
        &redactor,
    )?;
    clients.pins.max = 2;
    let (first, second, third) = (runtime_scope(11), runtime_scope(12), runtime_scope(13));
    clients.admit_scope(&first, &"d".repeat(32)).await?;
    clients.admit_scope(&second, &"d".repeat(32)).await?;
    // Live pins fill the table: nothing is reclaimable.
    assert!(clients.admit_scope(&third, &"d".repeat(32)).await.is_err());
    clients.release_scope(&first).await?;
    // Released but inside the window: still pinned, still counted.
    assert!(clients.admit_scope(&first, &"e".repeat(32)).await.is_err());
    assert!(clients.admit_scope(&third, &"d".repeat(32)).await.is_err());
    // Past the window the pin is reclaimed and the subject may use another stream.
    clients.pins.ttl = std::time::Duration::ZERO;
    clients.admit_scope(&third, &"d".repeat(32)).await?;
    // The table is full of live pins again, so a reclaimed subject must wait.
    assert!(clients.admit_scope(&first, &"e".repeat(32)).await.is_err());
    clients.release_scope(&third).await?;
    clients.admit_scope(&first, &"e".repeat(32)).await?;
    broker.abort();
    Ok(())
}
