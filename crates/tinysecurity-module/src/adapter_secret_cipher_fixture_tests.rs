use super::*;
pub(super) struct Slot {
    identity: SecretCipherDeliveryIdentity2,
    plain: Zeroizing<Vec<u8>>,
    replacement: Option<Zeroizing<Vec<u8>>>,
}
pub(super) fn config(mode: u32) -> SecretCipherConfig2 {
    SecretCipherConfig2 {
        registration_id: "b".repeat(32),
        consumer_id: "f".repeat(32),
        enabled: mode != 21,
        slots: 1,
        timeout_ms: 50,
    }
}
pub(super) fn audit_boundary(state: &Backend, request: &AuditSinkRequest2) -> tinybus::Result<()> {
    let phase = serde_json::from_str::<serde_json::Value>(&request.events[0].arguments_json)?;
    match (state.mode, phase["phase"].as_str()) {
        (27, Some("output-stage")) | (28, Some("publication")) => return Err(denied()),
        (30, Some("output-stage")) => state
            .registry
            .lock()
            .map_err(|_| denied())?
            .as_ref()
            .ok_or_else(denied)?
            .revoke_scope(&"b".repeat(32))
            .map_err(|_| denied())?,
        (31, Some("publication")) => state
            .cipher_clock
            .lock()
            .map_err(|_| denied())?
            .as_ref()
            .ok_or_else(denied)?
            .0
            .store(999, Ordering::SeqCst),
        _ => {}
    }
    Ok(())
}
#[derive(Clone)]
pub(super) struct Consumer(pub(super) Arc<Backend>);
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.SecretCipherConsumer2")]
impl Consumer {
    #[tinybus(confidential)]
    async fn deliver(
        &self,
        request: SecretCipherDeliveryRequest2,
    ) -> tinybus::Result<SecretCipherDeliveryResponse2> {
        let mut identity = request.identity;
        if identity.consumer_id != "f".repeat(32)
            || identity.registration_id != "b".repeat(32)
            || identity.slot != 0
            || identity.generation != 1
        {
            return Err(denied());
        }
        {
            let mut slots = self.0.cipher_slots.lock().map_err(|_| denied())?;
            if slots.contains_key(&identity.slot) {
                return Err(denied());
            }
            slots.insert(
                identity.slot,
                Slot {
                    identity: identity.clone(),
                    plain: Zeroizing::new(request.plaintext),
                    replacement: request.replacement.map(Zeroizing::new),
                },
            );
        }
        match self.0.mode {
            22 => identity.operation_id.push('x'),
            23 => identity.output_id.push('x'),
            24 => identity.consumer_id.push('x'),
            25 => identity.generation += 1,
            29 => self
                .0
                .cipher_clock
                .lock()
                .map_err(|_| denied())?
                .as_ref()
                .ok_or_else(denied)?
                .0
                .store(identity.expires_at_ms, Ordering::SeqCst),
            32 => std::future::pending::<()>().await,
            _ => {}
        }
        Ok(SecretCipherDeliveryResponse2 {
            identity,
            staged: self.0.mode != 26,
        })
    }
}
type FixtureCipher = Option<Arc<super::super::super::cipher::CipherState>>;
pub(super) fn configured_fixture(
    connection: &Connection,
    binding: &crate::callbacks::PeerBinding,
    audit: &AuditConfig2,
    clock: &Arc<FixedClock>,
    state: &Backend,
    secret: &Arc<SecretState>,
    engine: &Arc<tinysecurity::approval::Engine>,
) -> tinybus::Result<(FixtureCipher, Arc<crate::callbacks::AuditClient>)> {
    let audit_client = Arc::new(crate::callbacks::AuditClient::new_for_test(
        connection.clone(),
        binding.clone(),
        audit.clone(),
        tinysecurity::Redactor::new(&RedactorConfig::default()).map_err(|_| denied())?,
    )?);
    *state.cipher_clock.lock().map_err(|_| denied())? = Some(clock.clone());
    if state.mode == 20 {
        reject_invalid_setup(connection, secret, engine, &audit_client)?;
    }
    let cipher = if state.mode >= 20 {
        Some(super::super::super::cipher::create(
            config(state.mode),
            connection,
            connection
                .unique_name()
                .as_ref()
                .map(tinybus::BusName::as_str),
            Some(secret),
            Some(engine),
            Some(&audit_client),
        )?)
    } else {
        None
    };
    Ok((cipher, audit_client))
}
fn reject_invalid_setup(
    connection: &Connection,
    secret: &Arc<SecretState>,
    engine: &Arc<tinysecurity::approval::Engine>,
    audit: &Arc<crate::callbacks::AuditClient>,
) -> tinybus::Result<()> {
    use super::super::super::cipher::create;
    let peer = connection.unique_name().ok_or_else(denied)?;
    for mode in 0..6 {
        let mut invalid = config(20);
        match mode {
            0 => invalid.consumer_id.clear(),
            1 => invalid.registration_id = "a".repeat(32),
            2 => invalid.slots = 0,
            3 => invalid.slots = 129,
            4 => invalid.timeout_ms = 0,
            _ => invalid.timeout_ms = 30001,
        }
        assert!(
            create(
                invalid,
                connection,
                Some(peer.as_str()),
                Some(secret),
                Some(engine),
                Some(audit)
            )
            .is_err()
        );
    }
    assert!(
        create(
            config(20),
            connection,
            None,
            Some(secret),
            Some(engine),
            Some(audit)
        )
        .is_err()
    );
    assert!(
        create(
            config(20),
            connection,
            Some("ai.fixture.Untrusted"),
            Some(secret),
            Some(engine),
            Some(audit)
        )
        .is_err()
    );
    assert!(
        create(
            config(20),
            connection,
            Some(peer.as_str()),
            None,
            Some(engine),
            Some(audit)
        )
        .is_err()
    );
    assert!(
        create(
            config(20),
            connection,
            Some(peer.as_str()),
            Some(secret),
            None,
            Some(audit)
        )
        .is_err()
    );
    assert!(
        create(
            config(20),
            connection,
            Some(peer.as_str()),
            Some(secret),
            Some(engine),
            None
        )
        .is_err()
    );
    Ok(())
}
fn request(
    handle: &str,
    call: u64,
    operation: SecretCipherKind2,
    input: Vec<u8>,
) -> SecretCipherRequest2 {
    SecretCipherRequest2 {
        registration_id: "b".repeat(32),
        master_handle: handle.into(),
        call_id: format!("private-cipher-{call}"),
        operation,
        input,
        ttl_ms: 30000,
    }
}

impl Control {
    async fn expired_pending_releases_capacity_before_readmission(
        &self,
        handle: &str,
    ) -> tinybus::Result<()> {
        for sequence in 100..104 {
            let mut original = request(
                handle,
                sequence,
                SecretCipherKind2::Decrypt,
                b"private-output".to_vec(),
            );
            original.ttl_ms = 1;
            self.service
                .cipher_evaluate(EvaluateSecretCipherRequest2 {
                    request: original,
                    audit: audit(sequence),
                })
                .await?;
        }
        let next = request(
            handle,
            105,
            SecretCipherKind2::Decrypt,
            b"private-output".to_vec(),
        );
        assert!(
            self.service
                .cipher_evaluate(EvaluateSecretCipherRequest2 {
                    request: next.clone(),
                    audit: audit(105)
                })
                .await
                .is_err()
        );
        self.clock.0.store(1001, Ordering::SeqCst);
        assert!(
            self.service
                .cipher_evaluate(EvaluateSecretCipherRequest2 {
                    request: next,
                    audit: audit(105)
                })
                .await
                .is_ok()
        );
        Ok(())
    }
    async fn reject_substituted_execution(
        &self,
        handle: &str,
        mut sequence: u64,
    ) -> tinybus::Result<()> {
        for mode in 0..6 {
            let original = request(
                handle,
                sequence,
                SecretCipherKind2::Decrypt,
                b"private-output".to_vec(),
            );
            let pending = self
                .service
                .cipher_evaluate(EvaluateSecretCipherRequest2 {
                    request: original.clone(),
                    audit: audit(sequence),
                })
                .await?;
            sequence += 1;
            let mut changed = original.clone();
            match mode {
                0 => changed.input.push(0),
                1 => changed.operation = SecretCipherKind2::Encrypt,
                2 => changed.master_handle.push('x'),
                3 => changed.call_id.push('x'),
                4 => changed.ttl_ms -= 1,
                _ => changed.registration_id.push('x'),
            }
            let execute = ExecuteSecretCipherRequest2 {
                request: changed,
                pending_id: pending.pending_id,
                audit: audit(sequence),
                delivery_audit: audit(sequence + 1),
                completion_audit: audit(sequence + 2),
            };
            sequence += 3;
            assert!(self.service.cipher_execute(execute.clone()).await.is_err());
            assert!(
                self.service
                    .cipher_execute(ExecuteSecretCipherRequest2 {
                        request: original,
                        ..execute
                    })
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
    async fn exercise_denial(
        &self,
        proxy: &tinybus::Proxy,
        original: SecretCipherRequest2,
        mut sequence: u64,
    ) -> tinybus::Result<serde_json::Value> {
        let next_request = original.clone();
        let pending: SecretCipherPending2 = proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET_CIPHER2,
                (EvaluateSecretCipherRequest2 {
                    request: original.clone(),
                    audit: audit(sequence),
                },),
            )
            .await?;
        sequence += 1;
        let execute = ExecuteSecretCipherRequest2 {
            request: original,
            pending_id: pending.pending_id,
            audit: audit(sequence),
            delivery_audit: audit(sequence + 1),
            completion_audit: audit(sequence + 2),
        };
        let result = proxy
            .call_confidential::<SecretCipherResponse2>(
                names::methods::EXECUTE_SECRET_CIPHER2,
                (&execute,),
            )
            .await;
        assert!(result.is_err());
        // The private pending was consumed even when staged delivery/final audit failed.
        assert!(self.service.cipher_execute(execute).await.is_err());
        // Failed/late output is never locally published. Receiver owns only one
        // physical slot and wipes it; sender's uncertainty fence remains sticky.
        self.state
            .cipher_slots
            .lock()
            .map_err(|_| denied())?
            .clear();
        if self.state.mode <= 28 || self.state.mode == 32 {
            let mut next = next_request;
            next.call_id.push_str("-next");
            let pending = self
                .service
                .cipher_evaluate(EvaluateSecretCipherRequest2 {
                    request: next.clone(),
                    audit: audit(20),
                })
                .await?;
            assert!(
                self.service
                    .cipher_execute(ExecuteSecretCipherRequest2 {
                        request: next,
                        pending_id: pending.pending_id,
                        audit: audit(21),
                        delivery_audit: audit(22),
                        completion_audit: audit(23)
                    })
                    .await
                    .is_err()
            );
        }
        Ok(serde_json::json!({"denied":true}))
    }
    pub(super) async fn exercise_cipher(
        &self,
        proxy: &tinybus::Proxy,
        master: SecretResponse2,
    ) -> tinybus::Result<serde_json::Value> {
        let SecretResponse2::MasterHandle { handle, .. } = master;
        let mut sequence = 4;
        let cipher_request = |call, operation, input| request(&handle, call, operation, input);
        // Ordinary dispatch never observes confidential input/output.
        let original = cipher_request(1, SecretCipherKind2::Decrypt, b"private-output".to_vec());
        assert!(
            proxy
                .call::<SecretCipherPending2>(
                    names::methods::EVALUATE_SECRET_CIPHER2,
                    (EvaluateSecretCipherRequest2 {
                        request: original.clone(),
                        audit: audit(sequence)
                    },)
                )
                .await
                .is_err()
        );
        if self.state.mode >= 22 {
            return self.exercise_denial(proxy, original, sequence).await;
        }
        let mut encrypted = None;
        for (instance, operation, input) in [
            (1, SecretCipherKind2::Encrypt, b"private-output".to_vec()),
            (2, SecretCipherKind2::Encrypt, Vec::new()),
            (3, SecretCipherKind2::Decrypt, b"private-output".to_vec()),
            (
                4,
                SecretCipherKind2::DecryptAndMigrate,
                b"enc:dad8c3dccbdecf87c5dfdedadfde".to_vec(),
            ),
        ] {
            let request = cipher_request(instance, operation, input);
            let pending: SecretCipherPending2 = proxy
                .call_confidential(
                    names::methods::EVALUATE_SECRET_CIPHER2,
                    (EvaluateSecretCipherRequest2 {
                        request: request.clone(),
                        audit: audit(sequence),
                    },),
                )
                .await?;
            sequence += 1;
            let execute = ExecuteSecretCipherRequest2 {
                request,
                pending_id: pending.pending_id,
                audit: audit(sequence),
                delivery_audit: audit(sequence + 1),
                completion_audit: audit(sequence + 2),
            };
            sequence += 3;
            let response = proxy
                .call_confidential::<SecretCipherResponse2>(
                    names::methods::EXECUTE_SECRET_CIPHER2,
                    (&execute,),
                )
                .await;
            let response = response?;
            let value = serde_json::to_string(&response)?;
            assert!(!value.contains("private-output"));
            match response {
                SecretCipherResponse2::Ciphertext { ciphertext } => {
                    assert!(ciphertext.starts_with("enc2:"));
                    encrypted = Some(ciphertext);
                }
                SecretCipherResponse2::Delivered {
                    identity,
                    replacement_ciphertext,
                    ..
                } => {
                    let slot = self
                        .state
                        .cipher_slots
                        .lock()
                        .map_err(|_| denied())?
                        .remove(&identity.slot)
                        .ok_or_else(denied)?;
                    assert_eq!(slot.identity, identity);
                    assert_eq!(
                        replacement_ciphertext.is_some(),
                        instance == 4 && self.state.mode == 20
                    );
                    assert_eq!(slot.replacement.is_some(), instance == 4);
                    assert!(slot.plain.as_slice().eq(if instance == 2 {
                        &b""[..]
                    } else {
                        &b"private-output"[..]
                    }));
                }
            }
            assert!(self.service.cipher_execute(execute).await.is_err());
        }
        assert_eq!(encrypted.is_some(), self.state.mode == 20);
        self.reject_substituted_execution(&handle, sequence).await?;
        self.expired_pending_releases_capacity_before_readmission(&handle)
            .await?;
        Ok(serde_json::json!({"completed":true}))
    }
}
#[tokio::test]
async fn actual_confidential_cipher_dispatch_stages_only_at_fixed_slots_and_fails_closed()
-> TestResult {
    if isolate_process_owned_fixture(
        "actual_confidential_cipher_dispatch_stages_only_at_fixed_slots_and_fails_closed",
        "cipher",
    )? {
        return Ok(());
    }
    for mode in 20..=32 {
        let bus = MemoryBus::new();
        let owner = Broker::new();
        let task = owner.spawn(bus.clone());
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
        let result: serde_json::Value = client
            .proxy(
                peer.as_str(),
                "/fixture",
                "ai.tinyhumans.tinysecurity.SecretFixture",
            )?
            .with_timeout(std::time::Duration::from_secs(10))
            .call("Exercise", ())
            .await?;
        assert_eq!(
            result[if mode >= 22 { "denied" } else { "completed" }].as_bool(),
            Some(true)
        );
        assert!(
            client
                .proxy(peer.as_str(), names::OBJECT_PATH, names::INTERFACE)?
                .call_confidential::<SecretCipherPending2>(
                    names::methods::EVALUATE_SECRET_CIPHER2,
                    (EvaluateSecretCipherRequest2 {
                        request: SecretCipherRequest2 {
                            registration_id: "b".repeat(32),
                            master_handle: "untrusted".into(),
                            call_id: "untrusted".into(),
                            operation: SecretCipherKind2::Decrypt,
                            input: b"private-input".to_vec(),
                            ttl_ms: 1
                        },
                        audit: audit(100)
                    },)
                )
                .await
                .is_err()
        );
        task.abort();
    }
    Ok(())
}
