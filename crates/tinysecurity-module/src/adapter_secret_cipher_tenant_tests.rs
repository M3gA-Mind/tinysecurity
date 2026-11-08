//! Two runtime tenants on one neutrally booted module: each owns its approval
//! scope, secret registration, master, cipher, slots and audit subject.
use super::*;

/// Fixture modes from here on boot neutral and register the tenants at runtime.
pub(in super::super) const TENANT_MODES: u32 = 40;

/// One runtime tenant; every identity derives from its index.
pub(in super::super) struct Tenant {
    index: u8,
}
pub(in super::super) const TENANTS: [Tenant; 2] = [Tenant { index: 1 }, Tenant { index: 2 }];
/// A tenant that is registered only to probe refused cipher requests.
pub(in super::super) const PROBE: Tenant = Tenant { index: 3 };

impl Tenant {
    fn id(&self, kind: char) -> String {
        format!("{}{kind}", self.index).repeat(16)
    }
    fn scope_id(&self) -> String {
        self.id('a')
    }
    pub(in super::super) fn registration_id(&self) -> String {
        self.id('b')
    }
    pub(in super::super) fn backend_id(&self) -> String {
        self.id('c')
    }
    fn consumer_id(&self) -> String {
        self.id('d')
    }
    fn stream_id(&self) -> String {
        self.id('e')
    }
    /// A distinct stored master per tenant, so one key never opens another's data.
    pub(in super::super) fn key(&self) -> Zeroizing<Vec<u8>> {
        let byte = if self.index == 1 { "AA" } else { "BC" };
        Zeroizing::new(byte.repeat(32).into_bytes())
    }
    fn subject(&self) -> SubjectScope {
        SubjectScope {
            user: format!("tenant-{}-user", self.index),
            workspace: format!("tenant-{}-workspace", self.index),
            agent: format!("tenant-{}-agent", self.index),
        }
    }
    fn approval(&self) -> RegisterApprovalScopeRequest2 {
        RegisterApprovalScopeRequest2 {
            scope: ApprovalScope2 {
                scope_id: self.scope_id(),
                subject: self.subject(),
                policy_ref: format!("tenant-{}-policy", self.index),
                generation: 1,
                ceiling: AccessTier::Full,
                require_approval: true,
                auto_approve_all: false,
            },
            grants: ApprovalGrants2::default(),
            audit_stream_id: self.stream_id(),
            report_handle: false,
        }
    }
    fn registration(&self) -> SecretRegistration2 {
        SecretRegistration2 {
            registration_id: self.registration_id(),
            approval_scope_id: self.scope_id(),
            origin: Origin::Operator,
            purpose: MasterPurpose2::ConfigUserMaster,
            target: SecretBinding2 {
                backend_id: self.backend_id(),
                slot: MasterSlotKind2::User,
            },
            legacy: vec![],
        }
    }
    fn cipher(&self) -> SecretScopeCipher2 {
        SecretScopeCipher2 {
            consumer_id: self.consumer_id(),
            enabled: true,
            slots: 1,
            timeout_ms: 1000,
            audit_stream_id: self.stream_id(),
        }
    }
    fn request(&self) -> RegisterSecretScopeRequest2 {
        RegisterSecretScopeRequest2 {
            registration: self.registration(),
            cipher: Some(self.cipher()),
        }
    }
}

/// The consumer callback accepts only a registered (consumer, registration) pair
/// at a slot that registration owns.
/// Stored master of each tenant backend. Mode 48 gives tenant two tenant one's
/// key bytes, so two live registrations hold identical masters.
pub(in super::super) fn tenant_targets(mode: u32) -> BTreeMap<String, Zeroizing<Vec<u8>>> {
    let mut targets: BTreeMap<String, Zeroizing<Vec<u8>>> = TENANTS
        .iter()
        .map(|tenant| (tenant.backend_id(), tenant.key()))
        .collect();
    if mode == 48 {
        targets.insert(TENANTS[1].backend_id(), TENANTS[0].key());
        targets.insert(PROBE.backend_id(), TENANTS[0].key());
    }
    if mode == 49 || mode == 50 {
        targets.insert(TENANTS[1].backend_id(), TENANTS[0].key());
    }
    targets
}
pub(in super::super) fn registered_consumer(
    mode: u32,
    identity: &SecretCipherDeliveryIdentity2,
) -> bool {
    if mode < TENANT_MODES {
        return identity.consumer_id == "f".repeat(32)
            && identity.registration_id == "b".repeat(32)
            && identity.slot == 0;
    }
    TENANTS.iter().any(|tenant| {
        identity.consumer_id == tenant.consumer_id()
            && identity.registration_id == tenant.registration_id()
            && identity.slot < tenant.cipher().slots
    })
}

impl Control {
    fn next_audit(&self) -> AuditCorrelation2 {
        audit(self.state.sequence.fetch_add(1, Ordering::SeqCst))
    }
    async fn register(
        &self,
        proxy: &tinybus::Proxy,
        request: &RegisterSecretScopeRequest2,
    ) -> tinybus::Result<SecretScopeReceipt2> {
        proxy
            .call_confidential(names::methods::REGISTER_SECRET_SCOPE2, (request,))
            .await
    }
    async fn register_approval(
        &self,
        proxy: &tinybus::Proxy,
        tenant: &Tenant,
    ) -> tinybus::Result<()> {
        let _: ApprovalScopeReceipt2 = proxy
            .call(
                names::methods::REGISTER_APPROVAL_SCOPE2,
                (&tenant.approval(),),
            )
            .await?;
        Ok(())
    }
    async fn register_tenants(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        for tenant in &TENANTS {
            self.register_approval(proxy, tenant).await?;
            let receipt = self.register(proxy, &tenant.request()).await?;
            assert!(receipt.active);
            assert_eq!(receipt.registration_id, tenant.registration_id());
        }
        Ok(())
    }
    /// Acquire a tenant's master: it still takes an authenticated human decision.
    async fn tenant_master(
        &self,
        proxy: &tinybus::Proxy,
        tenant: &Tenant,
    ) -> tinybus::Result<String> {
        self.tenant_master_call(proxy, tenant, format!("tenant-{}-master", tenant.index))
            .await
    }
    /// Acquire the tenant's master under one call id, so a tenant may acquire again.
    async fn tenant_master_call(
        &self,
        proxy: &tinybus::Proxy,
        tenant: &Tenant,
        call_id: String,
    ) -> tinybus::Result<String> {
        let request = SecretRequest2 {
            registration_id: tenant.registration_id(),
            call_id,
            ttl_ms: 30000,
            operation: SecretOperation2::ResolveConfigMaster,
        };
        let loads = self.state.loads.load(Ordering::SeqCst);
        let row: ApprovalRow2 = proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET2,
                (EvaluateSecretRequest2 {
                    request: request.clone(),
                    audit: self.next_audit(),
                },),
            )
            .await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending);
        assert_eq!(self.state.loads.load(Ordering::SeqCst), loads);
        let approved: ApprovalRow2 = proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: tenant.scope_id(),
                    request_id: row.request_id.clone(),
                    decision_ticket: "actual-fixture-human-ticket".into(),
                    audit: self.next_audit(),
                },),
            )
            .await?;
        assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
        let response: SecretResponse2 = proxy
            .call_confidential(
                names::methods::EXECUTE_SECRET2,
                (&ExecuteSecretRequest2 {
                    request,
                    request_id: row.request_id,
                    audit: self.next_audit(),
                },),
            )
            .await?;
        let SecretResponse2::MasterHandle { handle, .. } = response;
        Ok(handle)
    }
    fn cipher_request(
        tenant: &Tenant,
        handle: &str,
        call: &str,
        operation: SecretCipherKind2,
        input: &[u8],
    ) -> SecretCipherRequest2 {
        SecretCipherRequest2 {
            registration_id: tenant.registration_id(),
            master_handle: handle.into(),
            call_id: format!("tenant-{}-{call}", tenant.index),
            operation,
            input: input.to_vec(),
            ttl_ms: 30000,
        }
    }
    async fn evaluate(
        &self,
        proxy: &tinybus::Proxy,
        request: &SecretCipherRequest2,
    ) -> tinybus::Result<SecretCipherPending2> {
        proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET_CIPHER2,
                (EvaluateSecretCipherRequest2 {
                    request: request.clone(),
                    audit: self.next_audit(),
                },),
            )
            .await
    }
    async fn execute(
        &self,
        proxy: &tinybus::Proxy,
        request: SecretCipherRequest2,
        pending_id: String,
    ) -> tinybus::Result<SecretCipherResponse2> {
        let execute = ExecuteSecretCipherRequest2 {
            request,
            pending_id,
            audit: self.next_audit(),
            delivery_audit: self.next_audit(),
            completion_audit: self.next_audit(),
        };
        proxy
            .call_confidential(names::methods::EXECUTE_SECRET_CIPHER2, (&execute,))
            .await
    }
    async fn run(
        &self,
        proxy: &tinybus::Proxy,
        request: SecretCipherRequest2,
    ) -> tinybus::Result<SecretCipherResponse2> {
        let pending = self.evaluate(proxy, &request).await?;
        self.execute(proxy, request, pending.pending_id).await
    }
    async fn encrypt(
        &self,
        proxy: &tinybus::Proxy,
        tenant: &Tenant,
        handle: &str,
        call: &str,
        plaintext: &[u8],
    ) -> tinybus::Result<String> {
        let request =
            Self::cipher_request(tenant, handle, call, SecretCipherKind2::Encrypt, plaintext);
        match self.run(proxy, request).await? {
            SecretCipherResponse2::Ciphertext { ciphertext } => Ok(ciphertext),
            SecretCipherResponse2::Delivered { .. } => Err(denied()),
        }
    }
    /// Decrypt into the tenant's own receiver and return what that receiver staged.
    async fn decrypt(
        &self,
        proxy: &tinybus::Proxy,
        tenant: &Tenant,
        handle: &str,
        call: &str,
        ciphertext: &str,
    ) -> tinybus::Result<Vec<u8>> {
        let request = Self::cipher_request(
            tenant,
            handle,
            call,
            SecretCipherKind2::Decrypt,
            ciphertext.as_bytes(),
        );
        let SecretCipherResponse2::Delivered { identity, .. } = self.run(proxy, request).await?
        else {
            return Err(denied());
        };
        assert_eq!(identity.consumer_id, tenant.consumer_id());
        assert_eq!(identity.registration_id, tenant.registration_id());
        let slot = self
            .state
            .cipher_slots
            .lock()
            .map_err(|_| denied())?
            .remove(&(identity.consumer_id.clone(), identity.slot))
            .ok_or_else(denied)?;
        assert_eq!(slot.identity, identity);
        Ok(slot.plain.to_vec())
    }
    fn delivered_to(&self, tenant: &Tenant) -> tinybus::Result<bool> {
        Ok(self
            .state
            .cipher_slots
            .lock()
            .map_err(|_| denied())?
            .keys()
            .any(|(consumer, _)| consumer == &tenant.consumer_id()))
    }
    /// Mode 40: a registration's cipher request is accepted, idempotent and
    /// checked before anything is registered.
    async fn tenant_registration(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, _] = &TENANTS;
        assert_eq!(
            self.register(proxy, &one.request()).await?.registration_id,
            one.registration_id()
        );
        let mut resized = one.request();
        if let Some(cipher) = &mut resized.cipher {
            cipher.slots = 2;
        }
        assert!(
            self.register(proxy, &resized).await.is_err(),
            "a live cipher is immutable"
        );
        let without = RegisterSecretScopeRequest2 {
            cipher: None,
            ..one.request()
        };
        assert!(
            self.register(proxy, &without).await.is_err(),
            "a cipher cannot be dropped"
        );
        self.register_approval(proxy, &PROBE).await?;
        let mut shared = PROBE.request();
        if let Some(cipher) = &mut shared.cipher {
            cipher.consumer_id = one.consumer_id();
        }
        assert!(
            self.register(proxy, &shared).await.is_err(),
            "a consumer serves one registration"
        );
        let mut forked = PROBE.request();
        if let Some(cipher) = &mut forked.cipher {
            cipher.audit_stream_id = "3f".repeat(16);
        }
        assert!(
            self.register(proxy, &forked).await.is_err(),
            "one stream per subject"
        );
        let mut invalid = PROBE.request();
        if let Some(cipher) = &mut invalid.cipher {
            cipher.slots = 0;
        }
        assert!(self.register(proxy, &invalid).await.is_err());
        // Only a ConfigUserMaster registration owns a cipher. The refusal comes before
        // native registration, so the same id still registers cleanly afterwards.
        let mut app = PROBE.request();
        app.registration.purpose = MasterPurpose2::AppEncryptionMaster;
        app.registration.target.slot = MasterSlotKind2::App;
        assert!(
            self.register(proxy, &app).await.is_err(),
            "an app master owns no cipher"
        );
        let secret = self.service.secret.as_ref().ok_or_else(denied)?;
        assert!(
            secret.registration_id(&PROBE.registration_id()).is_err(),
            "refusals register nothing"
        );
        assert!(self.register(proxy, &PROBE.request()).await?.active);
        let info: tinysecurity_bus::PolicyInfo = proxy
            .call(names::methods::POLICY_INFO, serde_json::json!([]))
            .await?;
        assert!(
            info.callbacks.secret_cipher,
            "a runtime cipher is reported after a neutral boot"
        );
        Ok(())
    }
    /// Mode 41: one tenant's ciphertext never opens under another tenant's master.
    async fn tenant_cross_decrypt(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        let ciphertext = self
            .encrypt(proxy, one, &first, "seal", b"tenant-one-secret")
            .await?;
        assert!(
            self.decrypt(proxy, two, &second, "open", &ciphertext)
                .await
                .is_err()
        );
        assert!(!self.delivered_to(two)?);
        assert_eq!(
            self.decrypt(proxy, one, &first, "open", &ciphertext)
                .await?,
            b"tenant-one-secret"
        );
        // The refused decrypt never reached tenant two's consumer, so its only
        // slot is free again and tenant two still round-trips its own secret.
        let own = self
            .encrypt(proxy, two, &second, "own-seal", b"tenant-two-secret")
            .await?;
        assert_eq!(
            self.decrypt(proxy, two, &second, "own-open", &own).await?,
            b"tenant-two-secret"
        );
        Ok(())
    }
    /// Mode 42: no tenant takes another's pending entry or master grant.
    async fn tenant_pending_and_grant(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        let owned = Self::cipher_request(one, &first, "seal", SecretCipherKind2::Encrypt, b"one");
        let pending = self.evaluate(proxy, &owned).await?;
        let foreign =
            Self::cipher_request(two, &second, "seal", SecretCipherKind2::Encrypt, b"one");
        assert!(
            self.execute(proxy, foreign, pending.pending_id.clone())
                .await
                .is_err()
        );
        let stolen = Self::cipher_request(two, &first, "steal", SecretCipherKind2::Encrypt, b"x");
        assert!(
            self.evaluate(proxy, &stolen).await.is_err(),
            "a master grant is its registration's"
        );
        let mut crossed =
            Self::cipher_request(one, &second, "cross", SecretCipherKind2::Encrypt, b"x");
        crossed.registration_id = one.registration_id();
        assert!(self.evaluate(proxy, &crossed).await.is_err());
        // The refused takeover left the owner's pending intact.
        let SecretCipherResponse2::Ciphertext { .. } =
            self.execute(proxy, owned, pending.pending_id).await?
        else {
            return Err(denied());
        };
        self.encrypt(proxy, two, &second, "own", b"two").await?;
        Ok(())
    }
    /// Mode 43: each registration audits under its own subject and stream.
    async fn tenant_audit_subjects(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let mut expected = BTreeMap::new();
        let engine = self.service.approvals.as_ref().ok_or_else(denied)?;
        for tenant in &TENANTS {
            let handle = self.tenant_master(proxy, tenant).await?;
            self.encrypt(proxy, tenant, &handle, "audited", b"audited")
                .await?;
            expected.insert(
                tenant.stream_id(),
                engine
                    .durable_policy_ref(&tenant.scope_id())
                    .map_err(|_| denied())?,
            );
        }
        // The sink sees a pseudonymized subject: one distinct subject per stream.
        let mut seen: BTreeMap<String, (SubjectScope, usize)> = BTreeMap::new();
        for batch in self.state.batches.lock().map_err(|_| denied())?.iter() {
            if batch.events[0].attribution != "native-config-cipher" {
                continue;
            }
            let arguments: serde_json::Value =
                serde_json::from_str(&batch.events[0].arguments_json)?;
            assert_eq!(
                expected.get(&batch.stream_id).map(String::as_str),
                arguments["policy"].as_str(),
                "cipher audit uses its own registration's stream and policy"
            );
            let entry = seen
                .entry(batch.stream_id.clone())
                .or_insert_with(|| (batch.scope.clone(), 0));
            assert_eq!(entry.0, batch.scope, "one subject per stream");
            entry.1 += 1;
        }
        let subjects: Vec<_> = seen.values().map(|(subject, _)| subject).collect();
        assert_eq!(subjects.len(), 2);
        assert_ne!(subjects[0], subjects[1]);
        assert!(seen.values().all(|(_, count)| *count >= 3));
        Ok(())
    }
    /// Mode 44: a tenant's failed delivery leaves the other tenant working.
    async fn tenant_failed_delivery(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        let sealed_one = self
            .encrypt(proxy, one, &first, "seal", b"one-plain")
            .await?;
        let sealed_two = self
            .encrypt(proxy, two, &second, "seal", b"two-plain")
            .await?;
        *self.state.failing_consumer.lock().map_err(|_| denied())? = Some(two.consumer_id());
        assert!(
            self.decrypt(proxy, two, &second, "open", &sealed_two)
                .await
                .is_err()
        );
        *self.state.failing_consumer.lock().map_err(|_| denied())? = None;
        // Tenant two's only slot stays uncertain for the process lifetime.
        assert!(
            self.decrypt(proxy, two, &second, "retry", &sealed_two)
                .await
                .is_err()
        );
        assert_eq!(
            self.decrypt(proxy, one, &first, "open", &sealed_one)
                .await?,
            b"one-plain"
        );
        assert_eq!(
            self.decrypt(proxy, one, &first, "again", &sealed_one)
                .await?,
            b"one-plain"
        );
        Ok(())
    }
    /// Mode 45: after a neutral boot, runtime tenants work end to end and
    /// retiring one leaves the other untouched.
    async fn tenant_runtime_lifecycle(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        assert!(
            self.service.secret_cipher.is_none(),
            "neutral boot has no static cipher"
        );
        let [one, two] = &TENANTS;
        let early = Self::cipher_request(one, "none", "early", SecretCipherKind2::Encrypt, b"x");
        assert!(self.evaluate(proxy, &early).await.is_err());
        self.register_tenants(proxy).await?;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        for (tenant, handle) in [(one, &first), (two, &second)] {
            let sealed = self
                .encrypt(proxy, tenant, handle, "seal", b"round-trip")
                .await?;
            assert!(sealed.starts_with("enc2:"));
            assert_eq!(
                self.decrypt(proxy, tenant, handle, "open", &sealed).await?,
                b"round-trip"
            );
        }
        let _: ApprovalScopeReceipt2 = proxy
            .call(
                names::methods::RETIRE_APPROVAL_SCOPE2,
                (RetireApprovalScopeRequest2 {
                    scope_id: one.scope_id(),
                },),
            )
            .await?;
        assert!(
            self.encrypt(proxy, one, &first, "retired", b"x")
                .await
                .is_err()
        );
        self.encrypt(proxy, two, &second, "survivor", b"x").await?;
        Ok(())
    }
    /// Mode 48: two live cipher registrations never share one master. The second
    /// is refused while the first holds it, and retiring the first releases it.
    async fn tenant_duplicate_master_is_refused(
        &self,
        proxy: &tinybus::Proxy,
    ) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        // Mode 48 stores tenant two's master under tenant one's key bytes.
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        let sealed = self.encrypt(proxy, one, &first, "seal", b"shared").await?;
        assert!(
            self.encrypt(proxy, two, &second, "dup", b"x")
                .await
                .is_err(),
            "a second live registration cannot seal under an identical master"
        );
        assert!(
            self.decrypt(proxy, two, &second, "open", &sealed)
                .await
                .is_err(),
            "a second live registration cannot open another registration's ciphertext"
        );
        let _: ApprovalScopeReceipt2 = proxy
            .call(
                names::methods::RETIRE_APPROVAL_SCOPE2,
                (RetireApprovalScopeRequest2 {
                    scope_id: one.scope_id(),
                },),
            )
            .await?;
        self.encrypt(proxy, two, &second, "after-release", b"two")
            .await?;
        // Removing the second releases its fingerprint too. A new registration
        // (the probe tenant, which mode 48 gives the same master) then binds it.
        let _: ApprovalScopeReceipt2 = proxy
            .call(
                names::methods::RETIRE_APPROVAL_SCOPE2,
                (RetireApprovalScopeRequest2 {
                    scope_id: two.scope_id(),
                },),
            )
            .await?;
        self.register_approval(proxy, &PROBE).await?;
        assert!(self.register(proxy, &PROBE.request()).await?.active);
        let reregistered = self.tenant_master(proxy, &PROBE).await?;
        self.encrypt(proxy, &PROBE, &reregistered, "reregistered", b"probe")
            .await?;
        Ok(())
    }
    /// Mode 49: a registration keeps the fingerprint of every master it has used.
    /// Rotating its key must not release the old fingerprint to another registration
    /// that still holds the old key bytes, because the old handles stay valid.
    async fn tenant_rotated_master_stays_bound(
        &self,
        proxy: &tinybus::Proxy,
    ) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        // Mode 49 gives tenant two tenant one's original key bytes.
        let first = self.tenant_master(proxy, one).await?;
        self.encrypt(proxy, one, &first, "before", b"old-key")
            .await?;
        let second = self.tenant_master(proxy, two).await?;
        // The stored key of tenant one rotates; its next acquisition loads new bytes.
        self.state.targets.lock().map_err(|_| denied())?.insert(
            one.backend_id(),
            Zeroizing::new("CD".repeat(32).into_bytes()),
        );
        let rotated = self
            .tenant_master_call(proxy, one, "tenant-one-rotated".into())
            .await?;
        assert_ne!(first, rotated, "a rotated key loads a new master handle");
        self.encrypt(proxy, one, &rotated, "after", b"new-key")
            .await?;
        assert!(
            self.encrypt(proxy, two, &second, "old", b"x")
                .await
                .is_err(),
            "rotating a key must not free its old fingerprint for another registration"
        );
        Ok(())
    }
    /// Mode 50: a request refused after its master is checked binds nothing, so the
    /// master stays available to another registration.
    async fn tenant_refused_request_binds_nothing(
        &self,
        proxy: &tinybus::Proxy,
    ) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        // Mode 50 gives tenant two tenant one's original key bytes.
        let first = self.tenant_master(proxy, one).await?;
        let mut malformed =
            Self::cipher_request(one, &first, "malformed", SecretCipherKind2::Encrypt, b"x");
        malformed.input = vec![b'x'; (1 << 20) + 1];
        assert!(self.evaluate(proxy, &malformed).await.is_err());
        let second = self.tenant_master(proxy, two).await?;
        self.encrypt(proxy, two, &second, "own", b"two").await?;
        Ok(())
    }
    /// Mode 46: replacing one tenant's approval scope drops only that scope's
    /// pending master requests, so the other tenant's request still resolves.
    async fn tenant_pending_survives_other_scope(
        &self,
        proxy: &tinybus::Proxy,
    ) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        let request = SecretRequest2 {
            registration_id: one.registration_id(),
            call_id: "tenant-one-pending".into(),
            ttl_ms: 30000,
            operation: SecretOperation2::ResolveConfigMaster,
        };
        let row: ApprovalRow2 = proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET2,
                (EvaluateSecretRequest2 {
                    request: request.clone(),
                    audit: self.next_audit(),
                },),
            )
            .await?;
        assert_eq!(row.state, ApprovalLifecycle2::Pending);
        // Tenant two's own request is decided before its scope is replaced.
        let two_request = SecretRequest2 {
            registration_id: two.registration_id(),
            call_id: "tenant-two-pending".into(),
            ttl_ms: 30000,
            operation: SecretOperation2::ResolveConfigMaster,
        };
        let two_row: ApprovalRow2 = proxy
            .call_confidential(
                names::methods::EVALUATE_SECRET2,
                (EvaluateSecretRequest2 {
                    request: two_request.clone(),
                    audit: self.next_audit(),
                },),
            )
            .await?;
        assert_eq!(two_row.state, ApprovalLifecycle2::Pending);
        let two_approved: ApprovalRow2 = proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: two.scope_id(),
                    request_id: two_row.request_id.clone(),
                    decision_ticket: "actual-fixture-human-ticket".into(),
                    audit: self.next_audit(),
                },),
            )
            .await?;
        assert_eq!(two_approved.choice, Some(ApprovalChoice2::Once));
        let mut replacement = two.approval();
        replacement.scope.policy_ref = "tenant-two-replaced".into();
        let _: ApprovalScopeReceipt2 = proxy
            .call(names::methods::REPLACE_APPROVAL_SCOPE2, (&replacement,))
            .await?;
        // The replaced scope's decided request is gone, so its execution is refused.
        assert!(
            proxy
                .call_confidential::<SecretResponse2>(
                    names::methods::EXECUTE_SECRET2,
                    (&ExecuteSecretRequest2 {
                        request: two_request,
                        request_id: two_row.request_id,
                        audit: self.next_audit(),
                    },),
                )
                .await
                .is_err(),
            "replacing a scope drops the replaced scope's pending master request"
        );
        let approved: ApprovalRow2 = proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: one.scope_id(),
                    request_id: row.request_id.clone(),
                    decision_ticket: "actual-fixture-human-ticket".into(),
                    audit: self.next_audit(),
                },),
            )
            .await?;
        assert_eq!(approved.choice, Some(ApprovalChoice2::Once));
        let response: SecretResponse2 = proxy
            .call_confidential(
                names::methods::EXECUTE_SECRET2,
                (&ExecuteSecretRequest2 {
                    request,
                    request_id: row.request_id,
                    audit: self.next_audit(),
                },),
            )
            .await?;
        let SecretResponse2::MasterHandle { .. } = response;
        Ok(())
    }
    pub(in super::super) async fn exercise_tenants(
        &self,
        proxy: &tinybus::Proxy,
    ) -> tinybus::Result<serde_json::Value> {
        match self.state.mode {
            40 => self.tenant_registration(proxy).await?,
            41 => self.tenant_cross_decrypt(proxy).await?,
            42 => self.tenant_pending_and_grant(proxy).await?,
            43 => self.tenant_audit_subjects(proxy).await?,
            44 => self.tenant_failed_delivery(proxy).await?,
            45 => self.tenant_runtime_lifecycle(proxy).await?,
            46 => self.tenant_pending_survives_other_scope(proxy).await?,
            48 => self.tenant_duplicate_master_is_refused(proxy).await?,
            49 => self.tenant_rotated_master_stays_bound(proxy).await?,
            50 => self.tenant_refused_request_binds_nothing(proxy).await?,
            _ => return Err(denied()),
        }
        Ok(serde_json::json!({"tenants": true}))
    }
}

/// Attach the linked fixture in `mode` in its own process and run its exercise.
async fn tenant_fixture(test: &str, mode: u32) -> TestResult {
    if isolate_process_owned_fixture(test, &format!("tenant-{mode}"))? {
        return Ok(());
    }
    let bus = MemoryBus::new();
    let owner = Broker::new();
    let task = owner.spawn(bus.clone());
    let client = Connection::connect(bus.connect().await?).await?;
    let host = tinybus::module::ModuleHost::new(owner);
    let info = host.attach_linked_with_config(
        linked_fixture::linked_module()?,
        serde_json::json!({ "mode": mode }),
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
        .await
        .map_err(|error| format!("mode {mode}: {error}"))?;
    assert_eq!(result["tenants"], true);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn runtime_registration_accepts_a_registration_owned_cipher() -> TestResult {
    tenant_fixture(
        "runtime_registration_accepts_a_registration_owned_cipher",
        40,
    )
    .await
}
#[tokio::test]
async fn tenant_ciphertext_never_opens_under_another_tenants_master() -> TestResult {
    tenant_fixture(
        "tenant_ciphertext_never_opens_under_another_tenants_master",
        41,
    )
    .await
}
#[tokio::test]
async fn tenant_cannot_take_another_tenants_pending_entry_or_grant() -> TestResult {
    tenant_fixture(
        "tenant_cannot_take_another_tenants_pending_entry_or_grant",
        42,
    )
    .await
}
#[tokio::test]
async fn each_registration_audits_under_its_own_subject() -> TestResult {
    tenant_fixture("each_registration_audits_under_its_own_subject", 43).await
}
#[tokio::test]
async fn one_tenants_failed_delivery_leaves_the_other_working() -> TestResult {
    tenant_fixture("one_tenants_failed_delivery_leaves_the_other_working", 44).await
}
#[tokio::test]
async fn runtime_tenants_work_after_a_neutral_boot_and_retire_alone() -> TestResult {
    tenant_fixture(
        "runtime_tenants_work_after_a_neutral_boot_and_retire_alone",
        45,
    )
    .await
}
#[tokio::test]
async fn a_refused_request_binds_no_master() -> TestResult {
    tenant_fixture("a_refused_request_binds_no_master", 50).await
}
#[tokio::test]
async fn a_rotated_master_keeps_its_fingerprint_bound() -> TestResult {
    tenant_fixture("a_rotated_master_keeps_its_fingerprint_bound", 49).await
}
#[tokio::test]
async fn two_live_registrations_never_share_one_master() -> TestResult {
    tenant_fixture("two_live_registrations_never_share_one_master", 48).await
}
#[tokio::test]
async fn pending_master_requests_survive_another_tenants_scope_replacement() -> TestResult {
    tenant_fixture(
        "pending_master_requests_survive_another_tenants_scope_replacement",
        46,
    )
    .await
}
