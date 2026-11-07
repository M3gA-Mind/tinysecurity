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
const PROBE: Tenant = Tenant { index: 3 };

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
    async fn tenant_master(&self, proxy: &tinybus::Proxy, tenant: &Tenant) -> tinybus::Result<String> {
        let request = SecretRequest2 {
            registration_id: tenant.registration_id(),
            call_id: format!("tenant-{}-master", tenant.index),
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
        assert_eq!(self.register(proxy, &one.request()).await?.registration_id, one.registration_id());
        let mut resized = one.request();
        if let Some(cipher) = &mut resized.cipher {
            cipher.slots = 2;
        }
        assert!(self.register(proxy, &resized).await.is_err(), "a live cipher is immutable");
        let without = RegisterSecretScopeRequest2 { cipher: None, ..one.request() };
        assert!(self.register(proxy, &without).await.is_err(), "a cipher cannot be dropped");
        self.register_approval(proxy, &PROBE).await?;
        let mut shared = PROBE.request();
        if let Some(cipher) = &mut shared.cipher {
            cipher.consumer_id = one.consumer_id();
        }
        assert!(self.register(proxy, &shared).await.is_err(), "a consumer serves one registration");
        let mut forked = PROBE.request();
        if let Some(cipher) = &mut forked.cipher {
            cipher.audit_stream_id = "3f".repeat(16);
        }
        assert!(self.register(proxy, &forked).await.is_err(), "one stream per subject");
        let mut invalid = PROBE.request();
        if let Some(cipher) = &mut invalid.cipher {
            cipher.slots = 0;
        }
        assert!(self.register(proxy, &invalid).await.is_err());
        let secret = self.service.secret.as_ref().ok_or_else(denied)?;
        assert!(secret.registration_id(&PROBE.registration_id()).is_err(), "refusals register nothing");
        assert!(self.register(proxy, &PROBE.request()).await?.active);
        Ok(())
    }
    /// Mode 41: one tenant's ciphertext never opens under another tenant's master.
    async fn tenant_cross_decrypt(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        let ciphertext = self.encrypt(proxy, one, &first, "seal", b"tenant-one-secret").await?;
        assert!(self.decrypt(proxy, two, &second, "open", &ciphertext).await.is_err());
        assert!(!self.delivered_to(two)?);
        assert_eq!(self.decrypt(proxy, one, &first, "open", &ciphertext).await?, b"tenant-one-secret");
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
        let foreign = Self::cipher_request(two, &second, "seal", SecretCipherKind2::Encrypt, b"one");
        assert!(self.execute(proxy, foreign, pending.pending_id.clone()).await.is_err());
        let stolen = Self::cipher_request(two, &first, "steal", SecretCipherKind2::Encrypt, b"x");
        assert!(self.evaluate(proxy, &stolen).await.is_err(), "a master grant is its registration's");
        let mut crossed = Self::cipher_request(one, &second, "cross", SecretCipherKind2::Encrypt, b"x");
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
            self.encrypt(proxy, tenant, &handle, "audited", b"audited").await?;
            expected.insert(
                (tenant.subject().user, tenant.stream_id()),
                engine.durable_policy_ref(&tenant.scope_id()).map_err(|_| denied())?,
            );
        }
        let mut seen = BTreeMap::new();
        for batch in self.state.batches.lock().map_err(|_| denied())?.iter() {
            if batch.events[0].attribution != "native-config-cipher" {
                continue;
            }
            let arguments: serde_json::Value =
                serde_json::from_str(&batch.events[0].arguments_json)?;
            let key = (batch.scope.user.clone(), batch.stream_id.clone());
            assert_eq!(
                expected.get(&key).map(String::as_str),
                arguments["policy"].as_str(),
                "cipher audit carries its own registration's subject, stream and policy"
            );
            *seen.entry(key).or_insert(0) += 1;
        }
        assert_eq!(seen.len(), 2);
        assert!(seen.values().all(|count| *count >= 3));
        Ok(())
    }
    /// Mode 44: a tenant's failed delivery leaves the other tenant working.
    async fn tenant_failed_delivery(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        self.register_tenants(proxy).await?;
        let [one, two] = &TENANTS;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        let sealed_one = self.encrypt(proxy, one, &first, "seal", b"one-plain").await?;
        let sealed_two = self.encrypt(proxy, two, &second, "seal", b"two-plain").await?;
        *self.state.failing_consumer.lock().map_err(|_| denied())? = Some(two.consumer_id());
        assert!(self.decrypt(proxy, two, &second, "open", &sealed_two).await.is_err());
        *self.state.failing_consumer.lock().map_err(|_| denied())? = None;
        // Tenant two's only slot stays uncertain for the process lifetime.
        assert!(self.decrypt(proxy, two, &second, "retry", &sealed_two).await.is_err());
        assert_eq!(self.decrypt(proxy, one, &first, "open", &sealed_one).await?, b"one-plain");
        assert_eq!(self.decrypt(proxy, one, &first, "again", &sealed_one).await?, b"one-plain");
        Ok(())
    }
    /// Mode 45: after a neutral boot, runtime tenants work end to end and
    /// retiring one leaves the other untouched.
    async fn tenant_runtime_lifecycle(&self, proxy: &tinybus::Proxy) -> tinybus::Result<()> {
        assert!(self.service.secret_cipher.is_none(), "neutral boot has no static cipher");
        let [one, two] = &TENANTS;
        let early = Self::cipher_request(one, "none", "early", SecretCipherKind2::Encrypt, b"x");
        assert!(self.evaluate(proxy, &early).await.is_err());
        self.register_tenants(proxy).await?;
        let first = self.tenant_master(proxy, one).await?;
        let second = self.tenant_master(proxy, two).await?;
        for (tenant, handle) in [(one, &first), (two, &second)] {
            let sealed = self.encrypt(proxy, tenant, handle, "seal", b"round-trip").await?;
            assert!(sealed.starts_with("enc2:"));
            assert_eq!(self.decrypt(proxy, tenant, handle, "open", &sealed).await?, b"round-trip");
        }
        let _: ApprovalScopeReceipt2 = proxy
            .call(
                names::methods::RETIRE_APPROVAL_SCOPE2,
                (RetireApprovalScopeRequest2 { scope_id: one.scope_id() },),
            )
            .await?;
        assert!(self.encrypt(proxy, one, &first, "retired", b"x").await.is_err());
        self.encrypt(proxy, two, &second, "survivor", b"x").await?;
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
        .proxy(peer.as_str(), "/fixture", "ai.tinyhumans.tinysecurity.SecretFixture")?
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
    tenant_fixture("runtime_registration_accepts_a_registration_owned_cipher", 40).await
}
#[tokio::test]
async fn tenant_ciphertext_never_opens_under_another_tenants_master() -> TestResult {
    tenant_fixture("tenant_ciphertext_never_opens_under_another_tenants_master", 41).await
}
#[tokio::test]
async fn tenant_cannot_take_another_tenants_pending_entry_or_grant() -> TestResult {
    tenant_fixture("tenant_cannot_take_another_tenants_pending_entry_or_grant", 42).await
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
    tenant_fixture("runtime_tenants_work_after_a_neutral_boot_and_retire_alone", 45).await
}
