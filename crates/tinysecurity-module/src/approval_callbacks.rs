//! Bounded exact approval callback clients, fixed to the trusted unique init peer.
use crate::callbacks::{AuditClient, PeerBinding};
use crate::stream_pins::StreamPins;
use std::sync::{Arc, RwLock};
use tinysecurity::approval::{Error, NativeAuditAcknowledgement, Ports, Result};
use tinysecurity_bus::{
    ApprovalCasRequest2, ApprovalCasResponse2, ApprovalConfig2, ApprovalDeliveryRequest2,
    ApprovalDeliveryResponse2, ApprovalLifecycle2, ApprovalLoadRequest2, ApprovalLoadResponse2,
    ApprovalPurgeSessionRequest2, ApprovalPurgeSessionResponse2, ApprovalRow2, ApprovalScope2,
    AuditConfig2, AuditEvent2, AuditKind2, AuditSinkRequest2, AuditSinkResponse2,
    HumanDecisionReceipt2, SubjectScope, VerifyHumanRequest2, callback_names2,
};
/// Captured registered callback identity; no model-provided destination or scope.
pub(crate) struct ApprovalStoreClient {
    connection: tinybus::Connection,
    peer: tinybus::BusName,
    timeout_ms: u32,
    scopes: RwLock<Vec<SubjectScope>>,
    #[cfg(test)]
    test_ordinary_calls: bool,
}
impl std::fmt::Debug for ApprovalStoreClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalStoreClient([REDACTED])")
    }
}
impl ApprovalStoreClient {
    pub(crate) fn new(
        connection: tinybus::Connection,
        peer: Option<&str>,
        config: &ApprovalConfig2,
    ) -> tinybus::Result<Self> {
        let peer = peer
            .ok_or_else(|| tinybus::Error::failed("approval authority unavailable"))?
            .parse::<tinybus::BusName>()?;
        if !peer.is_unique() || !(1..=30000).contains(&config.timeout_ms) {
            return Err(tinybus::Error::failed("invalid approval initialization"));
        }
        let scopes = config
            .scopes
            .iter()
            .map(|s| tinysecurity::approval::scope_handle(&s.subject))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| tinybus::Error::failed("invalid approval scope"))?;
        if scopes.is_empty() || scopes.len() > 128 {
            return Err(tinybus::Error::failed("invalid approval scope"));
        }
        Ok(Self {
            connection,
            peer,
            timeout_ms: config.timeout_ms,
            scopes: RwLock::new(scopes),
            #[cfg(test)]
            test_ordinary_calls: false,
        })
    }
    /// Build a client for unit tests that exercise callback semantics on an
    /// unauthenticated `MemoryBus` mock. Production always uses confidential calls.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        connection: tinybus::Connection,
        peer: Option<&str>,
        config: &ApprovalConfig2,
    ) -> tinybus::Result<Self> {
        let mut client = Self::new(connection, peer, config)?;
        client.test_ordinary_calls = true;
        Ok(client)
    }
    fn scope(&self, scope: &SubjectScope) -> Result<()> {
        if self
            .scopes
            .read()
            .map_err(|_| Error::Unavailable)?
            .contains(scope)
        {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    /// Admit a runtime subject, bounded like the init set plus the engine's own cap.
    fn admit(&self, handle: SubjectScope) -> Result<()> {
        let mut scopes = self.scopes.write().map_err(|_| Error::Unavailable)?;
        if !scopes.contains(&handle) {
            if scopes.len() >= tinysecurity_bus::MAX_APPROVAL_SCOPES2 {
                return Err(Error::Unavailable);
            }
            scopes.push(handle);
        }
        Ok(())
    }
    fn release(&self, handle: &SubjectScope) -> Result<()> {
        self.scopes
            .write()
            .map_err(|_| Error::Unavailable)?
            .retain(|scope| scope != handle);
        Ok(())
    }
    fn proxy(&self, interface: &str) -> Result<tinybus::Proxy> {
        self.connection
            .proxy(self.peer.as_str(), callback_names2::OBJECT_PATH, interface)
            .map(|p| p.with_timeout(std::time::Duration::from_millis(u64::from(self.timeout_ms))))
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) async fn load(
        &self,
        request: ApprovalLoadRequest2,
    ) -> Result<ApprovalLoadResponse2> {
        self.scope(&request.scope)?;
        let proxy = self.proxy(callback_names2::APPROVAL_STORE)?;
        #[cfg(test)]
        let response = if self.test_ordinary_calls {
            proxy.call(callback_names2::LOAD, (request.clone(),)).await
        } else {
            proxy
                .call_confidential(callback_names2::LOAD, (request.clone(),))
                .await
        }
        .map_err(|_| Error::Unavailable)?;
        #[cfg(not(test))]
        let response = proxy
            .call_confidential(callback_names2::LOAD, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        request
            .verify_response(&response)
            .map_err(|_| Error::Invalid)?;
        Ok(response)
    }
    pub(crate) async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.scope(&request.scope)?;
        let proxy = self.proxy(callback_names2::APPROVAL_STORE)?;
        #[cfg(test)]
        let response = if self.test_ordinary_calls {
            proxy.call(callback_names2::CAS, (request.clone(),)).await
        } else {
            proxy
                .call_confidential(callback_names2::CAS, (request.clone(),))
                .await
        }
        .map_err(|_| Error::Unavailable)?;
        #[cfg(not(test))]
        let response = proxy
            .call_confidential(callback_names2::CAS, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        request
            .verify_receipt(&response)
            .map_err(|_| Error::Invalid)?;
        Ok(response)
    }
    pub(crate) async fn purge_session(
        &self,
        request: ApprovalPurgeSessionRequest2,
    ) -> Result<ApprovalPurgeSessionResponse2> {
        self.scope(&request.scope)?;
        let response = self
            .proxy(callback_names2::APPROVAL_STORE)?
            .call(callback_names2::PURGE_SESSION, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        request
            .verify_response(&response)
            .map_err(|_| Error::Invalid)?;
        Ok(response)
    }
}
/// Real authenticated store, delivery, human-ticket verification and audit ports.
pub(crate) struct ApprovalClients {
    store: ApprovalStoreClient,
    audit: RwLock<Vec<(SubjectScope, Arc<AuditClient>)>>,
    /// Runtime subjects forward audit to the host sink under this base policy.
    runtime: RuntimeAudit,
    /// The audit stream of each runtime subject; see [`StreamPins`].
    pins: StreamPins,
    #[cfg(test)]
    test_ordinary_calls: bool,
}
struct RuntimeAudit {
    connection: tinybus::Connection,
    binding: PeerBinding,
    base: AuditConfig2,
    redactor: tinysecurity::Redactor,
}
impl std::fmt::Debug for ApprovalClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalClients([REDACTED])")
    }
}
impl ApprovalClients {
    pub(crate) fn new(
        connection: &tinybus::Connection,
        peer: Option<&str>,
        config: &ApprovalConfig2,
        audit: &AuditConfig2,
        redactor: &tinysecurity::Redactor,
    ) -> tinybus::Result<Self> {
        let store = ApprovalStoreClient::new(connection.clone(), peer, config)?;
        let binding = PeerBinding::new(peer)?;
        let runtime = RuntimeAudit {
            connection: connection.clone(),
            binding: binding.clone(),
            base: audit.clone(),
            redactor: redactor.clone(),
        };
        let mut clients = Vec::new();
        for registration in &config.scopes {
            let scope = tinysecurity::approval::scope_handle(&registration.subject)
                .map_err(|_| tinybus::Error::failed("invalid approval scope"))?;
            let mut scoped = audit.clone();
            scoped.scope = registration.subject.clone();
            // Host reserves audit sequencing per registered subject; the base audit
            // stream remains explicit and the sink validates exact scope and stream.
            let client = AuditClient::new(
                connection.clone(),
                binding.clone(),
                scoped,
                redactor.clone(),
            )?;
            clients.push((scope, Arc::new(client)));
        }
        Ok(Self {
            store,
            audit: RwLock::new(clients),
            runtime,
            pins: StreamPins::default(),
            #[cfg(test)]
            test_ordinary_calls: false,
        })
    }
    /// Build a client for unit tests that use unauthenticated `MemoryBus` mocks.
    /// Production and binding-backed tests always use confidential callback calls.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        connection: &tinybus::Connection,
        peer: Option<&str>,
        config: &ApprovalConfig2,
        audit: &AuditConfig2,
        redactor: &tinysecurity::Redactor,
    ) -> tinybus::Result<Self> {
        let mut clients = Self::new(connection, peer, config, audit, redactor)?;
        clients.store.test_ordinary_calls = true;
        clients.test_ordinary_calls = true;
        for (_, client) in clients
            .audit
            .get_mut()
            .map_err(|_| tinybus::Error::failed("approval audit unavailable"))?
        {
            std::sync::Arc::get_mut(client)
                .ok_or_else(|| tinybus::Error::failed("approval audit already shared"))?
                .test_ordinary_calls = true;
        }
        Ok(clients)
    }
    /// Build the audit client of a runtime subject: its own persisted stream, always
    /// forwarded to the host sink so no extra native journal is opened.
    fn runtime_client(&self, scope: &ApprovalScope2, stream_id: &str) -> Result<AuditClient> {
        let mut config = self.runtime.base.clone();
        config.scope = scope.subject.clone();
        config.stream_id = stream_id.into();
        config.native_path = None;
        let client = AuditClient::new(
            self.runtime.connection.clone(),
            self.runtime.binding.clone(),
            config,
            self.runtime.redactor.clone(),
        )
        .map_err(|_| Error::Invalid)?;
        #[cfg(test)]
        let client = {
            let mut client = client;
            if self.test_ordinary_calls {
                client.test_ordinary_calls = true;
            }
            client
        };
        Ok(client)
    }
}
#[async_trait::async_trait]
impl Ports for ApprovalClients {
    async fn load(&self, request: ApprovalLoadRequest2) -> Result<ApprovalLoadResponse2> {
        self.store.load(request).await
    }
    async fn cas(&self, request: ApprovalCasRequest2) -> Result<ApprovalCasResponse2> {
        self.store.cas(request).await
    }
    async fn purge_session(
        &self,
        request: ApprovalPurgeSessionRequest2,
    ) -> Result<ApprovalPurgeSessionResponse2> {
        self.store.purge_session(request).await
    }
    async fn prompt(&self, request: ApprovalDeliveryRequest2) -> Result<ApprovalDeliveryResponse2> {
        self.store.scope(&request.row.binding.scope)?;
        let proxy = self.store.proxy(callback_names2::APPROVAL_PROMPT)?;
        #[cfg(test)]
        let response: ApprovalDeliveryResponse2 = if self.store.test_ordinary_calls {
            proxy
                .call(callback_names2::PROMPT, (request.clone(),))
                .await
        } else {
            proxy
                .call_confidential(callback_names2::PROMPT, (request.clone(),))
                .await
        }
        .map_err(|_| Error::Unavailable)?;
        #[cfg(not(test))]
        let response: ApprovalDeliveryResponse2 = proxy
            .call_confidential(callback_names2::PROMPT, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.request_id != request.row.request_id
            || response.nonce != request.row.nonce
            || !response.delivered
        {
            return Err(Error::Denied);
        }
        Ok(response)
    }
    async fn human(&self, request: VerifyHumanRequest2) -> Result<HumanDecisionReceipt2> {
        self.store.scope(&request.row.binding.scope)?;
        let proxy = self.store.proxy(callback_names2::APPROVAL_PROMPT)?;
        #[cfg(test)]
        let response: HumanDecisionReceipt2 = if self.store.test_ordinary_calls {
            proxy
                .call(callback_names2::VERIFY_HUMAN, (request.clone(),))
                .await
        } else {
            proxy
                .call_confidential(callback_names2::VERIFY_HUMAN, (request.clone(),))
                .await
        }
        .map_err(|_| Error::Unavailable)?;
        #[cfg(not(test))]
        let response: HumanDecisionReceipt2 = proxy
            .call_confidential(callback_names2::VERIFY_HUMAN, (request.clone(),))
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.row != request.row {
            return Err(Error::Denied);
        }
        Ok(response)
    }
    async fn audit(&self, row: ApprovalRow2) -> Result<()> {
        self.append_row(row, false).await.map(|_| ())
    }
    async fn admit_scope(&self, scope: &ApprovalScope2, audit_stream_id: &str) -> Result<()> {
        let handle = tinysecurity::approval::scope_handle(&scope.subject)?;
        self.pins.pin(&scope.subject, audit_stream_id)?;
        let client = Arc::new(self.runtime_client(scope, audit_stream_id)?);
        self.store.admit(handle.clone())?;
        // The engine serializes lifecycles, so an existing client is stale (for
        // example after a failed release) and must not keep another stream.
        let mut audit = self.audit.write().map_err(|_| Error::Unavailable)?;
        audit.retain(|(s, _)| s != &handle);
        audit.push((handle, client));
        Ok(())
    }
    async fn release_scope(&self, scope: &ApprovalScope2) -> Result<()> {
        let handle = tinysecurity::approval::scope_handle(&scope.subject)?;
        self.audit
            .write()
            .map_err(|_| Error::Unavailable)?
            .retain(|(s, _)| s != &handle);
        self.pins.unpin(&scope.subject)?;
        self.store.release(&handle)
    }
    async fn native_audit(&self, row: ApprovalRow2) -> Result<NativeAuditAcknowledgement> {
        let (receipt, expected_scope) = self.append_row(row.clone(), true).await?;
        NativeAuditAcknowledgement::from_verified_sink(row, expected_scope, receipt)
    }
}
impl ApprovalClients {
    async fn append_row(
        &self,
        row: ApprovalRow2,
        required: bool,
    ) -> Result<(AuditSinkResponse2, SubjectScope)> {
        let client = self
            .audit
            .read()
            .map_err(|_| Error::Unavailable)?
            .iter()
            .find(|(s, _)| s == &row.binding.scope)
            .map(|(_, client)| Arc::clone(client))
            .ok_or(Error::Denied)?;
        if required && !client.required() {
            return Err(Error::Denied);
        }
        let batch = AuditSinkRequest2 {
            scope: client.scope().clone(),
            stream_id: client.stream_id().into(),
            expected_tail: row.audit.expected_tail,
            events: vec![AuditEvent2 {
                sequence: row
                    .audit
                    .expected_tail
                    .checked_add(1)
                    .ok_or(Error::Invalid)?,
                event_id: row.audit.event_id.clone(),
                generation: row.binding.generation,
                kind: if row.state == ApprovalLifecycle2::Executed {
                    AuditKind2::Execution
                } else {
                    AuditKind2::Approval
                },
                attribution: row.attribution.clone().unwrap_or_else(|| "pending".into()),
                arguments_json: serde_json::to_string(&row).map_err(|_| Error::Invalid)?,
                rule_ids: vec![],
            }],
        };
        let registry = client.registry().map_err(|_| Error::Unavailable)?;
        let expected_scope = tinysecurity::audit::sanitize(&batch, &registry)
            .map_err(|_| Error::Invalid)?
            .scope;
        let response = if required {
            client
                .append_native_with_registry(batch, Ok(registry))
                .await
        } else {
            client.append_with_registry(batch, Ok(registry)).await
        };
        if !response.committed || !response.permitted {
            return Err(Error::Unavailable);
        }
        Ok((response.receipt.ok_or(Error::Unavailable)?, expected_scope))
    }
}
#[cfg(test)]
#[path = "approval_callbacks_tests.rs"]
mod tests;
