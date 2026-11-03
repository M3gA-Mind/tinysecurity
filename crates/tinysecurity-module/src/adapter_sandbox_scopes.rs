//! Runtime sandbox scopes (contract 1.19): registration, retirement and the per-subject
//! audit streams their plans are recorded on.
use super::{Arc, BusResult, PolicyService, failure};
use crate::{callbacks::AuditClient, callbacks::PeerBinding, stream_pins::StreamPins};
use std::{collections::BTreeMap, sync::RwLock};
use tinysecurity::sandbox::{Engine, Registration};
use tinysecurity_bus::{
    AuditConfig2, RegisterSandboxScopeRequest2, RetireSandboxScopeRequest2, SandboxScopeOutcome2,
    SandboxScopeReceipt2, SubjectScope,
};

/// Audit state of the scopes registered after init. Initialized scopes keep using the
/// base audit client; every runtime scope forwards to the host sink on its own stream
/// and never opens a native journal.
pub(super) struct SandboxRuntime {
    connection: tinybus::Connection,
    binding: PeerBinding,
    base: AuditConfig2,
    redactor: tinysecurity::Redactor,
    /// One client per runtime scope identity.
    clients: RwLock<BTreeMap<String, Arc<AuditClient>>>,
    /// Stream of each subject while live and for a retention window after release.
    pub(super) pins: StreamPins,
    /// Registration and retirement are serialized so a failed step is ours to undo.
    lifecycle: tokio::sync::Mutex<()>,
}
impl SandboxRuntime {
    pub(super) fn new(
        connection: tinybus::Connection,
        binding: PeerBinding,
        base: AuditConfig2,
        redactor: tinysecurity::Redactor,
    ) -> Self {
        Self {
            connection,
            binding,
            base,
            redactor,
            clients: RwLock::new(BTreeMap::new()),
            pins: StreamPins::default(),
            lifecycle: tokio::sync::Mutex::new(()),
        }
    }
    /// The audit client of a runtime scope, if one is registered.
    pub(super) fn client(&self, scope_id: &str) -> BusResult<Option<Arc<AuditClient>>> {
        Ok(self
            .clients
            .read()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get(scope_id)
            .cloned())
    }
    fn build_client(&self, subject: &SubjectScope, stream_id: &str) -> BusResult<AuditClient> {
        let mut config = self.base.clone();
        config.scope = subject.clone();
        config.stream_id = stream_id.into();
        config.native_path = None;
        #[cfg(test)]
        let client = AuditClient::new_for_test(
            self.connection.clone(),
            self.binding.clone(),
            config,
            self.redactor.clone(),
        );
        #[cfg(not(test))]
        let client = AuditClient::new(
            self.connection.clone(),
            self.binding.clone(),
            config,
            self.redactor.clone(),
        );
        client
    }
    fn holds_subject(clients: &BTreeMap<String, Arc<AuditClient>>, subject: &SubjectScope) -> bool {
        clients.values().any(|client| client.scope() == subject)
    }
}

/// The subject exactly as `AuditSink2` receives it: identifier-hashed.
fn audit_handle(
    redactor: &tinysecurity::Redactor,
    subject: &SubjectScope,
) -> BusResult<SubjectScope> {
    let hash = |text: &str| {
        redactor
            .redact(&tinysecurity_bus::RedactRequest {
                text: text.into(),
                mode: tinysecurity_bus::RedactMode::IdentifierHash,
            })
            .map(|result| result.text)
            .map_err(|error| failure(&error))
    };
    Ok(SubjectScope {
        user: hash(&subject.user)?,
        workspace: hash(&subject.workspace)?,
        agent: hash(&subject.agent)?,
    })
}

fn refused(reason: &'static str) -> tinybus::Error {
    tinybus::Error::failed(reason)
}

impl PolicyService {
    /// Install the sandbox engine; runtime registration additionally needs an audit to
    /// record on, so without one only the initialized scopes exist.
    pub(super) fn attach_sandbox(
        &mut self,
        engine: Option<&Arc<Engine>>,
        audit: Option<AuditConfig2>,
        peer: (&tinybus::Connection, &PeerBinding),
    ) -> BusResult<()> {
        self.sandbox = engine.cloned();
        self.sandbox_runtime = match (engine, audit) {
            (Some(_), Some(base)) => {
                let redactor = self.read()?.redactor();
                Some(Arc::new(SandboxRuntime::new(
                    peer.0.clone(),
                    peer.1.clone(),
                    base,
                    redactor,
                )))
            }
            _ => None,
        };
        Ok(())
    }
    fn sandbox_parts(&self) -> BusResult<(&Arc<Engine>, &SandboxRuntime)> {
        let engine = self
            .sandbox
            .as_ref()
            .ok_or_else(|| refused("sandbox unavailable"))?;
        let runtime = self
            .sandbox_runtime
            .as_deref()
            .ok_or_else(|| refused("sandbox audit unavailable"))?;
        Ok((engine, runtime))
    }
    /// Whether the scope's approval link names a live approval scope of the same subject.
    fn approval_link_holds(&self, request: &RegisterSandboxScopeRequest2) -> bool {
        let Some(id) = &request.scope.approval_scope_id else {
            return true;
        };
        let Some(approvals) = &self.approvals else {
            return false;
        };
        match (
            approvals.durable_scope(id),
            tinysecurity::approval::scope_handle(&request.scope.subject),
        ) {
            (Ok(registered), Ok(expected)) => registered == expected,
            _ => false,
        }
    }
    // Private host-only configuration: the facts are a trusted-adapter claim.
    pub(super) async fn register_sandbox_scope(
        &self,
        request: RegisterSandboxScopeRequest2,
    ) -> BusResult<SandboxScopeReceipt2> {
        let (engine, runtime) = self.sandbox_parts()?;
        if request.audit_stream_id.len() != 32
            || !request
                .audit_stream_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !self.approval_link_holds(&request)
        {
            return Err(refused("invalid sandbox scope"));
        }
        let redactor = self.read()?.redactor();
        let handle = request
            .report_handle
            .then(|| audit_handle(&redactor, &request.scope.subject))
            .transpose()?;
        let _lifecycle = runtime.lifecycle.lock().await;
        let id = request.scope.scope_id.clone();
        let subject = request.scope.subject.clone();
        let live = |engine: &Engine| {
            engine
                .live_scopes()
                .ok()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| failure(&tinysecurity_bus::Error::Faulted))
        };
        let receipt = |outcome, live| SandboxScopeReceipt2 {
            scope_id: id.clone(),
            scope_handle: handle.clone(),
            outcome,
            live_scopes: live,
        };
        if let Some(existing) = runtime.client(&id)? {
            // The same facts on the same stream repeat idempotently; anything else
            // under a live identity is a conflict, never a rebind.
            if existing.stream_id() != request.audit_stream_id {
                return Err(refused("conflicting sandbox scope"));
            }
            return match engine.register_scope(request.scope) {
                Ok(Registration::Unchanged) => {
                    Ok(receipt(SandboxScopeOutcome2::Unchanged, live(engine)?))
                }
                _ => Err(refused("conflicting sandbox scope")),
            };
        }
        if engine
            .has_scope(&id)
            .map_err(|_| refused("sandbox unavailable"))?
        {
            // An initialized identity is immutable and keeps its init audit stream.
            return Err(refused("conflicting sandbox scope"));
        }
        runtime
            .pins
            .pin(&subject, &request.audit_stream_id)
            .map_err(|_| refused("conflicting sandbox audit stream"))?;
        let rollback = |clients: &BTreeMap<String, Arc<AuditClient>>| {
            if !SandboxRuntime::holds_subject(clients, &subject) {
                let _ = runtime.pins.unpin(&subject);
            }
        };
        let client = match runtime.build_client(&subject, &request.audit_stream_id) {
            Ok(client) => Arc::new(client),
            Err(error) => {
                if let Ok(clients) = runtime.clients.read() {
                    rollback(&clients);
                }
                return Err(error);
            }
        };
        let mut clients = runtime
            .clients
            .write()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
        match engine.register_scope(request.scope) {
            Ok(Registration::Created) => {
                clients.insert(id.clone(), client);
                drop(clients);
                Ok(receipt(SandboxScopeOutcome2::Created, live(engine)?))
            }
            Ok(Registration::Unchanged) | Err(_) => {
                rollback(&clients);
                Err(refused("sandbox scope refused"))
            }
        }
    }
    pub(super) async fn retire_sandbox_scope(
        &self,
        request: RetireSandboxScopeRequest2,
    ) -> BusResult<SandboxScopeReceipt2> {
        let (engine, runtime) = self.sandbox_parts()?;
        let _lifecycle = runtime.lifecycle.lock().await;
        let mut clients = runtime
            .clients
            .write()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
        // Initialized scopes are replaced by reinitialization, never retired.
        let subject = engine
            .retire_scope(&request.scope_id)
            .map_err(|_| refused("sandbox scope cannot be retired"))?;
        clients.remove(&request.scope_id);
        if !SandboxRuntime::holds_subject(&clients, &subject) {
            let _ = runtime.pins.unpin(&subject);
        }
        drop(clients);
        let live = engine
            .live_scopes()
            .ok()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| failure(&tinysecurity_bus::Error::Faulted))?;
        Ok(SandboxScopeReceipt2 {
            scope_id: request.scope_id,
            scope_handle: None,
            outcome: SandboxScopeOutcome2::Retired,
            live_scopes: live,
        })
    }
}
