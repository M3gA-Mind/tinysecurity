//! Transport authority bound only during trusted native initialization.
use async_trait::async_trait;
use serde_json::Value;
use tinybus::{BusName, CallContext, Interface, InterfaceName, MemberName, Result};

#[derive(Clone, Debug)]
pub(crate) struct PeerBinding(Option<BusName>);
impl PeerBinding {
    pub(crate) fn new(peer: Option<&str>) -> Result<Self> {
        let name = peer.map(str::parse::<BusName>).transpose()?;
        if name.as_ref().is_some_and(|name| !name.is_unique()) {
            return Err(tinybus::Error::failed(
                "unavailable authenticated authority",
            ));
        }
        Ok(Self(name))
    }
    pub(crate) fn verify_reinit(&self, peer: Option<&str>) -> Result<()> {
        if peer.is_some() && Self::new(peer)?.0 != self.0 {
            return Err(tinybus::Error::failed("immutable authenticated authority"));
        }
        Ok(())
    }
    fn authorize(&self, context: &CallContext) -> Result<()> {
        if self.0.is_none() || context.authenticated_sender() != self.0.as_ref() {
            return Err(tinybus::Error::failed(
                "unavailable authenticated authority",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Authenticated<T> {
    inner: T,
    binding: PeerBinding,
}
impl<T> Authenticated<T> {
    pub(crate) fn new(inner: T, binding: PeerBinding) -> Self {
        Self { inner, binding }
    }
}
#[async_trait]
impl<T: Interface> Interface for Authenticated<T> {
    fn name(&self) -> InterfaceName {
        self.inner.name()
    }
    fn members(&self) -> Vec<MemberName> {
        self.inner.members()
    }
    fn requires_confidential(&self, member: &MemberName) -> bool {
        self.inner.requires_confidential(member)
    }
    async fn call(&self, _member: &MemberName, _args: Value) -> Result<Value> {
        Err(tinybus::Error::failed(
            "unavailable authenticated authority",
        ))
    }
    async fn call_with_context(
        &self,
        member: &MemberName,
        args: Value,
        context: &CallContext,
    ) -> Result<Value> {
        self.binding.authorize(context)?;
        let result = self.inner.call(member, args).await;
        if matches!(
            member.as_str(),
            tinysecurity_bus::names::methods::PASSWORD_CRYPT2
                | tinysecurity_bus::names::methods::KEYRING_ACCESS2
                | tinysecurity_bus::names::methods::PAIRING_CONTROL2
                | tinysecurity_bus::names::methods::DEVICE_PAIRING2
        ) {
            return result.map_err(|_| {
                tinybus::Error::failed(
                    if member.as_str() == tinysecurity_bus::names::methods::DEVICE_PAIRING2 {
                        "device pairing authority denied"
                    } else {
                        "crypto authority denied"
                    },
                )
            });
        }
        if matches!(
            member.as_str(),
            tinysecurity_bus::names::methods::EVALUATE_SECRET_CIPHER2
                | tinysecurity_bus::names::methods::EXECUTE_SECRET_CIPHER2
                | tinysecurity_bus::names::methods::EVALUATE_SECRET2
                | tinysecurity_bus::names::methods::EXECUTE_SECRET2
                | tinysecurity_bus::names::methods::EVALUATE_DEVICE2
                | tinysecurity_bus::names::methods::EXECUTE_DEVICE2
        ) {
            result.map_err(|_| {
                tinybus::Error::failed(
                    if matches!(
                        member.as_str(),
                        tinysecurity_bus::names::methods::EVALUATE_SECRET_CIPHER2
                            | tinysecurity_bus::names::methods::EXECUTE_SECRET_CIPHER2
                            | tinysecurity_bus::names::methods::EVALUATE_SECRET2
                            | tinysecurity_bus::names::methods::EXECUTE_SECRET2
                    ) {
                        "secret authority denied"
                    } else {
                        "device authority denied"
                    },
                )
            })
        } else {
            result
        }
    }
}

/// Exact audit forwarding; scope derives only from trusted immutable SDK config.
pub(crate) struct AuditClient {
    connection: tinybus::Connection,
    binding: PeerBinding,
    config: tinysecurity_bus::AuditConfig2,
    redactor: std::sync::RwLock<tinysecurity::Redactor>,
    native: Option<std::sync::Arc<tinysecurity::audit::JsonlSink>>,
    /// The stream each host-recorded subject is bound to (`RecordAudit2`).
    pins: crate::stream_pins::StreamPins,
    #[cfg(test)]
    pub(crate) test_ordinary_calls: bool,
}
impl std::fmt::Debug for AuditClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditClient([REDACTED])")
    }
}
impl AuditClient {
    pub(crate) fn required(&self) -> bool {
        self.config.required
    }
    pub(crate) fn scope(&self) -> &tinysecurity_bus::SubjectScope {
        &self.config.scope
    }
    pub(crate) fn stream_id(&self) -> &str {
        &self.config.stream_id
    }
    pub(crate) fn new(
        connection: tinybus::Connection,
        binding: PeerBinding,
        config: tinysecurity_bus::AuditConfig2,
        redactor: tinysecurity::Redactor,
    ) -> Result<Self> {
        if binding.0.is_none()
            || config.timeout_ms == 0
            || config.timeout_ms > 30_000
            || config.stream_id.len() != 32
            || !config
                .stream_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(tinybus::Error::failed("invalid audit initialization"));
        }
        let native = config
            .native_path
            .as_ref()
            .map(|path| {
                tinysecurity::audit::JsonlSink::with_journal_capacity(
                    std::path::Path::new(path),
                    config.max_bytes,
                    config.max_archives,
                    config.journal_max_bytes,
                    config.journal_max_events,
                    redactor.clone(),
                )
                .map(std::sync::Arc::new)
            })
            .transpose()
            .map_err(|_| tinybus::Error::failed("unavailable restricted audit storage"))?;
        Ok(Self {
            connection,
            binding,
            config,
            redactor: std::sync::RwLock::new(redactor),
            native,
            pins: crate::stream_pins::StreamPins::default(),
            #[cfg(test)]
            test_ordinary_calls: false,
        })
    }
    /// Use ordinary mock-bus callbacks in unit tests without confidential module
    /// provenance. Production clients always use confidential callback calls.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        connection: tinybus::Connection,
        binding: PeerBinding,
        config: tinysecurity_bus::AuditConfig2,
        redactor: tinysecurity::Redactor,
    ) -> Result<Self> {
        let mut client = Self::new(connection, binding, config, redactor)?;
        client.test_ordinary_calls = true;
        Ok(client)
    }
    /// Append one host-recorded event to `request.subject`'s stream (`RecordAudit2`).
    ///
    /// The subject is bound to the first stream it is recorded under, the event is
    /// sanitized with the policy's redactor and forwarded to the host sink exactly like
    /// every other event, and the answer carries the same durable-receipt evidence. A
    /// request the module refuses (module-only kind, malformed identity, a stream other
    /// than the subject's, a stale policy generation) answers denied and uncommitted.
    pub(crate) async fn record(
        &self,
        request: tinysecurity_bus::AuditRecordRequest2,
        generation: u64,
        redactor: tinysecurity::Redactor,
    ) -> tinysecurity_bus::AuditResponse2 {
        use tinysecurity_bus::{AuditEvent2, AuditHealth2, AuditResponse2, AuditSinkRequest2};
        let denied = || AuditResponse2 {
            permitted: false,
            committed: false,
            health: AuditHealth2::Denied,
            receipt: None,
        };
        if request.validate().is_err()
            || request.audit.generation != generation
            || self.pins.pin(&request.subject, &request.stream_id).is_err()
        {
            return denied();
        }
        let mut config = self.config.clone();
        config.scope = request.subject.clone();
        config.stream_id = request.stream_id.clone();
        // Subjects other than the init one always forward to the host sink.
        config.native_path = None;
        #[cfg(test)]
        let client = Self::new_for_test(
            self.connection.clone(),
            self.binding.clone(),
            config,
            redactor.clone(),
        );
        #[cfg(not(test))]
        let client = Self::new(
            self.connection.clone(),
            self.binding.clone(),
            config,
            redactor.clone(),
        );
        let Ok(client) = client else {
            return denied();
        };
        let Some(sequence) = request.audit.expected_tail.checked_add(1) else {
            return denied();
        };
        let batch = AuditSinkRequest2 {
            scope: request.subject,
            stream_id: request.stream_id,
            expected_tail: request.audit.expected_tail,
            events: vec![AuditEvent2 {
                sequence,
                event_id: request.audit.event_id,
                generation,
                kind: request.kind,
                attribution: request.attribution,
                arguments_json: request.arguments_json,
                rule_ids: request.rule_ids,
            }],
        };
        client.append_with_registry(batch, Ok(redactor)).await
    }
    pub(crate) fn registry(&self) -> Result<tinysecurity::Redactor> {
        self.redactor
            .read()
            .map(|registry| registry.clone())
            .map_err(|_| tinybus::Error::failed("audit registry unavailable"))
    }
    pub(crate) fn verify_reinit(
        &self,
        config: Option<&tinysecurity_bus::AuditConfig2>,
    ) -> Result<()> {
        if config.is_some_and(|config| config != &self.config) {
            return Err(tinybus::Error::failed("immutable audit initialization"));
        }
        Ok(())
    }
    pub(crate) fn replace_registry(&self, registry: tinysecurity::Redactor) -> Result<()> {
        *self
            .redactor
            .write()
            .map_err(|_| tinybus::Error::failed("audit registry unavailable"))? = registry;
        Ok(())
    }
    pub(crate) async fn append(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
    ) -> tinysecurity_bus::AuditResponse2 {
        self.append_with_registry(batch, self.registry()).await
    }
    pub(crate) async fn append_with_registry(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
        registry: Result<tinysecurity::Redactor>,
    ) -> tinysecurity_bus::AuditResponse2 {
        #[cfg(test)]
        let confidential = !self.test_ordinary_calls;
        #[cfg(not(test))]
        let confidential = true;
        self.append_mode(batch, registry, confidential).await
    }
    pub(crate) async fn append_native_with_registry(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
        registry: Result<tinysecurity::Redactor>,
    ) -> tinysecurity_bus::AuditResponse2 {
        self.append_mode(batch, registry, true).await
    }
    async fn append_mode(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
        registry: Result<tinysecurity::Redactor>,
        confidential: bool,
    ) -> tinysecurity_bus::AuditResponse2 {
        use tinysecurity_bus::{AuditHealth2, AuditResponse2};
        let clean = registry.and_then(|registry| {
            tinysecurity::audit::sanitize(&batch, &registry)
                .map_err(|_| tinybus::Error::failed("audit sanitation failed"))
        });
        if batch.scope != self.config.scope
            || batch.stream_id != self.config.stream_id
            || clean.is_err()
        {
            return AuditResponse2 {
                permitted: false,
                committed: false,
                health: AuditHealth2::Denied,
                receipt: None,
            };
        }
        let result = match clean {
            Ok(clean) => self.append_exact(clean, confidential).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(receipt) => AuditResponse2 {
                permitted: true,
                committed: true,
                health: AuditHealth2::Healthy,
                receipt: Some(receipt),
            },
            Err(_) => AuditResponse2 {
                permitted: !self.config.required,
                committed: false,
                health: if self.config.required {
                    AuditHealth2::Denied
                } else {
                    AuditHealth2::Degraded
                },
                receipt: None,
            },
        }
    }
    async fn append_exact(
        &self,
        batch: tinysecurity_bus::AuditSinkRequest2,
        confidential: bool,
    ) -> Result<tinysecurity_bus::AuditSinkResponse2> {
        use tinysecurity_bus::callback_names2 as names;
        let clean = batch;
        let receipt = if let Some(native) = &self.native {
            let sink = std::sync::Arc::clone(native);
            let request = clean.clone();
            await_native_worker(
                tokio::task::spawn_blocking(move || sink.append(&request)),
                self.config.timeout_ms,
            )
            .await?
        } else {
            let peer = self
                .binding
                .0
                .as_ref()
                .ok_or_else(|| tinybus::Error::failed("audit authority unavailable"))?;
            // Fixed unique destination: replacement of a well-known name grants no authority.
            let proxy = self
                .connection
                .proxy(peer.as_str(), names::OBJECT_PATH, names::AUDIT_SINK)?
                .with_timeout(std::time::Duration::from_millis(u64::from(
                    self.config.timeout_ms,
                )));
            if confidential {
                proxy
                    .call_confidential(names::APPEND, (clean.clone(),))
                    .await?
            } else {
                proxy.call(names::APPEND, (clean.clone(),)).await?
            }
        };
        clean
            .verify_receipt(&receipt)
            .map_err(|_| tinybus::Error::failed("invalid exact audit receipt"))?;
        Ok(receipt)
    }
}
async fn await_native_worker(
    worker: tokio::task::JoinHandle<
        tinysecurity::audit::Result<tinysecurity_bus::AuditSinkResponse2>,
    >,
    timeout_ms: u32,
) -> Result<tinysecurity_bus::AuditSinkResponse2> {
    // Dropping the join handle detaches an already-running blocking write. Its
    // outcome remains indeterminate and must be reconciled with the same batch.
    tokio::time::timeout(
        std::time::Duration::from_millis(u64::from(timeout_ms)),
        worker,
    )
    .await
    .map_err(|_| tinybus::Error::failed("audit worker deadline exceeded"))?
    .map_err(|_| tinybus::Error::failed("audit worker unavailable"))?
    .map_err(|_| tinybus::Error::failed("audit storage unavailable"))
}
#[cfg(test)]
#[path = "callbacks_tests.rs"]
mod tests;
