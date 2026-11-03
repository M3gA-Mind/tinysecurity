//! Fixed authenticated confidential callbacks own bounded zeroizing output slots.
#[path = "../approval_native_contract/callback.rs"]
mod callback;
#[path = "../approval_native_contract/store.rs"]
mod store;
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tinybus::{
    BusName, CallContext, Connection, Interface, InterfaceName, MemberName, broker::Broker,
    module::ModuleHost, transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    AccessTier, ApprovalChoice2, ApprovalConfig2, ApprovalLifecycle2, ApprovalRow2, ApprovalScope2,
    AuditConfig2, AuditCorrelation2, AuditSinkRequest2, DecideRequest2, DeviceConfig2,
    DevicePairingConfig2, DevicePairingContextRequest2, DevicePairingContextResponse2,
    DevicePairingLegacyFormat2, DevicePairingLegacyLoadRequest2, DevicePairingLegacyLoadResponse2,
    DevicePairingLegacyRecord2, DevicePairingPersistenceOperation2,
    DevicePairingPersistenceRequest2, DevicePairingPersistenceResponse2, DevicePairingPurpose2,
    DevicePairingScope2, DevicePairingSource2, DeviceScope2, EvaluateSecretCipherRequest2,
    EvaluateSecretRequest2, ExecuteSecretCipherRequest2, ExecuteSecretRequest2, MasterPurpose2,
    MasterSlotKind2, ModuleConfig, Origin, PolicyInfo, RedactorConfig, SecretBackendLoadRequest2,
    SecretBackendLoadResponse2, SecretBackendLoadStatus2, SecretBackendSetRequest2,
    SecretBackendSetResponse2, SecretBackendSetStatus2, SecretBinding2, SecretCipherConfig2,
    SecretCipherDeliveryIdentity2, SecretCipherDeliveryRequest2, SecretCipherDeliveryResponse2,
    SecretCipherKind2, SecretCipherPending2, SecretCipherRequest2, SecretCipherResponse2,
    SecretConfig2, SecretLimits2, SecretOperation2, SecretPhase2, SecretRegistration2,
    SecretRequest2, SecretResponse2, SubjectScope, callback_names2, names,
};
use zeroize::Zeroizing;

fn legacy_import_handle(host_event_id: &str) -> String {
    match host_event_id {
        "legacy-import-foreign-source" => "fixture-legacy-foreign-source".into(),
        "legacy-import-corrupt" => "fixture-legacy-corrupt".into(),
        event_id => format!("fixture-legacy-import-handle-{event_id}"),
    }
}

fn denied() -> tinybus::Error {
    tinybus::Error::failed("native fixture denied")
}
fn audit(sequence: u64) -> AuditCorrelation2 {
    audit_at(sequence, 1)
}
fn audit_at(sequence: u64, generation: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation,
    }
}
fn registration() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "fixture-user".into(),
            workspace: "fixture-workspace".into(),
            agent: "fixture-agent".into(),
        },
        policy_ref: "native-cipher-policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: false,
        auto_approve_all: true,
    }
}
struct Slot {
    identity: SecretCipherDeliveryIdentity2,
    plain: Zeroizing<Vec<u8>>,
    replacement: Option<Zeroizing<Vec<u8>>>,
}
struct State {
    mode: u32,
    module: Mutex<Option<BusName>>,
    store: Arc<Mutex<store::DiskStore>>,
    sink: tinysecurity::audit::JsonlSink,
    target: Mutex<Option<Zeroizing<Vec<u8>>>>,
    slots: Mutex<BTreeMap<u16, Slot>>,
    prompts: Mutex<u32>,
    master_alias: Mutex<Option<String>>,
    pairing_record: Mutex<Option<Vec<u8>>>,
    pairing_revision: Mutex<u64>,
    legacy_device_records: Mutex<Vec<DevicePairingLegacyRecord2>>,
    pairing_pause_load: AtomicBool,
    pairing_load_entered: tokio::sync::Notify,
    pairing_release_load: tokio::sync::Notify,
    pairing_pause_store: AtomicBool,
    pairing_store_entered: tokio::sync::Notify,
    pairing_release_store: tokio::sync::Notify,
    generation: AtomicU64,
}
static CALLBACK_STATE: OnceLock<Arc<State>> = OnceLock::new();
static CALLBACK_READY: OnceLock<tokio::sync::Notify> = OnceLock::new();
static CALLBACK_CONNECTION: OnceLock<Connection> = OnceLock::new();
mod admitted_callbacks {
    async fn setup(connection: tinybus::Connection, _: serde_json::Value) -> tinybus::Result<()> {
        use super::{
            CALLBACK_CONNECTION, CALLBACK_READY, CALLBACK_STATE, Callback, callback_names2, denied,
        };
        let state = CALLBACK_STATE.get().ok_or_else(denied)?.clone();
        for interface in [
            callback_names2::APPROVAL_STORE,
            callback_names2::APPROVAL_PROMPT,
            callback_names2::AUDIT_SINK,
            callback_names2::SECRET_BACKEND,
            callback_names2::SECRET_CIPHER_CONSUMER,
            callback_names2::DEVICE_PAIRING_HOST,
        ] {
            connection
                .serve_at(
                    callback_names2::OBJECT_PATH.parse()?,
                    Callback {
                        state: state.clone(),
                        host: connection.clone(),
                        interface: interface.parse()?,
                    },
                )
                .await?;
        }
        CALLBACK_CONNECTION.set(connection).map_err(|_| denied())?;
        CALLBACK_READY
            .get_or_init(tokio::sync::Notify::new)
            .notify_one();
        Ok(())
    }
    tinybus_module::module_export_static! { setup = setup, config = serde_json::Value,
    worker_threads = 1, provides = ["ai.tinyhumans.tinysecurity.NativeCipherFixture"],
    methods = [], signals = [], requires = [], optional = [], lazy = false, }
}
struct Callback {
    state: Arc<State>,
    host: Connection,
    interface: InterfaceName,
}
#[async_trait]
impl Interface for Callback {
    fn name(&self) -> InterfaceName {
        self.interface.clone()
    }
    fn members(&self) -> Vec<MemberName> {
        let members: &[&str] = match self.interface.as_str() {
            callback_names2::APPROVAL_STORE => &[callback_names2::LOAD, callback_names2::CAS],
            callback_names2::APPROVAL_PROMPT => {
                &[callback_names2::PROMPT, callback_names2::VERIFY_HUMAN]
            }
            callback_names2::SECRET_BACKEND => &[callback_names2::LOAD, callback_names2::SET],
            callback_names2::DEVICE_PAIRING_HOST => &[
                callback_names2::RESOLVE_PAIRING_EVENT,
                callback_names2::PERSIST_DEVICE_PAIRING,
                callback_names2::LOAD_LEGACY_DEVICE_IDENTITIES,
            ],
            callback_names2::AUDIT_SINK => &[callback_names2::APPEND],
            _ => &[callback_names2::DELIVER],
        };
        members.iter().filter_map(|s| s.parse().ok()).collect()
    }
    fn requires_confidential(&self, _: &MemberName) -> bool {
        matches!(
            self.interface.as_str(),
            callback_names2::SECRET_BACKEND
                | callback_names2::SECRET_CIPHER_CONSUMER
                | callback_names2::AUDIT_SINK
                | callback_names2::DEVICE_PAIRING_HOST
        )
    }
    async fn call(
        &self,
        _: &MemberName,
        _: serde_json::Value,
    ) -> tinybus::Result<serde_json::Value> {
        Err(denied())
    }
    async fn call_with_context(
        &self,
        member: &MemberName,
        args: serde_json::Value,
        context: &CallContext,
    ) -> tinybus::Result<serde_json::Value> {
        let module = self
            .state
            .module
            .lock()
            .map_err(|_| denied())?
            .clone()
            .ok_or_else(denied)?;
        if context.authenticated_sender() != Some(&module) {
            return Err(denied());
        }
        if matches!(
            self.interface.as_str(),
            callback_names2::APPROVAL_STORE | callback_names2::APPROVAL_PROMPT
        ) {
            if member.as_str() == callback_names2::PROMPT {
                *self.state.prompts.lock().map_err(|_| denied())? += 1;
            }
            let callback = callback::Callback {
                module,
                host: self.host.clone(),
                interface: self.interface.clone(),
                scope: tinysecurity::approval::scope_handle(&registration().subject)
                    .map_err(|_| denied())?,
                store: self.state.store.clone(),
                reentrant: Arc::new(AtomicBool::new(false)),
                prompt_failure: Arc::new(AtomicBool::new(false)),
            };
            return callback.call_with_context(member, args, context).await;
        }
        match member.as_str() {
            callback_names2::APPEND => self.append(args),
            callback_names2::LOAD => self.load_secret(args),
            callback_names2::SET => self.set_secret(args),
            callback_names2::DELIVER => self.stage(args).await,
            callback_names2::RESOLVE_PAIRING_EVENT => self.resolve_pairing(args),
            callback_names2::PERSIST_DEVICE_PAIRING => {
                let operation =
                    serde_json::from_value::<(DevicePairingPersistenceRequest2,)>(args.clone())
                        .map(|(request,)| request.operation)
                        .ok();
                let should_pause = match &operation {
                    Some(DevicePairingPersistenceOperation2::Load) => {
                        self.state.pairing_pause_load.swap(false, Ordering::AcqRel)
                    }
                    Some(DevicePairingPersistenceOperation2::Store { .. }) => {
                        self.state.pairing_pause_store.swap(false, Ordering::AcqRel)
                    }
                    None => false,
                };
                if should_pause {
                    let (entered, release) = match &operation {
                        Some(DevicePairingPersistenceOperation2::Load) => (
                            &self.state.pairing_load_entered,
                            &self.state.pairing_release_load,
                        ),
                        _ => (
                            &self.state.pairing_store_entered,
                            &self.state.pairing_release_store,
                        ),
                    };
                    entered.notify_one();
                    release.notified().await;
                }
                self.persist_pairing(args)
            }
            callback_names2::LOAD_LEGACY_DEVICE_IDENTITIES => self.load_legacy_pairings(args),
            _ => Err(denied()),
        }
    }
}
impl Callback {
    #[allow(clippy::too_many_lines)] // The fixture's source-to-context table is kept explicit for audit.
    fn resolve_pairing(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (DevicePairingContextRequest2,) = serde_json::from_value(args)?;
        let (source, alias, channel, nonce) =
            match (request.purpose, request.host_event_id.as_str()) {
                (DevicePairingPurpose2::UserController, "user-event") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-1",
                    "fixture-nonce-1",
                ),
                (DevicePairingPurpose2::UserController, "user-event-after-cancel") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-after-cancel",
                    "fixture-nonce-after-cancel",
                ),
                (DevicePairingPurpose2::UserController, "user-event-after-revoke") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-after-revoke",
                    "fixture-nonce-after-revoke",
                ),
                (DevicePairingPurpose2::UserController, "recover-legacy-a") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "legacy-channel-a",
                    "",
                ),
                (DevicePairingPurpose2::UserController, "recover-legacy-b") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "legacy-channel-b",
                    "",
                ),
                (DevicePairingPurpose2::UserController, "recover-lost-confirm") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-after-revoke",
                    "",
                ),
                (DevicePairingPurpose2::LegacyImport, "legacy-import-event") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "",
                    "",
                ),
                (
                    DevicePairingPurpose2::LegacyImport,
                    "legacy-import-agent"
                    | "legacy-import-expired"
                    | "legacy-import-foreign-source"
                    | "legacy-import-corrupt"
                    | "legacy-import-revoked",
                ) => (
                    if request.host_event_id == "legacy-import-agent" {
                        DevicePairingSource2::Agent
                    } else {
                        DevicePairingSource2::AuthenticatedUserController
                    },
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "",
                    "",
                ),
                (DevicePairingPurpose2::UserController, "agent-event") => (
                    DevicePairingSource2::Agent,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-1",
                    "fixture-nonce-1",
                ),
                (DevicePairingPurpose2::UserController, "expired-user-event") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-1",
                    "fixture-nonce-1",
                ),
                (DevicePairingPurpose2::UserController, "foreign-scope-event") => (
                    DevicePairingSource2::AuthenticatedUserController,
                    self.state
                        .master_alias
                        .lock()
                        .map_err(|_| denied())?
                        .clone(),
                    "fixture-channel-1",
                    "fixture-nonce-1",
                ),
                (
                    DevicePairingPurpose2::SocketEvent,
                    "socket-event" | "socket-event-new" | "socket-event-confirm-race",
                ) => {
                    if request.host_event_id == "socket-event-new" {
                        (
                            DevicePairingSource2::RegisteredSocket,
                            None,
                            "fixture-channel-2",
                            "fixture-nonce-2",
                        )
                    } else {
                        (
                            DevicePairingSource2::RegisteredSocket,
                            None,
                            "fixture-channel-1",
                            "fixture-nonce-1",
                        )
                    }
                }
                (DevicePairingPurpose2::SocketEvent, "socket-event-after-revoke") => (
                    DevicePairingSource2::RegisteredSocket,
                    None,
                    "fixture-channel-after-revoke",
                    "fixture-nonce-after-revoke",
                ),
                (DevicePairingPurpose2::Reconnect, "reconnect-event") => (
                    DevicePairingSource2::BackendReconnect,
                    None,
                    "fixture-channel-2",
                    "fixture-nonce-2",
                ),
                (DevicePairingPurpose2::Reconnect, "reconnect-legacy-a") => (
                    DevicePairingSource2::BackendReconnect,
                    None,
                    "legacy-channel-a",
                    "legacy-renewal-nonce-a",
                ),
                (DevicePairingPurpose2::Reconnect, "reconnect-legacy-b") => (
                    DevicePairingSource2::BackendReconnect,
                    None,
                    "legacy-channel-b",
                    "legacy-renewal-nonce-b",
                ),
                (DevicePairingPurpose2::SocketEvent, "legacy-socket-a") => (
                    DevicePairingSource2::RegisteredSocket,
                    None,
                    "legacy-channel-a",
                    "legacy-renewal-nonce-a",
                ),
                (DevicePairingPurpose2::SocketEvent, "legacy-socket-b") => (
                    DevicePairingSource2::RegisteredSocket,
                    None,
                    "legacy-channel-b",
                    "legacy-renewal-nonce-b",
                ),
                (DevicePairingPurpose2::SocketClosed, "socket-close-old") => (
                    DevicePairingSource2::SocketClosed,
                    None,
                    "fixture-channel-1",
                    "fixture-nonce-1",
                ),
                (
                    DevicePairingPurpose2::UserLogout,
                    "logout-event" | "logout-event-confirm-race",
                ) => (
                    DevicePairingSource2::AuthenticatedUserLogout,
                    None,
                    "fixture-channel-1",
                    "fixture-nonce-1",
                ),
                _ => return Err(denied()),
            };
        let legacy_import_handle = if request.purpose == DevicePairingPurpose2::LegacyImport {
            Some(legacy_import_handle(&request.host_event_id))
        } else {
            None
        };
        if request
            .requested_channel_id
            .as_deref()
            .is_some_and(|requested| requested != channel)
        {
            return Err(denied());
        }
        let tokenless_recovery = matches!(
            request.host_event_id.as_str(),
            "recover-legacy-a" | "recover-legacy-b" | "recover-lost-confirm"
        );
        if tokenless_recovery
            && (request.requested_channel_id.as_deref() != Some(channel) || !nonce.is_empty())
        {
            return Err(denied());
        }
        let pairing_token =
            (!channel.is_empty() && !tokenless_recovery).then(|| "fixture-pairing-token".into());
        if tokenless_recovery && pairing_token.is_some() {
            return Err(denied());
        }
        let expires_at_ms = if matches!(
            request.host_event_id.as_str(),
            "expired-user-event" | "legacy-import-expired"
        ) {
            0
        } else {
            u64::MAX
        };
        let scope_id = if request.host_event_id == "foreign-scope-event" {
            "9".repeat(32)
        } else {
            "a".repeat(32)
        };
        serde_json::to_value(DevicePairingContextResponse2 {
            scope_id,
            user_binding: "fixture-user-binding".into(),
            secret_master_handle: alias,
            legacy_import_handle,
            channel_id: channel.into(),
            pairing_token,
            connection_nonce: nonce.into(),
            generation: self.state.generation.load(Ordering::Acquire),
            source,
            expires_at_ms,
        })
        .map_err(Into::into)
    }

    fn load_legacy_pairings(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (DevicePairingLegacyLoadRequest2,) = serde_json::from_value(args)?;
        if request.handle != "fixture-legacy-foreign-source"
            && request.handle != "fixture-legacy-corrupt"
            && !request.handle.starts_with("fixture-legacy-import-handle-")
        {
            return Err(denied());
        }
        let mut records = self
            .state
            .legacy_device_records
            .lock()
            .map_err(|_| denied())?
            .clone();
        if request.handle == "fixture-legacy-corrupt" {
            records.first_mut().ok_or_else(denied)?.ciphertext[0] ^= 1;
        }
        serde_json::to_value(DevicePairingLegacyLoadResponse2 {
            scope_id: "a".repeat(32),
            user_binding: "fixture-user-binding".into(),
            generation: self.state.generation.load(Ordering::Acquire),
            backend_id: if request.handle == "fixture-legacy-foreign-source" {
                "9".repeat(32)
            } else {
                "e".repeat(32)
            },
            source_registration_id: "b".repeat(32),
            records,
        })
        .map_err(Into::into)
    }

    fn persist_pairing(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (DevicePairingPersistenceRequest2,) = serde_json::from_value(args)?;
        if request.backend_id != "c".repeat(32)
            || request.scope_id != "a".repeat(32)
            || request.secret_registration_id != "b".repeat(32)
        {
            return Err(denied());
        }
        let mut revision = self.state.pairing_revision.lock().map_err(|_| denied())?;
        let mut record = self.state.pairing_record.lock().map_err(|_| denied())?;
        let ciphertext = match request.operation {
            DevicePairingPersistenceOperation2::Load => record.clone(),
            DevicePairingPersistenceOperation2::Store {
                expected_revision,
                ciphertext,
            } => {
                if expected_revision != revision.to_string() || ciphertext.is_empty() {
                    return Err(denied());
                }
                *record = Some(ciphertext);
                *revision += 1;
                record.clone()
            }
        };
        serde_json::to_value(DevicePairingPersistenceResponse2 {
            backend_id: request.backend_id,
            scope_id: request.scope_id,
            secret_registration_id: request.secret_registration_id,
            revision: revision.to_string(),
            ciphertext,
        })
        .map_err(Into::into)
    }
    fn append(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (AuditSinkRequest2,) = serde_json::from_value(args)?;
        let phase: serde_json::Value = serde_json::from_str(&request.events[0].arguments_json)?;
        if (self.state.mode == 10 && phase["phase"] == "output-stage")
            || (self.state.mode == 11 && phase["phase"] == "publication")
        {
            return Err(denied());
        }
        serde_json::to_value(self.state.sink.append(&request).map_err(|_| denied())?)
            .map_err(Into::into)
    }
    fn load_secret(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (request,): (SecretBackendLoadRequest2,) = serde_json::from_value(args)?;
        if request.identity.registration_id != "b".repeat(32)
            || request.identity.generation != self.state.generation.load(Ordering::Acquire)
        {
            return Err(denied());
        }
        let mut identity = request.identity;
        let target = self.state.target.lock().map_err(|_| denied())?;
        let encoded = if identity.phase == SecretPhase2::LegacyRead {
            if self.state.mode == 2 && identity.backend_id == "d".repeat(32) {
                Some(Zeroizing::new("AA".repeat(32).into_bytes()))
            } else {
                None
            }
        } else {
            target.clone()
        };
        let mut status = encoded.map_or(SecretBackendLoadStatus2::Absent, |v| {
            SecretBackendLoadStatus2::Present {
                encoded: v.to_vec(),
            }
        });
        if self.state.mode == 3 {
            identity.operation_id.push('x');
        }
        if self.state.mode == 4 {
            status = SecretBackendLoadStatus2::Present {
                encoded: vec![0; 4097],
            };
        }
        if self.state.mode == 5 {
            status = SecretBackendLoadStatus2::Present {
                encoded: b"invalid".to_vec(),
            };
        }
        if self.state.mode == 6 && identity.phase == SecretPhase2::TargetReadback {
            status = SecretBackendLoadStatus2::Present {
                encoded: "AB".repeat(32).into_bytes(),
            };
        }
        serde_json::to_value(SecretBackendLoadResponse2 { identity, status }).map_err(Into::into)
    }
    fn set_secret(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (mut request,): (SecretBackendSetRequest2,) = serde_json::from_value(args)?;
        let encoded = Zeroizing::new(std::mem::take(&mut request.encoded));
        if request.identity.phase != SecretPhase2::TargetSet
            || request.identity.backend_id != "c".repeat(32)
        {
            return Err(denied());
        }
        *self.state.target.lock().map_err(|_| denied())? = Some(encoded);
        serde_json::to_value(SecretBackendSetResponse2 {
            identity: request.identity,
            status: SecretBackendSetStatus2::Stored,
        })
        .map_err(Into::into)
    }
    async fn stage(&self, args: serde_json::Value) -> tinybus::Result<serde_json::Value> {
        let (mut request,): (SecretCipherDeliveryRequest2,) = serde_json::from_value(args)?;
        let plain = Zeroizing::new(std::mem::take(&mut request.plaintext));
        let replacement = request.replacement.take().map(Zeroizing::new);
        let mut identity = request.identity;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| denied())?
                .as_millis(),
        )
        .map_err(|_| denied())?;
        if now >= identity.expires_at_ms
            || identity.consumer_id != "f".repeat(32)
            || identity.registration_id != "b".repeat(32)
            || identity.generation != self.state.generation.load(Ordering::Acquire)
            || identity.slot >= 2
            || plain.len() > 2_097_213
            || replacement.as_ref().is_some_and(|p| p.len() > 2_097_213)
        {
            return Err(denied());
        }
        {
            let mut slots = self.state.slots.lock().map_err(|_| denied())?;
            if slots.contains_key(&identity.slot) {
                return Err(denied());
            }
            slots.insert(
                identity.slot,
                Slot {
                    identity: identity.clone(),
                    plain,
                    replacement,
                },
            );
        }
        if self.state.mode == 7 {
            identity.operation_id.push('x');
        }
        if self.state.mode == 8 {
            identity.output_id.push('x');
        }
        if self.state.mode == 12 {
            std::future::pending::<()>().await;
        }
        serde_json::to_value(SecretCipherDeliveryResponse2 {
            identity,
            staged: self.state.mode != 9,
        })
        .map_err(Into::into)
    }
}
fn make_state(
    root: &Path,
    mode: u32,
) -> std::result::Result<Arc<State>, Box<dyn std::error::Error>> {
    Ok(Arc::new(State {
        mode,
        module: Mutex::new(None),
        store: Arc::new(Mutex::new(store::DiskStore::open(
            &root.join("approvals.journal"),
        )?)),
        sink: tinysecurity::audit::JsonlSink::with_journal_capacity(
            &root.join("audit"),
            1_000_000,
            3,
            4_000_000,
            10000,
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?,
        target: Mutex::new(
            (!matches!(mode, 1 | 2 | 6)).then(|| Zeroizing::new("AA".repeat(32).into_bytes())),
        ),
        slots: Mutex::new(BTreeMap::new()),
        prompts: Mutex::new(0),
        master_alias: Mutex::new(None),
        pairing_record: Mutex::new(None),
        pairing_revision: Mutex::new(0),
        legacy_device_records: Mutex::new(Vec::new()),
        pairing_pause_load: AtomicBool::new(false),
        pairing_load_entered: tokio::sync::Notify::new(),
        pairing_release_load: tokio::sync::Notify::new(),
        pairing_pause_store: AtomicBool::new(false),
        pairing_store_entered: tokio::sync::Notify::new(),
        pairing_release_store: tokio::sync::Notify::new(),
        generation: AtomicU64::new(1),
    }))
}
#[allow(clippy::too_many_lines)] // Mode-specific config makes the native compatibility matrix explicit.
fn configuration(
    host: &Connection,
    mode: u32,
) -> std::result::Result<ModuleConfig, Box<dyn std::error::Error>> {
    let mut approval_registration = registration();
    if mode == 18 {
        approval_registration.require_approval = true;
        approval_registration.auto_approve_all = false;
    }
    let mut config = ModuleConfig {
        trusted_host: host.unique_name().map(|n| n.to_string()),
        approvals: Some(ApprovalConfig2 {
            scopes: vec![approval_registration],
            timeout_ms: 10000,
        }),
        audit: Some(AuditConfig2 {
            scope: registration().subject,
            stream_id: "e".repeat(32),
            timeout_ms: 10000,
            required: true,
            native_path: None,
            max_bytes: 1_000_000,
            max_archives: 3,
            journal_max_bytes: 4_000_000,
            journal_max_events: 10000,
        }),
        secret: Some(SecretConfig2 {
            registrations: vec![SecretRegistration2 {
                registration_id: "b".repeat(32),
                approval_scope_id: "a".repeat(32),
                origin: Origin::Operator,
                purpose: MasterPurpose2::ConfigUserMaster,
                target: SecretBinding2 {
                    backend_id: "c".repeat(32),
                    slot: MasterSlotKind2::User,
                },
                legacy: vec![SecretBinding2 {
                    backend_id: "d".repeat(32),
                    slot: MasterSlotKind2::File,
                }],
            }],
            limits: SecretLimits2 {
                operations_per_minute: 4096,
                ..Default::default()
            },
            callback_timeout_ms: 1000,
        }),
        secret_cipher: Some(SecretCipherConfig2 {
            registration_id: "b".repeat(32),
            consumer_id: "f".repeat(32),
            enabled: mode != 13,
            slots: 2,
            timeout_ms: 1000,
        }),
        device: (mode == 18).then(|| DeviceConfig2 {
            scopes: vec![DeviceScope2 {
                scope_id: "a".repeat(32),
                origin: Origin::Operator,
                static_secret: Some([7; 32]),
            }],
            max_handles: 32,
            max_in_flight: 4,
            operations_per_minute: 4096,
            frames_per_minute: 12_000,
            max_ttl_ms: 300_000,
            max_message_bytes: 1024,
            max_bootstrap_nonces: 64,
        }),
        device_pairing: (mode == 18).then(|| DevicePairingConfig2 {
            scopes: vec![DevicePairingScope2 {
                scope_id: "a".repeat(32),
                secret_registration_id: "b".repeat(32),
                persistence_backend_id: "c".repeat(32),
                legacy_device_backend_id: Some("e".repeat(32)),
                legacy_source_registration_id: Some("b".repeat(32)),
            }],
            runtime_scope: None,
            max_pairings: 32,
            max_pending: 8,
            max_pending_ttl_ms: 300_000,
            max_session_ttl_ms: 604_800_000,
            max_state_bytes: 1_048_576,
            callback_timeout_ms: 10_000,
        }),
        ..Default::default()
    };
    if mode == 17 {
        let secret = config.secret.as_mut().ok_or("native app config")?;
        secret.registrations[0].purpose = MasterPurpose2::AppEncryptionMaster;
        secret.registrations[0].target.slot = MasterSlotKind2::App;
        secret.registrations[0].legacy.clear();
        config.secret_cipher = None;
    }
    if mode == 14 {
        config.contract_version = (1, 10);
        config.secret_cipher = None;
    }
    if mode == 15 {
        config
            .secret_cipher
            .as_mut()
            .ok_or("native cipher config")?
            .consumer_id
            .clear();
    }
    if mode == 16 {
        config
            .secret_cipher
            .as_mut()
            .ok_or("native cipher config")?
            .registration_id = "a".repeat(32);
    }
    Ok(config)
}
async fn acquire_master(
    proxy: &tinybus::Proxy,
    state: &State,
    generation: u64,
    call_id: &str,
    audit_sequence: &mut u64,
) -> tinybus::Result<SecretResponse2> {
    let request = SecretRequest2 {
        registration_id: "b".repeat(32),
        call_id: call_id.into(),
        ttl_ms: 30000,
        operation: if state.mode == 17 {
            SecretOperation2::ResolveAppMaster
        } else {
            SecretOperation2::ResolveConfigMaster
        },
    };
    let row: ApprovalRow2 = proxy
        .call_confidential(
            names::methods::EVALUATE_SECRET2,
            (EvaluateSecretRequest2 {
                request: request.clone(),
                audit: audit_at(*audit_sequence, generation),
            },),
        )
        .await?;
    assert_eq!(row.state, ApprovalLifecycle2::Pending); // permissive policy cannot replace Human Once
    let ticket = state
        .store
        .lock()
        .map_err(|_| denied())?
        .human_action(row.clone(), ApprovalChoice2::Once)?;
    let _: ApprovalRow2 = proxy
        .call(
            names::methods::DECIDE2,
            (DecideRequest2 {
                scope_id: "a".repeat(32),
                request_id: row.request_id.clone(),
                decision_ticket: ticket,
                audit: audit_at(*audit_sequence + 1, generation),
            },),
        )
        .await?;
    let response = proxy
        .call_confidential::<SecretResponse2>(
            names::methods::EXECUTE_SECRET2,
            (ExecuteSecretRequest2 {
                request,
                request_id: row.request_id,
                audit: audit_at(*audit_sequence + 2, generation),
            },),
        )
        .await?;
    *audit_sequence += 3;
    Ok(response)
}
async fn exercise_cipher(
    proxy: &tinybus::Proxy,
    state: &State,
    handle: &str,
) -> std::result::Result<u64, Box<dyn std::error::Error>> {
    let mode = state.mode;
    let mut sequence = 4;
    let mut encrypted = None;
    for (call, operation, input) in [
        (1, SecretCipherKind2::Encrypt, b"private-output".to_vec()),
        (2, SecretCipherKind2::Decrypt, b"private-output".to_vec()),
        (3, SecretCipherKind2::Encrypt, Vec::new()),
    ] {
        if (7..=12).contains(&mode) && call != 2 {
            continue;
        }
        let request = cipher_request(handle, call, operation, input);
        let response = execute(proxy, request, &mut sequence).await;
        if (7..=12).contains(&mode) && (call == 2 || mode == 13) {
            assert!(response.is_err());
            state.slots.lock().map_err(|_| denied())?.clear();
            break;
        }
        let response = response?;
        assert!(!serde_json::to_string(&response)?.contains("private-output"));
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
                let slot = state
                    .slots
                    .lock()
                    .map_err(|_| denied())?
                    .remove(&identity.slot)
                    .ok_or("native slot missing")?;
                assert_eq!(slot.identity, identity);
                assert!(replacement_ciphertext.is_none() && slot.replacement.is_none());
                assert!(slot.plain.as_slice().eq(if call == 3 {
                    &b""[..]
                } else {
                    &b"private-output"[..]
                }));
            }
        }
    }
    if let Some(encrypted) = encrypted
        && !(7..=12).contains(&mode)
    {
        let response = execute(
            proxy,
            cipher_request(
                handle,
                4,
                SecretCipherKind2::Decrypt,
                encrypted.into_bytes(),
            ),
            &mut sequence,
        )
        .await?;
        let SecretCipherResponse2::Delivered { identity, .. } = response else {
            return Err("native decrypt classification".into());
        };
        let slot = state
            .slots
            .lock()
            .map_err(|_| denied())?
            .remove(&identity.slot)
            .ok_or("native decrypt slot")?;
        assert_eq!(slot.identity, identity);
        assert!(slot.plain.as_slice().eq(b"private-output"));
    }
    exercise_migration(proxy, state, handle, &mut sequence).await?;
    Ok(sequence)
}

#[allow(clippy::too_many_lines)] // One real bus flow proves the composed lifecycle and protocol.
async fn device_pairing_roundtrip(
    lifecycle: &ModuleHost,
    module_name: &str,
    configuration: &ModuleConfig,
    proxy: &tinybus::Proxy,
    state: &State,
    master_alias: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity::crypto::device::{KeyPair, PublicKey, Role, Tunnel};
    use tinysecurity_bus::{
        DeviceFrameOperation2, DeviceFrameRequest2, DeviceFrameResponse2, DevicePairingOperation2,
        DevicePairingRequest2, DevicePairingResponse2,
    };
    let call = |call_id: &str, operation| DevicePairingRequest2 {
        call_id: call_id.into(),
        operation,
    };
    for (call_id, event_id) in [
        ("pair-unlock-agent-denied", "agent-event"),
        ("pair-unlock-expired-denied", "expired-user-event"),
        ("pair-unlock-foreign-scope-denied", "foreign-scope-event"),
        ("pair-unlock-unknown-event-denied", "foreign-user-event"),
    ] {
        assert!(
            proxy
                .call_confidential::<DevicePairingResponse2>(
                    names::methods::DEVICE_PAIRING2,
                    (call(
                        call_id,
                        DevicePairingOperation2::Unlock {
                            host_event_id: event_id.into(),
                        },
                    ),),
                )
                .await
                .is_err(),
            "untrusted, expired, and unknown controller events must not unlock"
        );
    }
    // Pause the first encrypted-state load while logout removes the not-yet-published
    // owner. The unlock must fail after the callback resumes instead of resurrecting
    // a loaded identity after logout has returned.
    state.pairing_pause_load.store(true, Ordering::Release);
    let unlock_proxy = proxy.clone();
    let unlock_call = call(
        "pair-unlock-racing-logout",
        DevicePairingOperation2::Unlock {
            host_event_id: "user-event".into(),
        },
    );
    let racing_unlock = tokio::spawn(async move {
        unlock_proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (unlock_call,),
            )
            .await
    });
    state.pairing_load_entered.notified().await;
    proxy
        .call_confidential::<DevicePairingResponse2>(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-lock-before-first-load-publishes",
                DevicePairingOperation2::Lock {
                    host_event_id: "logout-event".into(),
                },
            ),),
        )
        .await
        .map_err(|error| format!("logout lock during unlock race failed: {error}"))?;
    state.pairing_release_load.notify_one();
    assert!(
        racing_unlock.await?.is_err(),
        "logout fences an in-flight unlock"
    );

    let unlock: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-unlock",
                DevicePairingOperation2::Unlock {
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await
        .map_err(|error| format!("unlock after logout race failed: {error}"))?;
    let initial_public = unlock.core_public_key.ok_or("pairing public identity")?;
    let legacy_secrets = [[0x31; 32], [0x32; 32]];
    let legacy_devices = [KeyPair::generate()?, KeyPair::generate()?];
    let mut cipher_sequence = 4;
    let mut legacy_records = Vec::new();
    for (index, (secret, device)) in legacy_secrets.iter().zip(&legacy_devices).enumerate() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, secret);
        let response = execute(
            proxy,
            cipher_request(
                master_alias,
                200 + index as u64,
                SecretCipherKind2::Encrypt,
                encoded.into_bytes(),
            ),
            &mut cipher_sequence,
        )
        .await?;
        let SecretCipherResponse2::Ciphertext { ciphertext } = response else {
            return Err("legacy key ciphertext".into());
        };
        legacy_records.push(DevicePairingLegacyRecord2 {
            channel_id: format!("legacy-channel-{}", if index == 0 { "a" } else { "b" }),
            device_public_key: device.public_key().encode(),
            format: DevicePairingLegacyFormat2::Enc2,
            ciphertext: ciphertext.into_bytes(),
            revoked: false,
        });
    }
    *state.legacy_device_records.lock().map_err(|_| denied())? = legacy_records;
    state
        .legacy_device_records
        .lock()
        .map_err(|_| denied())?
        .first_mut()
        .ok_or("legacy fixture record")?
        .revoked = true;
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-legacy-revoked-row-denied",
                    DevicePairingOperation2::ImportLegacy {
                        host_event_id: "legacy-import-revoked".into(),
                    },
                ),),
            )
            .await
            .is_err(),
        "revoked legacy metadata is not imported"
    );
    state
        .legacy_device_records
        .lock()
        .map_err(|_| denied())?
        .first_mut()
        .ok_or("legacy fixture record")?
        .revoked = false;
    for (index, event) in [
        "legacy-import-agent",
        "legacy-import-expired",
        "legacy-import-foreign-source",
        "legacy-import-corrupt",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            proxy
                .call_confidential::<DevicePairingResponse2>(
                    names::methods::DEVICE_PAIRING2,
                    (call(
                        &format!("pair-legacy-denied-{index}"),
                        DevicePairingOperation2::ImportLegacy {
                            host_event_id: event.into(),
                        },
                    ),),
                )
                .await
                .is_err(),
            "untrusted, expired, foreign-source and corrupted legacy imports fail closed"
        );
    }
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-import-legacy-identities",
                DevicePairingOperation2::ImportLegacy {
                    host_event_id: "legacy-import-event".into(),
                },
            ),),
        )
        .await?;
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-recover-foreign-channel-denied",
                    DevicePairingOperation2::Recover {
                        channel_id: "legacy-channel-a".into(),
                        host_event_id: "recover-legacy-b".into(),
                    },
                ),),
            )
            .await
            .is_err(),
        "a host event authorizing another channel cannot recover this pairing"
    );
    let mut legacy_pairing_ids = Vec::new();
    for (index, secret) in legacy_secrets.iter().enumerate() {
        let channel = format!("legacy-channel-{}", if index == 0 { "a" } else { "b" });
        let event = format!("recover-legacy-{}", if index == 0 { "a" } else { "b" });
        let recovered: DevicePairingResponse2 = proxy
            .call_confidential(
                names::methods::DEVICE_PAIRING2,
                (call(
                    &format!("pair-recover-legacy-{index}"),
                    DevicePairingOperation2::Recover {
                        channel_id: channel,
                        host_event_id: event,
                    },
                ),),
            )
            .await
            .map_err(|error| format!("legacy channel Recover {index} failed: {error}"))?;
        let expected = KeyPair::from_secret(Zeroizing::new(*secret))?
            .public_key()
            .encode();
        assert_eq!(
            recovered.core_public_key.as_deref(),
            Some(expected.as_str())
        );
        let expected_device = legacy_devices[index].public_key().encode();
        assert_eq!(
            recovered.device_public_key.as_deref(),
            Some(expected_device.as_str())
        );
        legacy_pairing_ids.push(recovered.pairing_id.ok_or("legacy pairing id")?);
    }
    for (index, pairing_id) in legacy_pairing_ids.iter().enumerate() {
        let suffix = if index == 0 { "a" } else { "b" };
        let expected_core = KeyPair::from_secret(Zeroizing::new(legacy_secrets[index]))?
            .public_key()
            .encode();
        let renewed: DevicePairingResponse2 = proxy
            .call_confidential(
                names::methods::DEVICE_PAIRING2,
                (call(
                    &format!("pair-renew-legacy-{suffix}"),
                    DevicePairingOperation2::Renew {
                        pairing_id: pairing_id.clone(),
                        host_event_id: format!("reconnect-legacy-{suffix}"),
                    },
                ),),
            )
            .await?;
        assert_eq!(
            renewed.core_public_key.as_deref(),
            Some(expected_core.as_str())
        );
        let receipt = renewed.receipt.ok_or("legacy renewal receipt")?;
        let core = PublicKey::decode(&expected_core)?;
        let bootstrap = KeyPair::generate()?;
        let session_ephemeral = KeyPair::generate()?;
        let device = &legacy_devices[index];
        let payload = serde_json::to_vec(&serde_json::json!({
            "device_pubkey": device.public_key().encode(),
            "client_ephemeral_pubkey": session_ephemeral.public_key().encode(),
        }))?;
        let frame = bootstrap.seal_handshake(core, &payload)?;
        let socket_event = format!("legacy-socket-{suffix}");
        let ack: DevicePairingResponse2 = proxy
            .call_confidential(
                names::methods::DEVICE_PAIRING2,
                (call(
                    &format!("pair-renew-handshake-{suffix}"),
                    DevicePairingOperation2::Handshake {
                        receipt: receipt.clone(),
                        host_event_id: socket_event.clone(),
                        frame,
                    },
                ),),
            )
            .await?;
        let ack_payload: serde_json::Value =
            serde_json::from_slice(&session_ephemeral.open_ack(core, &ack.frame)?)?;
        let server_ephemeral = PublicKey::decode(
            ack_payload["server_ephemeral_pubkey"]
                .as_str()
                .ok_or("legacy renewal server ephemeral")?,
        )?;
        let keys = device.session_keys(
            core,
            &session_ephemeral,
            server_ephemeral,
            session_ephemeral.public_key(),
            server_ephemeral,
        )?;
        let client_tunnel = Tunnel::new(Role::Client, keys);
        let proof = client_tunnel.seal(b"legacy same-key renewal proof")?;
        let confirmed: DevicePairingResponse2 = proxy
            .call_confidential(
                names::methods::DEVICE_PAIRING2,
                (call(
                    &format!("pair-renew-confirm-{suffix}"),
                    DevicePairingOperation2::Confirm {
                        receipt,
                        host_event_id: socket_event,
                        frame: proof,
                    },
                ),),
            )
            .await?;
        assert_eq!(confirmed.pairing_id.as_deref(), Some(pairing_id.as_str()));
        assert_eq!(
            confirmed.device_public_key.as_deref(),
            Some(device.public_key().encode().as_str())
        );
    }
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-revoke-legacy-import",
                DevicePairingOperation2::Revoke {
                    pairing_id: legacy_pairing_ids[0].clone(),
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-lock-before-stale-import",
                DevicePairingOperation2::Lock {
                    host_event_id: "logout-event".into(),
                },
            ),),
        )
        .await?;
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-unlock-before-stale-import",
                DevicePairingOperation2::Unlock {
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-deny-revoked-legacy-reimport",
                    DevicePairingOperation2::ImportLegacy {
                        host_event_id: "legacy-import-event".into(),
                    },
                ),),
            )
            .await
            .is_err(),
        "module tombstones prevent stale legacy metadata from reviving a revoked channel"
    );
    let reloaded_legacy: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-recover-legacy-after-reload",
                DevicePairingOperation2::Recover {
                    channel_id: "legacy-channel-b".into(),
                    host_event_id: "recover-legacy-b".into(),
                },
            ),),
        )
        .await
        .map_err(|error| format!("reloaded legacy Recover failed: {error}"))?;
    let expected_legacy = KeyPair::from_secret(Zeroizing::new(legacy_secrets[1]))?
        .public_key()
        .encode();
    assert_eq!(
        reloaded_legacy.core_public_key.as_deref(),
        Some(expected_legacy.as_str()),
        "the second channel retains its distinct core identity after module reload"
    );
    let begin: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-begin",
                DevicePairingOperation2::Begin {
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    assert_eq!(
        begin.core_public_key.as_deref(),
        Some(initial_public.as_str())
    );
    let receipt = begin.receipt.ok_or("pairing receipt")?;
    let core = PublicKey::decode(&initial_public)?;
    let device_static = KeyPair::generate()?;
    let bootstrap = KeyPair::generate()?;
    let session_ephemeral = KeyPair::generate()?;
    let handshake_payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": device_static.public_key().encode(),
        "client_ephemeral_pubkey": session_ephemeral.public_key().encode(),
    }))?;
    let handshake = bootstrap.seal_handshake(core, &handshake_payload)?;
    let response: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-handshake",
                DevicePairingOperation2::Handshake {
                    receipt: receipt.clone(),
                    host_event_id: "socket-event".into(),
                    frame: handshake,
                },
            ),),
        )
        .await?;
    let ack: serde_json::Value =
        serde_json::from_slice(&session_ephemeral.open_ack(core, &response.frame)?)?;
    let server_ephemeral = PublicKey::decode(
        ack["server_ephemeral_pubkey"]
            .as_str()
            .ok_or("ack server ephemeral")?,
    )?;
    let keys = device_static.session_keys(
        core,
        &session_ephemeral,
        server_ephemeral,
        session_ephemeral.public_key(),
        server_ephemeral,
    )?;
    let mut device_tunnel = Tunnel::new(Role::Client, keys);
    let proof = device_tunnel.seal(b"static-device-possession")?;
    let confirmed: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-confirm",
                DevicePairingOperation2::Confirm {
                    receipt: receipt.clone(),
                    host_event_id: "socket-event".into(),
                    frame: proof.clone(),
                },
            ),),
        )
        .await?;
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-confirm-replay",
                    DevicePairingOperation2::Confirm {
                        receipt,
                        host_event_id: "socket-event".into(),
                        frame: proof,
                    },
                ),),
            )
            .await
            .is_err(),
        "a confirmed receipt must not be reusable"
    );
    let pairing_id = confirmed.pairing_id.ok_or("confirmed pairing id")?;
    let session_id = confirmed.session_id.ok_or("confirmed session handle")?;
    let sealed: DeviceFrameResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_FRAME2,
            (DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: session_id.clone(),
                call_id: "pair-frame-seal".into(),
                operation: DeviceFrameOperation2::Seal {
                    plaintext: b"paired-frame-secret".to_vec(),
                },
            },),
        )
        .await?;
    assert_eq!(&*device_tunnel.open(&sealed.bytes)?, b"paired-frame-secret");
    let incoming = device_tunnel.seal(b"reply")?;
    let opened: DeviceFrameResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_FRAME2,
            (DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: session_id.clone(),
                call_id: "pair-frame-open".into(),
                operation: DeviceFrameOperation2::Open {
                    frame: incoming.clone(),
                },
            },),
        )
        .await?;
    assert_eq!(opened.bytes, b"reply");
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "a".repeat(32),
                    handle: session_id.clone(),
                    call_id: "pair-frame-replay".into(),
                    operation: DeviceFrameOperation2::Open { frame: incoming }
                },)
            )
            .await
            .is_err()
    );

    let refreshed: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-refresh",
                DevicePairingOperation2::RefreshSession {
                    session_id: session_id.clone(),
                    host_event_id: "socket-event".into(),
                },
            ),),
        )
        .await?;
    assert_eq!(refreshed.session_id.as_deref(), Some(session_id.as_str()));

    let renewed: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-renew",
                DevicePairingOperation2::Renew {
                    pairing_id: pairing_id.clone(),
                    host_event_id: "reconnect-event".into(),
                },
            ),),
        )
        .await?;
    let renewal_receipt = renewed.receipt.ok_or("renewal receipt")?;
    let impostor = KeyPair::generate()?;
    let wrong_ephemeral = KeyPair::generate()?;
    let wrong_session = KeyPair::generate()?;
    let wrong_payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": impostor.public_key().encode(),
        "client_ephemeral_pubkey": wrong_session.public_key().encode(),
    }))?;
    let wrong_handshake = wrong_ephemeral.seal_handshake(core, &wrong_payload)?;
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-renew-wrong-key",
                    DevicePairingOperation2::Handshake {
                        receipt: renewal_receipt.clone(),
                        host_event_id: "socket-event-new".into(),
                        frame: wrong_handshake,
                    },
                ),),
            )
            .await
            .is_err(),
        "renewal must reject a different static device key"
    );
    let new_bootstrap = KeyPair::generate()?;
    let new_session_ephemeral = KeyPair::generate()?;
    let new_payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": device_static.public_key().encode(),
        "client_ephemeral_pubkey": new_session_ephemeral.public_key().encode(),
    }))?;
    let new_handshake = new_bootstrap.seal_handshake(core, &new_payload)?;
    let new_ack: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-renew-handshake",
                DevicePairingOperation2::Handshake {
                    receipt: renewal_receipt.clone(),
                    host_event_id: "socket-event-new".into(),
                    frame: new_handshake,
                },
            ),),
        )
        .await?;
    let ack: serde_json::Value =
        serde_json::from_slice(&new_session_ephemeral.open_ack(core, &new_ack.frame)?)?;
    let server_ephemeral = PublicKey::decode(
        ack["server_ephemeral_pubkey"]
            .as_str()
            .ok_or("renew ack ephemeral")?,
    )?;
    let keys = device_static.session_keys(
        core,
        &new_session_ephemeral,
        server_ephemeral,
        new_session_ephemeral.public_key(),
        server_ephemeral,
    )?;
    let mut renewed_tunnel = Tunnel::new(Role::Client, keys);
    let renewed_proof = renewed_tunnel.seal(b"same-static-key-renewal")?;
    let result: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-renew-confirm",
                DevicePairingOperation2::Confirm {
                    receipt: renewal_receipt,
                    host_event_id: "socket-event-new".into(),
                    frame: renewed_proof,
                },
            ),),
        )
        .await?;
    let new_session = result.session_id.ok_or("renewed session")?;
    assert_eq!(result.pairing_id.as_deref(), Some(pairing_id.as_str()));
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "a".repeat(32),
                    handle: session_id.clone(),
                    call_id: "pair-old-session-retired".into(),
                    operation: DeviceFrameOperation2::Seal { plaintext: vec![1] }
                },)
            )
            .await
            .is_err()
    );
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-stale-close",
                    DevicePairingOperation2::EndSession {
                        session_id: session_id.clone(),
                        host_event_id: "socket-close-old".into()
                    }
                ),)
            )
            .await
            .is_err()
    );
    let still_live: DeviceFrameResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_FRAME2,
            (DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: new_session.clone(),
                call_id: "pair-new-session-live".into(),
                operation: DeviceFrameOperation2::Seal {
                    plaintext: b"still-live".to_vec(),
                },
            },),
        )
        .await?;
    assert_eq!(&*renewed_tunnel.open(&still_live.bytes)?, b"still-live");

    let mut reinit = configuration.clone();
    for scope in &mut reinit
        .device
        .as_mut()
        .ok_or("pairing device config")?
        .scopes
    {
        scope.static_secret = None;
    }
    lifecycle
        .reinitialize(module_name, serde_json::to_value(&reinit)?)
        .await?;
    state.generation.store(2, Ordering::Release);
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 2);
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "a".repeat(32),
                    handle: new_session.clone(),
                    call_id: "pair-frame-after-reinit".into(),
                    operation: DeviceFrameOperation2::Seal { plaintext: vec![1] },
                },),
            )
            .await
            .is_err()
    );
    let resolved = acquire_master(
        proxy,
        state,
        2,
        "native-master-after-reinit",
        &mut cipher_sequence,
    )
    .await?;
    let SecretResponse2::MasterHandle { handle, .. } = resolved;
    *state.master_alias.lock().map_err(|_| denied())? = Some(handle);
    let unlocked: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-unlock-after-reinit",
                DevicePairingOperation2::Unlock {
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    assert_eq!(
        unlocked.core_public_key.as_deref(),
        Some(initial_public.as_str())
    );
    let recovered_after_reinit: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-recover-channel-after-module-reinit",
                DevicePairingOperation2::Recover {
                    channel_id: "legacy-channel-b".into(),
                    host_event_id: "recover-legacy-b".into(),
                },
            ),),
        )
        .await?;
    let expected_legacy_after_reinit = KeyPair::from_secret(Zeroizing::new([0x32; 32]))?
        .public_key()
        .encode();
    assert_eq!(
        recovered_after_reinit.core_public_key.as_deref(),
        Some(expected_legacy_after_reinit.as_str()),
        "legacy channel identity survives module generation reinitialization"
    );
    let before = *state.prompts.lock().map_err(|_| denied())?;
    assert_eq!(before, 2, "only the explicit Secret2 unlocks prompt");
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-revoke",
                DevicePairingOperation2::Revoke {
                    pairing_id: pairing_id.clone(),
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "a".repeat(32),
                    handle: new_session,
                    call_id: "pair-frame-after-revoke".into(),
                    operation: DeviceFrameOperation2::Seal { plaintext: vec![1] }
                },)
            )
            .await
            .is_err()
    );
    let retry_begin: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-begin-confirm-logout-race",
                DevicePairingOperation2::Begin {
                    host_event_id: "user-event-after-revoke".into(),
                },
            ),),
        )
        .await?;
    let retry_receipt = retry_begin.receipt.ok_or("retry pairing receipt")?;
    let retry_core = PublicKey::decode(
        retry_begin
            .core_public_key
            .as_deref()
            .ok_or("retry core public key")?,
    )?;
    let retry_session = KeyPair::generate()?;
    let retry_bootstrap = KeyPair::generate()?;
    let retry_payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": device_static.public_key().encode(),
        "client_ephemeral_pubkey": retry_session.public_key().encode(),
    }))?;
    let retry_handshake: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-handshake-confirm-logout-race",
                DevicePairingOperation2::Handshake {
                    receipt: retry_receipt.clone(),
                    host_event_id: "socket-event-after-revoke".into(),
                    frame: retry_bootstrap.seal_handshake(retry_core, &retry_payload)?,
                },
            ),),
        )
        .await?;
    let retry_ack: serde_json::Value =
        serde_json::from_slice(&retry_session.open_ack(retry_core, &retry_handshake.frame)?)?;
    let retry_server_ephemeral = PublicKey::decode(
        retry_ack["server_ephemeral_pubkey"]
            .as_str()
            .ok_or("retry server ephemeral")?,
    )?;
    let retry_keys = device_static.session_keys(
        retry_core,
        &retry_session,
        retry_server_ephemeral,
        retry_session.public_key(),
        retry_server_ephemeral,
    )?;
    let retry_tunnel = Tunnel::new(Role::Client, retry_keys);
    let retry_proof = retry_tunnel.seal(b"logout wins confirmation publication")?;
    state.pairing_pause_store.store(true, Ordering::Release);
    let confirm_proxy = proxy.clone();
    let confirm_receipt = retry_receipt.clone();
    let racing_confirm = tokio::spawn(async move {
        confirm_proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-confirm-racing-logout",
                    DevicePairingOperation2::Confirm {
                        receipt: confirm_receipt,
                        host_event_id: "socket-event-after-revoke".into(),
                        frame: retry_proof,
                    },
                ),),
            )
            .await
    });
    state.pairing_store_entered.notified().await;
    let logout_proxy = proxy.clone();
    let mut racing_logout = tokio::spawn(async move {
        logout_proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-logout-racing-confirm",
                    DevicePairingOperation2::Lock {
                        host_event_id: "logout-event".into(),
                    },
                ),),
            )
            .await
    });
    let second_logout_proxy = proxy.clone();
    let mut second_logout = tokio::spawn(async move {
        second_logout_proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-logout-confirm-race-fence",
                    DevicePairingOperation2::Lock {
                        host_event_id: "logout-event-confirm-race".into(),
                    },
                ),),
            )
            .await
    });
    let logout_a_finished = tokio::select! {
        result = &mut racing_logout => { result??; true },
        result = &mut second_logout => { result??; false },
    };
    state.pairing_release_store.notify_one();
    assert!(
        racing_confirm.await?.is_err(),
        "logout fences confirmation publication after persistence"
    );
    if logout_a_finished {
        second_logout.await??;
    } else {
        racing_logout.await??;
    }
    assert!(
        state
            .pairing_record
            .lock()
            .map_err(|_| denied())?
            .as_ref()
            .is_some_and(|ciphertext| !String::from_utf8_lossy(ciphertext).contains("device_key"))
    );
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-lock-for-corrupt-state-check",
                DevicePairingOperation2::Lock {
                    host_event_id: "logout-event".into(),
                },
            ),),
        )
        .await?;
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-unlock-before-recovering-lost-confirm",
                DevicePairingOperation2::Unlock {
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    let orphan = proxy
        .call_confidential::<DevicePairingResponse2>(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-recover-lost-confirm-response",
                DevicePairingOperation2::Recover {
                    channel_id: "fixture-channel-after-revoke".into(),
                    host_event_id: "recover-lost-confirm".into(),
                },
            ),),
        )
        .await
        .map_err(|error| format!("lost-confirm Recover failed: {error}"))?;
    assert!(orphan.pairing_id.is_some());
    assert!(orphan.device_public_key.is_some());
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-revoke-recovered-lost-confirm",
                DevicePairingOperation2::Revoke {
                    pairing_id: orphan.pairing_id.ok_or("recovered pairing id")?,
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    let _: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-lock-after-recovered-lost-confirm",
                DevicePairingOperation2::Lock {
                    host_event_id: "logout-event".into(),
                },
            ),),
        )
        .await?;
    let persisted_pairing_state = state
        .pairing_record
        .lock()
        .map_err(|_| denied())?
        .clone()
        .ok_or("encrypted pairing record")?;
    state
        .pairing_record
        .lock()
        .map_err(|_| denied())?
        .as_mut()
        .ok_or("encrypted pairing record")?[0] ^= 1;
    assert!(
        proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (call(
                    "pair-unlock-corrupt-state-denied",
                    DevicePairingOperation2::Unlock {
                        host_event_id: "user-event".into(),
                    },
                ),),
            )
            .await
            .is_err(),
        "corrupted ciphertext must never load an identity"
    );
    assert_eq!(*state.prompts.lock().map_err(|_| denied())?, before);

    // Reinitialize after the trusted persistence callback has loaded the
    // ciphertext but before the loaded scope can be published.
    *state.pairing_record.lock().map_err(|_| denied())? = Some(persisted_pairing_state);
    state.pairing_pause_load.store(true, Ordering::Release);
    let unlock_proxy = proxy.clone();
    let unlock_call = call(
        "pair-unlock-racing-reinitialize",
        DevicePairingOperation2::Unlock {
            host_event_id: "user-event".into(),
        },
    );
    let racing_unlock = tokio::spawn(async move {
        unlock_proxy
            .call_confidential::<DevicePairingResponse2>(
                names::methods::DEVICE_PAIRING2,
                (unlock_call,),
            )
            .await
    });
    state.pairing_load_entered.notified().await;
    let mut reinit = configuration.clone();
    for scope in &mut reinit
        .device
        .as_mut()
        .ok_or("pairing device config")?
        .scopes
    {
        scope.static_secret = None;
    }
    lifecycle
        .reinitialize(module_name, serde_json::to_value(&reinit)?)
        .await?;
    state.generation.store(3, Ordering::Release);
    state.pairing_release_load.notify_one();
    assert!(
        racing_unlock.await?.is_err(),
        "reinitialization fences an in-flight unlock"
    );
    let resolved = acquire_master(
        proxy,
        state,
        3,
        "native-master-after-pending-load-reinit",
        &mut cipher_sequence,
    )
    .await?;
    let SecretResponse2::MasterHandle { handle, .. } = resolved;
    *state.master_alias.lock().map_err(|_| denied())? = Some(handle);
    let unlocked: DevicePairingResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_PAIRING2,
            (call(
                "pair-unlock-after-pending-load-reinit",
                DevicePairingOperation2::Unlock {
                    host_event_id: "user-event".into(),
                },
            ),),
        )
        .await?;
    assert_eq!(
        unlocked.core_public_key.as_deref(),
        Some(initial_public.as_str()),
        "a fresh approved alias recovers the same persisted module identity"
    );

    Ok(())
}
async fn exercise_migration(
    proxy: &tinybus::Proxy,
    state: &State,
    handle: &str,
    sequence: &mut u64,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if matches!(state.mode, 0 | 13) {
        for (call, stored) in [
            (5, b"enc:dad8c3dccbdecf87c5dfdedadfde".as_slice()),
            (6, b"enc:DAD8C3DCCBDECF87C5DFDEDADFDE".as_slice()),
        ] {
            let response = execute(
                proxy,
                cipher_request(
                    handle,
                    call,
                    SecretCipherKind2::DecryptAndMigrate,
                    stored.to_vec(),
                ),
                sequence,
            )
            .await?;
            let SecretCipherResponse2::Delivered {
                identity,
                migrated,
                replacement_ciphertext,
            } = response
            else {
                return Err("native migration classification".into());
            };
            let slot = state
                .slots
                .lock()
                .map_err(|_| denied())?
                .remove(&identity.slot)
                .ok_or("native migration slot")?;
            assert!(slot.identity == identity && migrated);
            assert!(slot.plain.as_slice().eq(b"private-output"));
            let replacement = slot.replacement.ok_or("native migration replacement")?;
            if state.mode == 0 {
                let ciphertext =
                    replacement_ciphertext.ok_or("native public migration ciphertext")?;
                assert!(
                    ciphertext.starts_with("enc2:")
                        && replacement.as_slice().eq(ciphertext.as_bytes())
                );
            } else {
                assert!(
                    replacement_ciphertext.is_none()
                        && replacement.as_slice().eq(b"private-output")
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "fixture_tests.rs"]
mod tests;
async fn reject_wrong_peer(bus: &MemoryBus, module: &BusName, handle: &str) -> tinybus::Result<()> {
    let attacker = Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .with_timeout(Duration::from_millis(100))
            .call_confidential::<SecretCipherPending2>(
                names::methods::EVALUATE_SECRET_CIPHER2,
                (EvaluateSecretCipherRequest2 {
                    request: cipher_request(
                        handle,
                        99,
                        SecretCipherKind2::Decrypt,
                        b"private-output".to_vec()
                    ),
                    audit: audit(99)
                },)
            )
            .await
            .is_err()
    );
    Ok(())
}
async fn start_callbacks(
    lifecycle: &ModuleHost,
    state: &Arc<State>,
) -> tinybus::Result<Connection> {
    CALLBACK_STATE.set(state.clone()).map_err(|_| denied())?;
    let mut callbacks = admitted_callbacks::linked_module()?;
    // Both exports originate in this package; give the host-trusted linked
    // fixture its own descriptor/manifest identity before ordinary admission.
    callbacks.manifest.module.name = "tinysec-native-cipher-fixture".into();
    callbacks.descriptor = tinybus::module::abi::TbAbiDescriptor::current(
        "tinysec-native-cipher-fixture",
        env!("CARGO_PKG_VERSION"),
    );
    lifecycle.attach_linked_with_config(callbacks, serde_json::json!({}))?;
    CALLBACK_READY
        .get_or_init(tokio::sync::Notify::new)
        .notified()
        .await;
    let host = CALLBACK_CONNECTION.get().ok_or_else(denied)?.clone();
    Ok(host)
}
async fn generation_boundary(
    lifecycle: &ModuleHost,
    name: &str,
    configuration: &ModuleConfig,
    proxy: &tinybus::Proxy,
    handle: &str,
    sequence: u64,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Use the actual tail left by all successful routine calls.
    let pending: SecretCipherPending2 = proxy
        .call_confidential(
            names::methods::EVALUATE_SECRET_CIPHER2,
            (EvaluateSecretCipherRequest2 {
                request: cipher_request(
                    handle,
                    80,
                    SecretCipherKind2::Decrypt,
                    b"private-output".to_vec(),
                ),
                audit: audit(sequence),
            },),
        )
        .await?;
    lifecycle
        .reinitialize(name, serde_json::to_value(configuration)?)
        .await?;
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 2);
    assert!(
        proxy
            .call_confidential::<SecretCipherResponse2>(
                names::methods::EXECUTE_SECRET_CIPHER2,
                (ExecuteSecretCipherRequest2 {
                    request: cipher_request(
                        handle,
                        80,
                        SecretCipherKind2::Decrypt,
                        b"private-output".to_vec()
                    ),
                    pending_id: pending.pending_id,
                    audit: audit(sequence + 1),
                    delivery_audit: audit(sequence + 2),
                    completion_audit: audit(sequence + 3)
                },)
            )
            .await
            .is_err()
    );
    let mut omitted = configuration.clone();
    omitted.secret = None;
    omitted.secret_cipher = None;
    lifecycle
        .reinitialize(name, serde_json::to_value(omitted)?)
        .await?;
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 3);
    Ok(())
}
async fn reject_invalid_config(
    lifecycle: &ModuleHost,
    host: &Connection,
    loaded: tinybus::Result<tinybus::module::ModuleInfo>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if let Ok(info) = loaded {
        assert!(
            host.proxy(
                info.manifest.bus_name.as_str(),
                names::OBJECT_PATH,
                names::INTERFACE
            )?
            .with_timeout(Duration::from_secs(5))
            .call::<PolicyInfo>(names::methods::POLICY_INFO, ())
            .await
            .is_err()
        );
        // Asynchronous adapter setup errors do not report SDK Failed here.
        // The relevant boundary is that invalid authority never serves.
        assert!(lifecycle.list().iter().all(|current| {
            current.name != info.name
                || !matches!(
                    current.state,
                    tinybus::module::ModuleState::Ready | tinybus::module::ModuleState::Serving
                )
        }));
    }
    Ok(())
}
#[allow(clippy::too_many_lines)] // Retains the existing native contract modes beside the new mode.
pub(super) async fn run(
    library: &Path,
    mode: u32,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let hash = tinybus::module::sha256_file(library)?;
    let name = library
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("native fixture filename")?;
    std::fs::write(
        library
            .parent()
            .ok_or("native fixture parent")?
            .join("modules.toml"),
        format!("\"{name}\" = \"{hash}\"\n"),
    )?;
    let (_directory, root) = super::namespace::create()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let state = make_state(&root, mode)?;
    // A confidential destination must itself be SDK-admitted. Register a fixed
    // trusted native callback module before loading the real TinySecurity cdylib.
    // Ordinary unattested host connections remain denied by the broker.
    let host = start_callbacks(&lifecycle, &state).await?;
    let config = configuration(&host, mode)?;
    let loaded = lifecycle.load_file_with_config(library, serde_json::to_value(&config)?);
    if matches!(mode, 15 | 16) {
        reject_invalid_config(&lifecycle, &host, loaded).await?;
        task.abort();
        return Ok(());
    }
    let loaded =
        loaded.map_err(|error| format!("native module load failed in mode {mode}: {error}"))?;
    let module = host
        .name_owner(loaded.manifest.bus_name.as_str())
        .await?
        .ok_or("native module peer")?;
    *state.module.lock().map_err(|_| denied())? = Some(module.clone());
    let proxy = host
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        // Let the module's own callback deadline settle pending work. In
        // particular, the duplicate-execution assertion below must observe the
        // module's replay rejection rather than another client-side timeout.
        .with_timeout(Duration::from_secs(35));
    assert!(proxy.attestation().await?.is_some());
    if mode == 18 {
        let _: PolicyInfo = proxy
            .call(names::methods::POLICY_INFO, ())
            .await
            .map_err(|error| format!("device pairing module readiness failed: {error}"))?;
    }
    let mut audit_sequence = 1;
    let resolved = acquire_master(&proxy, &state, 1, "native-master", &mut audit_sequence).await;
    if (3..=6).contains(&mode) {
        assert!(resolved.is_err());
        task.abort();
        return Ok(());
    }
    let SecretResponse2::MasterHandle { handle, .. } = resolved
        .map_err(|error| format!("native master acquisition failed in mode {mode}: {error}"))?;
    *state.master_alias.lock().map_err(|_| denied())? = Some(handle.clone());
    assert_eq!(*state.prompts.lock().map_err(|_| denied())?, 1);
    if matches!(mode, 14 | 17) {
        assert!(
            proxy
                .call_confidential::<SecretCipherPending2>(
                    names::methods::EVALUATE_SECRET_CIPHER2,
                    (EvaluateSecretCipherRequest2 {
                        request: cipher_request(
                            &handle,
                            1,
                            SecretCipherKind2::Decrypt,
                            b"private-output".to_vec()
                        ),
                        audit: audit(4)
                    },)
                )
                .await
                .is_err()
        );
        task.abort();
        return Ok(());
    }
    if mode == 18 {
        device_pairing_roundtrip(&lifecycle, &loaded.name, &config, &proxy, &state, &handle)
            .await
            .map_err(|error| format!("native device pairing roundtrip failed: {error}"))?;
        lifecycle.shutdown(Duration::from_secs(5)).await;
        task.abort();
        println!(
            "native pairing: reinit-stable identity, approved Secret2 master, possession proof, confidential frame session, refresh, renewal, close and revoke passed"
        );
        return Ok(());
    }
    let sequence = exercise_cipher(&proxy, &state, &handle).await?;
    assert_eq!(*state.prompts.lock().map_err(|_| denied())?, 1); // routine operations never prompt
    reject_wrong_peer(&bus, &module, &handle).await?;
    if mode == 0 {
        generation_boundary(&lifecycle, &loaded.name, &config, &proxy, &handle, sequence).await?;
    }
    let mut changed = config.clone();
    changed
        .secret_cipher
        .as_mut()
        .ok_or("native initialized cipher")?
        .consumer_id = "d".repeat(32);
    assert!(
        lifecycle
            .reinitialize(&loaded.name, serde_json::to_value(changed)?)
            .await
            .is_err()
    );
    state.slots.lock().map_err(|_| denied())?.clear();
    lifecycle.shutdown(Duration::from_secs(5)).await;
    task.abort();
    assert_eq!(hash, tinybus::module::sha256_file(library)?);
    Ok(())
}
fn cipher_request(
    handle: &str,
    call: u64,
    operation: SecretCipherKind2,
    input: Vec<u8>,
) -> SecretCipherRequest2 {
    SecretCipherRequest2 {
        registration_id: "b".repeat(32),
        master_handle: handle.into(),
        call_id: format!("native-{call}"),
        operation,
        input,
        ttl_ms: 30000,
    }
}
async fn execute(
    proxy: &tinybus::Proxy,
    request: SecretCipherRequest2,
    sequence: &mut u64,
) -> tinybus::Result<SecretCipherResponse2> {
    let pending: SecretCipherPending2 = proxy
        .call_confidential(
            names::methods::EVALUATE_SECRET_CIPHER2,
            (EvaluateSecretCipherRequest2 {
                request: request.clone(),
                audit: audit(*sequence),
            },),
        )
        .await?;
    *sequence += 1;
    let execute = ExecuteSecretCipherRequest2 {
        request,
        pending_id: pending.pending_id,
        audit: audit(*sequence),
        delivery_audit: audit(*sequence + 1),
        completion_audit: audit(*sequence + 2),
    };
    *sequence += 3;
    let response = proxy
        .call_confidential(names::methods::EXECUTE_SECRET_CIPHER2, (&execute,))
        .await;
    assert!(
        proxy
            .call_confidential::<SecretCipherResponse2>(
                names::methods::EXECUTE_SECRET_CIPHER2,
                (&execute,)
            )
            .await
            .is_err()
    );
    response
}
