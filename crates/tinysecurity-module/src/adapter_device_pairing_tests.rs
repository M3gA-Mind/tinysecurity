use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tinysecurity::crypto::device_pairing::{DevicePairingOwner, LegacyDeviceIdentity, Time};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn unlock_master_authority_is_checked_after_waiting_for_scope_lock() -> TestResult {
    let scope = Arc::new(tokio::sync::Mutex::new(()));
    let held = scope.lock().await;
    let now = Arc::new(std::sync::atomic::AtomicU64::new(9));
    let task_now = Arc::clone(&now);
    let task_scope = Arc::clone(&scope);
    let task = tokio::spawn(async move {
        lock_and_validate_scope(&task_scope, move |()| {
            if task_now.load(Ordering::SeqCst) >= 10 {
                Err(denied())
            } else {
                Ok(())
            }
        })
        .await
        .map(|_| ())
    });
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "validation must wait for the scope lock"
    );
    now.store(10, Ordering::SeqCst);
    drop(held);
    assert!(task.await?.is_err());
    Ok(())
}

const SCOPE_ID: &str = "0123456789abcdef0123456789abcdef";
const FRAME_HANDLE: &str = "abcdef0123456789abcdef0123456789";
const SECOND_FRAME_HANDLE: &str = "bcdef0123456789abcdef0123456789a";

#[test]
#[allow(clippy::too_many_lines)] // Pins the admitted scope bindings and each rejected authority input.
fn runtime_pairing_scope_derives_secret_and_backend_bindings_from_init_policy() -> TestResult {
    use tinysecurity_bus::{
        AccessTier, ApprovalScope2, DevicePairingRuntimeScope2, MasterPurpose2, MasterSlotKind2,
        Origin, SecretBinding2, SecretRegistration2, SubjectScope,
    };

    let approval = ApprovalScope2 {
        scope_id: SCOPE_ID.into(),
        subject: SubjectScope {
            user: "real-user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "policy".into(),
        generation: 7,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let secret = SecretRegistration2 {
        registration_id: "b".repeat(32),
        approval_scope_id: SCOPE_ID.into(),
        origin: Origin::Operator,
        purpose: MasterPurpose2::ConfigUserMaster,
        target: SecretBinding2 {
            backend_id: "c".repeat(32),
            slot: MasterSlotKind2::User,
        },
        legacy: vec![],
    };
    let defaults = DevicePairingRuntimeScope2 {
        persistence_backend_id: "pairing-state".into(),
        legacy_device_backend_id: Some("d".repeat(32)),
        allowed_origins: vec![Origin::Operator],
    };
    assert!(validate_runtime_defaults(&defaults).is_ok());
    let (scope, origin) = derive_runtime_scope(&approval, &secret, &defaults)?;
    assert_eq!(scope.scope_id, approval.scope_id);
    assert_eq!(scope.secret_registration_id, secret.registration_id);
    assert_eq!(
        scope.persistence_backend_id,
        defaults.persistence_backend_id
    );
    assert_eq!(
        scope.legacy_device_backend_id,
        defaults.legacy_device_backend_id
    );
    assert_eq!(
        scope.legacy_source_registration_id.as_deref(),
        Some(secret.registration_id.as_str())
    );
    assert_eq!(origin, Origin::Operator);
    let denied_approval = ApprovalScope2 {
        require_approval: false,
        ..approval.clone()
    };
    assert!(validate_runtime_approval_snapshot(&approval, approval.generation).is_ok());
    assert!(validate_runtime_approval_snapshot(&denied_approval, approval.generation).is_err());
    assert!(validate_runtime_approval_snapshot(&approval, approval.generation + 1).is_err());
    let automatic_approval = ApprovalScope2 {
        auto_approve_all: true,
        ..approval.clone()
    };
    assert!(validate_runtime_approval_snapshot(&automatic_approval, approval.generation).is_err());
    assert!(validate_secret_scope_binding(&approval, &approval, &approval).is_ok());
    let changed_secret_scope = ApprovalScope2 {
        subject: SubjectScope {
            user: "different-user".into(),
            ..approval.subject.clone()
        },
        ..approval.clone()
    };
    assert!(validate_secret_scope_binding(&approval, &changed_secret_scope, &approval).is_err());
    assert!(validate_secret_scope_binding(&approval, &approval, &changed_secret_scope).is_err());
    assert!(derive_runtime_scope(&denied_approval, &secret, &defaults).is_err());
    let mut wrong_purpose = secret.clone();
    wrong_purpose.purpose = MasterPurpose2::AppEncryptionMaster;
    assert!(derive_runtime_scope(&approval, &wrong_purpose, &defaults).is_err());
    let mut wrong_slot = secret.clone();
    wrong_slot.target.slot = MasterSlotKind2::App;
    assert!(derive_runtime_scope(&approval, &wrong_slot, &defaults).is_err());
    let denied_defaults = DevicePairingRuntimeScope2 {
        allowed_origins: vec![Origin::Copilot],
        ..defaults.clone()
    };
    assert!(derive_runtime_scope(&approval, &secret, &denied_defaults).is_err());
    let duplicate_defaults = DevicePairingRuntimeScope2 {
        allowed_origins: vec![Origin::Operator, Origin::Operator],
        ..defaults.clone()
    };
    assert!(validate_runtime_defaults(&duplicate_defaults).is_err());
    let empty_origins = DevicePairingRuntimeScope2 {
        allowed_origins: vec![],
        ..defaults.clone()
    };
    assert!(validate_runtime_defaults(&empty_origins).is_err());
    let invalid_legacy_backend = DevicePairingRuntimeScope2 {
        legacy_device_backend_id: Some("bad".into()),
        ..defaults.clone()
    };
    assert!(validate_runtime_defaults(&invalid_legacy_backend).is_err());
    let denied_defaults = DevicePairingRuntimeScope2 {
        persistence_backend_id: "invalid\nbackend".into(),
        ..defaults
    };
    assert!(validate_runtime_defaults(&denied_defaults).is_err());
    assert!(derive_runtime_scope(&approval, &secret, &denied_defaults).is_err());
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // Exercises successful, duplicate, and two rejected admissions.
fn runtime_pairing_scope_admission_is_idempotent_and_fails_closed_without_partial_state()
-> TestResult {
    use std::collections::BTreeMap;
    use tinysecurity_bus::{
        AccessTier, ApprovalScope2, DeviceConfig2, DevicePairingScope2, DevicePairingScopeReceipt2,
        Origin, SubjectScope,
    };

    let registry = Arc::new(tinysecurity::crypto::device_handles::Registry::new(
        DeviceConfig2 {
            scopes: vec![],
            max_handles: 16,
            max_in_flight: 2,
            operations_per_minute: 100,
            frames_per_minute: 10,
            max_ttl_ms: 10_000,
            max_message_bytes: 1024,
            max_bootstrap_nonces: 1,
        },
        &[],
        ":1.1",
        1,
        tinysecurity::crypto::device_handles::Time {
            wall: 1_000,
            monotonic: 1_000,
        },
    )?);
    let approval = ApprovalScope2 {
        scope_id: SCOPE_ID.into(),
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
    let scope = DevicePairingScope2 {
        scope_id: SCOPE_ID.into(),
        secret_registration_id: "b".repeat(32),
        persistence_backend_id: "pairing-state".into(),
        legacy_device_backend_id: None,
        legacy_source_registration_id: None,
    };
    let mut epochs = BTreeMap::new();
    let mut catalog = BTreeMap::new();
    let now = tinysecurity::crypto::device_handles::Time {
        wall: 1_001,
        monotonic: 1_001,
    };
    let receipt = admit_runtime_scope(
        scope.clone(),
        approval.clone(),
        Origin::Operator,
        &registry,
        1,
        now,
        &mut epochs,
        &mut catalog,
    )?;
    assert_eq!(
        receipt,
        DevicePairingScopeReceipt2 {
            scope_id: SCOPE_ID.into(),
            active: true
        }
    );
    assert_eq!(
        admit_runtime_scope(
            scope.clone(),
            approval.clone(),
            Origin::Operator,
            &registry,
            1,
            now,
            &mut epochs,
            &mut catalog
        )?,
        receipt
    );
    assert_eq!(catalog.len(), 1);
    assert_eq!(epochs.len(), 1);

    let mismatched_scope = DevicePairingScope2 {
        scope_id: "e".repeat(32),
        ..catalog[SCOPE_ID].clone()
    };
    assert!(
        admit_runtime_scope(
            mismatched_scope,
            approval.clone(),
            Origin::Operator,
            &registry,
            1,
            now,
            &mut epochs,
            &mut catalog,
        )
        .is_err()
    );
    assert_eq!(catalog.len(), 1);
    assert_eq!(epochs.len(), 1);

    let mut changed = scope;
    changed.persistence_backend_id = "changed-backend".into();
    assert!(
        admit_runtime_scope(
            changed,
            approval.clone(),
            Origin::Operator,
            &registry,
            1,
            now,
            &mut epochs,
            &mut catalog
        )
        .is_err()
    );
    assert_eq!(catalog.len(), 1);
    assert_eq!(epochs.len(), 1);

    let rejected_approval = ApprovalScope2 {
        scope_id: "d".repeat(32),
        require_approval: false,
        ..approval.clone()
    };
    let rejected_scope = DevicePairingScope2 {
        scope_id: rejected_approval.scope_id.clone(),
        secret_registration_id: "d".repeat(32),
        ..catalog[SCOPE_ID].clone()
    };
    assert!(
        admit_runtime_scope(
            rejected_scope,
            rejected_approval,
            Origin::Operator,
            &registry,
            1,
            now,
            &mut epochs,
            &mut catalog
        )
        .is_err(),
        "native device registry refusal must prevent either pairing-map insert"
    );
    assert_eq!(catalog.len(), 1);
    assert_eq!(epochs.len(), 1);

    let new_approval = ApprovalScope2 {
        scope_id: "c".repeat(32),
        generation: 2,
        ..approval.clone()
    };
    let unregistered = DevicePairingScope2 {
        scope_id: new_approval.scope_id.clone(),
        secret_registration_id: "e".repeat(32),
        ..catalog[SCOPE_ID].clone()
    };
    assert!(
        admit_runtime_scope(
            unregistered,
            new_approval,
            Origin::Operator,
            &registry,
            2,
            now,
            &mut epochs,
            &mut catalog
        )
        .is_err()
    );
    assert_eq!(catalog.len(), 1);
    assert_eq!(epochs.len(), 1);

    let mut full_epochs = (0..128)
        .map(|index| (format!("{index:032x}"), 0))
        .collect::<BTreeMap<_, _>>();
    let mut full_catalog = (0..128)
        .map(|index| {
            let id = format!("{index:032x}");
            (
                id.clone(),
                DevicePairingScope2 {
                    scope_id: id,
                    ..catalog[SCOPE_ID].clone()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let full_scope = DevicePairingScope2 {
        scope_id: "f".repeat(32),
        ..catalog[SCOPE_ID].clone()
    };
    let full_approval = ApprovalScope2 {
        scope_id: full_scope.scope_id.clone(),
        ..approval.clone()
    };
    assert!(
        admit_runtime_scope(
            full_scope,
            full_approval,
            Origin::Operator,
            &registry,
            1,
            now,
            &mut full_epochs,
            &mut full_catalog,
        )
        .is_err()
    );
    assert_eq!(full_catalog.len(), 128);
    assert_eq!(full_epochs.len(), 128);
    Ok(())
}

#[test]
fn legacy_import_handles_are_single_use_per_pairing_scope() {
    let mut consumed = std::collections::BTreeSet::new();
    assert!(consume_legacy_import_handle(&mut consumed, SCOPE_ID, "one-shot-handle", 2,).is_ok());
    assert!(consume_legacy_import_handle(&mut consumed, SCOPE_ID, "one-shot-handle", 2,).is_err());
    assert!(
        consume_legacy_import_handle(&mut consumed, "b".repeat(32).as_str(), "one-shot-handle", 2,)
            .is_ok()
    );
    assert!(consume_legacy_import_handle(&mut consumed, SCOPE_ID, "another-handle", 2,).is_err());
}

#[test]
fn dynamic_pairing_catalog_supplies_only_the_requested_scope() -> TestResult {
    use tinysecurity_bus::{
        DevicePairingConfig2, DevicePairingRuntimeScope2, DevicePairingScope2, Origin,
    };

    let scope = DevicePairingScope2 {
        scope_id: SCOPE_ID.into(),
        secret_registration_id: "b".repeat(32),
        persistence_backend_id: "pairing-state".into(),
        legacy_device_backend_id: Some("c".repeat(32)),
        legacy_source_registration_id: Some("b".repeat(32)),
    };
    let catalog = RwLock::new([(SCOPE_ID.into(), scope.clone())].into());
    assert_eq!(lookup_scope(&catalog, SCOPE_ID)?, scope);
    assert!(lookup_scope(&catalog, "d".repeat(32).as_str()).is_err());

    let config = DevicePairingConfig2 {
        scopes: vec![],
        runtime_scope: Some(DevicePairingRuntimeScope2 {
            persistence_backend_id: "pairing-state".into(),
            legacy_device_backend_id: Some("c".repeat(32)),
            allowed_origins: vec![Origin::Operator],
        }),
        max_pairings: 32,
        max_pending: 8,
        max_pending_ttl_ms: 30_000,
        max_session_ttl_ms: 3_600_000,
        max_state_bytes: 65_536,
        callback_timeout_ms: 1_000,
    };
    let one_scope = one_scope_config(&config, &catalog, SCOPE_ID)?;
    assert_eq!(one_scope.scopes, vec![scope]);
    assert_eq!(one_scope.runtime_scope, config.runtime_scope);
    assert_eq!(one_scope.max_pairings, config.max_pairings);
    Ok(())
}

#[test]
fn legacy_callback_consumption_locks_and_records_the_one_shot_handle() {
    let consumed = Mutex::new(std::collections::BTreeSet::new());
    assert!(consume_legacy_import(&consumed, SCOPE_ID, "callback-handle").is_ok());
    assert!(consume_legacy_import(&consumed, SCOPE_ID, "callback-handle").is_err());
}

#[tokio::test]
async fn legacy_host_callback_consumes_its_handle_before_dispatch() -> TestResult {
    use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
    use tinysecurity_bus::{
        DevicePairingConfig2, DevicePairingContextResponse2, DevicePairingRuntimeScope2,
        DevicePairingScope2, DevicePairingSource2, Origin,
    };

    let bus = MemoryBus::new();
    let owner = Broker::new();
    let broker = owner.spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await?).await?;
    let peer = connection.unique_name().ok_or("fixture peer")?;
    let scope = DevicePairingScope2 {
        scope_id: SCOPE_ID.into(),
        secret_registration_id: "b".repeat(32),
        persistence_backend_id: "pairing-state".into(),
        legacy_device_backend_id: Some("c".repeat(32)),
        legacy_source_registration_id: Some("b".repeat(32)),
    };
    let callbacks = HostCallbacks {
        connection,
        peer,
        config: DevicePairingConfig2 {
            scopes: vec![],
            runtime_scope: Some(DevicePairingRuntimeScope2 {
                persistence_backend_id: "pairing-state".into(),
                legacy_device_backend_id: Some("c".repeat(32)),
                allowed_origins: vec![Origin::Operator],
            }),
            max_pairings: 32,
            max_pending: 8,
            max_pending_ttl_ms: 30_000,
            max_session_ttl_ms: 3_600_000,
            max_state_bytes: 65_536,
            callback_timeout_ms: 1_000,
        },
        scope_catalog: Arc::new(RwLock::new([(SCOPE_ID.into(), scope.clone())].into())),
        consumed_legacy_imports: Mutex::new(BTreeSet::new()),
    };
    assert_eq!(callbacks.scope(SCOPE_ID)?, scope);
    let context = DevicePairingContextResponse2 {
        scope_id: SCOPE_ID.into(),
        user_binding: "opaque-user-binding".into(),
        secret_master_handle: None,
        legacy_import_handle: Some("callback-handle".into()),
        channel_id: String::new(),
        pairing_token: None,
        connection_nonce: String::new(),
        generation: 1,
        source: DevicePairingSource2::AuthenticatedUserController,
        expires_at_ms: 2_000,
    };
    assert!(
        callbacks
            .load_legacy(SCOPE_ID, "callback-handle", &context)
            .await
            .is_err()
    );
    assert!(
        callbacks
            .load_legacy(SCOPE_ID, "callback-handle", &context)
            .await
            .is_err()
    );
    let consumed = callbacks
        .consumed_legacy_imports
        .lock()
        .map_err(|_| "legacy import lock poisoned")?;
    assert_eq!(consumed.len(), 1);
    broker.abort();
    Ok(())
}

fn registry_with_frame()
-> Result<Arc<tinysecurity::crypto::device_handles::Registry>, Box<dyn std::error::Error>> {
    use tinysecurity::crypto::{
        device::{KeyPair, Tunnel},
        device_handles::PairedTunnelRegistration,
    };
    use tinysecurity_bus::{
        AccessTier, ApprovalScope2, DeviceConfig2, DeviceScope2, Origin, SubjectScope,
    };

    let registration = ApprovalScope2 {
        scope_id: SCOPE_ID.into(),
        subject: SubjectScope {
            user: "pairing-test-user".into(),
            workspace: "pairing-test-workspace".into(),
            agent: "pairing-test-agent".into(),
        },
        policy_ref: "pairing-test-policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    let registry = Arc::new(tinysecurity::crypto::device_handles::Registry::new(
        DeviceConfig2 {
            scopes: vec![DeviceScope2 {
                scope_id: SCOPE_ID.into(),
                origin: Origin::Operator,
                static_secret: Some([0x61; 32]),
            }],
            max_handles: 4,
            max_in_flight: 1,
            operations_per_minute: 10,
            frames_per_minute: 10,
            max_ttl_ms: 10_000,
            max_message_bytes: 1024,
            max_bootstrap_nonces: 1,
        },
        &[registration],
        ":1.1",
        1,
        tinysecurity::crypto::device_handles::Time {
            wall: 1_000,
            monotonic: 1_000,
        },
    )?);
    let key = tinysecurity::crypto::device::KeyPair::generate()?;
    let public = key.public_key();
    let keys = key.session_keys(public, &key, public, public, public)?;
    registry.register_paired_tunnel(PairedTunnelRegistration {
        scope_id: SCOPE_ID,
        handle: FRAME_HANDLE,
        tunnel: Arc::new(std::sync::Mutex::new(Tunnel::new(
            tinysecurity::crypto::device::Role::Server,
            keys,
        ))),
        generation: 1,
        expires_wall: 5_000,
        expires_monotonic: 5_000,
        now: tinysecurity::crypto::device_handles::Time {
            wall: 1_000,
            monotonic: 1_000,
        },
    })?;
    let second_key = KeyPair::generate()?;
    let second_public = second_key.public_key();
    let second_keys = second_key.session_keys(
        second_public,
        &second_key,
        second_public,
        second_public,
        second_public,
    )?;
    registry.register_paired_tunnel(PairedTunnelRegistration {
        scope_id: SCOPE_ID,
        handle: SECOND_FRAME_HANDLE,
        tunnel: Arc::new(std::sync::Mutex::new(Tunnel::new(
            tinysecurity::crypto::device::Role::Server,
            second_keys,
        ))),
        generation: 1,
        expires_wall: 5_000,
        expires_monotonic: 5_000,
        now: tinysecurity::crypto::device_handles::Time {
            wall: 1_000,
            monotonic: 1_000,
        },
    })?;
    Ok(registry)
}

fn frame_seal(registry: &tinysecurity::crypto::device_handles::Registry) -> bool {
    frame_seal_handle(registry, FRAME_HANDLE)
}

fn frame_seal_handle(
    registry: &tinysecurity::crypto::device_handles::Registry,
    handle: &str,
) -> bool {
    registry
        .execute_frame(
            &tinysecurity_bus::DeviceFrameRequest2 {
                scope_id: SCOPE_ID.into(),
                handle: handle.into(),
                call_id: "pairing-test-call".into(),
                operation: tinysecurity_bus::DeviceFrameOperation2::Seal {
                    plaintext: b"live frame".to_vec(),
                },
            },
            1,
            tinysecurity::crypto::device_handles::Time {
                wall: 1_001,
                monotonic: 1_001,
            },
        )
        .is_ok()
}

fn owner() -> Result<DevicePairingOwner, Box<dyn std::error::Error>> {
    let config = tinysecurity_bus::DevicePairingConfig2 {
        scopes: vec![tinysecurity_bus::DevicePairingScope2 {
            scope_id: "0123456789abcdef0123456789abcdef".into(),
            secret_registration_id: "abcdef0123456789abcdef0123456789".into(),
            persistence_backend_id: "user-secret-store".into(),
            legacy_device_backend_id: None,
            legacy_source_registration_id: None,
        }],
        runtime_scope: None,
        max_pairings: 1,
        max_pending: 1,
        max_pending_ttl_ms: 1_000,
        max_session_ttl_ms: 1_000,
        max_state_bytes: 4096,
        callback_timeout_ms: 1000,
    };
    Ok(DevicePairingOwner::new(
        config,
        1,
        Time {
            wall: 1000,
            monotonic: 1000,
        },
        [(
            "0123456789abcdef0123456789abcdef".into(),
            zeroize::Zeroizing::new([0x41; 32]),
        )]
        .into(),
    )?)
}

fn controller(channel: &str) -> tinysecurity_bus::DevicePairingContextResponse2 {
    tinysecurity_bus::DevicePairingContextResponse2 {
        scope_id: "0123456789abcdef0123456789abcdef".into(),
        user_binding: "pairing-test-user".into(),
        secret_master_handle: None,
        legacy_import_handle: None,
        channel_id: channel.into(),
        pairing_token: (!channel.is_empty()).then(|| "fixture-pairing-token".into()),
        connection_nonce: "pairing-test-nonce".into(),
        generation: 1,
        source: tinysecurity_bus::DevicePairingSource2::AuthenticatedUserController,
        expires_at_ms: 10_000,
    }
}

#[test]
fn unlock_rejects_agent_before_loaded_scope_lookup() {
    let mut context = controller("agent-unlock");
    context.source = tinysecurity_bus::DevicePairingSource2::Agent;
    let lookup_ran = std::cell::Cell::new(false);
    let result = unlock_scope_lookup(
        &context,
        1,
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || {
            lookup_ran.set(true);
            Ok(Some("already-loaded-scope"))
        },
    );
    assert!(result.is_err());
    assert!(
        !lookup_ran.get(),
        "agent context must be denied before the existing-scope fast path runs"
    );
}

#[test]
fn plaintext_pairing_snapshot_is_rejected() {
    let scope = tinysecurity_bus::DevicePairingScope2 {
        scope_id: SCOPE_ID.into(),
        secret_registration_id: "abcdef0123456789abcdef0123456789".into(),
        persistence_backend_id: "user-secret-store".into(),
        legacy_device_backend_id: None,
        legacy_source_registration_id: None,
    };
    let plaintext = serde_json::json!({
        "version": 1,
        "scope_id": SCOPE_ID,
        "backend_id": "user-secret-store",
        "secret_registration_id": "abcdef0123456789abcdef0123456789",
        "state": ""
    })
    .to_string();
    assert!(
        decode_state_with(plaintext.as_bytes(), &scope, |text| {
            Ok(Zeroizing::new(text.to_owned()))
        })
        .is_err()
    );
}

#[test]
fn failed_refresh_retires_the_paired_tunnel() -> TestResult {
    let registry = registry_with_frame()?;
    assert!(frame_seal(&registry));
    let mut owner = owner()?;
    let result = finish_refresh::<()>(Err(denied()), &mut owner, &registry, SCOPE_ID, FRAME_HANDLE);
    assert!(result.is_err());
    assert!(!frame_seal(&registry));
    Ok(())
}

#[test]
fn clock_rollback_retires_every_tunnel_in_the_scope() -> TestResult {
    let registry = registry_with_frame()?;
    assert!(frame_seal_handle(&registry, FRAME_HANDLE));
    assert!(frame_seal_handle(&registry, SECOND_FRAME_HANDLE));
    let mut owner = owner()?;
    let context = controller("clock-rollback");
    let result = owner.refresh_session(
        "missing-session",
        &context,
        Time {
            wall: 999,
            monotonic: 999,
        },
    );
    assert!(result.is_err());
    assert!(
        finish_refresh(
            result.map_err(|_| denied()),
            &mut owner,
            &registry,
            SCOPE_ID,
            FRAME_HANDLE
        )
        .is_err()
    );
    assert!(!frame_seal_handle(&registry, FRAME_HANDLE));
    assert!(!frame_seal_handle(&registry, SECOND_FRAME_HANDLE));
    Ok(())
}

fn import_one(
    owner: &mut DevicePairingOwner,
    channel: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(owner.import_legacy_identities(
        &controller(channel),
        vec![LegacyDeviceIdentity {
            channel_id: channel.into(),
            device_public_key: tinysecurity::crypto::device::KeyPair::generate()?
                .public_key()
                .encode(),
            core_private_key: zeroize::Zeroizing::new([0x52; 32]),
            revoked: false,
        }],
        Time {
            wall: 1000,
            monotonic: 1000,
        },
    )?[0]
        .pairing_id
        .clone())
}

#[tokio::test]
async fn canceled_revoke_callback_faults_the_mutated_owner() -> TestResult {
    let mut owner = owner()?;
    let pairing_id = import_one(&mut owner, "channel-revoke")?;
    let faulted = Arc::new(AtomicBool::new(false));
    let task_faulted = Arc::clone(&faulted);
    let callback_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&callback_started);
    let committed = Arc::new(AtomicBool::new(false));
    let cas_committed = Arc::clone(&committed);
    let context = controller("channel-revoke");
    let registry = registry_with_frame()?;
    let notified = callback_started.notified();
    tokio::pin!(notified);
    let mut operation = Box::pin(revoke_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: task_faulted,
            registry,
            scope_id: SCOPE_ID.into(),
        },
        &pairing_id,
        &context,
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || Ok(()),
        move |_snapshot| async move {
            cas_committed.store(true, Ordering::Release);
            started.notify_one();
            std::future::pending::<tinybus::Result<String>>().await
        },
    ));
    tokio::select! {
        () = &mut notified => {},
        result = &mut operation => panic!("revoke unexpectedly completed: {result:?}"),
    }
    drop(operation);
    assert!(committed.load(Ordering::Acquire));
    assert!(check_persistence_fault(&mut owner, &faulted).is_err());
    assert!(
        owner
            .recover_channel(
                "channel-revoke",
                &controller("channel-revoke"),
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn canceled_confirmation_persistence_retires_existing_frame_handles() -> TestResult {
    let registry = registry_with_frame()?;
    assert!(frame_seal(&registry));
    let faulted = Arc::new(AtomicBool::new(false));
    let callback_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&callback_started);
    let notified = callback_started.notified();
    tokio::pin!(notified);
    let mut operation = Box::pin(persist_fenced(
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: Arc::clone(&registry),
            scope_id: SCOPE_ID.into(),
        },
        async move {
            started.notify_one();
            std::future::pending::<tinybus::Result<()>>().await
        },
    ));
    tokio::select! {
        () = &mut notified => {},
        result = &mut operation => panic!("persistence unexpectedly completed: {result:?}"),
    }
    drop(operation);
    assert!(faulted.load(Ordering::Acquire));
    assert!(!frame_seal(&registry));
    Ok(())
}

#[tokio::test]
async fn successful_revoke_persistence_keeps_owner_usable() -> TestResult {
    let mut owner = owner()?;
    let pairing_id = import_one(&mut owner, "channel-revoke-success")?;
    let faulted = Arc::new(AtomicBool::new(false));
    let registry = registry_with_frame()?;
    revoke_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: Arc::clone(&registry),
            scope_id: SCOPE_ID.into(),
        },
        &pairing_id,
        &controller("channel-revoke-success"),
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || Ok(()),
        |_snapshot| async { Ok("revision-2".into()) },
    )
    .await?
    .complete();
    check_persistence_fault(&mut owner, &faulted)?;
    assert!(frame_seal(&registry));
    assert!(
        owner
            .public_key(
                "0123456789abcdef0123456789abcdef",
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn denied_revoke_does_not_fault_the_pairing_owner() -> TestResult {
    let mut owner = owner()?;
    import_one(&mut owner, "channel-revoke-denied")?;
    let faulted = Arc::new(AtomicBool::new(false));
    let result = revoke_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: registry_with_frame()?,
            scope_id: SCOPE_ID.into(),
        },
        "unknown-pairing",
        &controller("channel-revoke-denied"),
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        || Ok(()),
        |_snapshot| async { Ok("unreachable-revision".into()) },
    )
    .await;
    assert!(result.is_err(), "unknown pairing ids must be denied");

    fail_revoke_owner_on_error(&mut owner, &faulted);

    assert!(
        owner
            .public_key(
                SCOPE_ID,
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_ok(),
        "a denied revoke before persistence must leave the owner usable"
    );
    Ok(())
}

#[tokio::test]
async fn expired_begin_receipts_release_their_master_aliases_before_a_new_begin() -> TestResult {
    let mut owner = owner()?;
    let mut aliases = std::collections::BTreeMap::new();
    let first = begin_with_master_alias(
        &mut owner,
        &mut aliases,
        &controller("channel-expiring"),
        1000,
        "master-alias-1",
        Time {
            wall: 1000,
            monotonic: 1000,
        },
    )?;
    let second = begin_with_master_alias(
        &mut owner,
        &mut aliases,
        &controller("channel-expiring"),
        1000,
        "master-alias-2",
        Time {
            wall: 2001,
            monotonic: 2001,
        },
    )?;

    assert_eq!(
        aliases.len(),
        1,
        "expired receipts must release alias entries"
    );
    assert!(!aliases.contains_key(&first.0));
    assert!(aliases.contains_key(&second.0));
    Ok(())
}

#[tokio::test]
async fn canceled_legacy_import_callback_faults_the_mutated_owner() -> TestResult {
    let mut owner = owner()?;
    let faulted = Arc::new(AtomicBool::new(false));
    let task_faulted = Arc::clone(&faulted);
    let callback_started = Arc::new(tokio::sync::Notify::new());
    let started = Arc::clone(&callback_started);
    let imported_cas_committed = Arc::new(AtomicBool::new(false));
    let cas_committed = Arc::clone(&imported_cas_committed);
    let context = controller("channel-import");
    let identities = vec![LegacyDeviceIdentity {
        channel_id: "channel-import".into(),
        device_public_key: tinysecurity::crypto::device::KeyPair::generate()?
            .public_key()
            .encode(),
        core_private_key: zeroize::Zeroizing::new([0x53; 32]),
        revoked: false,
    }];
    let notified = callback_started.notified();
    tokio::pin!(notified);
    let mut operation = Box::pin(import_legacy_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: task_faulted,
            registry: registry_with_frame()?,
            scope_id: SCOPE_ID.into(),
        },
        &context,
        identities,
        Time {
            wall: 1000,
            monotonic: 1000,
        },
        move |_snapshot| async move {
            cas_committed.store(true, Ordering::Release);
            started.notify_one();
            std::future::pending::<tinybus::Result<String>>().await
        },
    ));
    tokio::select! {
        () = &mut notified => {},
        result = &mut operation => panic!("legacy import unexpectedly completed: {result:?}"),
    }
    drop(operation);
    assert!(imported_cas_committed.load(Ordering::Acquire));
    assert!(check_persistence_fault(&mut owner, &faulted).is_err());
    assert!(
        owner
            .recover_channel(
                "channel-import",
                &context,
                Time {
                    wall: 1001,
                    monotonic: 1001,
                },
            )
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn successful_store_remains_fenced_until_post_store_validation_finishes() -> TestResult {
    let mut owner = owner()?;
    import_one(&mut owner, "post-store-validation")?;
    let registry = registry_with_frame()?;
    let faulted = Arc::new(AtomicBool::new(false));
    let stored = persist_fenced(
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: Arc::clone(&registry),
            scope_id: SCOPE_ID.into(),
        },
        async { Ok("committed-revision".to_owned()) },
    )
    .await?;
    // A context expiry or generation change rejects publication after the CAS has committed.
    stored.fail(&mut owner);
    assert!(faulted.load(Ordering::Acquire));
    assert!(
        owner
            .recover_channel(
                "post-store-validation",
                &controller("post-store-validation"),
                Time {
                    wall: 1001,
                    monotonic: 1001,
                },
            )
            .is_err()
    );
    assert!(!frame_seal(&registry));
    Ok(())
}

#[tokio::test]
async fn imported_store_remains_fenced_until_master_revalidation_finishes() -> TestResult {
    let mut owner = owner()?;
    let registry = registry_with_frame()?;
    let faulted = Arc::new(AtomicBool::new(false));
    let context = controller("post-store-import");
    let stored = import_legacy_and_persist(
        &mut owner,
        PersistenceContext {
            faulted: Arc::clone(&faulted),
            registry: Arc::clone(&registry),
            scope_id: SCOPE_ID.into(),
        },
        &context,
        Vec::new(),
        Time {
            wall: 1001,
            monotonic: 1001,
        },
        |_snapshot| async { Ok("committed-import-revision".into()) },
    )
    .await?;
    stored.1.fail(&mut owner);
    assert!(faulted.load(Ordering::Acquire));
    assert!(
        owner
            .recover_channel(
                "channel-import",
                &context,
                Time {
                    wall: 1002,
                    monotonic: 1002,
                },
            )
            .is_err()
    );
    assert!(!frame_seal(&registry));
    Ok(())
}

#[test]
fn expired_logout_context_is_denied_before_scope_mutation() {
    let mut context = controller("logout");
    context.source = tinysecurity_bus::DevicePairingSource2::AuthenticatedUserLogout;
    let now = Time {
        wall: context.expires_at_ms,
        monotonic: 1001,
    };
    assert!(validate_logout_context(&context, 1, now).is_err());
    context.expires_at_ms += 1;
    assert!(validate_logout_context(&context, 1, now).is_ok());
}

#[test]
fn persistence_backend_identifiers_are_bounded_opaque_names() {
    for accepted in ["user-secret-store", "backend:v2/user", &"x".repeat(128)] {
        assert!(valid_persistence_backend_id(accepted));
    }
    for rejected in ["", "backend\nname", &"x".repeat(129)] {
        assert!(!valid_persistence_backend_id(rejected));
    }
}

#[tokio::test]
async fn queued_handshake_cannot_read_crypto_state_after_scope_epoch_changes() -> TestResult {
    let scope = Arc::new(tokio::sync::Mutex::new(owner()?));
    let epoch = Arc::new(AtomicU64::new(1));
    let held = scope.lock().await;
    let task_scope = Arc::clone(&scope);
    let task_epoch = Arc::clone(&epoch);
    let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = waiting_tx.send(());
        let mut owner = lock_and_validate_scope(&task_scope, |_| {
            if task_epoch.load(Ordering::Acquire) == 1 {
                Ok(())
            } else {
                Err(denied())
            }
        })
        .await?;
        // Reading the handshake key must never happen on an epoch retired by logout.
        owner
            .public_key(
                SCOPE_ID,
                Time {
                    wall: 1001,
                    monotonic: 1001,
                },
            )
            .map_err(|_| denied())
    });
    waiting_rx.await?;
    epoch.store(2, Ordering::Release);
    drop(held);
    assert!(task.await?.is_err());
    Ok(())
}
