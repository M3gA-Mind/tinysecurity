use super::*;
use tinysecurity_bus::{
    AccessTier, DeviceFrameOperation2, DeviceFrameRequest2, DeviceScope2, SubjectScope,
};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn time(n: u64) -> Time {
    Time {
        wall: 1000 + n,
        monotonic: n,
    }
}
fn registration(id: &str) -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: id.into(),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: format!("agent-{id}"),
        },
        policy_ref: "immutable".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
fn config() -> DeviceConfig2 {
    DeviceConfig2 {
        scopes: vec![
            DeviceScope2 {
                scope_id: "a".repeat(32),
                origin: tinysecurity_bus::Origin::Operator,
                static_secret: Some([1; 32]),
            },
            DeviceScope2 {
                scope_id: "b".repeat(32),
                origin: tinysecurity_bus::Origin::Operator,
                static_secret: Some([2; 32]),
            },
        ],
        max_handles: 16,
        max_in_flight: 2,
        operations_per_minute: 100,
        frames_per_minute: 12_000,
        max_ttl_ms: 100,
        max_message_bytes: 1000,
        max_bootstrap_nonces: 2,
    }
}
fn registry() -> Result<Registry> {
    Registry::new(
        config(),
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        time(0),
    )
}
fn request(scope: char, operation: DeviceOperation2) -> DeviceRequest2 {
    DeviceRequest2 {
        scope_id: scope.to_string().repeat(32),
        call_id: "call".into(),
        ttl_ms: 100,
        operation,
    }
}
fn run(reg: &Registry, scope: char, op: DeviceOperation2) -> Result<DeviceResponse2> {
    let request = request(scope, op);
    let work = reg.reserve(&request, 1, time(0))?;
    reg.execute(&work, &request.operation, 1, time(0))
}
fn key(reg: &Registry, scope: char, purpose: DeviceKeyPurpose2) -> Result<(String, String)> {
    let response = run(reg, scope, DeviceOperation2::Key { purpose })?;
    Ok((
        response.handle.ok_or(Error::DeviceDenied)?,
        response.public_key.ok_or(Error::DeviceDenied)?,
    ))
}
#[test]
fn authenticated_bootstrap_is_accepted_once_and_duplicate_is_denied() -> TestResult {
    let reg = registry()?;
    let (server, public) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let client = KeyPair::from_secret(Zeroizing::new([3; 32]))?;
    let frame = client.seal_handshake(PublicKey::decode(&public)?, b"fixture-private")?;
    let op = DeviceOperation2::OpenHandshake {
        handle: server,
        frame,
    };
    assert_eq!(run(&reg, 'a', op.clone())?.bytes, b"fixture-private");
    assert!(
        matches!(run(&reg, 'a', op), Err(Error::Replay)),
        "duplicate bootstrap must not grant authority twice"
    );
    Ok(())
}

#[test]
fn runtime_scope_registration_is_idempotent_and_rejects_changed_authority() -> TestResult {
    use tinysecurity_bus::Origin;

    let registry = registry()?;
    let scope_id = "c".repeat(32);
    let canonical = ApprovalScope2 {
        scope_id: scope_id.clone(),
        subject: SubjectScope {
            user: "runtime-user".into(),
            workspace: "runtime-workspace".into(),
            agent: "runtime-agent".into(),
        },
        policy_ref: "immutable".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    registry.register_scope(canonical.clone(), Origin::Operator, 1, time(0))?;
    registry.register_scope(canonical.clone(), Origin::Operator, 1, time(0))?;
    assert!(key(&registry, 'c', DeviceKeyPurpose2::Static).is_ok());

    let mut changed = canonical;
    changed.subject.user = "different-user".into();
    assert!(
        registry
            .register_scope(changed, Origin::Operator, 1, time(0))
            .is_err()
    );
    assert!(
        registry
            .register_scope(registration(&scope_id), Origin::Operator, 2, time(0))
            .is_err()
    );
    Ok(())
}

#[test]
fn empty_device_config_allows_only_later_host_registered_scopes() -> TestResult {
    use tinysecurity_bus::DeviceConfig2;

    let registry = Registry::new(
        DeviceConfig2 {
            scopes: Vec::new(),
            max_handles: 16,
            max_in_flight: 2,
            operations_per_minute: 100,
            frames_per_minute: 12_000,
            max_ttl_ms: 100,
            max_message_bytes: 1000,
            max_bootstrap_nonces: 2,
        },
        &[],
        ":1.1",
        1,
        time(0),
    )?;
    assert!(key(&registry, 'a', DeviceKeyPurpose2::Static).is_err());
    Ok(())
}

#[test]
fn runtime_scope_catalog_has_a_hard_bounded_capacity() {
    assert!(ensure_scope_capacity(0).is_ok());
    assert!(ensure_scope_capacity(MAX_DEVICE_SCOPES - 1).is_ok());
    assert!(ensure_scope_capacity(MAX_DEVICE_SCOPES).is_err());
}

#[test]
fn static_key_aliases_cannot_bypass_bootstrap_replay() -> TestResult {
    let reg = registry()?;
    let (first, public) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (alias, same) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    assert_eq!(public, same);
    let client = KeyPair::from_secret(Zeroizing::new([3; 32]))?;
    let frame = client.seal_handshake(PublicKey::decode(&public)?, b"fixture-private")?;
    run(
        &reg,
        'a',
        DeviceOperation2::OpenHandshake {
            handle: first,
            frame: frame.clone(),
        },
    )?;
    assert!(matches!(
        run(
            &reg,
            'a',
            DeviceOperation2::OpenHandshake {
                handle: alias,
                frame
            }
        ),
        Err(Error::Replay)
    ));
    Ok(())
}
#[test]
fn failed_deadline_reservation_does_not_consume_work_capacity() -> TestResult {
    let mut cfg = config();
    cfg.max_in_flight = 1;
    let reg = Registry::new(
        cfg,
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        Time {
            wall: u64::MAX - 1,
            monotonic: 0,
        },
    )?;
    let mut operation_request = request('a', DeviceOperation2::Cancel);
    operation_request.ttl_ms = 2;
    assert!(
        reg.reserve(
            &operation_request,
            1,
            Time {
                wall: u64::MAX - 1,
                monotonic: 0
            }
        )
        .is_err()
    );
    operation_request.ttl_ms = 1;
    assert!(
        reg.reserve(
            &operation_request,
            1,
            Time {
                wall: u64::MAX - 1,
                monotonic: 0
            }
        )
        .is_ok()
    );
    Ok(())
}
fn tunnel(
    reg: &Registry,
    key: &str,
    eph: &str,
    peer: &str,
    peer_eph: &str,
    role: DeviceRole2,
) -> Result<String> {
    run(
        reg,
        'a',
        DeviceOperation2::Tunnel {
            key: key.into(),
            ephemeral: eph.into(),
            peer_static: peer.into(),
            peer_ephemeral: peer_eph.into(),
            role,
        },
    )?
    .handle
    .ok_or(Error::DeviceDenied)
}
#[test]
fn tunnel_authority_ends_when_its_parent_key_expires() -> TestResult {
    let reg = registry()?;
    let mut operation_request = request(
        'a',
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    operation_request.ttl_ms = 1;
    let work = reg.reserve(&operation_request, 1, time(0))?;
    let own = reg
        .execute(&work, &operation_request.operation, 1, time(0))?
        .handle
        .ok_or(Error::DeviceDenied)?;
    drop(work);
    let (eph, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let peer = KeyPair::from_secret(Zeroizing::new([3; 32]))?;
    let peer_eph = KeyPair::from_secret(Zeroizing::new([4; 32]))?;
    let handle = tunnel(
        &reg,
        &own,
        &eph,
        &peer.public_key().encode(),
        &peer_eph.public_key().encode(),
        DeviceRole2::Client,
    )?;
    let operation_request = request(
        'a',
        DeviceOperation2::Seal {
            handle,
            plaintext: vec![],
        },
    );
    let work = reg.reserve(&operation_request, 1, time(1))?;
    assert!(
        reg.execute(&work, &operation_request.operation, 1, time(1))
            .is_err()
    );
    Ok(())
}
#[test]
fn revocation_fences_pending_work_but_preserves_unrelated_handles() -> TestResult {
    let reg = registry()?;
    let (revoked, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (unrelated, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let pending = reg.reserve(&request('a', DeviceOperation2::Cancel), 1, time(0))?;
    run(&reg, 'a', DeviceOperation2::Revoke { handle: revoked })?;
    assert!(reg.validate(&pending, 1, time(0)).is_err());
    drop(pending);
    let peer = KeyPair::from_secret(Zeroizing::new([5; 32]))?;
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::SealHandshake {
                handle: unrelated,
                peer: peer.public_key().encode(),
                plaintext: vec![]
            }
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn a_reservation_cannot_transfer_authority_to_another_registry() -> TestResult {
    let first = registry()?;
    let other = registry()?;
    let operation_request = request(
        'a',
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    let work = first.reserve(&operation_request, 1, time(0))?;
    assert!(
        other
            .execute(&work, &operation_request.operation, 1, time(0))
            .is_err()
    );
    assert!(other.validate(&work, 1, time(0)).is_err());
    Ok(())
}

#[test]
fn scopes_purposes_and_exact_secret_operation_binding_are_immutable() -> TestResult {
    let reg = registry()?;
    let (static_key, public) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (ephemeral, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let peer = KeyPair::from_secret(Zeroizing::new([5; 32]))?
        .public_key()
        .encode();
    assert!(
        run(
            &reg,
            'b',
            DeviceOperation2::SealAck {
                handle: static_key.clone(),
                peer: peer.clone(),
                plaintext: vec![]
            }
        )
        .is_err()
    );
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::SealHandshake {
                handle: static_key,
                peer: peer.clone(),
                plaintext: vec![]
            }
        )
        .is_err()
    );
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::SealAck {
                handle: ephemeral,
                peer,
                plaintext: vec![]
            }
        )
        .is_err()
    );
    let mut operation_request = request(
        'a',
        DeviceOperation2::Seal {
            handle: "c".repeat(64),
            plaintext: b"private-secret".to_vec(),
        },
    );
    operation_request.call_id = "private-secret".into();
    let first = reg.approval_call(&operation_request)?;
    let serialized = serde_json::to_string(&first)?;
    assert!(!serialized.contains("private-secret"));
    assert_eq!(first.caller.agent, format!("agent-{}", "a".repeat(32)));
    assert_eq!(public.len(), 43);
    if let DeviceOperation2::Seal { plaintext, .. } = &mut operation_request.operation {
        plaintext.push(1);
    }
    assert_ne!(first, reg.approval_call(&operation_request)?);
    let other = Registry::new(
        config(),
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.2",
        1,
        time(0),
    )?;
    assert_ne!(
        reg.approval_call(&operation_request)?,
        other.approval_call(&operation_request)?
    );
    let wrapped = ConfidentialRequest::new(operation_request);
    assert_eq!(format!("{wrapped:?}"), "ConfidentialRequest([REDACTED])");
    assert_eq!(format!("{reg:?}"), "Registry([REDACTED])");
    Ok(())
}
#[test]
fn exact_expiry_cancellation_and_reinit_invalidate_old_work_and_handles() -> TestResult {
    let reg = registry()?;
    let (handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let operation_request = request('a', DeviceOperation2::Cancel);
    let work = reg.reserve(&operation_request, 1, time(0))?;
    assert!(reg.validate(&work, 1, time(100)).is_err());
    drop(work);
    let new = reg.reserve(&operation_request, 1, time(100))?;
    assert!(
        reg.execute(&new, &DeviceOperation2::Revoke { handle }, 1, time(100))
            .is_err()
    );
    drop(new);
    let cfg = reg.configuration()?;
    assert!(cfg.scopes.iter().all(|s| s.static_secret.is_none()));
    reg.reconfigure(cfg, 2)?;
    let mut operation_request = request(
        'a',
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    );
    assert!(reg.reserve(&operation_request, 1, time(100)).is_err());
    let pending = reg.reserve(&operation_request, 2, time(100))?;
    operation_request.operation = DeviceOperation2::Cancel;
    let cancel = reg.reserve(&operation_request, 2, time(100))?;
    reg.execute(&cancel, &operation_request.operation, 2, time(100))?;
    assert!(reg.validate(&pending, 2, time(100)).is_err());
    Ok(())
}
#[test]
fn rate_capacity_and_rollback_are_bounded_without_cross_scope_starvation() -> TestResult {
    let mut cfg = config();
    cfg.operations_per_minute = 1;
    cfg.max_in_flight = 1;
    let reg = Registry::new(
        cfg,
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        time(0),
    )?;
    let operation_request = request('a', DeviceOperation2::Cancel);
    let work = reg.reserve(&operation_request, 1, time(0))?;
    assert!(matches!(
        reg.reserve(&request('b', DeviceOperation2::Cancel), 1, time(0)),
        Err(Error::DeviceCapacity)
    ));
    drop(work);
    assert!(matches!(
        reg.reserve(&operation_request, 1, time(0)),
        Err(Error::DeviceRate)
    ));
    drop(reg.reserve(&request('b', DeviceOperation2::Cancel), 1, time(0))?);
    drop(reg.reserve(&operation_request, 1, time(60_000))?);
    assert!(matches!(
        reg.reserve(&operation_request, 1, time(59_999)),
        Err(Error::DeviceClock)
    ));
    assert!(matches!(
        reg.reserve(&operation_request, 1, time(60_001)),
        Err(Error::DeviceClock)
    ));
    assert!(reg.reconfigure(reg.configuration()?, 2).is_ok());
    assert!(reg.reserve(&operation_request, 2, time(60_002)).is_err());
    let other = registry()?;
    other.fail_clock()?;
    assert!(other.reserve(&operation_request, 1, time(0)).is_err());
    Ok(())
}
#[test]
fn bootstrap_failed_tags_do_not_consume_bounded_replay_evidence() -> TestResult {
    let reg = registry()?;
    let (server, public) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (client, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let op = DeviceOperation2::SealHandshake {
        handle: client.clone(),
        peer: public.clone(),
        plaintext: b"private-secret".to_vec(),
    };
    let frame = run(&reg, 'a', op)?.bytes;
    let mut bad = frame.clone();
    *bad.last_mut().ok_or("frame")? ^= 1;
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::OpenHandshake {
                handle: server.clone(),
                frame: bad
            }
        )
        .is_err()
    );
    assert_eq!(
        run(
            &reg,
            'a',
            DeviceOperation2::OpenHandshake {
                handle: server.clone(),
                frame: frame.clone()
            }
        )?
        .bytes,
        b"private-secret"
    );
    run(&reg, 'a', DeviceOperation2::Cancel)?;
    let (new_server, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    assert!(matches!(
        run(
            &reg,
            'a',
            DeviceOperation2::OpenHandshake {
                handle: new_server,
                frame
            }
        ),
        Err(Error::Replay)
    ));
    // A new ephemeral credential receives a different replay binding after cancellation.
    let (client, client_public) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let ack = run(
        &reg,
        'a',
        DeviceOperation2::SealAck {
            handle: key(&reg, 'a', DeviceKeyPurpose2::Static)?.0,
            peer: client_public.clone(),
            plaintext: b"ack".to_vec(),
        },
    )?
    .bytes;
    let op = DeviceOperation2::OpenAck {
        handle: client,
        peer: public,
        frame: ack,
    };
    assert_eq!(run(&reg, 'a', op.clone())?.bytes, b"ack");
    assert!(matches!(run(&reg, 'a', op), Err(Error::Replay)));
    let (client, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    assert!(matches!(
        run(
            &reg,
            'a',
            DeviceOperation2::OpenAck {
                handle: client,
                peer: client_public,
                frame: vec![4; 41]
            }
        ),
        Err(Error::DeviceCapacity)
    ));
    Ok(())
}
#[test]
fn both_native_tunnel_roles_preserve_direction_replay_and_reflection() -> TestResult {
    let reg = registry()?;
    let (static_a, public_a) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (static_b, public_b) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (eph_a, epublic_a) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let (eph_b, epublic_b) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let a = tunnel(
        &reg,
        &static_a,
        &eph_a,
        &public_b,
        &epublic_b,
        DeviceRole2::Client,
    )?;
    let b = tunnel(
        &reg,
        &static_b,
        &eph_b,
        &public_a,
        &epublic_a,
        DeviceRole2::Server,
    )?;
    let frame = run(
        &reg,
        'a',
        DeviceOperation2::Seal {
            handle: a.clone(),
            plaintext: b"private-secret".to_vec(),
        },
    )?
    .bytes;
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::Open {
                handle: a,
                frame: frame.clone()
            }
        )
        .is_err()
    );
    let mut bad = frame.clone();
    *bad.last_mut().ok_or("frame")? ^= 1;
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::Open {
                handle: b.clone(),
                frame: bad
            }
        )
        .is_err()
    );
    assert_eq!(
        run(
            &reg,
            'a',
            DeviceOperation2::Open {
                handle: b.clone(),
                frame: frame.clone()
            }
        )?
        .bytes,
        b"private-secret"
    );
    assert!(matches!(
        run(
            &reg,
            'a',
            DeviceOperation2::Open {
                handle: b.clone(),
                frame
            }
        ),
        Err(Error::Replay)
    ));
    assert!(run(&reg, 'a', DeviceOperation2::Revoke { handle: b.clone() }).is_ok());
    assert!(
        run(
            &reg,
            'a',
            DeviceOperation2::Seal {
                handle: b,
                plaintext: vec![]
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn confidential_frames_reuse_only_a_live_approved_tunnel_capability() -> TestResult {
    let reg = registry()?;
    let (static_a, public_a) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (static_b, public_b) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (eph_a, epublic_a) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let (eph_b, epublic_b) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let client = tunnel(
        &reg,
        &static_a,
        &eph_a,
        &public_b,
        &epublic_b,
        DeviceRole2::Client,
    )?;
    let server = tunnel(
        &reg,
        &static_b,
        &eph_b,
        &public_a,
        &epublic_a,
        DeviceRole2::Server,
    )?;
    let sealed = reg.execute_frame(
        &DeviceFrameRequest2 {
            scope_id: "a".repeat(32),
            handle: client.clone(),
            call_id: "socket-send-1".into(),
            operation: DeviceFrameOperation2::Seal {
                plaintext: b"confidential socket frame".to_vec(),
            },
        },
        1,
        time(0),
    )?;
    let opened = reg.execute_frame(
        &DeviceFrameRequest2 {
            scope_id: "a".repeat(32),
            handle: server.clone(),
            call_id: "socket-receive-1".into(),
            operation: DeviceFrameOperation2::Open {
                frame: sealed.bytes.clone(),
            },
        },
        1,
        time(0),
    )?;
    assert_eq!(opened.bytes, b"confidential socket frame");
    assert!(matches!(
        reg.execute_frame(
            &DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: server.clone(),
                call_id: "socket-receive-replay".into(),
                operation: DeviceFrameOperation2::Open {
                    frame: sealed.bytes.clone(),
                },
            },
            1,
            time(0),
        ),
        Err(Error::Replay)
    ));
    assert!(matches!(
        reg.execute_frame(
            &DeviceFrameRequest2 {
                scope_id: "b".repeat(32),
                handle: server.clone(),
                call_id: "wrong-device".into(),
                operation: DeviceFrameOperation2::Open {
                    frame: sealed.bytes
                },
            },
            1,
            time(0),
        ),
        Err(Error::DeviceDenied)
    ));
    run(
        &reg,
        'a',
        DeviceOperation2::Revoke {
            handle: server.clone(),
        },
    )?;
    assert!(
        reg.execute_frame(
            &DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: server,
                call_id: "after-revoke".into(),
                operation: DeviceFrameOperation2::Seal { plaintext: vec![] },
            },
            1,
            time(0),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn frame_revalidation_rejects_a_tunnel_after_generation_change() -> TestResult {
    let reg = registry()?;
    let (static_handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (ephemeral, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let remote = KeyPair::from_secret(Zeroizing::new([31; 32]))?;
    let remote_ephemeral = KeyPair::from_secret(Zeroizing::new([32; 32]))?;
    let handle = tunnel(
        &reg,
        &static_handle,
        &ephemeral,
        &remote.public_key().encode(),
        &remote_ephemeral.public_key().encode(),
        DeviceRole2::Client,
    )?;
    assert!(
        reg.validate_frame(&"a".repeat(32), &handle, 1, time(0))
            .is_ok()
    );
    run(
        &reg,
        'a',
        DeviceOperation2::Revoke {
            handle: handle.clone(),
        },
    )?;
    assert!(
        reg.validate_frame(&"a".repeat(32), &handle, 1, time(0))
            .is_err()
    );
    let mut next = config();
    for scope in &mut next.scopes {
        scope.static_secret = None;
    }
    reg.reconfigure(next, 2)?;
    assert!(
        reg.validate_frame(&"a".repeat(32), &handle, 1, time(0))
            .is_err()
    );
    Ok(())
}

#[test]
fn paired_tunnel_uses_device_frame_registry_and_transient_retirement() -> TestResult {
    let reg = registry()?;
    let server_static = KeyPair::from_secret(Zeroizing::new([51; 32]))?;
    let client_static = KeyPair::from_secret(Zeroizing::new([52; 32]))?;
    let server_ephemeral = KeyPair::from_secret(Zeroizing::new([53; 32]))?;
    let client_ephemeral = KeyPair::from_secret(Zeroizing::new([54; 32]))?;
    let keys = server_static.session_keys(
        client_static.public_key(),
        &server_ephemeral,
        client_ephemeral.public_key(),
        client_ephemeral.public_key(),
        server_ephemeral.public_key(),
    )?;
    let client_keys = client_static.session_keys(
        server_static.public_key(),
        &client_ephemeral,
        server_ephemeral.public_key(),
        client_ephemeral.public_key(),
        server_ephemeral.public_key(),
    )?;
    let client = Tunnel::new(Role::Client, client_keys);
    let server = Arc::new(Mutex::new(Tunnel::new(Role::Server, keys)));
    let handle = "ab".repeat(16);
    reg.register_paired_tunnel(PairedTunnelRegistration {
        scope_id: &"a".repeat(32),
        handle: &handle,
        tunnel: server.clone(),
        generation: 1,
        expires_wall: 20_000,
        expires_monotonic: 19_000,
        now: time(0),
    })?;
    let sealed = client.seal(b"paired frame")?;
    let opened = reg.execute_frame(
        &DeviceFrameRequest2 {
            scope_id: "a".repeat(32),
            handle: handle.clone(),
            call_id: "paired-frame".into(),
            operation: DeviceFrameOperation2::Open {
                frame: sealed.clone(),
            },
        },
        1,
        time(0),
    )?;
    assert_eq!(opened.bytes, b"paired frame");
    reg.refresh_paired_tunnel(&"a".repeat(32), &handle, 1, 30_000, 29_000, time(1))?;
    assert!(matches!(
        reg.execute_frame(
            &DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: handle.clone(),
                call_id: "paired-frame-replay".into(),
                operation: DeviceFrameOperation2::Open { frame: sealed },
            },
            1,
            time(1),
        ),
        Err(Error::Replay)
    ));
    assert!(
        reg.validate_frame(&"a".repeat(32), &handle, 1, time(1))
            .is_ok()
    );
    reg.retire_paired_tunnel(&handle)?;
    assert!(
        reg.validate_frame(&"a".repeat(32), &handle, 1, time(1))
            .is_err()
    );
    assert!(reg.retire_paired_tunnel(&handle).is_ok());
    let logout_handle = "cd".repeat(16);
    reg.register_paired_tunnel(PairedTunnelRegistration {
        scope_id: &"a".repeat(32),
        handle: &logout_handle,
        tunnel: server,
        generation: 1,
        expires_wall: 30_000,
        expires_monotonic: 29_000,
        now: time(1),
    })?;
    reg.retire_paired_scope(&"a".repeat(32))?;
    assert!(
        reg.validate_frame(&"a".repeat(32), &logout_handle, 1, time(1))
            .is_err()
    );
    assert!(matches!(
        reg.refresh_paired_tunnel_with_clock(
            &"a".repeat(32),
            &logout_handle,
            1,
            40_000,
            39_000,
            || Some(time(0)),
        ),
        Err(Error::DeviceClock)
    ));
    Ok(())
}

#[test]
fn paired_tunnel_retirement_preserves_ordinary_device_handles() -> TestResult {
    let reg = registry()?;
    let (static_handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    assert!(reg.lock()?.handles.contains_key(&static_handle));

    reg.retire_paired_tunnel(&static_handle)?;

    assert!(reg.lock()?.handles.contains_key(&static_handle));
    Ok(())
}

#[test]
fn confidential_frames_enforce_size_limits_expiry_and_replay() -> TestResult {
    let mut cfg = config();
    cfg.max_message_bytes = 4;
    let reg = Registry::new(
        cfg,
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        time(0),
    )?;
    let (static_handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (ephemeral, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let external = KeyPair::from_secret(Zeroizing::new([9; 32]))?;
    let remote_ephemeral = KeyPair::from_secret(Zeroizing::new([10; 32]))?;
    let tunnel_handle = tunnel(
        &reg,
        &static_handle,
        &ephemeral,
        &external.public_key().encode(),
        &remote_ephemeral.public_key().encode(),
        DeviceRole2::Client,
    )?;
    let too_large = reg.execute_frame(
        &DeviceFrameRequest2 {
            scope_id: "a".repeat(32),
            handle: tunnel_handle.clone(),
            call_id: "oversized".into(),
            operation: DeviceFrameOperation2::Seal {
                plaintext: b"12345".to_vec(),
            },
        },
        1,
        time(0),
    );
    assert!(matches!(too_large, Err(Error::Limit)));
    let expired_request = request(
        'a',
        DeviceOperation2::Seal {
            handle: tunnel_handle.clone(),
            plaintext: vec![],
        },
    );
    assert!(
        reg.execute_frame(
            &DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: tunnel_handle,
                call_id: expired_request.call_id,
                operation: DeviceFrameOperation2::Seal { plaintext: vec![] },
            },
            1,
            time(101),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn frame_budget_is_per_tunnel_and_independent_of_control_operations() -> TestResult {
    let mut cfg = config();
    cfg.frames_per_minute = 1;
    cfg.operations_per_minute = 100;
    let reg = Registry::new(
        cfg,
        &[registration(&"a".repeat(32)), registration(&"b".repeat(32))],
        ":1.1",
        1,
        time(0),
    )?;
    let (static_handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let (ephemeral, _) = key(&reg, 'a', DeviceKeyPurpose2::Ephemeral)?;
    let external = KeyPair::from_secret(Zeroizing::new([19; 32]))?;
    let remote_ephemeral = KeyPair::from_secret(Zeroizing::new([20; 32]))?;
    let handle = tunnel(
        &reg,
        &static_handle,
        &ephemeral,
        &external.public_key().encode(),
        &remote_ephemeral.public_key().encode(),
        DeviceRole2::Client,
    )?;
    let frame_request = |call_id: &str| DeviceFrameRequest2 {
        scope_id: "a".repeat(32),
        handle: handle.clone(),
        call_id: call_id.into(),
        operation: DeviceFrameOperation2::Seal {
            plaintext: b"x".to_vec(),
        },
    };
    reg.execute_frame(&frame_request("frame-1"), 1, time(0))?;
    assert!(matches!(
        reg.execute_frame(&frame_request("frame-2"), 1, time(0)),
        Err(Error::DeviceRate)
    ));
    // The independent control plane remains available after a frame budget is exhausted.
    key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    Ok(())
}

#[test]
fn invalid_initialization_inputs_and_every_operation_shape_fail_closed() -> TestResult {
    let regs = [registration(&"a".repeat(32)), registration(&"b".repeat(32))];
    let init = |cfg, rs: &[ApprovalScope2], peer, generation| {
        Registry::new(cfg, rs, peer, generation, time(0))
    };
    assert!(init(config(), &regs, "well.known", 1).is_err());
    assert!(init(config(), &regs, ":1.1", 0).is_err());
    assert!(init(config(), &[], ":1.1", 1).is_err());
    let mut runtime_only = config();
    runtime_only.scopes.clear();
    assert!(init(runtime_only, &regs, ":1.1", 1).is_ok());
    let mut duplicate = config();
    duplicate.scopes.push(duplicate.scopes[0].clone());
    assert!(init(duplicate, &regs, ":1.1", 1).is_err());
    for change in 1..9 {
        let mut cfg = config();
        match change {
            1 => cfg.max_handles = 0,
            2 => cfg.max_in_flight = 33,
            3 => cfg.operations_per_minute = 0,
            4 => cfg.max_ttl_ms = 300_001,
            5 => cfg.max_message_bytes = 1_048_577,
            6 => cfg.max_bootstrap_nonces = 0,
            7 => cfg.frames_per_minute = 0,
            _ => cfg.frames_per_minute = 60_001,
        }
        assert!(init(cfg, &regs, ":1.1", 1).is_err());
    }
    let mut rs = regs.clone();
    rs[0].auto_approve_all = true;
    assert!(init(config(), &rs, ":1.1", 1).is_err());
    let mut cfg = config();
    cfg.scopes[0].static_secret = Some([0; 32]);
    assert!(init(cfg, &regs, ":1.1", 1).is_err());
    let reg = registry()?;
    let mut operation_request = request('a', DeviceOperation2::Cancel);
    operation_request.call_id.clear();
    assert!(reg.reserve(&operation_request, 1, time(0)).is_err());
    operation_request.call_id = "call".into();
    operation_request.ttl_ms = 0;
    assert!(reg.reserve(&operation_request, 1, time(0)).is_err());
    operation_request.ttl_ms = 101;
    assert!(reg.reserve(&operation_request, 1, time(0)).is_err());
    for op in [
        DeviceOperation2::Seal {
            handle: "a".repeat(65),
            plaintext: vec![],
        },
        DeviceOperation2::SealAck {
            handle: "a".repeat(64),
            peer: "p".into(),
            plaintext: vec![0; 1001],
        },
        DeviceOperation2::OpenAck {
            handle: "a".repeat(64),
            peer: "p".into(),
            frame: vec![],
        },
        DeviceOperation2::OpenHandshake {
            handle: "a".repeat(64),
            frame: vec![0; 1074],
        },
    ] {
        assert!(reg.reserve(&request('a', op), 1, time(0)).is_err());
    }
    let mut cfg = reg.configuration()?;
    cfg.scopes[0].static_secret = Some([1; 32]);
    assert!(reg.reconfigure(cfg, 2).is_err());
    assert!(reg.reconfigure(reg.configuration()?, 1).is_err());
    let cfg = ConfidentialConfig::new(Some(config()));
    assert!(cfg.configuration().is_some());
    assert_eq!(format!("{cfg:?}"), "ConfidentialConfig([REDACTED])");
    Ok(())
}

#[test]
fn closing_retained_registry_drops_native_keys_and_denies_every_old_reservation() -> TestResult {
    let reg = registry()?;
    let weak = Arc::downgrade(&reg.lock()?.scopes[&"a".repeat(32)].key);
    let (handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    let operation_request = request('a', DeviceOperation2::Revoke { handle });
    let work = reg.reserve(&operation_request, 1, time(0))?;
    let observer = reg.clone();
    reg.close();
    assert!(weak.upgrade().is_none());
    assert!(
        observer
            .execute(&work, &operation_request.operation, 1, time(0))
            .is_err()
    );
    assert!(observer.reserve(&operation_request, 1, time(0)).is_err());
    assert!(observer.lock()?.scopes.is_empty());
    Ok(())
}

#[test]
fn canonical_secret_serialization_never_reallocates_written_plaintext()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: "call".into(),
        ttl_ms: 100,
        operation: DeviceOperation2::Seal {
            handle: "f".repeat(64),
            plaintext: vec![255; 8192],
        },
    };
    let canonical = canonical_request(&request)?;
    assert!(
        !canonical.grew,
        "serializer grew a buffer after confidential bytes were written"
    );
    assert_eq!(&*canonical.bytes, &serde_json::to_vec(&request)?);
    Ok(())
}

#[test]
fn bounded_canonical_writer_preserves_maximum_escaping_and_refuses_growth()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let request = DeviceRequest2 {
        scope_id: "\0".repeat(128),
        call_id: "\0".repeat(128),
        ttl_ms: u32::MAX,
        operation: DeviceOperation2::SealAck {
            handle: "\0".repeat(64),
            peer: "\0".repeat(64),
            plaintext: vec![255; 1 << 20],
        },
    };
    let canonical = canonical_request(&request)?;
    assert!(!canonical.grew);
    assert_eq!(&*canonical.bytes, &serde_json::to_vec(&request)?);
    let mut full = CanonicalRequest {
        bytes: Zeroizing::new(Vec::with_capacity(1)),
        grew: false,
    };
    full.write_all(&[7])?;
    assert!(full.write_all(&[8]).is_err());
    assert_eq!(&*full.bytes, &[7]);
    assert_eq!(full.bytes.capacity(), 1);
    let mut oversized = request;
    oversized.call_id.push('a');
    assert!(canonical_request(&oversized).is_err());
    Ok(())
}

#[test]
fn epoch_exhaustion_rejects_reconfiguration_without_partial_mutation() -> TestResult {
    let reg = registry()?;
    let (handle, _) = key(&reg, 'a', DeviceKeyPurpose2::Static)?;
    reg.lock()?
        .scopes
        .get_mut(&"b".repeat(32))
        .ok_or(Error::DeviceDenied)?
        .epoch = u64::MAX;
    let cfg = reg.configuration()?;
    assert!(reg.reconfigure(cfg.clone(), 2).is_err());
    let state = reg.lock()?;
    assert_eq!(state.generation, 1);
    assert_eq!(state.scopes[&"a".repeat(32)].epoch, 1);
    assert!(state.handles.contains_key(&handle));
    assert_eq!(state.limits, cfg);
    Ok(())
}

#[test]
fn clock_sampling_is_serialized_with_registry_state_transitions() -> TestResult {
    use std::sync::mpsc;

    let registry = registry()?;
    let (sampled_tx, sampled_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let earlier_registry = registry.clone();
    let earlier = std::thread::spawn(move || {
        earlier_registry.execute_frame_with_clock(
            &DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: "missing-frame-handle".into(),
                call_id: "earlier-clock-sample".into(),
                operation: DeviceFrameOperation2::Seal {
                    plaintext: b"frame".to_vec(),
                },
            },
            1,
            || {
                sampled_tx.send(()).ok()?;
                release_rx.recv().ok()?;
                Some(time(1))
            },
        )
    });
    sampled_rx.recv()?;

    // The old adapter sampled before entering the registry. Prove whether the first callback
    // still owns the state lock while paused; if it does not, commit the later observation first
    // to deterministically recreate the old out-of-order transition.
    let sample_order_was_unlocked = match registry.0.try_lock() {
        Ok(state) => {
            drop(state);
            assert!(matches!(
                registry.execute_frame_with_clock(
                    &DeviceFrameRequest2 {
                        scope_id: "a".repeat(32),
                        handle: "missing-frame-handle".into(),
                        call_id: "later-clock-sample".into(),
                        operation: DeviceFrameOperation2::Seal {
                            plaintext: b"frame".to_vec(),
                        },
                    },
                    1,
                    || Some(time(2)),
                ),
                Err(Error::DeviceDenied)
            ));
            true
        }
        Err(std::sync::TryLockError::WouldBlock) => false,
        Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::DeviceDenied.into()),
    };
    release_tx.send(())?;

    let earlier_result = earlier.join().map_err(|_| Error::DeviceDenied)?;
    assert!(matches!(earlier_result, Err(Error::DeviceDenied)));
    assert!(
        !sample_order_was_unlocked,
        "clock callback ran outside registry lock"
    );
    assert!(matches!(
        registry.execute_frame_with_clock(
            &DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: "still-missing".into(),
                call_id: "after-concurrent-clock-samples".into(),
                operation: DeviceFrameOperation2::Seal {
                    plaintext: b"frame".to_vec(),
                },
            },
            1,
            || Some(time(3)),
        ),
        Err(Error::DeviceDenied)
    ));
    Ok(())
}

#[test]
fn a_genuine_clock_rollback_still_faults_registry_authority() -> TestResult {
    let registry = registry()?;
    let request = DeviceFrameRequest2 {
        scope_id: "a".repeat(32),
        handle: "missing-frame-handle".into(),
        call_id: "clock-rollback".into(),
        operation: DeviceFrameOperation2::Seal {
            plaintext: b"frame".to_vec(),
        },
    };
    assert!(matches!(
        registry.execute_frame_with_clock(&request, 1, || Some(time(2))),
        Err(Error::DeviceDenied)
    ));
    assert!(matches!(
        registry.execute_frame_with_clock(&request, 1, || Some(time(1))),
        Err(Error::DeviceClock)
    ));
    assert!(matches!(
        registry.execute_frame_with_clock(&request, 1, || Some(time(3))),
        Err(Error::DeviceClock)
    ));
    Ok(())
}

#[test]
fn frame_admission_is_released_during_crypto_unwind() -> TestResult {
    let reg = registry()?;
    let mut state = reg.lock()?;
    let State { budget, scopes, .. } = &mut *state;
    let scope = scopes.get_mut(&"a".repeat(32)).ok_or(Error::DeviceDenied)?;
    assert!(budget.reserve(&mut scope.rate, 0, 1, 12_000).is_ok());
    drop(state);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = reg.with_frame_reservation(|| -> Result<()> {
            std::panic::resume_unwind(Box::new("crypto unwind"));
        });
    }));
    assert!(unwind.is_err());
    assert!(!reg.lock()?.budget.full(1));
    Ok(())
}
