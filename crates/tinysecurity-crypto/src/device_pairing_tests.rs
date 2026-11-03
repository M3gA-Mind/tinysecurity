// Small deterministic cryptographic fixtures use unwraps to keep each negative assertion focused;
// production paths remain fully fallible and the test-only allowance does not propagate upward.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::device::PublicKey;

const SCOPE: &str = "0123456789abcdef0123456789abcdef";

fn config() -> DevicePairingConfig2 {
    DevicePairingConfig2 {
        scopes: vec![tinysecurity_bus::DevicePairingScope2 {
            scope_id: SCOPE.into(),
            secret_registration_id: "abcdef0123456789abcdef0123456789".into(),
            persistence_backend_id: "user-secret-store".into(),
            legacy_device_backend_id: None,
            legacy_source_registration_id: None,
        }],
        runtime_scope: None,
        max_pairings: 8,
        max_pending: 4,
        max_pending_ttl_ms: 60_000,
        max_session_ttl_ms: 604_800_000,
        max_state_bytes: 65_536,
        callback_timeout_ms: 1000,
    }
}
fn time(ms: u64) -> Time {
    Time {
        wall: ms,
        monotonic: ms,
    }
}
fn context(
    source: DevicePairingSource2,
    channel: &str,
    nonce: &str,
    expiry: u64,
) -> DevicePairingContextResponse2 {
    DevicePairingContextResponse2 {
        scope_id: SCOPE.into(),
        user_binding: "user-binding".into(),
        secret_master_handle: None,
        legacy_import_handle: None,
        channel_id: channel.into(),
        pairing_token: (!channel.is_empty()).then(|| "host-pairing-token".into()),
        connection_nonce: nonce.into(),
        generation: 1,
        source,
        expires_at_ms: expiry,
    }
}
fn owner() -> DevicePairingOwner {
    DevicePairingOwner::new(
        config(),
        1,
        time(1_000),
        [(SCOPE.into(), Zeroizing::new([0x41; 32]))].into(),
    )
    .unwrap()
}

#[test]
fn handshake_payload_accepts_legacy_raw_device_key() {
    let device = KeyPair::generate().unwrap();
    let frame_ephemeral = KeyPair::generate().unwrap().public_key();
    let payload =
        parse_handshake_payload(device.public_key().encode().as_bytes(), &frame_ephemeral).unwrap();
    assert_eq!(payload.device_pubkey, device.public_key().encode());
    assert_eq!(payload.client_ephemeral_pubkey, frame_ephemeral.encode());
}

#[test]
fn handshake_rejects_a_substituted_host_pairing_token() {
    let mut owner = owner();
    let (receipt, core_public, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    let core = PublicKey::decode(&core_public).unwrap();
    let device = KeyPair::generate().unwrap();
    let frame_ephemeral = KeyPair::generate().unwrap();
    let session_ephemeral = KeyPair::generate().unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": device.public_key().encode(),
        "client_ephemeral_pubkey": session_ephemeral.public_key().encode(),
    }))
    .unwrap();
    let frame = frame_ephemeral.seal_handshake(core, &payload).unwrap();
    let mut substituted = context(
        DevicePairingSource2::RegisteredSocket,
        "channel-a",
        "nonce-a",
        10_000,
    );
    substituted.pairing_token = Some("attacker-token".into());
    assert!(
        owner
            .handshake(&receipt, &substituted, &frame, time(1_001))
            .is_err()
    );
}
fn start_handshake(
    owner: &mut DevicePairingOwner,
    receipt: &str,
    channel: &str,
    nonce: &str,
    device: &KeyPair,
    now: u64,
) -> (Tunnel, Vec<u8>) {
    let core = PublicKey::decode(&owner.public_key(SCOPE, time(now)).unwrap()).unwrap();
    let client_handshake_ephemeral = KeyPair::generate().unwrap();
    let client_session_ephemeral = KeyPair::generate().unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": device.public_key().encode(),
        "client_ephemeral_pubkey": client_session_ephemeral.public_key().encode(),
    }))
    .unwrap();
    let frame = client_handshake_ephemeral
        .seal_handshake(core, &payload)
        .unwrap();
    let ack = owner
        .handshake(
            receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                channel,
                nonce,
                10_000,
            ),
            &frame,
            time(now + 1),
        )
        .unwrap();
    let ack_payload: serde_json::Value =
        serde_json::from_slice(&client_session_ephemeral.open_ack(core, &ack).unwrap()).unwrap();
    let server_ephemeral =
        PublicKey::decode(ack_payload["server_ephemeral_pubkey"].as_str().unwrap()).unwrap();
    let keys = device
        .session_keys(
            core,
            &client_session_ephemeral,
            server_ephemeral,
            client_session_ephemeral.public_key(),
            server_ephemeral,
        )
        .unwrap();
    (Tunnel::new(Role::Client, keys), ack)
}

fn start_handshake_with_core(
    owner: &mut DevicePairingOwner,
    receipt: &str,
    core_public: &str,
    channel: &str,
    nonce: &str,
    device: &KeyPair,
    now: u64,
) -> Tunnel {
    let core = PublicKey::decode(core_public).unwrap();
    let client_handshake_ephemeral = KeyPair::generate().unwrap();
    let client_session_ephemeral = KeyPair::generate().unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": device.public_key().encode(),
        "client_ephemeral_pubkey": client_session_ephemeral.public_key().encode(),
    }))
    .unwrap();
    let frame = client_handshake_ephemeral
        .seal_handshake(core, &payload)
        .unwrap();
    let ack = owner
        .handshake(
            receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                channel,
                nonce,
                30_000,
            ),
            &frame,
            time(now),
        )
        .unwrap();
    let ack_payload: serde_json::Value =
        serde_json::from_slice(&client_session_ephemeral.open_ack(core, &ack).unwrap()).unwrap();
    let server_ephemeral =
        PublicKey::decode(ack_payload["server_ephemeral_pubkey"].as_str().unwrap()).unwrap();
    let keys = device
        .session_keys(
            core,
            &client_session_ephemeral,
            server_ephemeral,
            client_session_ephemeral.public_key(),
            server_ephemeral,
        )
        .unwrap();
    Tunnel::new(Role::Client, keys)
}

#[test]
fn enrollment_requires_first_static_key_authenticated_frame_and_durable_commit() {
    let mut owner = owner();
    let (receipt, core_public, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    assert_eq!(core_public, owner.public_key(SCOPE, time(1_001)).unwrap());
    let device = KeyPair::generate().unwrap();
    let (mut client, _) =
        start_handshake(&mut owner, &receipt, "channel-a", "nonce-a", &device, 1_001);
    let proof = client.seal(b"authenticated first frame").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            &proof,
            time(1_003),
        )
        .unwrap();
    assert_ne!(prepared.state_to_encrypt().first(), None);
    assert!(
        owner
            .seal("not-yet-committed", SCOPE, b"x", time(1_003))
            .is_err()
    );
    let result = owner.commit_confirmation(prepared, time(1_004)).unwrap();
    assert_eq!(result.device_public_key, device.public_key().encode());
    let sealed = owner
        .seal(
            &result.session_id,
            SCOPE,
            b"after durable commit",
            time(1_005),
        )
        .unwrap();
    assert_eq!(&*client.open(&sealed).unwrap(), b"after durable commit");
    assert!(
        owner
            .prepare_confirmation(
                &receipt,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "channel-a",
                    "nonce-a",
                    10_000
                ),
                &proof,
                time(1_006)
            )
            .is_err()
    );
}

#[test]
fn invalid_channel_ids_are_rejected_before_begin_or_renewal() {
    for invalid_channel in ["channel.with.dot".to_owned(), "c".repeat(129)] {
        let mut fresh = owner();
        assert!(
            fresh
                .begin(
                    &context(
                        DevicePairingSource2::AuthenticatedUserController,
                        &invalid_channel,
                        "nonce-a",
                        10_000,
                    ),
                    5_000,
                    time(1_001),
                )
                .is_err(),
            "Begin must reject invalid channel ids before accepting pending state"
        );

        let mut existing = owner();
        let paired = existing
            .import_legacy_identities(
                &context(
                    DevicePairingSource2::AuthenticatedUserController,
                    "valid-channel",
                    "nonce-existing",
                    10_000,
                ),
                vec![LegacyDeviceIdentity {
                    channel_id: "valid-channel".into(),
                    device_public_key: KeyPair::generate().unwrap().public_key().encode(),
                    core_private_key: Zeroizing::new([0x52; 32]),
                    revoked: false,
                }],
                time(1_001),
            )
            .unwrap();
        assert!(
            existing
                .renew(
                    &paired[0].pairing_id,
                    &context(
                        DevicePairingSource2::BackendReconnect,
                        &invalid_channel,
                        "nonce-b",
                        10_000,
                    ),
                    5_000,
                    time(1_002),
                )
                .is_err(),
            "Renew must reject invalid channel ids before accepting pending state"
        );
    }
}

#[test]
fn renewal_requires_same_static_key_and_fresh_context() {
    let mut owner = owner();
    let device = KeyPair::generate().unwrap();
    let (receipt, _, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    let (client, _) = start_handshake(&mut owner, &receipt, "channel-a", "nonce-a", &device, 1_001);
    let proof = client.seal(b"proof").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            &proof,
            time(1_003),
        )
        .unwrap();
    let paired = owner.commit_confirmation(prepared, time(1_004)).unwrap();
    let (renewal, _, _) = owner
        .renew(
            &paired.pairing_id,
            &context(
                DevicePairingSource2::BackendReconnect,
                "channel-b",
                "nonce-b",
                20_000,
            ),
            5_000,
            time(1_005),
        )
        .unwrap();
    let impostor = KeyPair::generate().unwrap();
    let core = PublicKey::decode(&owner.public_key(SCOPE, time(1_006)).unwrap()).unwrap();
    let handshake_ephemeral = KeyPair::generate().unwrap();
    let session_ephemeral = KeyPair::generate().unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "device_pubkey": impostor.public_key().encode(),
        "client_ephemeral_pubkey": session_ephemeral.public_key().encode(),
    }))
    .unwrap();
    let frame = handshake_ephemeral.seal_handshake(core, &payload).unwrap();
    assert!(
        owner
            .handshake(
                &renewal,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "channel-b",
                    "nonce-b",
                    20_000
                ),
                &frame,
                time(1_007)
            )
            .is_err()
    );
}

fn renewed_owner_with_history() -> (DevicePairingOwner, KeyPair, PairingResult) {
    let mut owner = owner();
    let device = KeyPair::generate().unwrap();
    let (receipt, _, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    let (client, _) = start_handshake(&mut owner, &receipt, "channel-a", "nonce-a", &device, 1_001);
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            &client.seal(b"initial proof").unwrap(),
            time(1_003),
        )
        .unwrap();
    let paired = owner.commit_confirmation(prepared, time(1_004)).unwrap();

    // Build enough legitimate channel history that converting each retained channel
    // to its standalone tombstone is larger than the active record representation.
    for index in 0..8 {
        let now = 1_005 + index * 3;
        let channel = format!("channel-{index}");
        let nonce = format!("nonce-{index}");
        let (renewal, _, _) = owner
            .renew(
                &paired.pairing_id,
                &context(
                    DevicePairingSource2::BackendReconnect,
                    &channel,
                    &nonce,
                    30_000,
                ),
                5_000,
                time(now),
            )
            .unwrap();
        let (tunnel, _) = start_handshake(&mut owner, &renewal, &channel, &nonce, &device, now + 1);
        let prepared = owner
            .prepare_confirmation(
                &renewal,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    &channel,
                    &nonce,
                    30_000,
                ),
                &tunnel.seal(b"renewal proof").unwrap(),
                time(now + 2),
            )
            .unwrap();
        owner.commit_confirmation(prepared, time(now + 3)).unwrap();
    }

    (owner, device, paired)
}

fn install_second_long_record(owner: &mut DevicePairingOwner, pairing_id: &str) -> String {
    let second_key = KeyPair::from_secret(Zeroizing::new([0x42; 32])).unwrap();
    let second_identity = "independent-identity".to_string();
    owner.identities.insert(
        second_identity.clone(),
        Identity {
            secret: Zeroizing::new([0x42; 32]),
            key: KeyPair::from_secret(Zeroizing::new([0x42; 32])).unwrap(),
        },
    );
    let mut second_record = owner.records.get(pairing_id).unwrap().clone();
    second_record.id = random_id().unwrap();
    second_record.device_key = second_key.public_key().encode();
    second_record.identity_id = second_identity;
    second_record.channel = "other-channel-7".into();
    second_record.channels = (0..8)
        .map(|index| format!("other-channel-{index}"))
        .collect();
    second_record.nonce = "other-nonce".into();
    let second_pairing_id = second_record.id.clone();
    owner
        .records
        .insert(second_pairing_id.clone(), second_record);
    second_pairing_id
}

fn candidate_snapshot_sizes(
    owner: &DevicePairingOwner,
    pairing_id: &str,
) -> (usize, usize, usize, BTreeMap<String, Record>) {
    let compact = owner.snapshot_state().unwrap();
    let mut renewed_record = owner.records.get(pairing_id).unwrap().clone();
    renewed_record.channel = "channel-b".into();
    renewed_record.channels.insert("channel-b".into());
    renewed_record.nonce = "nonce-b".into();
    let mut renewed_records = owner.records.clone();
    renewed_records.insert(pairing_id.into(), renewed_record);
    let candidate_bytes = owner.snapshot(&renewed_records).unwrap().len();
    let revocable_bytes = owner
        .snapshot_after_revoking(&renewed_records, pairing_id)
        .unwrap()
        .len();
    assert!(compact.len() <= candidate_bytes);
    assert!(revocable_bytes > candidate_bytes);
    (
        compact.len(),
        candidate_bytes,
        revocable_bytes,
        renewed_records,
    )
}

fn revocation_reserve(records: &BTreeMap<String, Record>) -> usize {
    records.values().fold(0usize, |total, record| {
        let tombstones = record
            .channels
            .iter()
            .map(|channel| Revocation {
                scope: record.scope.clone(),
                user: record.user.clone(),
                channel: channel.clone(),
                pairing_id: record.id.clone(),
            })
            .collect::<Vec<_>>();
        let tombstone_bytes = serde_json::to_vec(&tombstones)
            .unwrap()
            .len()
            .saturating_sub(2)
            .saturating_add(tombstones.len());
        let record_bytes = serde_json::to_vec(record).unwrap().len();
        total.saturating_add(tombstone_bytes.saturating_sub(record_bytes))
    })
}

#[test]
fn renewal_is_rejected_when_its_future_revocation_would_overflow_state() {
    let (mut owner, device, paired) = renewed_owner_with_history();
    let second_pairing_id = install_second_long_record(&mut owner, &paired.pairing_id);
    let (compact_bytes, candidate_bytes, revocable_bytes, renewed_records) =
        candidate_snapshot_sizes(&owner, &paired.pairing_id);
    owner.config.max_state_bytes = u32::try_from(candidate_bytes).unwrap();
    assert!(compact_bytes <= owner.config.max_state_bytes as usize);
    assert!(revocable_bytes > owner.config.max_state_bytes as usize);

    let (renewal, _, _) = owner
        .renew(
            &paired.pairing_id,
            &context(
                DevicePairingSource2::BackendReconnect,
                "channel-b",
                "nonce-b",
                20_000,
            ),
            5_000,
            time(1_035),
        )
        .unwrap();
    let (renewal_tunnel, _) =
        start_handshake(&mut owner, &renewal, "channel-b", "nonce-b", &device, 1_036);
    let error = owner.prepare_confirmation(
        &renewal,
        &context(
            DevicePairingSource2::RegisteredSocket,
            "channel-b",
            "nonce-b",
            20_000,
        ),
        &renewal_tunnel.seal(b"renewal proof").unwrap(),
        time(1_038),
    );
    assert!(error.is_err());
    assert!(owner.snapshot_state().is_ok());
    assert!(owner.records.contains_key(&paired.pairing_id));
    assert!(
        owner
            .revoke(
                &paired.pairing_id,
                &context(
                    DevicePairingSource2::AuthenticatedUserController,
                    "controller-channel",
                    "controller-nonce",
                    30_000,
                ),
                time(1_039),
            )
            .is_err()
    );
    assert!(owner.records.contains_key(&paired.pairing_id));

    let reserve = revocation_reserve(&renewed_records);
    owner.config.max_state_bytes = u32::try_from(candidate_bytes + reserve).unwrap();
    let prepared = owner
        .prepare_confirmation(
            &renewal,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-b",
                "nonce-b",
                20_000,
            ),
            &renewal_tunnel.seal(b"renewal proof").unwrap(),
            time(1_040),
        )
        .unwrap();
    owner.commit_confirmation(prepared, time(1_041)).unwrap();
    owner
        .revoke(
            &paired.pairing_id,
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "controller-channel",
                "controller-nonce",
                30_000,
            ),
            time(1_042),
        )
        .unwrap();
    owner
        .revoke(
            &second_pairing_id,
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "controller-channel",
                "controller-nonce",
                30_000,
            ),
            time(1_043),
        )
        .unwrap();
    assert!(owner.snapshot_state().is_ok());
}

#[test]
fn socket_close_retires_only_the_tunnel_and_reconnect_keeps_the_pairing() {
    let mut owner = owner();
    let device = KeyPair::generate().unwrap();
    let (receipt, _, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    let (client, _) = start_handshake(&mut owner, &receipt, "channel-a", "nonce-a", &device, 1_001);
    let proof = client.seal(b"proof").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            &proof,
            time(1_003),
        )
        .unwrap();
    let paired = owner.commit_confirmation(prepared, time(1_004)).unwrap();
    owner
        .end_session(
            &paired.session_id,
            &context(
                DevicePairingSource2::SocketClosed,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            time(1_005),
        )
        .unwrap();
    assert!(
        owner
            .refresh_session(
                &paired.session_id,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "channel-a",
                    "nonce-a",
                    20_000,
                ),
                time(1_006),
            )
            .is_err()
    );
    assert!(
        owner
            .seal(&paired.session_id, SCOPE, b"closed", time(1_006))
            .is_err()
    );
    assert!(
        owner
            .renew(
                &paired.pairing_id,
                &context(
                    DevicePairingSource2::BackendReconnect,
                    "channel-b",
                    "nonce-b",
                    20_000
                ),
                5_000,
                time(1_006)
            )
            .is_ok()
    );
}

#[test]
fn stale_socket_close_cannot_retire_a_newly_renewed_session() {
    let mut owner = owner();
    let device = KeyPair::generate().unwrap();
    let (receipt, _, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    let (client, _) = start_handshake(&mut owner, &receipt, "channel-a", "nonce-a", &device, 1_001);
    let proof = client.seal(b"proof").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            &proof,
            time(1_003),
        )
        .unwrap();
    let first = owner.commit_confirmation(prepared, time(1_004)).unwrap();
    let (renewal, _, _) = owner
        .renew(
            &first.pairing_id,
            &context(
                DevicePairingSource2::BackendReconnect,
                "channel-b",
                "nonce-b",
                20_000,
            ),
            5_000,
            time(1_005),
        )
        .unwrap();
    let (mut reconnect, _) =
        start_handshake(&mut owner, &renewal, "channel-b", "nonce-b", &device, 1_006);
    let proof = reconnect.seal(b"fresh proof").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &renewal,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-b",
                "nonce-b",
                20_000,
            ),
            &proof,
            time(1_008),
        )
        .unwrap();
    let second = owner.commit_confirmation(prepared, time(1_009)).unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(owner.session_expiries.len(), 1);
    assert!(!owner.session_expiries.contains_key(&first.session_id));
    assert!(
        owner
            .end_session(
                &first.session_id,
                &context(
                    DevicePairingSource2::SocketClosed,
                    "channel-a",
                    "nonce-a",
                    10_000
                ),
                time(1_010)
            )
            .is_err()
    );
    let sealed = owner
        .seal(&second.session_id, SCOPE, b"still live", time(1_011))
        .unwrap();
    assert_eq!(&*reconnect.open(&sealed).unwrap(), b"still live");
}

#[test]
fn live_session_refresh_preserves_tunnel_keys_and_replay_counters() {
    let mut owner = owner();
    let device = KeyPair::generate().unwrap();
    let (receipt, _, _) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            5_000,
            time(1_000),
        )
        .unwrap();
    let (mut client, _) =
        start_handshake(&mut owner, &receipt, "channel-a", "nonce-a", &device, 1_001);
    let proof = client.seal(b"proof").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                10_000,
            ),
            &proof,
            time(1_003),
        )
        .unwrap();
    let paired = owner.commit_confirmation(prepared, time(1_004)).unwrap();
    let frame = client.seal(b"one-use frame").unwrap();
    assert_eq!(
        &*owner
            .open(&paired.session_id, SCOPE, &frame, time(1_005))
            .unwrap(),
        b"one-use frame"
    );
    let refreshed = owner
        .refresh_session(
            &paired.session_id,
            &context(
                DevicePairingSource2::RegisteredSocket,
                "channel-a",
                "nonce-a",
                50_000,
            ),
            time(1_006),
        )
        .unwrap();
    assert!(refreshed.0 > paired.expires_at_ms);
    assert!(
        owner
            .open(&paired.session_id, SCOPE, &frame, time(1_007))
            .is_err()
    );
    let sealed = owner
        .seal(&paired.session_id, SCOPE, b"same tunnel", time(1_008))
        .unwrap();
    assert_eq!(&*client.open(&sealed).unwrap(), b"same tunnel");
    assert!(
        owner
            .refresh_session(
                &paired.session_id,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "channel-a",
                    "stale-nonce",
                    60_000,
                ),
                time(1_009),
            )
            .is_err()
    );
    assert!(
        owner
            .refresh_session(
                &paired.session_id,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "channel-a",
                    "nonce-a",
                    60_000,
                ),
                time(refreshed.0),
            )
            .is_err()
    );
}

#[test]
fn restore_preserves_public_identity_and_rejects_corrupt_or_foreign_state() {
    let mut owner = owner();
    let public = owner.public_key(SCOPE, time(1_001)).unwrap();
    let snapshot = owner.snapshot(&owner.records).unwrap();
    let mut restored = DevicePairingOwner::restore(config(), 2, time(2_000), &snapshot).unwrap();
    assert_eq!(restored.public_key(SCOPE, time(2_001)).unwrap(), public);
    assert!(DevicePairingOwner::restore(config(), 2, time(2_000), b"tampered").is_err());
    let foreign = context(
        DevicePairingSource2::AuthenticatedUserController,
        "channel-x",
        "nonce-x",
        10_000,
    );
    assert!(owner.begin(&foreign, 5_000, time(1_002)).is_ok());
}

#[test]
fn renewal_cannot_claim_another_pairings_or_revoked_channel() {
    let mut owner = owner();
    let first_secret = Zeroizing::new([0x51; 32]);
    let second_secret = Zeroizing::new([0x62; 32]);
    let first_device = KeyPair::generate().unwrap();
    let second_device = KeyPair::generate().unwrap();
    let imported = owner
        .import_legacy_identities(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "",
                "",
                10_000,
            ),
            vec![
                LegacyDeviceIdentity {
                    channel_id: "channel-first".into(),
                    device_public_key: first_device.public_key().encode(),
                    core_private_key: first_secret,
                    revoked: false,
                },
                LegacyDeviceIdentity {
                    channel_id: "channel-second".into(),
                    device_public_key: second_device.public_key().encode(),
                    core_private_key: second_secret,
                    revoked: false,
                },
            ],
            time(1_010),
        )
        .unwrap();
    let first_id = &imported[0].pairing_id;
    let second_id = &imported[1].pairing_id;
    assert!(
        owner
            .renew(
                first_id,
                &context(
                    DevicePairingSource2::BackendReconnect,
                    "channel-second",
                    "renew-collision",
                    10_000,
                ),
                5_000,
                time(1_020),
            )
            .is_err()
    );
    owner
        .revoke(
            second_id,
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "channel-second",
                "revoke",
                10_000,
            ),
            time(1_030),
        )
        .unwrap();
    assert!(
        owner
            .renew(
                first_id,
                &context(
                    DevicePairingSource2::BackendReconnect,
                    "channel-second",
                    "renew-tombstone",
                    10_000,
                ),
                5_000,
                time(1_040),
            )
            .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn imported_channel_identities_survive_reload_and_select_the_original_wire_key() {
    let mut owner = owner();
    let first_secret = Zeroizing::new([0x51; 32]);
    let second_secret = Zeroizing::new([0x62; 32]);
    let first_public = KeyPair::from_secret(Zeroizing::new(*first_secret))
        .unwrap()
        .public_key()
        .encode();
    let second_public = KeyPair::from_secret(Zeroizing::new(*second_secret))
        .unwrap()
        .public_key()
        .encode();
    assert_ne!(first_public, second_public);
    let first_device = KeyPair::generate().unwrap();
    let second_device = KeyPair::generate().unwrap();
    let imported = owner
        .import_legacy_identities(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "",
                "",
                10_000,
            ),
            vec![
                LegacyDeviceIdentity {
                    channel_id: "legacy-channel-a".into(),
                    device_public_key: first_device.public_key().encode(),
                    core_private_key: first_secret,
                    revoked: false,
                },
                LegacyDeviceIdentity {
                    channel_id: "legacy-channel-b".into(),
                    device_public_key: second_device.public_key().encode(),
                    core_private_key: second_secret,
                    revoked: false,
                },
            ],
            time(1_010),
        )
        .unwrap();
    assert_eq!(imported.len(), 2);
    let first = imported
        .iter()
        .find(|record| record.channel_id == "legacy-channel-a")
        .unwrap();
    let second = imported
        .iter()
        .find(|record| record.channel_id == "legacy-channel-b")
        .unwrap();
    assert_eq!(first.core_public_key, first_public);
    assert_eq!(second.core_public_key, second_public);
    let snapshot = owner.snapshot_state().unwrap();
    let mut restored = DevicePairingOwner::restore(config(), 1, time(1_020), &snapshot).unwrap();
    assert_eq!(
        restored
            .core_public_key_for_pairing(&first.pairing_id, time(1_021))
            .unwrap(),
        first_public
    );
    assert_eq!(
        restored
            .core_public_key_for_pairing(&second.pairing_id, time(1_022))
            .unwrap(),
        second_public
    );
    for (ordinal, imported, device, expected_public) in [
        (0_u64, first, &first_device, &first_public),
        (1_u64, second, &second_device, &second_public),
    ] {
        let _ = assert_legacy_wire_renewal(
            &mut restored,
            imported,
            device,
            expected_public,
            1_030 + ordinal * 10,
        );
    }
}

fn assert_legacy_wire_renewal(
    owner: &mut DevicePairingOwner,
    imported: &ImportedDevicePairing,
    device: &KeyPair,
    expected_public: &str,
    start: u64,
) -> String {
    let channel = format!("legacy-renewal-{start}");
    let nonce = format!("legacy-nonce-{start}");
    let (receipt, core_public, _) = owner
        .renew(
            &imported.pairing_id,
            &context(
                DevicePairingSource2::BackendReconnect,
                &channel,
                &nonce,
                30_000,
            ),
            5_000,
            time(start),
        )
        .unwrap();
    assert_eq!(core_public, expected_public);
    let client = start_handshake_with_core(
        owner,
        &receipt,
        expected_public,
        &channel,
        &nonce,
        device,
        start + 1,
    );
    let proof = client.seal(b"legacy device possession").unwrap();
    let prepared = owner
        .prepare_confirmation(
            &receipt,
            &context(
                DevicePairingSource2::RegisteredSocket,
                &channel,
                &nonce,
                30_000,
            ),
            &proof,
            time(start + 2),
        )
        .unwrap();
    owner
        .commit_confirmation(prepared, time(start + 3))
        .unwrap();
    channel
}

#[test]
fn renewed_pairing_keeps_legacy_channel_claim_until_every_channel_is_revoked() {
    let mut one_pairing_config = config();
    one_pairing_config.max_pairings = 1;
    let mut owner = DevicePairingOwner::new(
        one_pairing_config.clone(),
        1,
        time(1_000),
        [(SCOPE.into(), Zeroizing::new([0x41; 32]))].into(),
    )
    .unwrap();
    let secret = Zeroizing::new([0x73; 32]);
    let device = KeyPair::generate().unwrap();
    let device_public_key = device.public_key().encode();
    let authorized = context(
        DevicePairingSource2::AuthenticatedUserController,
        "",
        "",
        30_000,
    );
    let imported = owner
        .import_legacy_identities(
            &authorized,
            vec![LegacyDeviceIdentity {
                channel_id: "legacy-original".into(),
                device_public_key: device_public_key.clone(),
                core_private_key: Zeroizing::new(*secret),
                revoked: false,
            }],
            time(1_010),
        )
        .unwrap();
    let migrated_channel = assert_legacy_wire_renewal(
        &mut owner,
        &imported[0],
        &device,
        &imported[0].core_public_key,
        1_020,
    );
    let reimported = owner
        .import_legacy_identities(
            &authorized,
            vec![LegacyDeviceIdentity {
                channel_id: "legacy-original".into(),
                device_public_key,
                core_private_key: Zeroizing::new(*secret),
                revoked: false,
            }],
            time(1_030),
        )
        .unwrap();
    assert_eq!(reimported[0].pairing_id, imported[0].pairing_id);
    assert_eq!(owner.records.len(), 1);

    let renewed_context = context(
        DevicePairingSource2::AuthenticatedUserController,
        &migrated_channel,
        "revoke",
        30_000,
    );
    owner
        .revoke(&imported[0].pairing_id, &renewed_context, time(1_031))
        .unwrap();
    let snapshot = owner.snapshot_state().unwrap();
    let mut restored =
        DevicePairingOwner::restore(one_pairing_config.clone(), 1, time(1_040), &snapshot).unwrap();
    let mut merged = DevicePairingOwner::new(
        one_pairing_config,
        1,
        time(1_040),
        [(SCOPE.into(), Zeroizing::new([0x41; 32]))].into(),
    )
    .unwrap();
    let recovery_context = DevicePairingContextResponse2 {
        channel_id: migrated_channel.clone(),
        pairing_token: None,
        connection_nonce: String::new(),
        ..authorized.clone()
    };
    merged
        .merge_recovered_durable_state(&snapshot, &recovery_context, time(1_040))
        .unwrap();
    assert!(merged.records.is_empty());
    assert_eq!(merged.revocations.len(), 2);
    for (channel, nonce) in [
        ("legacy-original", "new-original"),
        (&migrated_channel, "new-migrated"),
    ] {
        assert!(
            restored
                .begin(
                    &context(
                        DevicePairingSource2::AuthenticatedUserController,
                        channel,
                        nonce,
                        30_000
                    ),
                    5_000,
                    time(1_041),
                )
                .is_err()
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn legacy_import_is_atomic_idempotent_and_channel_recovery_is_user_scoped() {
    let mut owner = owner();
    let secret = Zeroizing::new([0x73; 32]);
    let device_key = KeyPair::generate().unwrap();
    let device = device_key.public_key().encode();
    let rows = || {
        vec![LegacyDeviceIdentity {
            channel_id: "legacy-channel-a".into(),
            device_public_key: device.clone(),
            core_private_key: Zeroizing::new(*secret),
            revoked: false,
        }]
    };
    let authorized = context(
        DevicePairingSource2::AuthenticatedUserController,
        "",
        "",
        10_000,
    );
    let imported = owner
        .import_legacy_identities(&authorized, rows(), time(1_010))
        .unwrap();
    let again = owner
        .import_legacy_identities(&authorized, rows(), time(1_011))
        .unwrap();
    assert_eq!(again, imported);
    let authorized_channel = DevicePairingContextResponse2 {
        channel_id: "legacy-channel-a".into(),
        pairing_token: None,
        connection_nonce: String::new(),
        ..authorized.clone()
    };
    let recovered = owner
        .recover_channel("legacy-channel-a", &authorized_channel, time(1_012))
        .unwrap();
    assert_eq!(recovered.pairing_id, imported[0].pairing_id);
    assert_eq!(recovered.device_public_key, device);
    let durable = owner.snapshot_state().unwrap();
    let mut reloaded = DevicePairingOwner::new(
        config(),
        1,
        time(1_012),
        [(SCOPE.into(), Zeroizing::new([0x41; 32]))].into(),
    )
    .unwrap();
    assert!(
        reloaded
            .merge_recovered_durable_state(&durable, &authorized_channel, time(1_012))
            .is_ok()
    );
    let foreign = DevicePairingContextResponse2 {
        user_binding: "another-user".into(),
        ..authorized.clone()
    };
    assert!(
        owner
            .recover_channel(
                "legacy-channel-a",
                &DevicePairingContextResponse2 {
                    channel_id: "legacy-channel-a".into(),
                    ..foreign
                },
                time(1_013),
            )
            .is_err()
    );
    assert!(
        owner
            .recover_channel(
                "legacy-channel-a",
                &DevicePairingContextResponse2 {
                    connection_nonce: "stale-socket-nonce".into(),
                    ..authorized_channel.clone()
                },
                time(1_013),
            )
            .is_err()
    );
    assert!(
        owner
            .recover_channel(
                "legacy-channel-a",
                &DevicePairingContextResponse2 {
                    channel_id: "another-channel".into(),
                    ..authorized_channel.clone()
                },
                time(1_013),
            )
            .is_err()
    );
    assert!(
        owner
            .recover_channel(
                "legacy-channel-a",
                &DevicePairingContextResponse2 {
                    pairing_token: Some("reused-qr-token".into()),
                    ..authorized_channel.clone()
                },
                time(1_013),
            )
            .is_err()
    );
    let conflicting = vec![LegacyDeviceIdentity {
        channel_id: "legacy-channel-a".into(),
        device_public_key: KeyPair::generate().unwrap().public_key().encode(),
        core_private_key: Zeroizing::new([0x74; 32]),
        revoked: false,
    }];
    assert!(
        owner
            .import_legacy_identities(&authorized, conflicting, time(1_014))
            .is_err()
    );
    assert_eq!(owner.records.len(), 1);
    let (pending_renewal, renewed_core, _) = owner
        .renew(
            &imported[0].pairing_id,
            &context(
                DevicePairingSource2::BackendReconnect,
                "legacy-channel-a",
                "renewal-nonce",
                10_000,
            ),
            5_000,
            time(1_014),
        )
        .unwrap();
    let renewal_tunnel = start_handshake_with_core(
        &mut owner,
        &pending_renewal,
        &renewed_core,
        "legacy-channel-a",
        "renewal-nonce",
        &device_key,
        1_014,
    );
    let stale_proof = renewal_tunnel.seal(b"proof before revoke").unwrap();
    assert_eq!(
        owner.pending_for_pairing(&imported[0].pairing_id),
        vec![pending_renewal.clone()]
    );
    let tombstone = owner
        .revoke(&imported[0].pairing_id, &authorized, time(1_015))
        .unwrap();
    assert_eq!(
        owner.pending_for_pairing(&imported[0].pairing_id),
        Vec::<String>::new()
    );
    assert!(
        owner
            .handshake(
                &pending_renewal,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "legacy-channel-a",
                    "renewal-nonce",
                    20_000,
                ),
                b"stale receipt",
                time(1_016),
            )
            .is_err(),
        "revocation invalidates an already-issued renewal receipt"
    );
    assert!(
        owner
            .prepare_confirmation(
                &pending_renewal,
                &context(
                    DevicePairingSource2::RegisteredSocket,
                    "legacy-channel-a",
                    "renewal-nonce",
                    20_000,
                ),
                &stale_proof,
                time(1_016),
            )
            .is_err(),
        "a proof from a revoked renewal cannot confirm"
    );
    assert!(
        owner
            .begin(
                &context(
                    DevicePairingSource2::AuthenticatedUserController,
                    "legacy-channel-a",
                    "replacement-nonce",
                    20_000,
                ),
                5_000,
                time(1_016),
            )
            .is_err(),
        "a fresh enrollment cannot reuse a tombstoned channel"
    );
    let (_, _, expiry) = owner
        .begin(
            &context(
                DevicePairingSource2::AuthenticatedUserController,
                "different-channel",
                "fresh-nonce",
                20_000,
            ),
            5_000,
            time(1_016),
        )
        .unwrap();
    assert!(expiry > 1_016, "a different channel remains available");
    assert!(PublicKey::decode(&renewed_core).is_ok());
    let mut reloaded = DevicePairingOwner::restore(config(), 1, time(1_016), &tombstone).unwrap();
    let stale_legacy = vec![LegacyDeviceIdentity {
        channel_id: "legacy-channel-a".into(),
        device_public_key: device,
        core_private_key: Zeroizing::new([0x73; 32]),
        revoked: false,
    }];
    assert!(
        reloaded
            .import_legacy_identities(&authorized, stale_legacy, time(1_017))
            .is_err()
    );
    assert!(reloaded.records.is_empty());
    assert_eq!(reloaded.revocations.len(), 1);
    assert_eq!(
        reloaded.pending_for_pairing(&imported[0].pairing_id),
        Vec::<String>::new()
    );
}

#[test]
fn persistence_backend_identifiers_reject_oversized_and_control_names() {
    for backend in ["", "backend\nname", &"x".repeat(129)] {
        let mut config = config();
        config.scopes[0].persistence_backend_id = backend.into();
        assert!(
            DevicePairingOwner::new(
                config,
                1,
                time(1000),
                [(SCOPE.into(), Zeroizing::new([0x41; 32]))].into()
            )
            .is_err()
        );
    }
}
