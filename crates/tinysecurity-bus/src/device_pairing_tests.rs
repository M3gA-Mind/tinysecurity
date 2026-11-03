use super::*;
use crate::CONTRACT_VERSION;
use crate::Origin;
use serde_json::json;

#[test]
fn pairing_request_carries_only_event_or_receipt_and_confidential_protocol_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let request = DevicePairingRequest2 {
        call_id: "pair-1".into(),
        operation: DevicePairingOperation2::Begin {
            host_event_id: "event-1".into(),
        },
    };
    let encoded = serde_json::to_value(&request)?;
    assert_eq!(
        encoded,
        json!({
            "call_id": "pair-1",
            "operation": {"kind": "begin", "host_event_id": "event-1"}
        })
    );
    assert!(
        serde_json::from_value::<DevicePairingRequest2>(json!({
            "call_id": "pair-1",
            "scope_id": "caller-asserted",
            "operation": {"kind": "begin", "host_event_id": "event-1"}
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn pairing_request_and_response_debug_redact_protocol_bytes_and_receipts() {
    let request = DevicePairingRequest2 {
        call_id: "pair-1".into(),
        operation: DevicePairingOperation2::Confirm {
            receipt: "private-receipt".into(),
            host_event_id: "event-2".into(),
            frame: vec![1, 2, 3],
        },
    };
    let response = DevicePairingResponse2 {
        receipt: Some("private-receipt".into()),
        pairing_id: None,
        session_id: None,
        core_public_key: None,
        device_public_key: None,
        frame: vec![4, 5, 6],
        expires_at_ms: 42,
    };
    assert_eq!(format!("{request:?}"), "DevicePairingRequest2([REDACTED])");
    assert_eq!(
        format!("{response:?}"),
        "DevicePairingResponse2([REDACTED])"
    );
}

#[test]
fn refresh_and_close_are_distinct_transient_session_operations() {
    let refresh = DevicePairingRequest2 {
        call_id: "refresh-1".into(),
        operation: DevicePairingOperation2::RefreshSession {
            session_id: "module-session".into(),
            host_event_id: "socket-event".into(),
        },
    };
    let close = DevicePairingRequest2 {
        call_id: "close-1".into(),
        operation: DevicePairingOperation2::EndSession {
            session_id: "module-session".into(),
            host_event_id: "close-event".into(),
        },
    };
    assert!(format!("{refresh:?}").contains("REDACTED"));
    assert!(format!("{close:?}").contains("REDACTED"));
    let lock = DevicePairingRequest2 {
        call_id: "logout-1".into(),
        operation: DevicePairingOperation2::Lock {
            host_event_id: "logout-event".into(),
        },
    };
    assert!(format!("{lock:?}").contains("REDACTED"));
}

#[test]
fn pairing_contract_is_versioned_after_the_frame_contract() {
    assert_eq!(CONTRACT_VERSION, (1, 35));
}

#[test]
fn runtime_pairing_registration_contains_only_a_live_approval_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let request = RegisterDevicePairingScopeRequest2 {
        approval_scope_id: "a".repeat(32),
    };
    let encoded = serde_json::to_value(&request)?;
    assert_eq!(encoded, json!({ "approval_scope_id": "a".repeat(32) }));
    for forbidden in [
        "subject",
        "user",
        "secret_registration_id",
        "master_alias",
        "persistence_backend_id",
        "origin",
    ] {
        let mut forged = encoded.clone();
        forged[forbidden] = json!("caller-controlled");
        assert!(serde_json::from_value::<RegisterDevicePairingScopeRequest2>(forged).is_err());
    }
    let receipt = DevicePairingScopeReceipt2 {
        scope_id: "a".repeat(32),
        active: true,
    };
    assert_eq!(
        serde_json::from_value::<DevicePairingScopeReceipt2>(serde_json::to_value(
            receipt.clone()
        )?)?,
        receipt
    );
    Ok(())
}

#[test]
fn persistence_response_echoes_fixed_scope_and_backend_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let response = DevicePairingPersistenceResponse2 {
        backend_id: "backend-a".into(),
        scope_id: "scope-a".into(),
        secret_registration_id: "registration-a".into(),
        revision: "rev-1".into(),
        ciphertext: Some(b"enc2:opaque".to_vec()),
    };
    let encoded = serde_json::to_value(&response)?;
    assert_eq!(encoded["scope_id"], "scope-a");
    assert_eq!(encoded["backend_id"], "backend-a");
    assert_eq!(encoded["secret_registration_id"], "registration-a");
    assert!(format!("{response:?}").contains("REDACTED"));
    Ok(())
}

#[test]
fn runtime_scope_defaults_are_init_only_and_redacted() {
    let defaults = DevicePairingRuntimeScope2 {
        persistence_backend_id: "pairing-state".into(),
        legacy_device_backend_id: Some("a".repeat(32)),
        allowed_origins: vec![Origin::Operator],
    };
    assert_eq!(
        format!("{defaults:?}"),
        "DevicePairingRuntimeScope2([REDACTED])"
    );
}

#[test]
fn legacy_import_and_recovery_requests_carry_no_key_or_authority_claims()
-> Result<(), Box<dyn std::error::Error>> {
    for operation in [
        DevicePairingOperation2::ImportLegacy {
            host_event_id: "user-event".into(),
        },
        DevicePairingOperation2::Recover {
            channel_id: "host-known-channel".into(),
            host_event_id: "user-event".into(),
        },
    ] {
        let request = DevicePairingRequest2 {
            call_id: "user-controller-call".into(),
            operation,
        };
        let encoded = serde_json::to_value(&request)?;
        assert!(encoded.get("scope_id").is_none());
        assert!(encoded.get("user_binding").is_none());
        assert!(encoded.get("private_key").is_none());
        assert!(format!("{request:?}").contains("REDACTED"));
    }
    Ok(())
}

#[test]
fn legacy_source_callback_is_bounded_and_echoes_every_fixed_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let request = DevicePairingLegacyLoadRequest2 {
        handle: "one-shot-import-handle".into(),
    };
    let response = DevicePairingLegacyLoadResponse2 {
        scope_id: "scope-a".into(),
        user_binding: "user-a".into(),
        generation: 9,
        backend_id: "legacy-device-store".into(),
        source_registration_id: "legacy-key-registration".into(),
        records: vec![DevicePairingLegacyRecord2 {
            channel_id: "channel-a".into(),
            device_public_key: "device-public-key".into(),
            format: DevicePairingLegacyFormat2::Enc2,
            ciphertext: b"enc2:opaque".to_vec(),
            revoked: false,
        }],
    };
    let wire = serde_json::to_value(&response)?;
    assert_eq!(wire["generation"], 9);
    assert_eq!(wire["backend_id"], "legacy-device-store");
    assert_eq!(wire["source_registration_id"], "legacy-key-registration");
    assert_eq!(wire["records"][0]["revoked"], false);
    assert!(format!("{request:?}").contains("REDACTED"));
    assert!(format!("{response:?}").contains("REDACTED"));
    assert!(!format!("{response:?}").contains("enc2:opaque"));
    Ok(())
}
