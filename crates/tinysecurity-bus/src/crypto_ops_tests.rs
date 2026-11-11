use super::*;
use serde_json::json;

#[test]
fn password_wire_matches_legacy_byte_array_shape() -> Result<(), Box<dyn std::error::Error>> {
    let payload = PasswordPayload2 {
        ciphertext: vec![1],
        nonce: vec![2],
        salt: vec![3],
    };
    assert_eq!(
        serde_json::to_value(&payload)?,
        json!({"ciphertext":[1],"nonce":[2],"salt":[3]})
    );
    let op = PasswordOperation2::Encrypt {
        password: "p".into(),
        plaintext: vec![9],
        salt: None,
    };
    assert_eq!(
        serde_json::to_value(&op)?,
        json!({"kind":"encrypt","password":"p","plaintext":[9],"salt":null})
    );
    Ok(())
}

#[test]
fn unknown_fields_and_identity_claims_are_rejected() {
    let forged = json!({"account":"a","operation":{"kind":"status"},"peer":"x"});
    assert!(serde_json::from_value::<PairingRequest2>(forged).is_err());
    let request = json!({
        "operation": {"kind":"get","name":"n"},
        "purpose": "p",
        "caller": {"agent":"a","thread":null,"flow":null,"call_id":"c","origin":"operator","tier":"full"},
        "subject": "forged"
    });
    assert!(serde_json::from_value::<KeyringRequest2>(request).is_err());
}

#[test]
fn secret_bearing_types_never_debug_their_contents() {
    let request = PasswordRequest2 {
        operation: PasswordOperation2::Decrypt {
            password: "hunter2".into(),
            payload: PasswordPayload2 {
                ciphertext: vec![0xAA; 20],
                nonce: vec![0; 12],
                salt: vec![0; 16],
            },
        },
    };
    let shown = format!("{request:?}");
    assert!(!shown.contains("hunter2"));
    assert_eq!(shown, "PasswordRequest2([REDACTED])");
    let account = PairingAccount2 {
        scope: "s".into(),
        provider: "p".into(),
        account: "a".into(),
        lifecycle: "l".into(),
        require_pairing: true,
        tokens: vec!["bearer-secret".into()],
    };
    assert!(!format!("{account:?}").contains("bearer-secret"));
}

#[test]
fn config_round_trips_and_omits_absent_sections() -> Result<(), Box<dyn std::error::Error>> {
    let config = CryptoConfig2 {
        max_payload_bytes: 4096,
        operations_per_minute: 60,
        keyring: Some(KeyringConfig2 {
            service: "openhuman".into(),
            backend: KeyringBackend2::EncryptedFile {
                directory: "/tmp/x".into(),
            },
            consent_timeout_ms: 1000,
            read_grant: None,
        }),
        pairing: None,
    };
    let wire = serde_json::to_value(&config)?;
    assert_eq!(
        wire,
        json!({
            "max_payload_bytes":4096,
            "operations_per_minute":60,
            "keyring":{"service":"openhuman","backend":{"kind":"encrypted_file","directory":"/tmp/x"},"consent_timeout_ms":1000}
        })
    );
    assert_eq!(serde_json::from_value::<CryptoConfig2>(wire)?, config);
    Ok(())
}

#[test]
fn pairing_bearer_never_appears_in_debug_output() {
    let operation = PairingOperation2::Authenticate {
        bearer: "bearer-secret".into(),
    };
    assert_eq!(format!("{operation:?}"), "PairingOperation2([REDACTED])");
    let request = PairingRequest2 {
        account: "a".into(),
        operation,
    };
    assert!(!format!("{request:?}").contains("bearer-secret"));
}

#[test]
fn read_grant_fields_stay_off_the_wire_unless_offered() -> Result<(), Box<dyn std::error::Error>> {
    let request = KeyringConsentRequest2 {
        caller: CallerContext::default(),
        purpose: "read a token".into(),
        access: KeyringAccess2::Read,
        name: "user:token".into(),
        timeout_ms: 1000,
        offer: None,
    };
    assert!(serde_json::to_value(&request)?.get("offer").is_none());
    let offered = KeyringConsentRequest2 {
        offer: Some(KeyringReadGrant2 { max_ttl_ms: 60_000 }),
        ..request
    };
    assert_eq!(
        serde_json::to_value(&offered)?["offer"],
        json!({"max_ttl_ms":60000})
    );
    let plain: KeyringConsentResponse2 = serde_json::from_value(json!({"outcome":"allowed"}))?;
    assert_eq!(plain.grant, None);
    assert!(serde_json::to_value(&plain)?.get("grant").is_none());
    let granted: KeyringConsentResponse2 =
        serde_json::from_value(json!({"outcome":"allowed","grant":{"ttl_ms":5000}}))?;
    assert_eq!(granted.grant, Some(KeyringGrant2 { ttl_ms: 5000 }));
    assert_eq!(
        serde_json::to_value(KeyringOperation2::RevokeGrants { name: None })?,
        json!({"kind":"revoke_grants"})
    );
    assert_eq!(
        serde_json::to_value(KeyringOperation2::RevokeGrants {
            name: Some("user:token".into())
        })?,
        json!({"kind":"revoke_grants","name":"user:token"})
    );
    let config: KeyringConfig2 = serde_json::from_value(json!({
        "service":"openhuman",
        "backend":{"kind":"os"},
        "consent_timeout_ms":1000,
        "read_grant":{"max_ttl_ms":86_400_000}
    }))?;
    assert_eq!(
        config.read_grant,
        Some(KeyringReadGrant2 {
            max_ttl_ms: 86_400_000
        })
    );
    Ok(())
}
