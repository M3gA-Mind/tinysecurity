use super::*;

#[test]
fn frame_requests_and_responses_pin_the_confidential_wire_shape()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = DeviceFrameRequest2 {
        scope_id: "registered-device".into(),
        handle: "opaque-tunnel-handle".into(),
        call_id: "socket-frame-17".into(),
        operation: DeviceFrameOperation2::Seal {
            plaintext: b"device payload".to_vec(),
        },
    };
    let wire = serde_json::json!({
        "scope_id":"registered-device",
        "handle":"opaque-tunnel-handle",
        "call_id":"socket-frame-17",
        "operation":{"kind":"seal","plaintext":[100,101,118,105,99,101,32,112,97,121,108,111,97,100]}
    });
    assert_eq!(serde_json::to_value(&request)?, wire);
    assert_eq!(
        serde_json::from_value::<DeviceFrameRequest2>(wire)?,
        request
    );
    assert_eq!(format!("{request:?}"), "DeviceFrameRequest2([REDACTED])");

    let mut forged = serde_json::to_value(&request)?;
    forged["agent"] = serde_json::json!("model-controlled");
    assert!(serde_json::from_value::<DeviceFrameRequest2>(forged).is_err());

    let response = DeviceFrameResponse2 {
        bytes: vec![0, 128, 255],
    };
    assert_eq!(
        serde_json::to_value(&response)?,
        serde_json::json!({"bytes":[0,128,255]})
    );
    assert_eq!(format!("{response:?}"), "DeviceFrameResponse2([REDACTED])");
    Ok(())
}

#[test]
fn frame_operations_redact_both_payloads_without_changing_open_wire_shape()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let seal = DeviceFrameOperation2::Seal {
        plaintext: b"private seal payload".to_vec(),
    };
    let open = DeviceFrameOperation2::Open {
        frame: b"private open frame".to_vec(),
    };

    for operation in [&seal, &open] {
        let debug = format!("{operation:?}");
        assert_eq!(debug, "DeviceFrameOperation2([REDACTED])");
        assert!(!debug.contains("private"));
    }

    let wire = serde_json::to_value(&open)?;
    assert_eq!(
        wire,
        serde_json::json!({
            "kind": "open",
            "frame": b"private open frame"
        })
    );
    assert_eq!(serde_json::from_value::<DeviceFrameOperation2>(wire)?, open);
    Ok(())
}

#[test]
fn frame_member_name_is_stable_and_contract_version_is_bumped() {
    assert_eq!(crate::names::methods::DEVICE_FRAME2, "DeviceFrame2");
    assert_eq!(crate::CONTRACT_VERSION, (1, 35));
    assert!(crate::is_compatible((1, 35)));
    assert!(crate::is_compatible((1, 36)));
    assert!(!crate::is_compatible((1, 34)));
    assert!(!crate::is_compatible((1, 33)));
    assert!(!crate::is_compatible((1, 29)));
    assert!(!crate::is_compatible((2, 30)));
}
