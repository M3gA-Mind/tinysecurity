use super::*;
#[test]
fn audited_permission_wire_carries_original_request_and_correlation_without_caller_verdicts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let wire = serde_json::json!({
        "request": { "caller": {
            "agent": "private-agent", "thread": null, "flow": null,
            "call_id": "private-call", "origin": "operator", "tier": "full"
        }, "checks": [{"kind": "local_diagnostic"}] },
        "audit": { "event_id": "a".repeat(32), "expected_tail": 0, "generation": 1 }
    });
    let request: CheckAuditedRequest2 = serde_json::from_value(wire.clone())?;
    assert_eq!(serde_json::to_value(&request)?, wire);
    assert!(!format!("{request:?}").contains("private-"));
    for field in ["verdict", "arguments_json", "committed", "original_binding"] {
        let mut forged = wire.clone();
        forged[field] = true.into();
        assert!(serde_json::from_value::<CheckAuditedRequest2>(forged).is_err());
    }
    let mut forged = wire;
    forged["audit"]["scope"] = "other-user".into();
    assert!(serde_json::from_value::<CheckAuditedRequest2>(forged).is_err());
    let response = AuditedResponse2 {
        decision: crate::CheckResponse {
            generation: 1,
            decisions: vec![],
        },
        audit: crate::AuditResponse2 {
            permitted: false,
            committed: false,
            health: crate::AuditHealth2::Denied,
            receipt: None,
        },
    };
    assert_eq!(
        serde_json::from_value::<CheckAuditedResponse2>(serde_json::to_value(&response)?)?,
        response
    );
    Ok(())
}
#[test]
fn scoped_audited_wire_wraps_the_scoped_request_with_correlation_and_rejects_forgery()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let wire = serde_json::json!({
        "request": {
            "policy_id": "policy-ref",
            "caller": {
                "agent": "private-agent", "thread": null, "flow": null,
                "call_id": "private-call", "origin": "operator", "tier": "full"
            },
            "checks": [{"kind": "local_diagnostic"}]
        },
        "audit": { "event_id": "a".repeat(32), "expected_tail": 0, "generation": 1 }
    });
    let request: CheckScopedAuditedRequest = serde_json::from_value(wire.clone())?;
    assert_eq!(serde_json::to_value(&request)?, wire);
    assert!(!format!("{request:?}").contains("private-"));
    let mut forged = wire.clone();
    forged["verdict"] = true.into();
    assert!(serde_json::from_value::<CheckScopedAuditedRequest>(forged).is_err());
    let evaluate = serde_json::json!({
        "request": {
            "policy_id": "policy-ref",
            "caller": wire["request"]["caller"].clone(),
            "call": {
                "tool": "local_diagnostic",
                "arguments_json": "{}",
                "checks": [{"kind": "local_diagnostic"}]
            }
        },
        "audit": wire["audit"].clone()
    });
    let request: EvaluateScopedAuditedRequest = serde_json::from_value(evaluate.clone())?;
    assert_eq!(serde_json::to_value(&request)?, evaluate);
    let denied = crate::AuditResponse2 {
        permitted: false,
        committed: false,
        health: crate::AuditHealth2::Denied,
        receipt: None,
    };
    let response = EvaluateScopedAuditedResponse {
        decision: crate::ScopedDecision {
            decision: crate::Decision {
                generation: 1,
                verdict: crate::Verdict::Allow,
                cacheable: false,
            },
            policy_generation: 1,
            fingerprint: "f".repeat(64),
        },
        audit: denied.clone(),
    };
    assert_eq!(
        serde_json::from_value::<EvaluateScopedAuditedResponse>(serde_json::to_value(&response)?)?,
        response
    );
    let checks = CheckScopedAuditedResponse {
        decision: crate::ScopedCheckResponse {
            policy_generation: 1,
            fingerprint: "f".repeat(64),
            decisions: vec![],
        },
        audit: denied,
    };
    assert_eq!(
        serde_json::from_value::<CheckScopedAuditedResponse>(serde_json::to_value(&checks)?)?,
        checks
    );
    Ok(())
}

#[test]
fn audited_native_permission_vocabulary_rejects_execution_and_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let request = crate::PermissionAuditRequest2 {
        request: crate::PermissionRequest2::ValidateParent(crate::PathValidationRequest {
            policy_id: crate::PathPolicyId("fixture-path".into()),
            path: "/workspace/uploads/file".into(),
        }),
        audit: crate::AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    let value = serde_json::to_value(&request)?;
    let decoded: crate::PermissionAuditRequest2 = serde_json::from_value(value.clone())?;
    assert_eq!(serde_json::to_value(decoded)?, value);
    assert!(!format!("{request:?}").contains("workspace"));
    assert_eq!(
        format!("{:?}", request.request),
        "PermissionRequest2([REDACTED])"
    );
    let mut stateful = value.clone();
    stateful["request"]["operation"] = serde_json::json!("spend_action");
    assert!(serde_json::from_value::<crate::PermissionAuditRequest2>(stateful).is_err());
    let mut injected = value;
    injected["request"]["authorized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<crate::PermissionAuditRequest2>(injected).is_err());
    Ok(())
}
