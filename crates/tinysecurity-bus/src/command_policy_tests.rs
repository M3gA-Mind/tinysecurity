use super::*;

#[test]
fn audited_command_check_preserves_the_typed_request_wire_shape() -> Result<(), serde_json::Error> {
    let request = CheckCommandAuditedRequest2 {
        request: CommandRequest {
            policy_id: CommandPolicyId("scope".into()),
            command: "pwd".into(),
            declared_class: None,
        },
        audit: crate::AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 4,
            generation: 7,
        },
    };

    assert_eq!(
        serde_json::to_value(&request)?,
        serde_json::json!({
            "request": {
                "policy_id": "scope",
                "command": "pwd",
                "declared_class": null
            },
            "audit": {
                "event_id": "a".repeat(32),
                "expected_tail": 4,
                "generation": 7
            }
        })
    );
    assert!(!format!("{request:?}").contains("pwd"));
    Ok(())
}
