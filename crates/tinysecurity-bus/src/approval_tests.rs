use super::*;
#[test]
fn legacy_execution_outcomes_are_explicit_and_unknown_values_reject() {
    assert_eq!(
        ExecutionOutcome::from_legacy("success"),
        Ok(ExecutionOutcome::Succeeded)
    );
    assert_eq!(
        ExecutionOutcome::from_legacy("failure"),
        Ok(ExecutionOutcome::Failed)
    );
    assert_eq!(
        ExecutionOutcome::from_legacy("aborted"),
        Ok(ExecutionOutcome::Cancelled)
    );
    assert!(ExecutionOutcome::from_legacy("approved").is_err());
}
#[test]
fn human_ticket_wire_is_strict_and_debug_never_discloses_opaque_authority()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = DecideRequest2 {
        scope_id: "scope-private".into(),
        request_id: "request-private".into(),
        decision_ticket: "ticket-private".into(),
        audit: AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    let mut value = serde_json::to_value(&request)?;
    assert_eq!(
        serde_json::from_value::<DecideRequest2>(value.clone())?,
        request
    );
    value["human"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<DecideRequest2>(value).is_err());
    assert_eq!(format!("{request:?}"), "DecideRequest2([REDACTED])");
    Ok(())
}

#[test]
fn purge_session_debug_redacts_the_raw_session_identity() {
    let request = PurgeApprovalSessionRequest2 {
        session_id: "private-session-id".into(),
    };

    assert_eq!(
        format!("{request:?}"),
        "PurgeApprovalSessionRequest2([REDACTED])"
    );
}
