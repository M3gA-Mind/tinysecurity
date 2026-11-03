use super::*;

#[test]
fn a_host_action_class_follows_permission_and_external_effect() {
    use CommandClass::{Destructive, Network, Read, Write};
    use ToolPermission as P;
    for (permission, external_effect, class) in [
        (P::None, false, Read),
        (P::ReadOnly, false, Read),
        (P::None, true, Network),
        (P::ReadOnly, true, Network),
        (P::Write, false, Write),
        (P::Execute, false, Write),
        (P::Write, true, Network),
        (P::Execute, true, Network),
        (P::Dangerous, false, Destructive),
        (P::Dangerous, true, Destructive),
    ] {
        let request = HostActionClassRequest2 {
            permission,
            external_effect,
        };
        assert_eq!(
            request.class(),
            class,
            "{permission:?} external={external_effect}"
        );
    }
}

#[test]
fn budget_decisions_have_stable_tagged_wire_forms() -> Result<(), serde_json::Error> {
    for (decision, wire) in [
        (BudgetDecision2::Allow, r#"{"status":"allow"}"#),
        (
            BudgetDecision2::ReadOnlyMode,
            r#"{"status":"read_only_mode"}"#,
        ),
        (
            BudgetDecision2::RateLimited { max_per_hour: 7 },
            r#"{"status":"rate_limited","max_per_hour":7}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&decision)?, wire);
        assert_eq!(serde_json::from_str::<BudgetDecision2>(wire)?, decision);
    }
    assert!(
        serde_json::from_str::<BudgetRequest2>(r#"{"command_policy":"p","spend":true}"#).is_err()
    );
    Ok(())
}

#[test]
fn member_names_are_stable_and_advertised() {
    for (name, wire) in [
        (crate::names::methods::SPEND_ACTION2, "SpendAction2"),
        (crate::names::methods::PEEK_BUDGET2, "PeekBudget2"),
        (
            crate::names::methods::RESERVE_ACTION_BUDGET_AUDITED2,
            "ReserveActionBudgetAudited2",
        ),
        (
            crate::names::methods::CLASSIFY_HOST_ACTION2,
            "ClassifyHostAction2",
        ),
    ] {
        assert_eq!(name, wire);
        assert!(crate::names::METHODS.contains(&name));
    }
}

#[test]
fn audited_reservation_reuses_the_stable_audit_event_as_operation_identity()
-> Result<(), serde_json::Error> {
    let request: crate::ReserveActionBudgetAuditedRequest2 = serde_json::from_str(
        r#"{"request":{"command_policy":"policy-1"},"audit":{"event_id":"0123456789abcdef0123456789abcdef","expected_tail":4,"generation":7}}"#,
    )?;
    assert_eq!(request.request.command_policy.0, "policy-1");
    assert_eq!(request.audit.event_id, "0123456789abcdef0123456789abcdef");
    assert_eq!(request.audit.expected_tail, 4);
    assert_eq!(request.audit.generation, 7);

    let response = crate::ReserveActionBudgetAuditedResponse2 {
        decision: BudgetDecision2::Allow,
        audit: crate::AuditResponse2 {
            permitted: true,
            committed: true,
            health: crate::AuditHealth2::Healthy,
            receipt: Some(crate::AuditSinkResponse2 {
                scope: crate::SubjectScope {
                    user: "user".into(),
                    workspace: "workspace".into(),
                    agent: "agent".into(),
                },
                stream_id: "s".repeat(32),
                new_tail: 5,
                events: vec![crate::AuditEventReceipt2 {
                    event_id: "0123456789abcdef0123456789abcdef".into(),
                    sequence: 5,
                }],
            }),
        },
    };
    let wire = serde_json::to_value(response)?;
    assert_eq!(wire["decision"]["status"], "allow");
    assert_eq!(wire["audit"]["permitted"], true);
    assert_eq!(wire["audit"]["committed"], true);
    Ok(())
}
