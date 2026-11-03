//! Registered subject policy wire shapes and the 1.29 compatibility boundary.
use serde_json::json;
use tinysecurity_bus::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn registered() -> RegisteredPolicy {
    RegisteredPolicy {
        path_policy_id: PathPolicyId("p".into()),
        settings: PolicySettings {
            policy: PolicyConfig::default(),
            privacy: PrivacyMode::LocalOnly,
            egress_hosts: vec![],
            command_classes: vec![CommandClass::Read],
            auto_origins: vec![Origin::Copilot],
            judge_enabled: false,
        },
        tool_rules: vec![ToolRule {
            tool: "shell".into(),
            effect: ToolRuleEffect::Deny,
        }],
        command_policy_id: CommandPolicyId("c".into()),
        subject_scope: SubjectScope {
            user: "u".into(),
            workspace: "w".into(),
            agent: "a".into(),
        },
    }
}

#[test]
fn registered_policy_and_scoped_requests_round_trip_and_reject_unknown_fields() -> TestResult {
    let policy = registered();
    let wire = serde_json::to_value(&policy)?;
    assert_eq!(
        serde_json::from_value::<RegisteredPolicy>(wire.clone())?,
        policy
    );
    let mut extra = wire;
    extra["surprise"] = json!(true);
    assert!(serde_json::from_value::<RegisteredPolicy>(extra).is_err());
    let request = ScopedCheckRequest {
        policy_id: PolicyId("id".into()),
        caller: CallerContext {
            agent: "a".into(),
            call_id: "1".into(),
            ..Default::default()
        },
        checks: vec![Check::PolicyChange { digest: "d".into() }],
    };
    let wire = serde_json::to_value(&request)?;
    assert_eq!(wire["checks"][0]["kind"], "policy_change");
    assert_eq!(serde_json::from_value::<ScopedCheckRequest>(wire)?, request);
    let response = SupersedePolicyResponse::Activated {
        policy_id: PolicyId("n".into()),
        policy_generation: 2,
    };
    let wire = serde_json::to_value(&response)?;
    assert_eq!(wire["status"], "activated");
    assert_eq!(
        serde_json::from_value::<SupersedePolicyResponse>(wire)?,
        response
    );
    Ok(())
}

#[test]
fn new_members_are_advertised_and_named_by_contract_constants() {
    for name in [
        names::methods::REGISTER_POLICY,
        names::methods::SUPERSEDE_POLICY,
        names::methods::EVALUATE_SCOPED,
        names::methods::CHECK_SCOPED,
        names::methods::SCOPED_POLICY_INFO,
        names::methods::EVALUATE_SCOPED_AUDITED,
        names::methods::CHECK_SCOPED_AUDITED,
        names::methods::DEVICE_FRAME2,
        names::methods::REVOKE_TOOL_BY_ID2,
        names::methods::AUTHORIZE_BROWSER_DIAL,
        names::methods::CONSUME_BROWSER_DIAL,
        names::methods::VALIDATE_BROWSER_DIAL,
        names::methods::REGISTER_SECRET_SCOPE2,
        names::methods::LIST_RECENT_DECISIONS2,
        names::methods::PURGE_APPROVAL_SESSION2,
        names::methods::RECORD_AUDIT_ERROR2,
        names::methods::CLASSIFY_PROVIDER_ENDPOINT2,
    ] {
        assert!(names::METHODS.contains(&name), "{name}");
    }
    assert_eq!(names::methods::REGISTER_POLICY, "RegisterPolicy");
}

#[test]
fn contract_bump_is_additive_for_older_hosts_and_modules() {
    assert_eq!(CONTRACT_VERSION, (1, 35));
    // A host built against 1.35 accepts this module and newer minors, not a 1.34 module.
    assert!(is_compatible((1, 35)));
    assert!(is_compatible((1, 36)));
    assert!(!is_compatible((1, 34)));
    assert!(!is_compatible((1, 33)));
    assert!(!is_compatible((1, 30)));
    assert!(!is_compatible((1, 29)));
    assert!(!is_compatible((1, 28)));
    assert!(!is_compatible((1, 26)));
    assert!(!is_compatible((1, 25)));
    assert!(!is_compatible((1, 24)));
    assert!(!is_compatible((1, 23)));
    assert!(!is_compatible((1, 22)));
    assert!(!is_compatible((1, 21)));
    assert!(!is_compatible((1, 20)));
    assert!(!is_compatible((1, 19)));
    assert!(!is_compatible((1, 18)));
    assert!(!is_compatible((1, 17)));
    assert!(!is_compatible((1, 16)));
    assert!(!is_compatible((1, 15)));
    assert!(!is_compatible((1, 14)));
    assert!(!is_compatible((1, 13)));
    // A 1.12 module cannot supply the audited scoped members.
    assert!(!is_compatible((1, 12)));
    assert!(!is_compatible((1, 11)));
    assert!(!is_compatible((2, 0)));
}

#[test]
fn policy_info_from_a_1_11_module_still_parses_with_empty_new_fields() -> TestResult {
    let legacy = json!({
        "contract_version": [1, 11],
        "generation": 4,
        "policy": serde_json::to_value(PolicyConfig::default())?,
        "capabilities": ["Evaluate"],
    });
    let info: PolicyInfo = serde_json::from_value(legacy)?;
    assert_eq!(info.generation, 4);
    assert_eq!(info.judge, None);
    assert_eq!(info.callbacks, CallbackAvailability::default());
    assert_eq!(info.scoped_policies, 0);
    // The full info round-trips and never names credentials.
    let full = PolicyInfo {
        contract_version: CONTRACT_VERSION,
        generation: 1,
        policy: PolicyConfig::default(),
        capabilities: vec![],
        judge: Some(JudgeInfo {
            provider: JudgeProvider::OpenJev,
            threshold_millis: 900,
            exfiltrate_millis: 100,
            thresholds: vec![],
            timeout_ms: 2000,
            origins: vec![Origin::Operator],
            max_requests: 5,
            budget_window_ms: 1000,
            cache_entries: 0,
            cache_ttl_ms: 0,
        }),
        callbacks: CallbackAvailability {
            audit: true,
            ..Default::default()
        },
        scoped_policies: 2,
    };
    let text = serde_json::to_string(&full)?;
    assert!(!text.contains("credential") && !text.contains("endpoint"));
    assert_eq!(serde_json::from_str::<PolicyInfo>(&text)?, full);
    Ok(())
}

#[test]
fn policy_changed_old_payloads_parse_and_scoped_ones_carry_the_policy() -> TestResult {
    let old: PolicyChanged = serde_json::from_value(json!({"generation": 3}))?;
    assert_eq!((old.policy_id, old.policy_generation), (None, None));
    let reinit = PolicyChanged {
        generation: 3,
        policy_id: None,
        policy_generation: None,
    };
    assert_eq!(serde_json::to_value(&reinit)?, json!({"generation": 3}));
    let scoped = PolicyChanged {
        generation: 4,
        policy_id: Some(PolicyId("x".into())),
        policy_generation: Some(2),
    };
    assert_eq!(
        serde_json::from_value::<PolicyChanged>(serde_json::to_value(&scoped)?)?,
        scoped
    );
    Ok(())
}

#[test]
fn legacy_checks_keep_their_wire_shape() -> TestResult {
    assert_eq!(
        serde_json::to_value(Check::Command {
            command: "ls".into()
        })?,
        json!({"kind": "command", "command": "ls"})
    );
    assert!(serde_json::from_value::<Check>(json!({"kind": "policy_change"})).is_err());
    Ok(())
}
