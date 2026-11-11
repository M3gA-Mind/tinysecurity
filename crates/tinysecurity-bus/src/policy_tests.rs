use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn only_levels_above_read_only_act() {
    assert!(!ToolPermission::None.acts());
    assert!(!ToolPermission::ReadOnly.acts());
    for level in [
        ToolPermission::Write,
        ToolPermission::Execute,
        ToolPermission::Dangerous,
    ] {
        assert!(level.acts(), "{level:?}");
    }
}

#[test]
fn permission_levels_are_ordered_like_the_host_levels() {
    assert!(ToolPermission::None < ToolPermission::ReadOnly);
    assert!(ToolPermission::ReadOnly < ToolPermission::Write);
    assert!(ToolPermission::Write < ToolPermission::Execute);
    assert!(ToolPermission::Execute < ToolPermission::Dangerous);
}

#[test]
fn each_permission_level_names_the_lowest_tier_that_reaches_it() {
    assert_eq!(ToolPermission::None.minimum_tier(), AccessTier::Read);
    assert_eq!(ToolPermission::ReadOnly.minimum_tier(), AccessTier::Read);
    assert_eq!(ToolPermission::Write.minimum_tier(), AccessTier::Write);
    assert_eq!(ToolPermission::Execute.minimum_tier(), AccessTier::Full);
    assert_eq!(ToolPermission::Dangerous.minimum_tier(), AccessTier::Full);
}

#[test]
fn tiers_reach_themselves_and_lower_tiers_only() {
    let tiers = [AccessTier::Read, AccessTier::Write, AccessTier::Full];
    for (i, tier) in tiers.iter().enumerate() {
        for (j, required) in tiers.iter().enumerate() {
            assert_eq!(tier.reaches(required), i >= j, "{tier:?} -> {required:?}");
        }
    }
}

#[test]
fn host_action_has_a_stable_strict_wire_form() -> TestResult {
    let check = Check::HostAction {
        permission: ToolPermission::Write,
        external_effect: false,
        spend: true,
        command_policy: None,
    };
    let value = serde_json::to_value(&check)?;
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "host_action",
            "permission": "write",
            "external_effect": false,
            "spend": true
        })
    );
    assert_eq!(serde_json::from_value::<Check>(value)?, check);
    let with_scope = Check::HostAction {
        permission: ToolPermission::Dangerous,
        external_effect: true,
        spend: false,
        command_policy: Some(CommandPolicyId("scope".into())),
    };
    let value = serde_json::to_value(&with_scope)?;
    assert_eq!(value["command_policy"], "scope");
    assert_eq!(serde_json::from_value::<Check>(value)?, with_scope);
    assert!(
        serde_json::from_value::<Check>(serde_json::json!({
            "kind": "host_action",
            "permission": "write",
            "external_effect": false,
            "spend": false,
            "tier": "full"
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn host_shell_has_a_stable_strict_wire_form() -> TestResult {
    let check = Check::HostShell {
        command: "ls".into(),
        declared_class: Some(CommandClass::Destructive),
        spend: false,
        command_policy: Some(CommandPolicyId("scope".into())),
    };
    let value = serde_json::to_value(&check)?;
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "host_shell",
            "command": "ls",
            "declared_class": "destructive",
            "spend": false,
            "command_policy": "scope"
        })
    );
    assert_eq!(serde_json::from_value::<Check>(value)?, check);
    let minimal: Check = serde_json::from_value(serde_json::json!({
        "kind": "host_shell", "command": "ls", "spend": true
    }))?;
    assert_eq!(
        minimal,
        Check::HostShell {
            command: "ls".into(),
            declared_class: None,
            spend: true,
            command_policy: None
        }
    );
    Ok(())
}

#[test]
fn skill_scan_has_stable_verdict_wire_forms() -> TestResult {
    for (verdict, wire) in [
        (SkillScanVerdict::Pass, "pass"),
        (SkillScanVerdict::Warn, "warn"),
        (SkillScanVerdict::Block, "block"),
    ] {
        let check = Check::SkillScan {
            verdict,
            bundle_sha256: "a".repeat(64),
        };
        let value = serde_json::to_value(&check)?;
        assert_eq!(
            value,
            serde_json::json!({
                "kind":"skill_scan",
                "verdict":wire,
                "bundle_sha256":"a".repeat(64),
            })
        );
        assert_eq!(serde_json::from_value::<Check>(value)?, check);
    }
    Ok(())
}

#[test]
fn new_denial_reasons_have_stable_wire_forms_and_old_ones_are_unchanged() -> TestResult {
    for (reason, wire) in [
        (
            DenialReason::ReadOnlyMode,
            serde_json::json!("read_only_mode"),
        ),
        (
            DenialReason::ScheduledReadOnly,
            serde_json::json!("scheduled_read_only"),
        ),
        (DenialReason::HighRisk, serde_json::json!("high_risk")),
        (DenialReason::Privacy, serde_json::json!("privacy")),
        (
            DenialReason::RateLimited { max_per_hour: 7 },
            serde_json::json!({"rate_limited": {"max_per_hour": 7}}),
        ),
        (DenialReason::Floor, serde_json::json!("floor")),
        (
            DenialReason::ApprovalUnavailable,
            serde_json::json!("approval_unavailable"),
        ),
    ] {
        assert_eq!(serde_json::to_value(&reason)?, wire);
        assert_eq!(serde_json::from_value::<DenialReason>(wire)?, reason);
    }
    let verdict: Verdict = serde_json::from_value(
        serde_json::json!({"kind": "deny", "reason": {"rate_limited": {"max_per_hour": 3}}}),
    )?;
    assert_eq!(
        verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 3 }
        }
    );
    Ok(())
}

#[test]
fn a_1_18_check_payload_still_deserializes() -> TestResult {
    // Older hosts send only the pre-1.20 vocabulary; it must keep parsing.
    for kind in ["host_tool", "local_diagnostic"] {
        let check: Check = serde_json::from_value(serde_json::json!({"kind": kind}))?;
        assert_eq!(serde_json::to_value(&check)?["kind"], kind);
    }
    Ok(())
}

#[test]
fn judge_credential_callback_and_optional_credential_pin_their_wire_form()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        serde_json::to_value(JudgeCredentialRequest2 {
            reason: JudgeCredentialReason2::Rejected
        })?,
        serde_json::json!({"reason":"rejected"})
    );
    assert_eq!(
        serde_json::to_value(JudgeCredentialRequest2 {
            reason: JudgeCredentialReason2::Initial
        })?,
        serde_json::json!({"reason":"initial"})
    );
    let empty: JudgeCredentialResponse2 = serde_json::from_value(serde_json::json!({}))?;
    assert_eq!(empty.credential, None);
    assert_eq!(serde_json::to_value(&empty)?, serde_json::json!({}));
    let held = JudgeCredentialResponse2 {
        credential: Some(Secret("host-held-key".into())),
    };
    assert_eq!(
        serde_json::to_value(&held)?,
        serde_json::json!({"credential":"host-held-key"})
    );
    assert!(!format!("{held:?}").contains("host-held-key"));
    // A judge configured without a credential omits the field entirely.
    let judge: JudgeConfig = serde_json::from_value(
        serde_json::json!({"threshold_millis":900,"timeout_ms":1000,"origins":[]}),
    )?;
    assert_eq!(judge.credential, None);
    assert!(serde_json::to_value(&judge)?.get("credential").is_none());
    Ok(())
}
