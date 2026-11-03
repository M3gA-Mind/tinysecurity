use super::*;
use tinysecurity_bus::{AccessTier, SubjectScope};
#[test]
fn cron_external_denies_before_shortcuts_and_saas_has_no_implicit_permission() {
    let mut scope = ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    assert_eq!(evaluate(&scope, &Origin::Operator, false), Rule::Approval);
    assert_eq!(evaluate(&scope, &Origin::Unknown, false), Rule::GrantOnly);
    for automatic in [false, true] {
        scope.auto_approve_all = automatic;
        for required in [false, true] {
            scope.require_approval = required;
            assert_eq!(evaluate(&scope, &Origin::Cron, true), Rule::Deny);
            assert_eq!(evaluate(&scope, &Origin::Saas, false), Rule::Approval);
            assert_eq!(evaluate(&scope, &Origin::Cron, false), Rule::Automatic);
            assert_eq!(
                evaluate(&scope, &Origin::Operator, false),
                if automatic || !required {
                    Rule::Automatic
                } else {
                    Rule::Approval
                }
            );
        }
    }
}

#[test]
fn trusted_automation_and_local_operator_are_automatic_whatever_the_posture() {
    let mut scope = ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        policy_ref: "policy".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    };
    for automatic in [false, true] {
        scope.auto_approve_all = automatic;
        for required in [false, true] {
            scope.require_approval = required;
            for external in [false, true] {
                for origin in [Origin::TrustedAutomation, Origin::LocalOperator] {
                    assert_eq!(evaluate(&scope, &origin, external), Rule::Automatic);
                }
                assert_eq!(
                    evaluate(&scope, &Origin::Unlabelled, external),
                    Rule::GrantOnly
                );
                assert_eq!(
                    evaluate(&scope, &Origin::Unknown, external),
                    Rule::GrantOnly
                );
            }
        }
    }
}
