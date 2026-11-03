use super::*;
#[test]
fn session_purge_contract_roundtrips_and_rejects_unrelated_responses()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let request = ApprovalPurgeSessionRequest2 {
        scope: SubjectScope {
            user: "user-hash".into(),
            workspace: "workspace-hash".into(),
            agent: "agent-hash".into(),
        },
        session_id: "session-hash".into(),
    };
    let encoded = serde_json::to_string(&request)?;
    let decoded: ApprovalPurgeSessionRequest2 = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, request);
    let response = ApprovalPurgeSessionResponse2 {
        scope: request.scope.clone(),
        session_id: request.session_id.clone(),
        removed: 3,
    };
    assert_eq!(request.verify_response(&response), Ok(()));
    let mut unrelated = response;
    unrelated.session_id = "other-session".into();
    assert_eq!(
        request.verify_response(&unrelated),
        Err(crate::Error::InvalidArguments)
    );
    Ok(())
}

#[test]
fn session_purge_debug_redacts_the_session_identifier() {
    let request = ApprovalPurgeSessionRequest2 {
        scope: SubjectScope {
            user: "user-hash".into(),
            workspace: "workspace-hash".into(),
            agent: "agent-hash".into(),
        },
        session_id: "private-session-hash".into(),
    };
    let response = ApprovalPurgeSessionResponse2 {
        scope: request.scope.clone(),
        session_id: request.session_id.clone(),
        removed: 1,
    };
    let debug = format!("{request:?}{response:?}");
    assert!(debug.contains("ApprovalPurgeSessionRequest2([REDACTED])"));
    assert!(debug.contains("ApprovalPurgeSessionResponse2([REDACTED])"));
    assert!(!debug.contains("private-session-hash"));
}

fn mutation() -> ApprovalCasRequest2 {
    ApprovalCasRequest2 {
        scope: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        record_id: "a".repeat(32),
        expected_version: None,
        next_record: ApprovalRecord2 {
            record_id: "a".repeat(32),
            version: 1,
            policy_id: "policy".into(),
            generation: 1,
            fingerprint: "b".repeat(32),
            record_json: "{}".into(),
        },
        mutation_id: "c".repeat(32),
    }
}
fn receipt(request: &ApprovalCasRequest2) -> ApprovalCasResponse2 {
    ApprovalCasResponse2 {
        scope: request.scope.clone(),
        record_id: request.record_id.clone(),
        mutation_id: request.mutation_id.clone(),
        resulting_version: request.next_record.version,
    }
}
#[test]
fn an_exact_cas_echo_cannot_authorize_an_unscoped_mutation() {
    let mut request = mutation();
    request.scope.user.clear();
    assert_eq!(
        request.verify_receipt(&receipt(&request)),
        Err(crate::Error::InvalidArguments)
    );
}

#[test]
fn cas_receipts_bind_scope_target_mutation_create_only_and_checked_versions() {
    let request = mutation();
    assert_eq!(request.verify_receipt(&receipt(&request)), Ok(()));
    for index in 0..5 {
        let mut echo = receipt(&request);
        match index {
            0 => echo.scope.workspace.push('x'),
            1 => echo.scope.agent.push('x'),
            2 => echo.record_id.push('x'),
            3 => echo.mutation_id.push('x'),
            _ => echo.resulting_version += 1,
        }
        assert_eq!(
            request.verify_receipt(&echo),
            Err(crate::Error::InvalidArguments)
        );
    }
    for index in 0..8 {
        let mut invalid = request.clone();
        match index {
            0 => invalid.next_record.record_id.push('x'),
            1 => invalid.next_record.version += 1,
            2 => invalid.mutation_id.clear(),
            3 => invalid.record_id.clear(),
            4 => invalid.next_record.fingerprint.clear(),
            5 => invalid.next_record.policy_id.clear(),
            6 => invalid.next_record.generation = 0,
            _ => invalid.next_record.record_json.clear(),
        }
        assert_eq!(
            invalid.verify_receipt(&receipt(&invalid)),
            Err(crate::Error::InvalidArguments)
        );
    }
    let mut update = request;
    update.expected_version = Some(1);
    update.next_record.version = 2;
    assert_eq!(update.verify_receipt(&receipt(&update)), Ok(()));
    update.expected_version = Some(u64::MAX);
    assert_eq!(
        update.verify_receipt(&receipt(&update)),
        Err(crate::Error::InvalidArguments)
    );
    assert!(
        !format!(
            "{:?}{:?}{:?}{:?}",
            update,
            receipt(&update),
            update.next_record,
            ApprovalLoadRequest2 {
                scope: update.scope.clone()
            }
        )
        .contains("policy")
    );
}

#[test]
fn scoped_load_rejects_unrelated_duplicate_or_invalid_rows() {
    let request = ApprovalLoadRequest2 {
        scope: mutation().scope,
    };
    let response = ApprovalLoadResponse2 {
        scope: request.scope.clone(),
        records: vec![mutation().next_record],
    };
    assert_eq!(request.verify_response(&response), Ok(()));
    let mut unrelated = response.clone();
    unrelated.scope.user.push('x');
    assert_eq!(
        request.verify_response(&unrelated),
        Err(crate::Error::InvalidArguments)
    );
    let mut duplicate = response.clone();
    duplicate.records.push(duplicate.records[0].clone());
    assert_eq!(
        request.verify_response(&duplicate),
        Err(crate::Error::InvalidArguments)
    );
    let mut invalid = response;
    invalid.records[0].version = 0;
    assert_eq!(
        request.verify_response(&invalid),
        Err(crate::Error::InvalidArguments)
    );
    assert!(!format!("{invalid:?}").contains("policy"));
}
