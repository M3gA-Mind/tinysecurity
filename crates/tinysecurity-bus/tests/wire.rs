//! Golden wire compatibility for every public payload family.
use serde_json::Value;
use tinysecurity_bus::*;
fn fixtures() -> std::result::Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!("fixtures/v1.json"))
}
macro_rules! golden {
    ($type:ty, $name:ident) => {
        #[test]
        fn $name() -> std::result::Result<(), Box<dyn std::error::Error>> {
            let v = fixtures()?[stringify!($type)].clone();
            let decoded: $type = serde_json::from_value(v.clone())?;
            assert_eq!(serde_json::to_value(&decoded)?, v);
            assert_eq!(
                serde_json::from_str::<$type>(&serde_json::to_string(&decoded)?)?,
                decoded
            );
            Ok(())
        }
    };
}
golden!(ApprovalDecision, roundtrip_approval_decision);
golden!(ApprovalRecord, roundtrip_approval_record);
golden!(ListPendingRequest, roundtrip_list_pending_request);
golden!(ListPendingResponse, roundtrip_list_pending_response);
golden!(ListDecisionsRequest, roundtrip_list_decisions_request);
golden!(ListDecisionsResponse, roundtrip_list_decisions_response);
golden!(RecordExecutionRequest, roundtrip_record_execution_request);
golden!(RecordExecutionResponse, roundtrip_record_execution_response);
golden!(PreauthorizeFlowRequest, roundtrip_preauthorize_flow_request);
golden!(
    PreauthorizeFlowResponse,
    roundtrip_preauthorize_flow_response
);
golden!(ParseReplyRequest, roundtrip_parse_reply_request);
golden!(ParseReplyResponse, roundtrip_parse_reply_response);
golden!(RedactRequest, roundtrip_redact_request);
golden!(RedactResponse, roundtrip_redact_response);
golden!(ScanPromptRequest, roundtrip_scan_prompt_request);
golden!(
    ScanToolDefinitionRequest,
    roundtrip_scan_tool_definition_request
);
golden!(ScanResponse, roundtrip_scan_response);
golden!(EgressCheckRequest, roundtrip_egress_check_request);
golden!(EgressCheckResponse, roundtrip_egress_check_response);
golden!(UrlGuardRequest, roundtrip_url_guard_request);
golden!(UrlGuardResponse, roundtrip_url_guard_response);
golden!(SandboxPlanRequest, roundtrip_sandbox_plan_request);
golden!(SandboxPlanResponse, roundtrip_sandbox_plan_response);
golden!(PathGrant, roundtrip_path_grant);
golden!(ResourceLimits, roundtrip_resource_limits);
golden!(DataDescriptor, roundtrip_data_descriptor);
golden!(AuditRequest, roundtrip_audit_request);
golden!(AuditResponse, roundtrip_audit_response);
golden!(AuditEvent, roundtrip_audit_event);
golden!(ApprovalStoreRequest, roundtrip_approval_store_request);
golden!(ApprovalStoreResponse, roundtrip_approval_store_response);
golden!(ApprovalPromptRequest, roundtrip_approval_prompt_request);
golden!(ApprovalPromptResponse, roundtrip_approval_prompt_response);
golden!(AuditSinkRequest, roundtrip_audit_sink_request);
golden!(AuditSinkResponse, roundtrip_audit_sink_response);
golden!(KeyringConsentRequest, roundtrip_keyring_consent_request);
golden!(KeyringConsentResponse, roundtrip_keyring_consent_response);
golden!(KeyringConsentResponse2, roundtrip_keyring_consent_response2);
golden!(CallerContext, roundtrip_caller_context);
golden!(ToolCall, roundtrip_tool_call);
golden!(EvaluateRequest, roundtrip_evaluate_request);
golden!(CheckRequest, roundtrip_check_request);
golden!(CheckResponse, roundtrip_check_response);
golden!(Decision, roundtrip_decision);
golden!(PolicyConfig, roundtrip_policy_config);
golden!(JudgeConfig, roundtrip_judge_config);
golden!(ModuleConfig, roundtrip_module_config);
golden!(PolicyInfo, roundtrip_policy_info);
golden!(PolicyChanged, roundtrip_policy_changed);
golden!(ApprovalState, roundtrip_approval_state);
golden!(ExecutionOutcome, roundtrip_execution_outcome);
golden!(ReplyVerdict, roundtrip_reply_verdict);
golden!(RedactMode, roundtrip_redact_mode);
golden!(ScanVerdict, roundtrip_scan_verdict);
golden!(PrivacyMode, roundtrip_privacy_mode);
golden!(SourceTrust, roundtrip_source_trust);
golden!(SandboxBackend, roundtrip_sandbox_backend);
golden!(NetworkPolicy, roundtrip_network_policy);
golden!(AuditKind, roundtrip_audit_kind);
golden!(StoreOperation, roundtrip_store_operation);
golden!(Origin, roundtrip_origin);
golden!(AccessTier, roundtrip_access_tier);
golden!(DenialReason, roundtrip_denial_reason);
golden!(Secret, roundtrip_secret);
golden!(Check, roundtrip_check);
golden!(Verdict, roundtrip_verdict);
#[test]
fn all_approval_state_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["ApprovalState"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: ApprovalState = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<ApprovalState>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_execution_outcome_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["ExecutionOutcome"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: ExecutionOutcome = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<ExecutionOutcome>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_reply_verdict_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["ReplyVerdict"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: ReplyVerdict = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<ReplyVerdict>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_redact_mode_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["RedactMode"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: RedactMode = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<RedactMode>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_scan_verdict_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["ScanVerdict"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: ScanVerdict = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<ScanVerdict>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_privacy_mode_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["PrivacyMode"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: PrivacyMode = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<PrivacyMode>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_source_trust_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["SourceTrust"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: SourceTrust = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<SourceTrust>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_sandbox_backend_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["SandboxBackend"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: SandboxBackend = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<SandboxBackend>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_network_policy_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["NetworkPolicy"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: NetworkPolicy = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<NetworkPolicy>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_audit_kind_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["AuditKind"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: AuditKind = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<AuditKind>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_store_operation_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["StoreOperation"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: StoreOperation = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<StoreOperation>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_origin_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["Origin"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: Origin = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<Origin>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_access_tier_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["AccessTier"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: AccessTier = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<AccessTier>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn all_denial_reason_variants_have_stable_wire_names()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["variants"]["DenialReason"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let decoded: DenialReason = serde_json::from_value(v.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, *v);
    }
    assert!(serde_json::from_str::<DenialReason>("\"future_unknown\"").is_err());
    Ok(())
}
#[test]
fn every_error_has_a_stable_wire_form() -> std::result::Result<(), Box<dyn std::error::Error>> {
    for v in fixtures()?["errors"]
        .as_array()
        .ok_or("fixture must contain an array")?
    {
        let e: Error = serde_json::from_value(v.clone())?;
        assert_ne!(e.to_string(), "");
        assert_eq!(serde_json::to_value(e)?, *v);
    }
    Ok(())
}
#[test]
fn init_secrets_are_redacted_and_never_present_in_call_types()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = fixtures()?["JudgeConfig"].clone();
    let judge: JudgeConfig = serde_json::from_value(config)?;
    let debug = format!("{judge:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("secret-fixture"));
    let config = ModuleConfig {
        judge: Some(judge),
        ..Default::default()
    };
    assert!(!format!("{config:?}").contains("secret-fixture"));
    Ok(())
}
#[test]
fn unknown_fields_and_enum_tags_are_rejected_at_security_boundaries()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut v = fixtures()?["EvaluateRequest"].clone();
    v["class"] = "read".into();
    assert!(serde_json::from_value::<EvaluateRequest>(v).is_err());
    assert!(
        serde_json::from_str::<Check>(r#"{"kind":"url","url":"https://example.com"}"#).is_err()
    );
    assert!(
        serde_json::from_str::<Check>(r#"{"kind":"local_diagnostic","unexpected":true}"#).is_err()
    );
    assert!(serde_json::from_str::<ModuleConfig>("{}").is_err());
    Ok(())
}

golden!(DecideRequest, roundtrip_decide_request);
golden!(DecideResponse, roundtrip_decide_response);

#[test]
fn remote_provider_with_newer_minor_supplies_this_hosts_older_vocabulary() {
    assert!(is_compatible(CONTRACT_VERSION));
    assert!(is_compatible((CONTRACT_VERSION.0, CONTRACT_VERSION.1 + 4)));
    assert!(!is_compatible((CONTRACT_VERSION.0 + 1, 0)));
}

#[test]
fn redactor_init_is_additive_and_secrets_never_enter_public_info()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let legacy = fixtures()?["ModuleConfig"].clone();
    let config: ModuleConfig = serde_json::from_value(legacy.clone())?;
    assert_eq!(config.redactor.secrets, Vec::<Secret>::new());
    assert_eq!(serde_json::to_value(config)?, legacy);
    let config = ModuleConfig {
        redactor: RedactorConfig {
            secrets: vec![Secret("literal-private".into())],
        },
        ..Default::default()
    };
    assert!(!format!("{config:?}").contains("literal-private"));
    assert_eq!(
        serde_json::to_value(&config)?["redactor"]["secrets"][0],
        "literal-private"
    );
    assert_eq!(CONTRACT_VERSION, (1, 35));
    for (mode, wire) in [
        (RedactMode::Text, "text"),
        (RedactMode::StructuredArguments, "structured_arguments"),
        (RedactMode::Endpoint, "endpoint"),
        (RedactMode::HomePath, "home_path"),
        (RedactMode::IdentifierHash, "identifier_hash"),
        (RedactMode::LegacyMask, "legacy_mask"),
        (RedactMode::EndpointOrigin, "endpoint_origin"),
        (RedactMode::EndpointHost, "endpoint_host"),
        (
            RedactMode::StructuredLogArguments,
            "structured_log_arguments",
        ),
        (RedactMode::BrowserResult, "browser_result"),
        (RedactMode::CredentialsOnly, "credentials_only"),
    ] {
        assert_eq!(serde_json::to_value(mode)?, wire);
    }
    Ok(())
}

#[test]
fn confidential_master_facade_is_additive_and_has_no_generic_secret_members() {
    assert!(tinysecurity_bus::names::METHODS.contains(&"EvaluateSecret2"));
    assert!(tinysecurity_bus::names::METHODS.contains(&"ExecuteSecret2"));
    for absent in ["GetSecret", "PutSecret", "DeleteSecret", "ReadMaster"] {
        assert!(!tinysecurity_bus::names::METHODS.contains(&absent));
    }
}

#[test]
fn redact_with_request_carries_literals_without_echoing_them()
-> std::result::Result<(), serde_json::Error> {
    let request = RedactWithRequest {
        text: "see value".into(),
        mode: RedactMode::CredentialsOnly,
        secrets: vec![Secret("literal-private".into())],
    };
    assert!(!format!("{request:?}").contains("literal-private"));
    let wire = serde_json::to_value(&request)?;
    assert_eq!(wire["mode"], "credentials_only");
    assert_eq!(wire["secrets"][0], "literal-private");
    assert_eq!(serde_json::from_value::<RedactWithRequest>(wire)?, request);
    assert!(
        serde_json::from_value::<RedactWithRequest>(
            serde_json::json!({"text":"x","mode":"text","secrets":[],"extra":1})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<RedactWithRequest>(serde_json::json!({"text":"x","mode":"text"}))
            .is_err(),
        "secrets is required so a Redact payload is not mistaken for RedactWith"
    );
    assert_eq!(names::methods::REDACT_WITH, "RedactWith");
    assert!(names::METHODS.contains(&names::methods::REDACT_WITH));
    assert_eq!(
        names::methods::REGISTER_SANDBOX_SCOPE2,
        "RegisterSandboxScope2"
    );
    assert_eq!(names::methods::RETIRE_SANDBOX_SCOPE2, "RetireSandboxScope2");
    assert!(names::METHODS.contains(&names::methods::REGISTER_SANDBOX_SCOPE2));
    assert!(names::METHODS.contains(&names::methods::RETIRE_SANDBOX_SCOPE2));
    Ok(())
}
