use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn service() -> std::result::Result<PolicyService, Box<dyn std::error::Error>> {
    Ok(service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        None,
    ))
}

fn scope_policy(
    budget: u32,
    autonomy: CommandAutonomy,
) -> std::result::Result<CommandPolicy, Box<dyn std::error::Error>> {
    Ok(CommandPolicy {
        enabled: true,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        autonomy,
        allowed_commands: vec![],
        max_actions_per_hour: budget,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir()?,
        home_dir: None,
    })
}

async fn register(
    service: &PolicyService,
    policy: CommandPolicy,
) -> std::result::Result<CommandPolicyId, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(
        service
            .call(
                &names::methods::REGISTER_COMMAND_POLICY.parse()?,
                serde_json::to_value((policy,))?,
            )
            .await?,
    )?)
}

fn request(tool: &str, checks: Vec<Check>) -> EvaluateRequest {
    EvaluateRequest {
        caller: CallerContext {
            agent: "agent".into(),
            call_id: "call".into(),
            tier: AccessTier::Full,
            ..Default::default()
        },
        call: ToolCall {
            tool: tool.into(),
            arguments_json: "{}".into(),
            checks,
        },
    }
}

fn acting(spend: bool, scope: &CommandPolicyId) -> Check {
    Check::HostAction {
        permission: ToolPermission::Write,
        external_effect: false,
        spend,
        command_policy: Some(scope.clone()),
    }
}

async fn evaluate(
    service: &PolicyService,
    request: EvaluateRequest,
) -> std::result::Result<Decision, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(
        service
            .call(
                &names::methods::EVALUATE.parse()?,
                serde_json::to_value((request,))?,
            )
            .await?,
    )?)
}

#[tokio::test]
async fn evaluate_reads_and_spends_the_named_command_scopes_budget() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(1, CommandAutonomy::Full)?).await?;
    let peek = request("write_file", vec![acting(false, &scope)]);
    for _ in 0..3 {
        assert_eq!(
            evaluate(&service, peek.clone()).await?.verdict,
            Verdict::Allow
        );
    }
    let spend = request("write_file", vec![acting(true, &scope)]);
    assert_eq!(
        evaluate(&service, spend.clone()).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, spend).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    // The spent budget is visible to a read-only peek and to the shell member.
    assert_eq!(
        evaluate(&service, peek).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    Ok(())
}

#[tokio::test]
async fn evaluate_applies_host_skill_scan_verdicts_before_run_workflow() -> TestResult {
    let service = service()?;
    for (verdict, expected) in [
        (
            tinysecurity_bus::SkillScanVerdict::Block,
            Verdict::Deny {
                reason: DenialReason::Content,
            },
        ),
        (
            tinysecurity_bus::SkillScanVerdict::Warn,
            Verdict::Deny {
                reason: DenialReason::ApprovalUnavailable,
            },
        ),
        (tinysecurity_bus::SkillScanVerdict::Pass, Verdict::Allow),
    ] {
        assert_eq!(
            evaluate(
                &service,
                request(
                    "run_workflow",
                    vec![
                        Check::HostAction {
                            permission: ToolPermission::None,
                            external_effect: false,
                            spend: false,
                            command_policy: None,
                        },
                        Check::SkillScan {
                            verdict,
                            bundle_sha256: "c".repeat(64),
                        },
                    ],
                ),
            )
            .await?
            .verdict,
            expected,
            "{verdict:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn evaluate_gates_a_shell_command_under_the_named_scope() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(5, CommandAutonomy::ReadOnly)?).await?;
    let shell = |command: &str| {
        request(
            "shell",
            vec![Check::HostShell {
                command: command.into(),
                declared_class: None,
                spend: false,
                command_policy: Some(scope.clone()),
            }],
        )
    };
    assert_eq!(
        evaluate(&service, shell("ls")).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, shell("touch f")).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::ReadOnlyMode
        }
    );
    Ok(())
}

#[tokio::test]
async fn evaluate_refuses_an_unknown_scope_and_two_different_scopes() -> TestResult {
    let service = service()?;
    let a = register(&service, scope_policy(5, CommandAutonomy::Full)?).await?;
    let b = register(&service, scope_policy(5, CommandAutonomy::Full)?).await?;
    let unknown = CommandPolicyId("not-registered".into());
    assert!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &unknown)])
        )
        .await
        .is_err()
    );
    assert!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &a), acting(false, &b)])
        )
        .await
        .is_err()
    );
    // A check that left the scope out never inherits another check's.
    let bare = Check::HostShell {
        command: "touch f".into(),
        declared_class: None,
        spend: false,
        command_policy: None,
    };
    assert!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &a), bare.clone()])
        )
        .await
        .is_err()
    );
    // The same scope named twice is one scope.
    assert_eq!(
        evaluate(
            &service,
            request("write_file", vec![acting(false, &a), acting(false, &a)])
        )
        .await?
        .verdict,
        Verdict::Allow
    );
    Ok(())
}

#[tokio::test]
async fn evaluate_without_a_scope_applies_tier_and_effect_rules_only() -> TestResult {
    let service = service()?;
    let action = |tier, external_effect| {
        let mut call = request(
            "gmail_send",
            vec![Check::HostAction {
                permission: ToolPermission::Write,
                external_effect,
                spend: true,
                command_policy: None,
            }],
        );
        call.caller.tier = tier;
        call
    };
    assert_eq!(
        evaluate(&service, action(AccessTier::Full, false))
            .await?
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, action(AccessTier::Read, false))
            .await?
            .verdict,
        Verdict::Deny {
            reason: DenialReason::Access
        }
    );
    assert_eq!(
        evaluate(&service, action(AccessTier::Full, true))
            .await?
            .verdict,
        Verdict::Deny {
            reason: DenialReason::ApprovalUnavailable
        }
    );
    Ok(())
}

#[tokio::test]
async fn a_mixed_request_is_not_an_admission_and_stays_audit_bound() -> TestResult {
    let mut call = request("write_file", vec![Check::LocalDiagnostic {}]);
    assert!(!admission_only(&call.call.checks));
    call.call.checks = vec![];
    assert!(!admission_only(&call.call.checks));
    let scope = CommandPolicyId("s".into());
    call.call.checks = vec![acting(false, &scope), Check::LocalDiagnostic {}];
    assert!(!admission_only(&call.call.checks));
    call.call.checks = vec![acting(false, &scope)];
    assert!(admission_only(&call.call.checks));
    let scan = Check::SkillScan {
        verdict: tinysecurity_bus::SkillScanVerdict::Pass,
        bundle_sha256: "a".repeat(64),
    };
    call.call.checks = vec![acting(false, &scope), scan.clone()];
    assert!(admission_only(&call.call.checks));
    call.call.checks = vec![scan];
    assert!(!admission_only(&call.call.checks));
    Ok(())
}

#[tokio::test]
async fn required_audit_refuses_an_unbound_admission_question() -> TestResult {
    let bus = tinybus::transport::memory::MemoryBus::new();
    let task = tinybus::broker::Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let audit = crate::callbacks::AuditClient::new_for_test(
        module,
        crate::callbacks::PeerBinding::new(
            host.unique_name().as_ref().map(tinybus::BusName::as_str),
        )?,
        AuditConfig2 {
            scope: SubjectScope {
                user: "user".into(),
                workspace: "workspace".into(),
                agent: "agent".into(),
            },
            stream_id: "a".repeat(32),
            timeout_ms: 100,
            required: true,
            native_path: None,
            max_bytes: 10000,
            max_archives: 3,
            journal_max_bytes: 100_000,
            journal_max_events: 1000,
        },
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let service = service_for(
        Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?)),
        Some(Arc::new(audit)),
    );
    let scope = register(&service, scope_policy(5, CommandAutonomy::Full)?).await?;
    assert!(
        evaluate(&service, request("write_file", vec![acting(false, &scope)]))
            .await
            .is_err(),
        "required audit must not let an unbound admission answer permit a call"
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn check_batches_read_the_named_scope_and_refuse_an_unknown_one() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(5, CommandAutonomy::ReadOnly)?).await?;
    let check = |checks: Vec<Check>| CheckRequest {
        caller: request("t", vec![]).caller,
        checks,
    };
    let member = names::methods::CHECK.parse()?;
    let call = |request: CheckRequest| {
        let (service, member) = (&service, &member);
        async move {
            service
                .call(member, serde_json::to_value((request,))?)
                .await
                .map_err(Box::<dyn std::error::Error>::from)
        }
    };
    let response: CheckResponse =
        serde_json::from_value(call(check(vec![acting(false, &scope)])).await?)?;
    assert_eq!(
        response.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::ReadOnlyMode
        }
    );
    let unknown = CommandPolicyId("not-registered".into());
    assert!(call(check(vec![acting(false, &unknown)])).await.is_err());
    Ok(())
}

#[tokio::test]
async fn a_spending_admission_reserves_only_when_it_is_allowed() -> TestResult {
    let service = service()?;
    let scope = register(&service, scope_policy(1, CommandAutonomy::Full)?).await?;
    let mut denied = request("write_file", vec![acting(true, &scope)]);
    denied.caller.tier = AccessTier::Read;
    for _ in 0..3 {
        assert_eq!(
            evaluate(&service, denied.clone()).await?.verdict,
            Verdict::Deny {
                reason: DenialReason::Access
            }
        );
    }
    let spend = request("write_file", vec![acting(true, &scope)]);
    assert_eq!(
        evaluate(&service, spend.clone()).await?.verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&service, spend).await?.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    Ok(())
}

#[tokio::test]
async fn an_audited_spend_the_audit_gate_refuses_is_given_back() -> TestResult {
    let bus = tinybus::transport::memory::MemoryBus::new();
    let task = tinybus::broker::Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let audit = |required| -> std::result::Result<_, Box<dyn std::error::Error>> {
        Ok(Arc::new(crate::callbacks::AuditClient::new_for_test(
            module.clone(),
            crate::callbacks::PeerBinding::new(
                host.unique_name().as_ref().map(tinybus::BusName::as_str),
            )?,
            AuditConfig2 {
                scope: SubjectScope {
                    user: "user".into(),
                    workspace: "workspace".into(),
                    agent: "agent".into(),
                },
                stream_id: "a".repeat(32),
                timeout_ms: 100,
                required,
                native_path: None,
                max_bytes: 10000,
                max_archives: 3,
                journal_max_bytes: 100_000,
                journal_max_events: 1000,
            },
            tinysecurity::Redactor::new(&RedactorConfig::default())?,
        )?))
    };
    let policy = Arc::new(RwLock::new(Policy::new(ModuleConfig::default())?));
    // No sink is served, so a required audit cannot commit and refuses the call.
    let required = service_for(policy.clone(), Some(audit(true)?));
    let optional = service_for(policy, Some(audit(false)?));
    let scope = register(&required, scope_policy(1, CommandAutonomy::Full)?).await?;
    let spending = |event: char| tinysecurity_bus::EvaluateAuditedRequest2 {
        request: request("write_file", vec![acting(true, &scope)]),
        audit: AuditCorrelation2 {
            event_id: event.to_string().repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    let ledger = || -> std::result::Result<bool, Box<dyn std::error::Error>> {
        let commands = required.commands.lock().map_err(|_| "ledger")?;
        Ok(commands.get_owned(&scope)?.exhausted())
    };
    for event in ['a', 'b', 'c'] {
        let refused = required.evaluate_audited2(spending(event)).await?;
        assert!(!refused.audit.permitted);
        assert!(matches!(refused.decision.verdict, Verdict::Deny { .. }));
        assert!(!ledger()?, "a refused audit gives the action back");
    }
    // Where the audit lets the call through, the action is spent once.
    let allowed = optional.evaluate_audited2(spending('d')).await?;
    assert!(allowed.audit.permitted);
    assert_eq!(allowed.decision.verdict, Verdict::Allow);
    assert!(ledger()?);
    let spent = optional.evaluate_audited2(spending('e')).await?;
    assert_eq!(
        spent.decision.verdict,
        Verdict::Deny {
            reason: DenialReason::RateLimited { max_per_hour: 1 }
        }
    );
    task.abort();
    Ok(())
}

fn ledger_is_spent(
    service: &PolicyService,
    scope: &CommandPolicyId,
) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    let commands = service.commands.lock().map_err(|_| "ledger")?;
    Ok(commands.get_owned(scope)?.exhausted())
}

#[tokio::test]
async fn a_reservation_is_given_back_when_the_call_errors_after_it() -> TestResult {
    // No audit client and no approval engine are configured, so the audited and
    // consuming members fail after the point where the action was reserved.
    let service = service()?;
    let scope = register(&service, scope_policy(1, CommandAutonomy::Full)?).await?;
    let audited = tinysecurity_bus::EvaluateAuditedRequest2 {
        request: request("write_file", vec![acting(true, &scope)]),
        audit: AuditCorrelation2 {
            event_id: "a".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    assert!(service.evaluate_audited2(audited).await.is_err());
    assert!(!ledger_is_spent(&service, &scope)?);
    let consume = tinysecurity_bus::ApprovalActionRequest2 {
        scope_id: "a".repeat(32),
        request_id: "b".repeat(32),
        request: request("gmail_send", vec![acting(true, &scope)]),
        audit: AuditCorrelation2 {
            event_id: "c".repeat(32),
            expected_tail: 0,
            generation: 1,
        },
    };
    assert!(service.consume_approval2(consume).await.is_err());
    assert!(!ledger_is_spent(&service, &scope)?);
    Ok(())
}
