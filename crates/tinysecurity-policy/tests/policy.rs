//! Regression tests for bootstrap permission boundaries.
use tinysecurity_policy::*;
fn caller() -> CallerContext {
    CallerContext {
        agent: "operator".into(),
        call_id: "call-1".into(),
        tier: AccessTier::Full,
        ..Default::default()
    }
}
#[test]
fn disabled_policy_keeps_credential_system_and_traversal_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    for path in [
        "/home/user/.ssh/id",
        "C:\\Users\\me\\.aws\\credentials",
        "/etc/passwd",
        "\\\\?\\C:\\Windows\\System32\\config",
        "C:\\Users\\me\\.ssh.\\key",
        "C:\\Users\\me\\.aws:stream",
        "/private/etc/passwd",
        "a/../b",
        "a\0b",
        "~/Library/Keychains/login",
    ] {
        let result = policy.check(&CheckRequest {
            caller: caller(),
            checks: vec![Check::Path {
                path: path.into(),
                write: false,
            }],
        })?;
        assert_eq!(
            result.decisions[0].verdict,
            Verdict::Deny {
                reason: DenialReason::Floor
            },
            "{path}"
        );
    }
    Ok(())
}
#[test]
fn claimed_read_checks_never_authorize_unknown_tools()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    let result = policy.evaluate(&EvaluateRequest {
        caller: caller(),
        call: ToolCall {
            tool: "send_email".into(),
            arguments_json: "{}".into(),
            checks: vec![Check::LocalDiagnostic {}],
        },
    })?;
    assert_eq!(
        result.verdict,
        Verdict::Deny {
            reason: DenialReason::UnsupportedEffect
        }
    );
    Ok(())
}
#[test]
fn failed_reinit_preserves_old_generation_and_configuration()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut policy = Policy::new(ModuleConfig::default())?;
    let old = policy.info();
    let bad = ModuleConfig {
        contract_version: (1, 29),
        ..Default::default()
    };
    assert_eq!(policy.reinitialize(bad), Err(Error::IncompatibleVersion));
    assert_eq!(policy.info(), old);
    let mut next = ModuleConfig::default();
    next.policy.enabled = true;
    assert_eq!(policy.reinitialize(next), Err(Error::InvalidConfig));
    assert_eq!(policy.info(), old);
    policy.reinitialize(ModuleConfig::default())?;
    assert_eq!(policy.info().generation, 2);
    Ok(())
}
#[test]
fn ordered_batch_allows_diagnostic_and_denies_unknown_effect()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    let r = policy.check(&CheckRequest {
        caller: caller(),
        checks: vec![
            Check::LocalDiagnostic {},
            Check::Unknown {
                description: "unknown".into(),
            },
            Check::Command {
                command: "mystery".into(),
            },
        ],
    })?;
    assert_eq!(r.decisions[0].verdict, Verdict::Allow);
    assert_eq!(
        r.decisions[1].verdict,
        Verdict::Deny {
            reason: DenialReason::UnsupportedEffect
        }
    );
    assert_eq!(
        r.decisions[2].verdict,
        Verdict::Deny {
            reason: DenialReason::Command
        }
    );
    Ok(())
}
#[test]
fn native_path_scope_access_and_approval_checks_are_conservative()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    let action = fixture.path().join("action");
    let workspace = action.join("state");
    let forbidden = action.join("private");
    std::fs::create_dir_all(&workspace)?;
    std::fs::create_dir_all(&forbidden)?;
    let config = ModuleConfig {
        policy: PolicyConfig {
            enabled: true,
            action_dir: action.to_string_lossy().into(),
            workspace_dir: workspace.to_string_lossy().into(),
            forbidden_paths: vec![forbidden.to_string_lossy().into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let policy = Policy::new(config)?;
    for (path, write, reason) in [
        ("readable", false, None),
        ("readable", true, Some(DenialReason::ApprovalUnavailable)),
        ("state/new", false, Some(DenialReason::PathScope)),
        ("private/new", false, Some(DenialReason::PathScope)),
        (
            fixture.path().to_str().ok_or("utf8 fixture")?,
            false,
            Some(DenialReason::PathScope),
        ),
    ] {
        let response = policy.check(&CheckRequest {
            caller: caller(),
            checks: vec![Check::Path {
                path: if std::path::Path::new(path).is_absolute() {
                    path.into()
                } else {
                    action.join(path).to_string_lossy().into()
                },
                write,
            }],
        })?;
        assert_eq!(
            response.decisions[0].verdict,
            reason.map_or(Verdict::Allow, |reason| Verdict::Deny { reason })
        );
    }
    let mut reader = caller();
    reader.tier = AccessTier::Read;
    let denied = policy.check(&CheckRequest {
        caller: reader,
        checks: vec![Check::Path {
            path: action.join("readable").to_string_lossy().into(),
            write: true,
        }],
    })?;
    assert_eq!(
        denied.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::Access
        }
    );
    let disabled = Policy::new(ModuleConfig::default())?;
    let mut cron = caller();
    cron.origin = Origin::Cron;
    let denied = disabled.check(&CheckRequest {
        caller: cron,
        checks: vec![Check::Path {
            path: action.to_string_lossy().into(),
            write: true,
        }],
    })?;
    assert_eq!(
        denied.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::ApprovalUnavailable
        }
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn symlinked_credential_store_and_outside_root_never_bypass_policy()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    let action = fixture.path().join("action");
    let state = fixture.path().join("state");
    let secrets = fixture.path().join(".ssh");
    let outside = fixture.path().join("outside");
    std::fs::create_dir_all(&outside)?;
    std::fs::create_dir_all(&action)?;
    std::fs::create_dir_all(&state)?;
    std::fs::create_dir_all(&secrets)?;
    std::os::unix::fs::symlink(&secrets, action.join("credentials"))?;
    std::os::unix::fs::symlink(&outside, action.join("outside"))?;
    std::os::unix::fs::symlink(action.join("missing"), action.join("broken"))?;
    let policy = Policy::new(ModuleConfig {
        policy: PolicyConfig {
            enabled: true,
            action_dir: action.to_string_lossy().into(),
            workspace_dir: state.to_string_lossy().into(),
            ..Default::default()
        },
        ..Default::default()
    })?;
    for (path, reason) in [
        ("credentials/new", DenialReason::Floor),
        ("outside/new", DenialReason::PathScope),
        ("broken/new", DenialReason::PathResolution),
    ] {
        let response = policy.check(&CheckRequest {
            caller: caller(),
            checks: vec![Check::Path {
                path: action.join(path).to_string_lossy().into(),
                write: false,
            }],
        })?;
        assert_eq!(response.decisions[0].verdict, Verdict::Deny { reason });
    }
    Ok(())
}
#[test]
fn unknown_commands_and_shell_expansion_are_denied_without_trusting_read_claims()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::new(ModuleConfig::default())?;
    for command in [
        "pwd; curl example.com",
        "$(whoami)",
        "date > file",
        "C:\\evil\\pwd",
        "pwd | whoami",
        "cat << 'EOF'\nsafe data\nEOF",
        "Get-Content file",
        "",
        "mystery",
    ] {
        let r = policy.check(&CheckRequest {
            caller: caller(),
            checks: vec![Check::Command {
                command: command.into(),
            }],
        })?;
        assert_eq!(
            r.decisions[0].verdict,
            Verdict::Deny {
                reason: DenialReason::Command
            },
            "{command}"
        );
    }
    for command in ["pwd", "date", "uname", "whoami"] {
        let r = policy.check(&CheckRequest {
            caller: caller(),
            checks: vec![Check::Command {
                command: command.into(),
            }],
        })?;
        assert_eq!(r.decisions[0].verdict, Verdict::Allow);
    }
    let r = policy.check(&CheckRequest {
        caller: caller(),
        checks: vec![Check::Command {
            command: "cat /etc/passwd".into(),
        }],
    })?;
    assert_eq!(
        r.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::Floor
        }
    );
    Ok(())
}
#[test]
fn invalid_judge_and_policy_configuration_do_not_activate()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut policy = Policy::new(ModuleConfig::default())?;
    let old = policy.info();
    let judge = JudgeConfig {
        credential: Secret("fixture-secret".into()),
        endpoint: "http://not-loopback.invalid/judge".into(),
        provider: JudgeProvider::TypeSafe,
        exfiltrate_millis: 100,
        thresholds: vec![],
        max_requests: 10,
        budget_window_ms: 60_000,
        cache_entries: 10,
        cache_ttl_ms: 1000,
        threshold_millis: 800,
        timeout_ms: 1000,
        origins: vec![Origin::Operator],
    };
    assert_eq!(
        policy.reinitialize(ModuleConfig {
            judge: Some(judge.clone()),
            ..Default::default()
        }),
        Err(Error::InvalidConfig)
    );
    let invalid = JudgeConfig {
        threshold_millis: 1001,
        ..judge
    };
    assert_eq!(
        policy.reinitialize(ModuleConfig {
            judge: Some(invalid),
            ..Default::default()
        }),
        Err(Error::InvalidConfig)
    );
    let invalid = ModuleConfig {
        policy: PolicyConfig {
            allowed_commands: vec!["bad command".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(policy.reinitialize(invalid), Err(Error::InvalidConfig));
    assert_eq!(policy.info(), old);
    let r = policy.check(&CheckRequest {
        caller: CallerContext::default(),
        checks: vec![Check::LocalDiagnostic {}],
    })?;
    assert_eq!(
        r.decisions[0].verdict,
        Verdict::Deny {
            reason: DenialReason::InvalidContext
        }
    );
    let r = policy.evaluate(&EvaluateRequest {
        caller: caller(),
        call: ToolCall {
            tool: "path_check".into(),
            arguments_json: "{}".into(),
            checks: vec![],
        },
    })?;
    assert_eq!(
        r.verdict,
        Verdict::Deny {
            reason: DenialReason::UnsupportedEffect
        }
    );
    let r = policy.evaluate(&EvaluateRequest {
        caller: caller(),
        call: ToolCall {
            tool: "local_diagnostic".into(),
            arguments_json: "{}".into(),
            checks: vec![Check::LocalDiagnostic {}],
        },
    })?;
    assert_eq!(r.verdict, Verdict::Allow);
    Ok(())
}
#[test]
fn enabled_command_allowlist_cannot_authorize_unknown_executables()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    let action = fixture.path().join("action");
    let state = fixture.path().join("state");
    std::fs::create_dir_all(&action)?;
    std::fs::create_dir_all(&state)?;
    let policy = Policy::new(ModuleConfig {
        policy: PolicyConfig {
            enabled: true,
            action_dir: action.to_string_lossy().into(),
            workspace_dir: state.to_string_lossy().into(),
            allowed_commands: vec!["pwd".into(), "unknown".into()],
            ..Default::default()
        },
        ..Default::default()
    })?;
    for (command, verdict) in [
        ("pwd", Verdict::Allow),
        (
            "date",
            Verdict::Deny {
                reason: DenialReason::Command,
            },
        ),
        (
            "unknown",
            Verdict::Deny {
                reason: DenialReason::Command,
            },
        ),
    ] {
        let r = policy.check(&CheckRequest {
            caller: caller(),
            checks: vec![Check::Command {
                command: command.into(),
            }],
        })?;
        assert_eq!(r.decisions[0].verdict, verdict);
    }
    Ok(())
}
#[test]
fn configuration_requiring_a_future_minor_is_rejected_without_activation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let future = ModuleConfig {
        contract_version: (CONTRACT_VERSION.0, CONTRACT_VERSION.1 + 1),
        ..Default::default()
    };
    assert_eq!(
        Policy::new(future.clone()).map(|p| p.info()),
        Err(Error::IncompatibleVersion)
    );
    let mut active = Policy::new(ModuleConfig::default())?;
    let before = active.info();
    assert_eq!(active.reinitialize(future), Err(Error::IncompatibleVersion));
    assert_eq!(active.info(), before);
    Ok(())
}
