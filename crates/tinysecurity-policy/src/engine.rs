//! Atomic policy activation and ordered evaluation.
use crate::{
    AccessTier, CONTRACT_VERSION, CallerContext, Check, CheckRequest, CheckResponse, CommandClass,
    Decision, DenialReason, Error, EvaluateRequest, ModuleConfig, Origin, POLICY_CHANGE_TOOL,
    PolicyConfig, PolicyInfo, RegisteredCommandPolicy, Result, Spent, Verdict, command, host_tool,
    names, path,
};

/// Registered command-scope check used instead of the bootstrap allowlist.
pub(crate) type CommandHook<'a> = dyn Fn(&str) -> std::result::Result<(), DenialReason> + 'a;
/// Registered filesystem scope check applied after the base path rules.
pub(crate) type PathHook<'a> = dyn Fn(&str, bool) -> std::result::Result<(), DenialReason> + 'a;

/// Registered scopes that replace or tighten the bootstrap checks for one subject.
pub(crate) struct Hooks<'a> {
    pub(crate) command: &'a CommandHook<'a>,
    pub(crate) path: &'a PathHook<'a>,
    /// Command classes the subject may run without a fresh review; empty means the
    /// command scope alone decides. Applies to `Command` and `HostShell` checks alike.
    pub(crate) classes: &'a [CommandClass],
}
/// Active validated policy instance. Failed reconfiguration never changes it.
#[derive(Clone, Debug)]
pub struct Policy {
    config: ModuleConfig,
    generation: u64,
    redactor: tinysecurity_redact::Redactor,
}
impl Policy {
    /// Validate and activate the first policy generation.
    /// # Errors
    /// Rejects incompatible wire versions, invalid judges and invalid roots.
    pub fn new(config: ModuleConfig) -> Result<Self> {
        validate(&config)?;
        Ok(Self {
            redactor: registry(&config)?,
            config,
            generation: 1,
        })
    }
    /// Activate a new generation after validating all settings.
    /// # Errors
    /// Rejects invalid settings or generation overflow without changing old state.
    pub fn reinitialize(&mut self, config: ModuleConfig) -> Result<()> {
        validate(&config)?;
        let generation = self.generation.checked_add(1).ok_or(Error::InvalidConfig)?;
        let redactor = registry(&config)?;
        self.config = config;
        self.redactor = redactor;
        self.generation = generation;
        Ok(())
    }
    /// Inspect effective public configuration, without init-only credentials.
    #[must_use]
    pub fn info(&self) -> PolicyInfo {
        PolicyInfo {
            contract_version: CONTRACT_VERSION,
            generation: self.generation,
            policy: self.config.policy.clone(),
            capabilities: names::METHODS.iter().map(|s| (*s).into()).collect(),
            judge: self.config.judge.as_ref().map(|j| crate::JudgeInfo {
                provider: j.provider,
                threshold_millis: j.threshold_millis,
                exfiltrate_millis: j.exfiltrate_millis,
                thresholds: j.thresholds.clone(),
                timeout_ms: j.timeout_ms,
                origins: j.origins.clone(),
                max_requests: j.max_requests,
                budget_window_ms: j.budget_window_ms,
                cache_entries: j.cache_entries,
                cache_ttl_ms: j.cache_ttl_ms,
            }),
            callbacks: crate::CallbackAvailability {
                judge: self.config.judge.is_some(),
                ..crate::CallbackAvailability::default()
            },
            scoped_policies: 0,
        }
    }
    /// Clone the active immutable registry without exposing initialization secrets.
    #[must_use]
    pub fn redactor(&self) -> tinysecurity_redact::Redactor {
        self.redactor.clone()
    }
    /// Authorize a supported host-owned tool and its complete concrete checks.
    /// # Errors
    /// Reserved for module failures; ordinary denial is a successful result.
    pub fn evaluate(&self, request: &EvaluateRequest) -> Result<Decision> {
        self.evaluate_with(&self.config.policy, None, None, request)
    }
    /// Authorize a host tool call under a registered command scope (contract 1.20):
    /// the scope supplies the autonomy tier and the hourly budget that
    /// `HostAction` and `HostShell` checks read. Reading never spends; the caller
    /// reserves an allowed spending call's action with [`Self::settle_spend`] after any
    /// later gate.
    /// # Errors
    /// Reserved for module failures; ordinary denial is a successful result.
    pub fn evaluate_hosted(
        &self,
        scope: Option<&RegisteredCommandPolicy>,
        request: &EvaluateRequest,
    ) -> Result<Decision> {
        self.evaluate_with(&self.config.policy, None, scope, request)
    }
    /// Evaluate under per-subject settings and an optional registered command scope.
    /// # Errors
    /// Reserved for module failures; ordinary denial is a successful result.
    pub(crate) fn evaluate_with(
        &self,
        settings: &PolicyConfig,
        hooks: Option<&Hooks<'_>>,
        scope: Option<&RegisteredCommandPolicy>,
        request: &EvaluateRequest,
    ) -> Result<Decision> {
        let matching = !request.call.checks.is_empty()
            && match request.call.tool.as_str() {
                "local_diagnostic" => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::LocalDiagnostic {})),
                "path_check" => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::Path { .. })),
                "command_check" => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::Command { .. })),
                POLICY_CHANGE_TOOL => request
                    .call
                    .checks
                    .iter()
                    .all(|c| matches!(c, Check::PolicyChange { .. })),
                tool if tinysecurity_bus::is_host_tool_name2(tool) => {
                    request.call.checks.iter().any(|c| {
                        matches!(
                            c,
                            Check::HostTool {}
                                | Check::HostAction { .. }
                                | Check::HostShell { .. }
                        )
                    }) && request
                        .call
                        .checks
                        .iter()
                        .all(|c| !matches!(c, Check::Unknown { .. } | Check::PolicyChange { .. }))
                        // A `Command` check reserves its own action, so a call that also asks
                        // a host check to spend would reserve twice.
                        && !(request.call.checks.iter().any(host_tool::spends)
                            && request
                                .call
                                .checks
                                .iter()
                                .any(|c| matches!(c, Check::Command { .. })))
                }
                _ => false,
            };
        if !matching {
            return Ok(self.denied(DenialReason::UnsupportedEffect));
        }
        let scan = self
            .redactor
            .scan_tool_definition(&crate::ScanToolDefinitionRequest {
                name: request.call.tool.clone(),
                definition_json: request.call.arguments_json.clone(),
            })?;
        if let Some(reason) = scan_denial(&scan.verdict) {
            return Ok(self.denied(reason));
        }
        // "A human must approve" is the weakest answer: every concrete check runs
        // first, so a later hard denial is never masked by an earlier approval
        // requirement or by the host-tool marker.
        let mut approvable = None;
        for check in &request.call.checks {
            let decision = self.one(settings, hooks, scope, &request.caller, check);
            match decision.verdict {
                Verdict::Allow => {}
                Verdict::Deny {
                    reason: DenialReason::ApprovalUnavailable,
                } => {
                    approvable.get_or_insert(decision);
                }
                _ => return Ok(decision),
            }
        }
        Ok(approvable.unwrap_or_else(|| self.allowed()))
    }
    /// Reserve the one action a spending call asked for, once the whole call is allowed
    /// (contract 1.20): after every check, and after any later gate that can still refuse it.
    /// The returned [`Spent`] gives the action back if it is dropped, so a gate that refuses
    /// the call, or an error, after this point costs nothing; commit it when the call is
    /// going to run. `decision` is returned unchanged, with no reservation, unless it is an
    /// `Allow` that spends; a spent ledger turns it into `rate_limited`.
    #[must_use]
    pub fn settle_spend(
        &self,
        scope: Option<&std::sync::Arc<RegisteredCommandPolicy>>,
        checks: &[Check],
        mut decision: Decision,
    ) -> (Decision, Option<Spent>) {
        let Some(scope) = scope else {
            return (decision, None);
        };
        if decision.verdict != Verdict::Allow || !checks.iter().any(host_tool::spends) {
            return (decision, None);
        }
        let spent = scope.reserve_guarded();
        if spent.is_none() {
            decision.verdict = Verdict::Deny {
                reason: DenialReason::RateLimited {
                    max_per_hour: scope.max_actions_per_hour(),
                },
            };
        }
        (decision, spent)
    }
    /// Evaluate an ordered batch against a single active generation.
    /// # Errors
    /// Reserved for module failures; individual denials remain ordered results.
    pub fn check(&self, request: &CheckRequest) -> Result<CheckResponse> {
        Ok(self.check_with(
            &self.config.policy,
            None,
            None,
            &request.caller,
            &request.checks,
        ))
    }
    /// An ordered batch whose host-tool checks read a registered command scope (contract
    /// 1.20). Never reserves.
    #[must_use]
    pub fn check_hosted(
        &self,
        scope: Option<&RegisteredCommandPolicy>,
        request: &CheckRequest,
    ) -> CheckResponse {
        self.check_with(
            &self.config.policy,
            None,
            scope,
            &request.caller,
            &request.checks,
        )
    }
    /// Ordered batch under per-subject settings and an optional command scope.
    pub(crate) fn check_with(
        &self,
        settings: &PolicyConfig,
        hooks: Option<&Hooks<'_>>,
        scope: Option<&RegisteredCommandPolicy>,
        caller: &CallerContext,
        checks: &[Check],
    ) -> CheckResponse {
        CheckResponse {
            generation: self.generation,
            decisions: checks
                .iter()
                .map(|check| self.one(settings, hooks, scope, caller, check))
                .collect(),
        }
    }
    /// Module generation.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn deny_with(&self, reason: DenialReason) -> Decision {
        self.denied(reason)
    }
    fn one(
        &self,
        settings: &PolicyConfig,
        hooks: Option<&Hooks<'_>>,
        scope: Option<&RegisteredCommandPolicy>,
        caller: &CallerContext,
        check: &Check,
    ) -> Decision {
        if caller.agent.is_empty() || caller.call_id.is_empty() {
            return self.denied(DenialReason::InvalidContext);
        }
        let result = match check {
            Check::LocalDiagnostic {} => Ok(()),
            Check::Unknown { .. } => Err(DenialReason::UnsupportedEffect),
            Check::HostTool {} | Check::PolicyChange { .. } => {
                Err(DenialReason::ApprovalUnavailable)
            }
            Check::HostAction {
                permission,
                external_effect,
                ..
            } => host_tool::action(caller, scope, *permission, *external_effect),
            Check::HostShell {
                command,
                declared_class,
                ..
            } => self.scan_command(command).and_then(|()| {
                host_tool::shell(
                    caller,
                    settings,
                    scope,
                    hooks.map_or(&[], |hooks| hooks.classes),
                    command,
                    *declared_class,
                )
            }),
            Check::SkillScan {
                verdict,
                bundle_sha256,
            } => {
                if is_sha256(bundle_sha256) {
                    match verdict {
                        tinysecurity_bus::SkillScanVerdict::Pass => Ok(()),
                        tinysecurity_bus::SkillScanVerdict::Warn => {
                            Err(DenialReason::ApprovalUnavailable)
                        }
                        tinysecurity_bus::SkillScanVerdict::Block => Err(DenialReason::Content),
                    }
                } else {
                    Err(DenialReason::InvalidContext)
                }
            }
            Check::Path { path, write } => path::check(settings, path, *write)
                .and_then(|()| hooks.map_or(Ok(()), |h| (h.path)(path, *write)))
                .and_then(|()| {
                    if *write && caller.tier == AccessTier::Read {
                        Err(DenialReason::Access)
                    } else if *write && (caller.origin == Origin::Cron || settings.enabled) {
                        Err(DenialReason::ApprovalUnavailable)
                    } else {
                        Ok(())
                    }
                }),
            Check::Command { command } => self.scan_command(command).and_then(|()| match hooks {
                Some(hooks) => (hooks.command)(command),
                None => command::check(settings, command),
            }),
        };
        match result {
            Ok(()) => self.allowed(),
            Err(reason) => self.denied(reason),
        }
    }
    /// The semantic scan every shell command text passes before its class is judged.
    fn scan_command(&self, command: &str) -> std::result::Result<(), DenialReason> {
        let scan = self
            .redactor
            .scan_prompt(&crate::ScanPromptRequest {
                text: command.to_owned(),
            })
            .map_err(|_| DenialReason::Content)?;
        scan_denial(&scan.verdict).map_or(Ok(()), Err)
    }
    fn allowed(&self) -> Decision {
        Decision {
            generation: self.generation,
            verdict: Verdict::Allow,
            cacheable: false,
        }
    }
    fn denied(&self, reason: DenialReason) -> Decision {
        Decision {
            generation: self.generation,
            verdict: Verdict::Deny { reason },
            cacheable: false,
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
/// Validate one subject's base settings with the same rules as module configuration.
pub(crate) fn validate_settings(p: &PolicyConfig) -> Result<()> {
    if p.enabled && (!path::valid_root(&p.action_dir) || !path::valid_root(&p.workspace_dir)) {
        return Err(Error::InvalidConfig);
    }
    if p.forbidden_paths
        .iter()
        .any(|root| !std::path::Path::new(root).is_absolute())
        || p.allowed_commands
            .iter()
            .any(|c| c.is_empty() || c.chars().any(char::is_whitespace))
    {
        return Err(Error::InvalidConfig);
    }
    // Protected paths in a denylist are redundant denials. Use the same
    // normalizer as registered policies to reject malformed paths without
    // mistaking an explicit credential/system denial for an invalid root.
    crate::scoped_forbidden::effective_forbidden(p, None).map_err(|_| Error::InvalidConfig)?;
    Ok(())
}

fn validate(config: &ModuleConfig) -> Result<()> {
    if config.contract_version.0 != CONTRACT_VERSION.0
        || config.contract_version.1 > CONTRACT_VERSION.1
    {
        return Err(Error::IncompatibleVersion);
    }
    if let Some(judge) = &config.judge {
        tinysecurity_auto::Engine::validate_config(judge).map_err(|_| Error::InvalidConfig)?;
    }
    validate_settings(&config.policy)?;
    Ok(())
}

fn registry(config: &ModuleConfig) -> Result<tinysecurity_redact::Redactor> {
    let mut registry = config.redactor.clone();
    if let Some(judge) = &config.judge {
        for secret in [&judge.credential, &crate::Secret(judge.endpoint.clone())] {
            if !registry.secrets.contains(secret) {
                registry.secrets.push(secret.clone());
            }
        }
    }
    tinysecurity_redact::Redactor::new(&registry)
}

fn scan_denial(verdict: &crate::ScanVerdict) -> Option<DenialReason> {
    match verdict {
        crate::ScanVerdict::Clean => None,
        crate::ScanVerdict::Suspicious => Some(DenialReason::ApprovalUnavailable),
        crate::ScanVerdict::Blocked => Some(DenialReason::Content),
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
