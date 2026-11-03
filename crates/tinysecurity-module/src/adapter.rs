//! SDK-configured native policy service, with no lifecycle RPC members.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tinybus::{Connection, Result as BusResult};
use tinysecurity::{
    CommandPolicyRegistry, EgressPolicyRegistry, PathPolicyRegistry, Policy, ScopedPolicyRegistry,
};
use tinysecurity_bus::{
    BudgetDecision2, CheckRequest, CheckResponse, CommandAutonomy, Decision, EvaluateRequest,
    ModuleConfig, PolicyInfo, names,
};

#[cfg(all(feature = "native-security-tests", debug_assertions))]
#[path = "native_test_resolver.rs"]
mod native_test_resolver;

#[path = "adapter_permission.rs"]
mod permission;

static PATH_SCOPES: OnceLock<Arc<Mutex<PathPolicyRegistry>>> = OnceLock::new();
static COMMAND_SCOPES: OnceLock<Arc<Mutex<CommandPolicyRegistry>>> = OnceLock::new();
static SCOPED_POLICIES: OnceLock<Arc<Mutex<ScopedPolicyRegistry>>> = OnceLock::new();
static EGRESS_SCOPES: OnceLock<Arc<Mutex<EgressPolicyRegistry>>> = OnceLock::new();
static EXTENDED_REDACTORS: OnceLock<Arc<tinysecurity::ExtendedRedactors>> = OnceLock::new();
static AUDIT_CLIENT: OnceLock<Option<Arc<crate::callbacks::AuditClient>>> = OnceLock::new();
static HOST_BINDING: OnceLock<crate::callbacks::PeerBinding> = OnceLock::new();
static SECRET_SCOPE_LIFECYCLE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static APPROVALS: OnceLock<
    Option<(
        tinysecurity_bus::ApprovalConfig2,
        Arc<tinysecurity::approval::Engine>,
    )>,
> = OnceLock::new();
static SANDBOX: OnceLock<
    Option<(
        tinysecurity_bus::SandboxConfig2,
        Arc<tinysecurity::sandbox::Engine>,
    )>,
> = OnceLock::new();
static ACTIVE: OnceLock<Arc<RwLock<Policy>>> = OnceLock::new();
type BudgetReplayKey = (String, String, String, String, String);
type BudgetReplayMap = HashMap<BudgetReplayKey, AuditedReplay>;
const MAX_AUDITED_REPLAYS: usize = 4096;
const AUDITED_REPLAY_TTL: Duration = Duration::from_secs(3600);
enum AuditedReplay {
    Budget(BudgetReplay),
    Command(CommandReplay),
}
impl AuditedReplay {
    fn is_live(&self) -> bool {
        match self {
            Self::Budget(replay) => replay.reserved_at.elapsed() < AUDITED_REPLAY_TTL,
            Self::Command(replay) => replay.cached_at.elapsed() < AUDITED_REPLAY_TTL,
        }
    }
}
#[derive(Clone)]
struct BudgetReplay {
    request: tinysecurity_bus::ReserveActionBudgetAuditedRequest2,
    response: tinysecurity_bus::ReserveActionBudgetAuditedResponse2,
    reserved_at: Instant,
}
#[derive(Clone)]
struct CommandReplay {
    request: tinysecurity_bus::CheckCommandAuditedRequest2,
    response: tinysecurity_bus::CheckCommandAuditedResponse2,
    cached_at: Instant,
}
#[derive(Clone)]
struct PolicyService {
    sandbox_clock: Arc<dyn tinysecurity::approval::Clock>,
    device: Option<Arc<tinysecurity::crypto::device_handles::Registry>>,
    crypto: Option<Arc<crypto::CryptoState>>,
    secret: Option<Arc<secret::SecretState>>,
    secret_cipher: Option<Arc<cipher::CipherState>>,
    sandbox: Option<Arc<tinysecurity::sandbox::Engine>>,
    sandbox_runtime: Option<Arc<sandbox_scopes::SandboxRuntime>>,
    approvals: Option<Arc<tinysecurity::approval::Engine>>,
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
    paths: Arc<Mutex<PathPolicyRegistry>>,
    commands: Arc<Mutex<CommandPolicyRegistry>>,
    egress: Arc<Mutex<EgressPolicyRegistry>>,
    extended: Arc<tinysecurity::ExtendedRedactors>,
    scoped: Arc<Mutex<ScopedPolicyRegistry>>,
    signals: Option<Connection>,
    budget_replays: Arc<tokio::sync::Mutex<BudgetReplayMap>>,
}
fn failure(error: &tinysecurity_bus::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}

#[cfg(all(feature = "native-security-tests", debug_assertions))]
fn egress_resolver() -> &'static dyn tinysecurity::Resolver {
    native_test_resolver::resolver()
}

#[cfg(not(all(feature = "native-security-tests", debug_assertions)))]
fn egress_resolver() -> &'static dyn tinysecurity::Resolver {
    &tinysecurity::SystemResolver
}

impl PolicyService {
    fn requires_bound_audit(&self) -> bool {
        self.approvals.is_some() || self.audit.as_ref().is_some_and(|client| client.required())
    }
    /// Whether the configured audit makes every permission carry its own durable event.
    fn audit_required(&self) -> bool {
        self.audit.as_ref().is_some_and(|client| client.required())
    }
    /// Refuse a permission member that has no audit correlation when audit is required.
    ///
    /// Configured approvals alone do not refuse these members: the durable approval
    /// lifecycle governs `EvaluateApproval2`, while filesystem, command and egress
    /// questions are separate permissions that never request a human decision. A host
    /// that configures approvals must keep validating paths and commands.
    fn require_unbound_permission(&self) -> BusResult<()> {
        if self.audit_required() {
            return Err(tinybus::Error::failed(
                "required audit needs bound permission",
            ));
        }
        Ok(())
    }
    async fn audit_permission(
        &self,
        request: serde_json::Value,
        result: serde_json::Value,
        correlation: tinysecurity_bus::AuditCorrelation2,
        generation: u64,
        redactor: tinysecurity::Redactor,
    ) -> BusResult<tinysecurity_bus::AuditResponse2> {
        self.audit_operation(
            request,
            result,
            correlation,
            generation,
            redactor,
            "permission",
        )
        .await
    }
    async fn audit_operation(
        &self,
        request: serde_json::Value,
        result: serde_json::Value,
        correlation: tinysecurity_bus::AuditCorrelation2,
        generation: u64,
        redactor: tinysecurity::Redactor,
        attribution: &str,
    ) -> BusResult<tinysecurity_bus::AuditResponse2> {
        use tinysecurity_bus::{
            AuditEvent2, AuditHealth2, AuditKind2, AuditResponse2, AuditSinkRequest2,
        };
        let denied = || AuditResponse2 {
            permitted: false,
            committed: false,
            health: AuditHealth2::Denied,
            receipt: None,
        };
        let client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("audit unavailable"))?;
        let Some(sequence) = correlation.expected_tail.checked_add(1) else {
            return Ok(denied());
        };
        if correlation.generation != generation {
            return Ok(denied());
        }
        let batch = AuditSinkRequest2 {
            scope: client.scope().clone(),
            stream_id: client.stream_id().to_owned(),
            expected_tail: correlation.expected_tail,
            events: vec![AuditEvent2 {
                sequence,
                event_id: correlation.event_id,
                generation,
                kind: AuditKind2::Shell,
                attribution: attribution.into(),
                arguments_json: permission_payload(serde_json::json!([request, result]))?,
                rule_ids: vec![],
            }],
        };
        let mut evidence = client.append_with_registry(batch, Ok(redactor)).await;
        if self.read()?.info().generation != generation {
            // A policy race cannot turn a durable old-generation event into permission.
            // Keep its exact committed receipt for reconciliation and diagnostics.
            evidence.permitted = false;
        }
        Ok(evidence)
    }
    /// Read or reserve one action from a registered command scope's hourly ledger.
    /// A read-only tier refuses before anything is spent; a disabled scope is inert.
    async fn budget_decision(
        &self,
        request: tinysecurity_bus::BudgetRequest2,
        spend: bool,
    ) -> BusResult<tinysecurity_bus::BudgetDecision2> {
        self.require_unbound_permission()?;
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.command_policy)
            .map_err(|error| failure(&error))?;
        let max_per_hour = scope.max_actions_per_hour();
        let decision = if !scope.enabled() {
            BudgetDecision2::Allow
        } else if scope.autonomy() == CommandAutonomy::ReadOnly {
            BudgetDecision2::ReadOnlyMode
        } else if (spend && !scope.reserve()) || (!spend && scope.exhausted()) {
            BudgetDecision2::RateLimited { max_per_hour }
        } else {
            BudgetDecision2::Allow
        };
        std::future::ready(Ok(decision)).await
    }
    /// Evaluate one registered command and expose its noncacheable execution
    /// decision only after the guarded action reservation has a durable receipt.
    async fn check_command_audited(
        &self,
        request: tinysecurity_bus::CheckCommandAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::CheckCommandAuditedResponse2> {
        let policy = self.read()?.clone();
        let generation = policy.info().generation;
        // Resolve current ownership before replay lookup. A cached allow cannot
        // outlive the service's registration of the command scope.
        let command_scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.request.policy_id)
            .map_err(|error| failure(&error))?;
        let denied = || tinysecurity_bus::CheckCommandAuditedResponse2 {
            decision: None,
            audit: tinysecurity_bus::AuditResponse2 {
                permitted: false,
                committed: false,
                health: tinysecurity_bus::AuditHealth2::Denied,
                receipt: None,
            },
        };
        if request.audit.generation != generation {
            return Ok(denied());
        }

        let audit_client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("command audit unavailable"))?;
        let audit_scope = audit_client.scope();
        let replay_key = (
            audit_scope.user.clone(),
            audit_scope.workspace.clone(),
            audit_scope.agent.clone(),
            audit_client.stream_id().to_owned(),
            request.audit.event_id.clone(),
        );
        let mut replays = self.budget_replays.lock().await;
        replays.retain(|_, replay| replay.is_live());
        if let Some(previous) = replays.get(&replay_key) {
            if let AuditedReplay::Command(previous) = previous
                && previous.request == request
            {
                return Ok(previous.response.clone());
            }
            return Err(tinybus::Error::failed(
                "audited operation conflicts with a prior request",
            ));
        }
        if replays.len() >= MAX_AUDITED_REPLAYS {
            return Err(tinybus::Error::failed(
                "audited operation replay cache is full",
            ));
        }

        let checked_request = request.request.clone();
        let (decision, spent) = tokio::task::spawn_blocking(move || {
            command_scope
                .check_guarded(&checked_request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let audit = self
            .audit_operation(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit.clone(),
                generation,
                policy.redactor(),
                "command_execution_check",
            )
            .await?;
        let committed = audit.permitted && audit.committed;
        let response = tinysecurity_bus::CheckCommandAuditedResponse2 {
            decision: committed.then_some(decision),
            audit,
        };
        if committed {
            if let Some(spent) = spent {
                spent.commit();
            }
            replays.insert(
                replay_key,
                AuditedReplay::Command(CommandReplay {
                    request,
                    response: response.clone(),
                    cached_at: Instant::now(),
                }),
            );
        }
        Ok(response)
    }
    /// Reserve action-budget accounting after durably auditing the exact operation.
    /// This result is accounting only; it does not authorize a tool, command, path,
    /// approval, or other execution. The host must complete all such checks itself.
    async fn reserve_audited_budget(
        &self,
        request: tinysecurity_bus::ReserveActionBudgetAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::ReserveActionBudgetAuditedResponse2> {
        let audit_client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("action budget audit unavailable"))?;
        let audit_scope = audit_client.scope();
        let replay_key = (
            audit_scope.user.clone(),
            audit_scope.workspace.clone(),
            audit_scope.agent.clone(),
            audit_client.stream_id().to_owned(),
            request.audit.event_id.clone(),
        );
        // Serialize reservations through their durable receipt. Identical concurrent
        // retries then observe the same completed reservation rather than spending twice.
        let mut replays = self.budget_replays.lock().await;
        replays.retain(|_, replay| replay.is_live());
        let policy = self.read()?.clone();
        let generation = policy.info().generation;
        if request.audit.generation != generation {
            return Err(tinybus::Error::failed(
                "stale action budget audit generation",
            ));
        }
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.request.command_policy)
            .map_err(|error| failure(&error))?;
        if let Some(previous) = replays.get(&replay_key) {
            if let AuditedReplay::Budget(previous) = previous
                && previous.request == request
            {
                return Ok(previous.response.clone());
            }
            return Err(tinybus::Error::failed(
                "audited operation conflicts with a prior request",
            ));
        }
        if replays.len() >= MAX_AUDITED_REPLAYS {
            return Err(tinybus::Error::failed(
                "audited operation replay cache is full",
            ));
        }
        let max_per_hour = scope.max_actions_per_hour();
        let (decision, spent, reserved_at) = if !scope.enabled() {
            (BudgetDecision2::Allow, None, None)
        } else if scope.autonomy() == CommandAutonomy::ReadOnly {
            (BudgetDecision2::ReadOnlyMode, None, None)
        } else if let Some(spent) = scope.reserve_guarded() {
            (BudgetDecision2::Allow, Some(spent), Some(Instant::now()))
        } else {
            (BudgetDecision2::RateLimited { max_per_hour }, None, None)
        };
        let audit = self
            .audit_operation(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit.clone(),
                generation,
                policy.redactor(),
                "action_budget_reservation",
            )
            .await?;
        if !audit.permitted || !audit.committed {
            return Err(tinybus::Error::failed("action budget audit did not commit"));
        }
        let response = tinysecurity_bus::ReserveActionBudgetAuditedResponse2 { decision, audit };
        if let Some(spent) = spent {
            let reserved_at = reserved_at.ok_or_else(|| {
                tinybus::Error::failed("action budget reservation timestamp unavailable")
            })?;
            // No await occurs between keeping the ledger reservation and publishing
            // its replay result, so cancellation cannot create an uncached committed spend.
            spent.commit();
            replays.insert(
                replay_key,
                AuditedReplay::Budget(BudgetReplay {
                    request,
                    response: response.clone(),
                    reserved_at,
                }),
            );
        }
        Ok(response)
    }
    async fn run_path<T, F>(&self, id: tinysecurity_bus::PathPolicyId, operation: F) -> BusResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&tinysecurity::PathScope) -> T + Send + 'static,
    {
        let scope = self
            .paths
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&id)
            .map_err(|error| failure(&error))?;
        // Drop the registry lock before filesystem I/O. A stalled mount must
        // neither serialize other agents nor block the sole SDK runtime worker.
        tokio::task::spawn_blocking(move || operation(&scope))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }

    async fn register_path_with<F>(
        &self,
        policy: tinysecurity_bus::PathPolicy,
        prepare: F,
    ) -> BusResult<tinysecurity_bus::PathPolicyId>
    where
        F: FnOnce(
                tinysecurity_bus::PathPolicy,
            ) -> tinysecurity_bus::Result<tinysecurity::PreparedPathPolicy>
            + Send
            + 'static,
    {
        let paths = Arc::clone(&self.paths);
        tokio::task::spawn_blocking(move || {
            let prepared = prepare(policy).map_err(|error| failure(&error))?;
            let mut registry = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            registry
                .register_prepared(prepared)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    async fn consume_egress_with<F>(
        &self,
        request: tinysecurity_bus::ConsumeEgressAuthorizationRequest,
        operation: F,
    ) -> BusResult<bool>
    where
        F: FnOnce(
                &tinysecurity::RegisteredEgressPolicy,
                &tinysecurity_bus::ConsumeEgressAuthorizationRequest,
                u64,
            ) -> bool
            + Send
            + 'static,
    {
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.authorization.policy_id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        tokio::task::spawn_blocking(move || operation(&scope, &request, generation))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }

    /// The one registered command scope a request's host-tool checks name,
    /// if any. A request that mixes checks naming a scope with checks that do not,
    /// names two different scopes, or names an unknown one, is refused.
    fn host_scope(
        &self,
        checks: &[tinysecurity_bus::Check],
    ) -> BusResult<Option<Arc<tinysecurity::RegisteredCommandPolicy>>> {
        let Some(id) = tinysecurity::host_tool_request_scope(checks)
            .map_err(|_| failure(&tinysecurity_bus::Error::InvalidArguments))?
        else {
            return Ok(None);
        };
        self.commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(id)
            .map(Some)
            .map_err(|error| failure(&error))
    }
    fn read(&self) -> BusResult<std::sync::RwLockReadGuard<'_, Policy>> {
        self.policy
            .read()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.Policy")]
impl PolicyService {
    #[tinybus(confidential)]
    async fn evaluate_secret_cipher2(
        &self,
        request: tinysecurity_bus::EvaluateSecretCipherRequest2,
    ) -> BusResult<tinysecurity_bus::SecretCipherPending2> {
        self.cipher_evaluate(request).await
    }
    #[tinybus(confidential)]
    async fn execute_secret_cipher2(
        &self,
        request: tinysecurity_bus::ExecuteSecretCipherRequest2,
    ) -> BusResult<tinysecurity_bus::SecretCipherResponse2> {
        self.cipher_execute(request).await
    }
    #[tinybus(confidential)]
    async fn evaluate_secret2(
        &self,
        request: tinysecurity_bus::EvaluateSecretRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.secret_approval(request).await
    }
    #[tinybus(confidential)]
    async fn execute_secret2(
        &self,
        request: tinysecurity_bus::ExecuteSecretRequest2,
    ) -> BusResult<tinysecurity_bus::SecretResponse2> {
        self.secret_execute(request).await
    }
    #[tinybus(confidential)]
    async fn password_crypt2(
        &self,
        request: tinysecurity_bus::PasswordRequest2,
    ) -> BusResult<tinysecurity_bus::PasswordResponse2> {
        self.password_crypt(request).await
    }
    #[tinybus(confidential)]
    async fn keyring_access2(
        &self,
        request: tinysecurity_bus::KeyringRequest2,
    ) -> BusResult<tinysecurity_bus::KeyringResponse2> {
        self.keyring_access(request).await
    }
    #[tinybus(confidential)]
    async fn pairing_control2(
        &self,
        request: tinysecurity_bus::PairingRequest2,
    ) -> BusResult<tinysecurity_bus::PairingResponse2> {
        std::future::ready(self.pairing_control(request)).await
    }
    #[tinybus(confidential)]
    async fn evaluate_device2(
        &self,
        request: tinysecurity_bus::EvaluateDeviceRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.device_approval(request).await
    }
    #[tinybus(confidential)]
    async fn execute_device2(
        &self,
        request: tinysecurity_bus::ExecuteDeviceRequest2,
    ) -> BusResult<tinysecurity_bus::DeviceResponse2> {
        self.device_execute(request).await
    }
    #[tinybus(confidential)]
    async fn device_pairing2(
        &self,
        request: tinysecurity_bus::DevicePairingRequest2,
    ) -> BusResult<tinysecurity_bus::DevicePairingResponse2> {
        device_pairing::invoke(request).await
    }
    #[tinybus(confidential)]
    /// Dispatch the no-human-prompt frame member; the adapter rechecks authority after crypto.
    async fn device_frame2(
        &self,
        request: tinysecurity_bus::DeviceFrameRequest2,
    ) -> BusResult<tinysecurity_bus::DeviceFrameResponse2> {
        self.device_frame(request).await
    }
    async fn plan(
        &self,
        _request: tinysecurity_bus::SandboxPlanRequest,
    ) -> BusResult<tinysecurity_bus::SandboxPlanResponse> {
        let generation = { self.read()?.info().generation };
        std::future::ready(Ok(tinysecurity_bus::SandboxPlanResponse {
            decision: Decision {
                generation,
                verdict: tinysecurity_bus::Verdict::Deny {
                    reason: tinysecurity_bus::DenialReason::InvalidContext,
                },
                cacheable: false,
            },
            backend: None,
            grants: vec![],
            network: tinysecurity_bus::NetworkPolicy::None,
            limits: tinysecurity_bus::ResourceLimits {
                memory_bytes: 0,
                cpu_millis: 0,
                processes: 0,
            },
        }))
        .await
    }
    async fn evaluate_sandbox_approval2(
        &self,
        request: tinysecurity_bus::EvaluateSandboxApprovalRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.sandbox_approval(request).await
    }
    async fn consume_sandbox_plan2(
        &self,
        request: tinysecurity_bus::ConsumeSandboxPlanRequest2,
    ) -> BusResult<tinysecurity_bus::ConsumeSandboxPlanResponse2> {
        self.sandbox_consume(request).await
    }
    async fn plan2(
        &self,
        request: tinysecurity_bus::SandboxPlanRequest2,
    ) -> BusResult<tinysecurity_bus::SandboxPlanResponse2> {
        self.sandbox_plan(request).await
    }
    async fn evaluate(&self, request: EvaluateRequest) -> BusResult<Decision> {
        let admission = admission_only(&request.call.checks);
        if admission {
            self.require_unbound_permission()?;
        }
        let policy = self.read()?.clone();
        let scope = self.host_scope(&request.call.checks)?;
        let bound = self.requires_bound_audit() && !admission;
        tokio::task::spawn_blocking(move || {
            let mut decision = policy
                .evaluate_hosted(scope.as_deref(), &request)
                .map_err(|error| failure(&error))?;
            // An admission question permits no effect the module audits: the host runs
            // the tool under its own accounting, so only refusals are bound to audit.
            if bound {
                deny_allow(&mut decision);
            }
            // The action is reserved last, so nothing that refuses the call spends it.
            let (decision, spent) =
                policy.settle_spend(scope.as_ref(), &request.call.checks, decision);
            if let Some(spent) = spent {
                spent.commit();
            }
            Ok(decision)
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check(&self, request: CheckRequest) -> BusResult<CheckResponse> {
        let policy = self.read()?.clone();
        let scope = self.host_scope(&request.checks)?;
        let mut response = tokio::task::spawn_blocking(move || {
            Ok::<_, tinybus::Error>(policy.check_hosted(scope.as_deref(), &request))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        if self.requires_bound_audit() {
            response.decisions.iter_mut().for_each(deny_allow);
        }
        Ok(response)
    }
    async fn evaluate_audited2(
        &self,
        request: tinysecurity_bus::EvaluateAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::EvaluateAuditedResponse2> {
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let original = request.request.clone();
        let scope = self.host_scope(&original.call.checks)?;
        let settler = policy.clone();
        let decision = tokio::task::spawn_blocking({
            let (scope, original) = (scope.clone(), original.clone());
            move || {
                policy
                    .evaluate_hosted(scope.as_deref(), &original)
                    .map_err(|error| failure(&error))
            }
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        // Reserved before the audit so the durable event records the final verdict. The
        // guard gives the action back on every early return and when the audit or the
        // approval gate still refuses the call.
        let (decision, spent) =
            settler.settle_spend(scope.as_ref(), &original.call.checks, decision);
        let audit = self
            .audit_permission(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit,
                decision.generation,
                registry,
            )
            .await?;
        let mut decision = decision;
        if !audit.permitted || self.approvals.is_some() {
            deny_allow(&mut decision);
        }
        if let Some(spent) = spent
            && decision.verdict == tinysecurity_bus::Verdict::Allow
        {
            spent.commit();
        }
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
    async fn check_audited2(
        &self,
        request: tinysecurity_bus::CheckAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::CheckAuditedResponse2> {
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let original = request.request.clone();
        let scope = self.host_scope(&original.checks)?;
        let mut decision = tokio::task::spawn_blocking(move || {
            Ok::<_, tinybus::Error>(policy.check_hosted(scope.as_deref(), &original))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let audit = self
            .audit_permission(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit,
                decision.generation,
                registry,
            )
            .await?;
        if !audit.permitted || self.approvals.is_some() {
            decision.decisions.iter_mut().for_each(deny_allow);
        }
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
    // Host-only configuration on a private, trusted in-process bus. This module
    // evaluates policy; it is not a public authentication or filesystem service.
    async fn check_permission_audited2(
        &self,
        request: tinysecurity_bus::PermissionAuditRequest2,
    ) -> BusResult<tinysecurity_bus::PermissionAuditResponse2> {
        self.audited_permission(request).await
    }
    async fn register_path_policy(
        &self,
        policy: tinysecurity_bus::PathPolicy,
    ) -> BusResult<tinysecurity_bus::PathPolicyId> {
        self.register_path_with(policy, tinysecurity::PreparedPathPolicy::new)
            .await
    }
    async fn validate_path(
        &self,
        request: tinysecurity_bus::PathValidationRequest,
    ) -> BusResult<tinysecurity_bus::PathValidationResult> {
        self.require_unbound_permission()?;
        self.run_path(request.policy_id, move |scope| {
            scope.validate(&request.path, false)
        })
        .await
    }
    async fn validate_parent(
        &self,
        request: tinysecurity_bus::PathValidationRequest,
    ) -> BusResult<tinysecurity_bus::PathValidationResult> {
        self.require_unbound_permission()?;
        self.run_path(request.policy_id, move |scope| {
            scope.validate(&request.path, true)
        })
        .await
    }
    async fn check_path(&self, request: tinysecurity_bus::PathCheckRequest) -> BusResult<bool> {
        self.require_unbound_permission()?;
        self.run_path(request.policy_id, move |scope| {
            scope.check_path(&request.path, request.kind)
        })
        .await
    }
    async fn check_paths2(
        &self,
        request: tinysecurity_bus::PathBatchRequest2,
    ) -> BusResult<tinysecurity_bus::PathBatchResponse2> {
        self.require_unbound_permission()?;
        request.validate().map_err(|error| failure(&error))?;
        let tinysecurity_bus::PathBatchRequest2 {
            policy_id,
            kind,
            paths,
        } = request;
        // One blocking hop for the whole batch; each entry is an independent
        // `CheckPath`-equivalent query with no result shared between entries.
        let allowed = self
            .run_path(policy_id, move |scope| {
                paths
                    .iter()
                    .map(|path| scope.check_path(path, kind))
                    .collect::<Vec<_>>()
            })
            .await?;
        Ok(tinysecurity_bus::PathBatchResponse2 { allowed })
    }
    async fn protected_path2(
        &self,
        request: tinysecurity_bus::ProtectedPathRequest2,
    ) -> BusResult<tinysecurity_bus::ProtectedPathResponse2> {
        request.validate().map_err(|error| failure(&error))?;
        std::future::ready(Ok(tinysecurity_bus::ProtectedPathResponse2 {
            protected: request
                .paths
                .iter()
                .map(|path| tinysecurity::lexical_floor(path))
                .collect(),
        }))
        .await
    }
    async fn protected_floor2(&self) -> BusResult<tinysecurity_bus::ProtectedFloor2> {
        std::future::ready(Ok(tinysecurity::floor_vocabulary())).await
    }
    async fn credential_roots2(
        &self,
        request: tinysecurity_bus::CredentialRootsRequest2,
    ) -> BusResult<tinysecurity_bus::CredentialRootsResponse2> {
        let roots = tokio::task::spawn_blocking(move || {
            tinysecurity::credential_roots(request.home.as_deref())
        })
        .await
        .map_err(|_| tinybus::Error::failed("credential root resolution unavailable"))?
        .map_err(|error| failure(&error))?;
        let response = tinysecurity_bus::CredentialRootsResponse2 { roots };
        response.validate().map_err(|error| failure(&error))?;
        std::future::ready(Ok(response)).await
    }
    async fn spend_action2(
        &self,
        request: tinysecurity_bus::BudgetRequest2,
    ) -> BusResult<tinysecurity_bus::BudgetDecision2> {
        self.budget_decision(request, true).await
    }
    async fn reserve_action_budget_audited2(
        &self,
        request: tinysecurity_bus::ReserveActionBudgetAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::ReserveActionBudgetAuditedResponse2> {
        self.reserve_audited_budget(request).await
    }
    async fn peek_budget2(
        &self,
        request: tinysecurity_bus::BudgetRequest2,
    ) -> BusResult<tinysecurity_bus::BudgetDecision2> {
        self.budget_decision(request, false).await
    }
    async fn classify_host_action2(
        &self,
        request: tinysecurity_bus::HostActionClassRequest2,
    ) -> BusResult<tinysecurity_bus::HostActionClassResponse2> {
        std::future::ready(Ok(tinysecurity_bus::HostActionClassResponse2 {
            class: request.class(),
        }))
        .await
    }
    async fn privacy_check2(
        &self,
        request: tinysecurity_bus::PrivacyCheckRequest2,
    ) -> BusResult<tinysecurity_bus::PrivacyCheckResponse2> {
        self.require_unbound_permission()?;
        request.validate().map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        std::future::ready(Ok(tinysecurity_bus::PrivacyCheckResponse2 {
            decision: Decision {
                generation,
                verdict: tinysecurity::privacy_verdict(&request),
                cacheable: false,
            },
        }))
        .await
    }

    async fn classify_provider_endpoint2(
        &self,
        request: tinysecurity_bus::ProviderEndpointRequest2,
    ) -> BusResult<tinysecurity_bus::ProviderEndpointResponse2> {
        request.validate().map_err(|error| failure(&error))?;
        std::future::ready(Ok(tinysecurity_bus::ProviderEndpointResponse2 {
            locality: tinysecurity::classify_provider_endpoint(&request.host),
        }))
        .await
    }

    async fn register_command_policy(
        &self,
        policy: tinysecurity_bus::CommandPolicy,
    ) -> BusResult<tinysecurity_bus::CommandPolicyId> {
        let result = {
            self.commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy)
                .map_err(|error| failure(&error))
        };
        std::future::ready(result).await
    }
    async fn classify_command(
        &self,
        request: tinysecurity_bus::CommandRequest,
    ) -> BusResult<tinysecurity_bus::CommandDecision> {
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        tokio::task::spawn_blocking(move || {
            scope.classify(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check_command(
        &self,
        request: tinysecurity_bus::CommandRequest,
    ) -> BusResult<tinysecurity_bus::CommandDecision> {
        self.require_unbound_permission()?;
        let scope = self
            .commands
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        tokio::task::spawn_blocking(move || scope.check(&request).map_err(|error| failure(&error)))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check_command_audited2(
        &self,
        request: tinysecurity_bus::CheckCommandAuditedRequest2,
    ) -> BusResult<tinysecurity_bus::CheckCommandAuditedResponse2> {
        self.check_command_audited(request).await
    }

    // Private host-only configuration. SubjectScope is a trusted-adapter claim,
    // not JSON authentication. Never expose these members to model/public callers.
    async fn register_egress_policy(
        &self,
        policy: tinysecurity_bus::EgressPolicy,
    ) -> BusResult<tinysecurity_bus::EgressPolicyId> {
        let registry = Arc::clone(&self.egress);
        tokio::task::spawn_blocking(move || {
            registry
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scoped_url_guard(
        &self,
        request: tinysecurity_bus::ScopedEgressRequest,
    ) -> BusResult<tinysecurity_bus::ScopedEgressResponse> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        // Drop every state lock before parsing, payload checks and bounded DNS.
        tokio::task::spawn_blocking(move || {
            scope.url_guard(&request, generation, egress_resolver(), &redactor)
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    async fn scoped_egress_check(
        &self,
        request: tinysecurity_bus::ScopedEgressRequest,
    ) -> BusResult<tinysecurity_bus::ScopedEgressResponse> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        tokio::task::spawn_blocking(move || {
            scope.check_with_redactor(&request, generation, egress_resolver(), &redactor)
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    async fn consume_egress_authorization(
        &self,
        request: tinysecurity_bus::ConsumeEgressAuthorizationRequest,
    ) -> BusResult<bool> {
        self.require_unbound_permission()?;
        self.consume_egress_with(request, |scope, request, generation| {
            scope.consume_request(
                &request.request,
                &request.authorization,
                &request.subject,
                generation,
            )
        })
        .await
    }
    /// Authorize one browser proxy destination using its registered egress policy.
    async fn authorize_browser_dial(
        &self,
        request: tinysecurity_bus::BrowserDialRequest,
    ) -> BusResult<tinysecurity_bus::BrowserDialResponse> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        tokio::task::spawn_blocking(move || {
            scope.authorize_browser_dial(&request, generation, egress_resolver())
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    /// Consume a one-use grant immediately before dialing the approved socket.
    async fn consume_browser_dial(
        &self,
        request: tinysecurity_bus::ConsumeBrowserDialRequest,
    ) -> BusResult<bool> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.authorization.policy_id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        tokio::task::spawn_blocking(move || scope.consume_browser_dial(&request, generation))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    /// Check that an established browser tunnel lease remains active.
    async fn validate_browser_dial(
        &self,
        request: tinysecurity_bus::ValidateBrowserDialRequest,
    ) -> BusResult<bool> {
        self.require_unbound_permission()?;
        let scope = self
            .egress
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.authorization.policy_id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        tokio::task::spawn_blocking(move || scope.validate_browser_dial(&request, generation))
            .await
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
    }
    // Legacy shapes cannot provide immutable scope/owner/transport authority.
    async fn url_guard(
        &self,
        _request: tinysecurity_bus::UrlGuardRequest,
    ) -> BusResult<tinysecurity_bus::UrlGuardResponse> {
        let decision = Decision {
            generation: self.read()?.info().generation,
            verdict: tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::InvalidContext,
            },
            cacheable: false,
        };
        std::future::ready(Ok(tinysecurity_bus::UrlGuardResponse {
            decision,
            hostname: String::new(),
            approved_addresses: vec![],
        }))
        .await
    }
    async fn egress_check(
        &self,
        _request: tinysecurity_bus::EgressCheckRequest,
    ) -> BusResult<tinysecurity_bus::EgressCheckResponse> {
        let decision = Decision {
            generation: self.read()?.info().generation,
            verdict: tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::InvalidContext,
            },
            cacheable: false,
        };
        std::future::ready(Ok(tinysecurity_bus::EgressCheckResponse { decision })).await
    }

    async fn redact(
        &self,
        request: tinysecurity_bus::RedactRequest,
    ) -> BusResult<tinysecurity_bus::RedactResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry.redact(&request).map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    #[tinybus(confidential)]
    async fn redact_with(
        &self,
        request: tinysecurity_bus::RedactWithRequest,
    ) -> BusResult<tinysecurity_bus::RedactResponse> {
        let registry = self.read()?.redactor();
        let extended = Arc::clone(&self.extended);
        tokio::task::spawn_blocking(move || {
            extended
                .redact(&registry, &request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_prompt(
        &self,
        request: tinysecurity_bus::ScanPromptRequest,
    ) -> BusResult<tinysecurity_bus::ScanResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_prompt(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_prompt2(
        &self,
        request: tinysecurity_bus::ScanPromptScoredRequest2,
    ) -> BusResult<tinysecurity_bus::ScanPromptScoredResponse2> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_prompt_scored(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn scan_tool_definition(
        &self,
        request: tinysecurity_bus::ScanToolDefinitionRequest,
    ) -> BusResult<tinysecurity_bus::ScanResponse> {
        let registry = self.read()?.redactor();
        tokio::task::spawn_blocking(move || {
            registry
                .scan_tool_definition(&request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }

    async fn audit2(
        &self,
        request: tinysecurity_bus::AuditSinkRequest2,
    ) -> BusResult<tinysecurity_bus::AuditResponse2> {
        let client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("audit unavailable"))?;
        Ok(client.append(request).await)
    }
    async fn record_audit2(
        &self,
        request: tinysecurity_bus::AuditRecordRequest2,
    ) -> BusResult<tinysecurity_bus::AuditResponse2> {
        let client = self
            .audit
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("audit unavailable"))?;
        let (generation, redactor) = {
            let policy = self.read()?;
            (policy.info().generation, policy.redactor())
        };
        Ok(client.record(request, generation, redactor).await)
    }
    async fn evaluate_approval2(
        &self,
        request: tinysecurity_bus::EvaluateApprovalRequest2,
    ) -> BusResult<tinysecurity_bus::EvaluateApprovalResponse2> {
        let engine = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?;
        let policy = self.read()?.clone();
        let actual = request.request.clone();
        // A named command scope's read-only tier and spent budget are hard denials a
        // human cannot approve away; they are read here and reserved at consumption.
        let scope = self.host_scope(&actual.call.checks)?;
        let decision = tokio::task::spawn_blocking({
            let scope = scope.clone();
            move || policy.evaluate_hosted(scope.as_deref(), &actual)
        })
        .await
        .map_err(|_| tinybus::Error::failed("approval unavailable"))?
        .map_err(|_| tinybus::Error::failed("approval denied"))?;
        // Human approval cannot override floors, unknown effects or policy denial.
        if matches!(decision.verdict,tinysecurity_bus::Verdict::Deny{ref reason} if *reason!=tinysecurity_bus::DenialReason::ApprovalUnavailable)
        {
            return Err(tinybus::Error::failed("approval denied"));
        }
        let request_for_recheck = request.request.clone();
        let row = engine.begin(request).await.map_err(approval_failure)?;
        let fresh = self
            .read()?
            .evaluate_hosted(scope.as_deref(), &request_for_recheck)
            .map_err(|_| tinybus::Error::failed("approval denied"))?;
        if fresh.generation != row.binding.generation
            || matches!(fresh.verdict,tinysecurity_bus::Verdict::Deny{ref reason} if *reason != tinysecurity_bus::DenialReason::ApprovalUnavailable)
        {
            return Err(tinybus::Error::failed("approval denied"));
        }
        let verdict = match row.state {
            tinysecurity_bus::ApprovalLifecycle2::Pending => {
                tinysecurity_bus::Verdict::RequireApproval {
                    request_id: row.request_id.clone(),
                }
            }
            tinysecurity_bus::ApprovalLifecycle2::Approved => tinysecurity_bus::Verdict::Allow,
            _ => tinysecurity_bus::Verdict::Deny {
                reason: tinysecurity_bus::DenialReason::ApprovalUnavailable,
            },
        };
        Ok(tinysecurity_bus::EvaluateApprovalResponse2 {
            decision: Decision {
                generation: row.binding.generation,
                verdict,
                cacheable: false,
            },
            record: row,
        })
    }
    async fn decide2(
        &self,
        request: tinysecurity_bus::DecideRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .decide(request)
            .await
            .map_err(approval_failure)
    }
    async fn consume_approval2(
        &self,
        request: tinysecurity_bus::ApprovalActionRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        let policy = self.read()?.clone();
        let scope = self.host_scope(&request.request.call.checks)?;
        let decision = policy
            .evaluate_hosted(scope.as_deref(), &request.request)
            .map_err(|_| tinybus::Error::failed("approval denied"))?;
        if matches!(decision.verdict,tinysecurity_bus::Verdict::Deny{ref reason} if *reason != tinysecurity_bus::DenialReason::ApprovalUnavailable)
        {
            return Err(tinybus::Error::failed("approval denied"));
        }
        let checks = request.request.call.checks.clone();
        // The approved call is about to run, so it spends the action it asked for. Reserved
        // before the once-only consumption so a spent ledger refuses the run without
        // burning the approval, and given back if the consumption fails.
        let allowed = Decision {
            generation: decision.generation,
            verdict: tinysecurity_bus::Verdict::Allow,
            cacheable: false,
        };
        let (settled, spent) = policy.settle_spend(scope.as_ref(), &checks, allowed);
        if matches!(settled.verdict, tinysecurity_bus::Verdict::Deny { .. }) {
            return Err(tinybus::Error::failed("approval denied"));
        }
        let row = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .consume(request)
            .await
            .map_err(approval_failure)?;
        if let Some(spent) = spent {
            spent.commit();
        }
        Ok(row)
    }
    async fn record_execution2(
        &self,
        request: tinysecurity_bus::RecordExecutionRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .record_execution(request)
            .await
            .map_err(approval_failure)
    }
    async fn list_approvals2(
        &self,
        request: tinysecurity_bus::ApprovalRecordRequest2,
    ) -> BusResult<Vec<tinysecurity_bus::ApprovalRow2>> {
        if !request.request_id.is_empty() {
            return Err(tinybus::Error::failed("invalid approval listing"));
        }
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .list(&request.scope_id)
            .await
            .map_err(approval_failure)
    }
    async fn list_recent_decisions2(
        &self,
        request: tinysecurity_bus::RecentApprovalDecisionsRequest2,
    ) -> BusResult<Vec<tinysecurity_bus::ApprovalRow2>> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .list_recent_decisions(request.limit)
            .await
            .map_err(approval_failure)
    }
    async fn purge_approval_session2(
        &self,
        request: tinysecurity_bus::PurgeApprovalSessionRequest2,
    ) -> BusResult<usize> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .purge_session(&request.session_id)
            .await
            .map_err(approval_failure)
    }
    async fn record_audit_error2(
        &self,
        request: tinysecurity_bus::RecordAuditErrorRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .record_audit_error(request)
            .await
            .map_err(approval_failure)
    }
    async fn cancel_approval2(
        &self,
        request: tinysecurity_bus::ApprovalRecordRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .cancel(request)
            .await
            .map_err(approval_failure)
    }
    async fn expire_approval2(
        &self,
        request: tinysecurity_bus::ApprovalRecordRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .expire(request)
            .await
            .map_err(approval_failure)
    }
    async fn preauthorize_flow2(
        &self,
        request: tinysecurity_bus::PreauthorizeFlowRequest2,
    ) -> BusResult<Vec<tinysecurity_bus::ApprovalRow2>> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .preauthorize_flow(request)
            .await
            .map_err(approval_failure)
    }
    // Private host-only members: the subject is a trusted-adapter claim, and the flow
    // and tool names are the user's decision, never model input.
    async fn grant_flow_tool2(
        &self,
        request: tinysecurity_bus::GrantFlowToolRequest2,
    ) -> BusResult<tinysecurity_bus::FlowTrustReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .grant_flow_tool(request)
            .await
            .map_err(approval_failure)
    }
    async fn revoke_flow_tool2(
        &self,
        request: tinysecurity_bus::RevokeFlowToolRequest2,
    ) -> BusResult<tinysecurity_bus::FlowTrustReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .revoke_flow_tool(request)
            .await
            .map_err(approval_failure)
    }
    async fn list_flow_trust2(
        &self,
        request: tinysecurity_bus::ListFlowTrustRequest2,
    ) -> BusResult<tinysecurity_bus::FlowTrustList2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .list_flow_trust(request)
            .await
            .map_err(approval_failure)
    }
    // Private host-only members: the registered scope is a trusted-adapter claim.
    async fn grant_tool2(
        &self,
        request: tinysecurity_bus::GrantToolRequest2,
    ) -> BusResult<tinysecurity_bus::ToolTrustReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .grant_tool(request)
            .await
            .map_err(approval_failure)
    }
    async fn revoke_tool2(
        &self,
        request: tinysecurity_bus::RevokeToolRequest2,
    ) -> BusResult<tinysecurity_bus::ToolTrustReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .revoke_tool(request)
            .await
            .map_err(approval_failure)
    }
    async fn revoke_tool_by_id2(
        &self,
        request: tinysecurity_bus::RevokeToolByIdRequest2,
    ) -> BusResult<tinysecurity_bus::ToolTrustReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .revoke_tool_by_id(request)
            .await
            .map_err(approval_failure)
    }
    async fn list_tool_trust2(
        &self,
        request: tinysecurity_bus::ListToolTrustRequest2,
    ) -> BusResult<tinysecurity_bus::ToolTrustList2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .list_tool_trust(request)
            .await
            .map_err(approval_failure)
    }
    // Private host-only migration: source identity is trusted adapter input.
    async fn import_trust_source2(
        &self,
        request: tinysecurity_bus::ImportTrustSourceRequest2,
    ) -> BusResult<tinysecurity_bus::ImportTrustReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .import_trust_source(request)
            .await
            .map_err(approval_failure)
    }
    // Private host-only configuration: the subject is a trusted-adapter claim.
    async fn register_approval_scope2(
        &self,
        request: tinysecurity_bus::RegisterApprovalScopeRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalScopeReceipt2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .register_scope(request)
            .await
            .map_err(approval_failure)
    }
    // Private host-only configuration: the approval scope is resolved inside
    // the module and cannot be supplied by the caller.
    async fn register_secret_scope2(
        &self,
        request: tinysecurity_bus::RegisterSecretScopeRequest2,
    ) -> BusResult<tinysecurity_bus::SecretScopeReceipt2> {
        let _lifecycle = SECRET_SCOPE_LIFECYCLE
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        // The TinyBus interface is asynchronous; registration itself only
        // updates the already-live in-process registries.
        std::future::ready(()).await;
        self.secret
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("secret authority unavailable"))?
            .register_scope(
                request,
                self.approvals
                    .as_ref()
                    .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?,
            )
    }
    // Private host-only registration. The module resolves the live approval
    // scope and derives all pairing and master bindings from trusted state.
    async fn register_device_pairing_scope2(
        &self,
        request: tinysecurity_bus::RegisterDevicePairingScopeRequest2,
    ) -> BusResult<tinysecurity_bus::DevicePairingScopeReceipt2> {
        let _lifecycle = SECRET_SCOPE_LIFECYCLE
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        let approvals = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?;
        device_pairing::register_scope(&request, approvals)
    }
    async fn replace_approval_scope2(
        &self,
        request: tinysecurity_bus::RegisterApprovalScopeRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalScopeReceipt2> {
        let _lifecycle = SECRET_SCOPE_LIFECYCLE
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        let engine = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?;
        let scope_id = request.scope.scope_id.clone();
        let receipt = engine
            .replace_scope(request)
            .await
            .map_err(approval_failure)?;
        if let Some(secret) = &self.secret {
            secret.retire_approval_scope(&scope_id)?;
            secret.refresh_approval_scope(&scope_id, engine)?;
            cipher::refresh_approval_scope(
                &scope_id,
                secret,
                engine,
                self.secret_cipher.as_deref(),
            )?;
        }
        Ok(receipt)
    }
    async fn retire_approval_scope2(
        &self,
        request: tinysecurity_bus::RetireApprovalScopeRequest2,
    ) -> BusResult<tinysecurity_bus::ApprovalScopeReceipt2> {
        let _lifecycle = SECRET_SCOPE_LIFECYCLE
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        let receipt = self
            .approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .retire_scope(request)
            .await
            .map_err(approval_failure)?;
        if let Some(secret) = &self.secret {
            secret.retire_approval_scope(&receipt.scope_id)?;
        }
        Ok(receipt)
    }
    // Private host-only configuration: the facts are a trusted-adapter claim.
    async fn register_sandbox_scope2(
        &self,
        request: tinysecurity_bus::RegisterSandboxScopeRequest2,
    ) -> BusResult<tinysecurity_bus::SandboxScopeReceipt2> {
        self.register_sandbox_scope(request).await
    }
    async fn retire_sandbox_scope2(
        &self,
        request: tinysecurity_bus::RetireSandboxScopeRequest2,
    ) -> BusResult<tinysecurity_bus::SandboxScopeReceipt2> {
        self.retire_sandbox_scope(request).await
    }
    async fn import_approval_history2(
        &self,
        request: tinysecurity_bus::ApprovalHistoryImport2,
    ) -> BusResult<tinysecurity_bus::ApprovalRow2> {
        self.approvals
            .as_ref()
            .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?
            .import_history(request)
            .await
            .map_err(approval_failure)
    }
    async fn parse_reply(
        &self,
        request: tinysecurity_bus::ParseReplyRequest,
    ) -> BusResult<tinysecurity_bus::ParseReplyResponse> {
        std::future::ready(tinysecurity::approval::parse_reply(&request).map_err(approval_failure))
            .await
    }
    async fn policy_info(&self) -> BusResult<PolicyInfo> {
        let mut info = { self.read()?.info() };
        info.callbacks.audit = self.audit.is_some();
        info.callbacks.audit_required = self.audit_required();
        info.callbacks.approvals = self.approvals.is_some();
        info.callbacks.sandbox = self.sandbox.is_some();
        info.callbacks.secret = self.secret.is_some();
        info.callbacks.secret_cipher = self.secret_cipher.is_some();
        info.callbacks.device = self.device.is_some();
        info.callbacks.crypto = self.crypto.is_some();
        info.scoped_policies = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .active();
        std::future::ready(Ok(info)).await
    }

    // Private host-only configuration. The subject is a trusted-adapter claim.
    async fn register_policy(
        &self,
        policy: tinysecurity_bus::RegisteredPolicy,
    ) -> BusResult<tinysecurity_bus::PolicyId> {
        let (paths, commands, scoped) = (
            Arc::clone(&self.paths),
            Arc::clone(&self.commands),
            Arc::clone(&self.scoped),
        );
        tokio::task::spawn_blocking(move || {
            let paths = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let commands = commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            scoped
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                .register(policy, &paths, &commands)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn supersede_policy(
        &self,
        request: tinysecurity_bus::SupersedePolicyRequest,
    ) -> BusResult<tinysecurity_bus::SupersedePolicyResponse> {
        let (paths, commands, scoped) = (
            Arc::clone(&self.paths),
            Arc::clone(&self.commands),
            Arc::clone(&self.scoped),
        );
        let (previous_id, next, caller) = (
            request.previous.clone(),
            request.next.clone(),
            request.caller.clone(),
        );
        // Validate and diff without exposing anything. Locks drop before any await.
        let (prepared, previous, review) = tokio::task::spawn_blocking(move || {
            let paths = paths
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let commands = commands
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let registry = scoped
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let previous = registry
                .get_owned(&previous_id)
                .map_err(|error| failure(&error))?;
            if caller.agent != previous.registered().subject_scope.agent {
                return Err(failure(&tinysecurity_bus::Error::InvalidArguments));
            }
            let prepared = registry
                .prepare_supersede(&previous_id, next.clone(), &paths, &commands)
                .map_err(|error| failure(&error))?;
            let review = previous.review_request(&caller, &next);
            Ok((prepared, previous, review))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let widenings = prepared.widenings().to_vec();
        if !widenings.is_empty() {
            let Some(approval) = request.approval else {
                return Ok(tinysecurity_bus::SupersedePolicyResponse::ReviewRequired {
                    review,
                    widenings,
                });
            };
            // The human approved this exact review under the old policy. Reservation
            // is once-only and happens after validation, before any activation.
            let engine = self
                .approvals
                .as_ref()
                .ok_or_else(|| tinybus::Error::failed("approval unavailable"))?;
            // Only an authenticated human may widen a policy: automatic and judge
            // approvals, and reused grants, carry no human decision ticket.
            let human = engine
                .list(&approval.scope_id)
                .await
                .map_err(approval_failure)?
                .into_iter()
                .any(|row| {
                    row.request_id == approval.request_id
                        && row.state == tinysecurity_bus::ApprovalLifecycle2::Approved
                        && row.decision_ticket_sha256.is_some()
                });
            if !human {
                return Err(tinybus::Error::failed(
                    "policy change needs a human decision",
                ));
            }
            engine
                .consume(tinysecurity_bus::ApprovalActionRequest2 {
                    scope_id: approval.scope_id,
                    request_id: approval.request_id,
                    request: review,
                    audit: approval.audit,
                })
                .await
                .map_err(approval_failure)?;
        }
        let generation = self.read()?.info().generation;
        let next_generation = previous.generation().saturating_add(1);
        let scoped = Arc::clone(&self.scoped);
        let signals = self.signals.clone();
        let (policy_id, policy_generation) = tokio::task::spawn_blocking(move || {
            let mut registry = scoped
                .lock()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            let id = prepared_id(&prepared);
            let committed = registry
                .commit_supersede(prepared)
                .map_err(|error| failure(&error))?;
            // Publish only a committed replacement. The registry is authoritative: a
            // full outbox loses this advisory signal, and hosts re-read the policy.
            drop(queue_scoped_changed(
                signals.as_ref(),
                generation,
                &id,
                next_generation,
            ));
            BusResult::Ok(committed)
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        Ok(tinysecurity_bus::SupersedePolicyResponse::Activated {
            policy_id,
            policy_generation,
        })
    }
    async fn evaluate_scoped(
        &self,
        request: tinysecurity_bus::ScopedEvaluateRequest,
    ) -> BusResult<tinysecurity_bus::ScopedDecision> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let admission = admission_only(&request.call.checks);
        if admission {
            self.require_unbound_permission()?;
        }
        let policy = self.read()?.clone();
        let bound = self.requires_bound_audit() && !admission;
        tokio::task::spawn_blocking(move || {
            let mut decision = scope
                .evaluate(&policy, &request)
                .map_err(|error| failure(&error))?;
            if bound {
                deny_allow(&mut decision.decision);
            }
            // The action is reserved last, so nothing that refuses the call spends it.
            let (decision, spent) = scope.settle_spend(&policy, &request.call.checks, decision);
            if let Some(spent) = spent {
                spent.commit();
            }
            Ok(decision)
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
    }
    async fn check_scoped(
        &self,
        request: tinysecurity_bus::ScopedCheckRequest,
    ) -> BusResult<tinysecurity_bus::ScopedCheckResponse> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let bound = self.requires_bound_audit();
        let mut response = tokio::task::spawn_blocking(move || {
            scope
                .check(&policy, &request)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        if bound {
            response.decisions.iter_mut().for_each(deny_allow);
        }
        Ok(response)
    }
    async fn scoped_policy_info(
        &self,
        id: tinysecurity_bus::PolicyId,
    ) -> BusResult<tinysecurity_bus::ScopedPolicyInfo> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&id)
            .map_err(|error| failure(&error))?;
        let generation = self.read()?.info().generation;
        std::future::ready(Ok(scope.info(generation))).await
    }
    async fn evaluate_scoped_audited(
        &self,
        request: tinysecurity_bus::EvaluateScopedAuditedRequest,
    ) -> BusResult<tinysecurity_bus::EvaluateScopedAuditedResponse> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let original = request.request.clone();
        let settler = policy.clone();
        let policy_scope = Arc::clone(&scope);
        let decision = tokio::task::spawn_blocking(move || {
            scope
                .evaluate(&policy, &original)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        // The policy id is a private reference; the fingerprint binds it instead.
        let audited = serde_json::to_value(tinysecurity_bus::EvaluateRequest {
            caller: request.request.caller.clone(),
            call: request.request.call.clone(),
        })?;
        // Reserved before the audit so the durable event records the final verdict. The
        // guard gives the action back on every early return and when the audit or the
        // approval gate still refuses the call.
        let (mut decision, spent) =
            policy_scope.settle_spend(&settler, &request.request.call.checks, decision);
        let audit = self
            .audit_permission(
                audited,
                serde_json::to_value(&decision)?,
                request.audit,
                decision.decision.generation,
                registry,
            )
            .await?;
        if !audit.permitted || self.approvals.is_some() {
            deny_allow(&mut decision.decision);
        }
        if let Some(spent) = spent
            && decision.decision.verdict == tinysecurity_bus::Verdict::Allow
        {
            spent.commit();
        }
        // Each use of an audited permission needs its own durable event.
        decision.decision.cacheable = false;
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
    async fn check_scoped_audited(
        &self,
        request: tinysecurity_bus::CheckScopedAuditedRequest,
    ) -> BusResult<tinysecurity_bus::CheckScopedAuditedResponse> {
        let scope = self
            .scoped
            .lock()
            .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            .get_owned(&request.request.policy_id)
            .map_err(|error| failure(&error))?;
        let policy = self.read()?.clone();
        let registry = policy.redactor();
        let generation = policy.info().generation;
        let original = request.request.clone();
        let mut decision = tokio::task::spawn_blocking(move || {
            scope
                .check(&policy, &original)
                .map_err(|error| failure(&error))
        })
        .await
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))??;
        let audited = serde_json::to_value(tinysecurity_bus::CheckRequest {
            caller: request.request.caller.clone(),
            checks: request.request.checks.clone(),
        })?;
        let audit = self
            .audit_permission(
                audited,
                serde_json::to_value(&decision)?,
                request.audit,
                generation,
                registry,
            )
            .await?;
        let denied = !audit.permitted || self.approvals.is_some();
        for item in &mut decision.decisions {
            if denied {
                deny_allow(item);
            }
            item.cacheable = false;
        }
        Ok(tinysecurity_bus::AuditedResponse2 { decision, audit })
    }
}
fn permission_payload(mut original: serde_json::Value) -> BusResult<String> {
    use sha2::{Digest, Sha256};
    // Explicit recursive key order is independent of serde_json's preserve_order feature.
    original.sort_all_objects();
    let serialized = serde_json::to_vec(&original)?;
    let mut digest = Sha256::new();
    digest.update(b"tinysecurity/audited-permission/v1\0");
    digest.update(serialized);
    let binding = format!("{:x}", digest.finalize());
    // This digest binds content across redaction collisions. It is correlation,
    // not authentication or anonymization of guessable low-entropy originals.
    Ok(serde_json::to_string(&serde_json::json!({
        "original_binding": binding,
        "request_and_decision": original,
    }))?)
}
fn approval_failure(error: tinysecurity::approval::Error) -> tinybus::Error {
    tinybus::Error::failed(error.to_string())
}
/// Whether host-tool checks are admission-only, with an optional supplemental scan.
fn admission_only(checks: &[tinysecurity_bus::Check]) -> bool {
    use tinysecurity_bus::Check;
    checks
        .iter()
        .any(|check| matches!(check, Check::HostAction { .. } | Check::HostShell { .. }))
        && checks.iter().all(|check| {
            matches!(
                check,
                Check::HostAction { .. } | Check::HostShell { .. } | Check::SkillScan { .. }
            )
        })
}
fn deny_allow(decision: &mut Decision) {
    if matches!(decision.verdict, tinysecurity_bus::Verdict::Allow) {
        decision.verdict = tinysecurity_bus::Verdict::Deny {
            reason: tinysecurity_bus::DenialReason::ApprovalUnavailable,
        };
        decision.cacheable = false;
    }
}
fn default_clock() -> Arc<dyn tinysecurity::approval::Clock> {
    Arc::new(tinysecurity::approval::SystemClock::default())
}
fn service_for(
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
) -> PolicyService {
    PolicyService {
        sandbox_clock: Arc::new(tinysecurity::approval::SystemClock::default()),
        device: None,
        crypto: None,
        secret: None,
        secret_cipher: None,
        sandbox: None,
        sandbox_runtime: None,
        approvals: None,
        policy,
        audit,
        egress: Arc::clone(
            EGRESS_SCOPES.get_or_init(|| Arc::new(Mutex::new(EgressPolicyRegistry::default()))),
        ),
        extended: Arc::clone(
            EXTENDED_REDACTORS.get_or_init(|| Arc::new(tinysecurity::ExtendedRedactors::new())),
        ),
        commands: Arc::clone(
            COMMAND_SCOPES.get_or_init(|| Arc::new(Mutex::new(CommandPolicyRegistry::default()))),
        ),
        paths: Arc::clone(
            PATH_SCOPES.get_or_init(|| Arc::new(Mutex::new(PathPolicyRegistry::default()))),
        ),
        scoped: Arc::clone(
            SCOPED_POLICIES.get_or_init(|| Arc::new(Mutex::new(ScopedPolicyRegistry::default()))),
        ),
        signals: None,
        budget_replays: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    }
}
fn configured_approvals(
    connection: &Connection,
    requested_host: Option<&str>,
    approval_config: Option<tinysecurity_bus::ApprovalConfig2>,
    audit_config: Option<&tinysecurity_bus::AuditConfig2>,
    candidate: &Policy,
    current: Option<
        &Option<(
            tinysecurity_bus::ApprovalConfig2,
            Arc<tinysecurity::approval::Engine>,
        )>,
    >,
) -> BusResult<
    Option<(
        tinysecurity_bus::ApprovalConfig2,
        Arc<tinysecurity::approval::Engine>,
    )>,
> {
    Ok(if let Some(current) = current {
        if let Some((existing, engine)) = current {
            if approval_config
                .as_ref()
                .is_some_and(|requested| requested != existing)
            {
                return Err(tinybus::Error::failed("immutable approval initialization"));
            }
            Some((existing.clone(), Arc::clone(engine)))
        } else if approval_config.is_some() {
            return Err(tinybus::Error::failed("immutable approval initialization"));
        } else {
            None
        }
    } else {
        approval_config
            .map(|config| {
                if config
                    .scopes
                    .iter()
                    .any(|scope| scope.generation != candidate.info().generation)
                {
                    return Err(tinybus::Error::failed("invalid approval generation"));
                }
                let audit_config = audit_config
                    .ok_or_else(|| tinybus::Error::failed("approval audit unavailable"))?;
                let ports = crate::approval_callbacks::ApprovalClients::new(
                    connection,
                    requested_host,
                    &config,
                    audit_config,
                    &candidate.redactor(),
                )?;
                let engine = tinysecurity::approval::Engine::new(
                    config.clone(),
                    Arc::new(ports),
                    Arc::new(tinysecurity::approval::SystemClock::default()),
                    candidate.redactor(),
                )
                .map_err(approval_failure)?;
                Ok((config, Arc::new(engine)))
            })
            .transpose()?
    })
}
fn configured_audit(
    connection: &Connection,
    binding: &crate::callbacks::PeerBinding,
    audit_config: Option<tinysecurity_bus::AuditConfig2>,
    candidate: &Policy,
) -> BusResult<Option<Arc<crate::callbacks::AuditClient>>> {
    Ok(if let Some(active) = AUDIT_CLIENT.get() {
        if let Some(client) = active {
            client.verify_reinit(audit_config.as_ref())?;
        } else if audit_config.is_some() {
            return Err(tinybus::Error::failed("immutable audit initialization"));
        }
        active.clone()
    } else {
        audit_config
            .map(|config| {
                #[cfg(test)]
                let client = crate::callbacks::AuditClient::new_for_test(
                    connection.clone(),
                    binding.clone(),
                    config,
                    candidate.redactor(),
                );
                #[cfg(not(test))]
                let client = crate::callbacks::AuditClient::new(
                    connection.clone(),
                    binding.clone(),
                    config,
                    candidate.redactor(),
                );
                client.map(Arc::new)
            })
            .transpose()?
    })
}
fn configured_automatic(
    config: Option<tinysecurity_bus::JudgeConfig>,
    approvals: Option<&Arc<tinysecurity::approval::Engine>>,
) -> BusResult<Option<Arc<tinysecurity::auto::Engine>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let engine =
        approvals.ok_or_else(|| tinybus::Error::failed("judge approval authority unavailable"))?;
    let previous = engine.previous_automatic().map_err(approval_failure)?;
    let candidate = if let Some(previous) = previous {
        previous.reconfigured(config)
    } else {
        tinysecurity::auto::Engine::new(
            config,
            Arc::new(tinysecurity::auto::SystemClock::default()),
        )
    }
    .map_err(|_| tinybus::Error::failed("invalid judge initialization"))?;
    Ok(Some(Arc::new(candidate)))
}
async fn configured_policy(config: ModuleConfig) -> BusResult<Policy> {
    let previous = ACTIVE
        .get()
        .map(|active| {
            active
                .read()
                .map(|policy| policy.clone())
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))
        })
        .transpose()?;
    tokio::task::spawn_blocking(move || {
        if let Some(mut candidate) = previous {
            candidate
                .reinitialize(config)
                .map_err(|error| failure(&error))?;
            Ok(candidate)
        } else {
            Policy::new(config).map_err(|error| failure(&error))
        }
    })
    .await
    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
}
fn host_binding(requested: Option<&str>) -> BusResult<crate::callbacks::PeerBinding> {
    if let Some(binding) = HOST_BINDING.get() {
        binding.verify_reinit(requested)?;
        Ok(binding.clone())
    } else {
        crate::callbacks::PeerBinding::new(requested)
    }
}
fn queue_policy_changed(connection: &Connection, generation: u64) -> BusResult<()> {
    let event = tinysecurity_bus::PolicyChanged {
        generation,
        policy_id: None,
        policy_generation: None,
    };
    let signal = tinybus::Message::signal(
        names::OBJECT_PATH.try_into()?,
        names::INTERFACE.try_into()?,
        names::POLICY_CHANGED.try_into()?,
        serde_json::to_value((event,))?,
    );
    connection.try_send(signal)
}
fn queue_scoped_changed(
    connection: Option<&Connection>,
    generation: u64,
    id: &tinysecurity_bus::PolicyId,
    policy_generation: u64,
) -> BusResult<()> {
    let connection = connection.ok_or_else(|| failure(&tinysecurity_bus::Error::Unavailable))?;
    let event = tinysecurity_bus::PolicyChanged {
        generation,
        policy_id: Some(id.clone()),
        policy_generation: Some(policy_generation),
    };
    let signal = tinybus::Message::signal(
        names::OBJECT_PATH.try_into()?,
        names::INTERFACE.try_into()?,
        names::POLICY_CHANGED.try_into()?,
        serde_json::to_value((event,))?,
    );
    connection.try_send(signal)
}
fn prepared_id(prepared: &tinysecurity::PreparedSupersede) -> tinysecurity_bus::PolicyId {
    prepared.next_id().clone()
}
fn activate_authorities(
    device: Option<&Arc<tinysecurity::crypto::device_handles::Registry>>,
    device_limits: Option<tinysecurity_bus::DeviceConfig2>,
    secret: Option<&Arc<secret::SecretState>>,
    generation: u64,
    publish: impl FnOnce() -> BusResult<()>,
) -> BusResult<()> {
    let cipher_prepared = cipher::prepare_generation()?;
    let secret_prepared = secret::prepare_generation(secret, generation)?;
    device::transition(device, device_limits, generation, publish)?;
    if let Some(prepared) = secret_prepared {
        prepared.commit();
    }
    if let Some(mut pending) = cipher_prepared {
        pending.clear();
    }
    Ok(())
}
fn publish_policy_generation(
    connection: &Connection,
    candidate: &Policy,
    audit: Option<&Arc<crate::callbacks::AuditClient>>,
    approvals: Option<&Arc<tinysecurity::approval::Engine>>,
    judge: Option<Arc<tinysecurity::auto::Engine>>,
) -> BusResult<()> {
    // Queue publication under the state lock before activation.
    // A full/closed outbox rejects reinit and leaves the old state intact.
    queue_policy_changed(connection, candidate.info().generation)?;
    EGRESS_SCOPES
        .get_or_init(|| Arc::new(Mutex::new(EgressPolicyRegistry::default())))
        .lock()
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
        .advance_generation(candidate.info().generation)
        .map_err(|error| failure(&error))?;
    if let Some(client) = audit {
        client.replace_registry(candidate.redactor())?;
    }
    if let Some(engine) = approvals {
        engine
            .replace_redactor(candidate.redactor())
            .map_err(approval_failure)?;
        engine.replace_automatic(judge).map_err(approval_failure)?;
        engine
            .advance_generation(candidate.info().generation)
            .map_err(approval_failure)?;
    }
    Ok(())
}
struct ConfidentialConfigs {
    secret: Option<tinysecurity_bus::SecretConfig2>,
    cipher: Option<tinysecurity_bus::SecretCipherConfig2>,
    crypto: Option<tinysecurity_bus::CryptoConfig2>,
    device_pairing: Option<tinysecurity_bus::DevicePairingConfig2>,
}
impl ConfidentialConfigs {
    fn take(config: &mut ModuleConfig) -> Self {
        Self {
            secret: config.secret.take(),
            cipher: config.secret_cipher.take(),
            crypto: config.crypto.take(),
            device_pairing: config.device_pairing.take(),
        }
    }
}
type ApprovalEngine = (
    tinysecurity_bus::ApprovalConfig2,
    Arc<tinysecurity::approval::Engine>,
);
struct ConfidentialContext<'a> {
    peer: Option<&'a str>,
    approvals: Option<&'a ApprovalEngine>,
    approval_config: Option<&'a tinysecurity_bus::ApprovalConfig2>,
    audit_config: Option<&'a tinysecurity_bus::AuditConfig2>,
    audit: Option<&'a Arc<crate::callbacks::AuditClient>>,
    generation: u64,
    clock: &'a Arc<dyn tinysecurity::approval::Clock>,
}
struct ConfidentialAuthorities {
    secret: Option<Arc<secret::SecretState>>,
    secret_cipher: Option<Arc<cipher::CipherState>>,
    crypto: Option<Arc<crypto::CryptoState>>,
    device_pairing: Option<Arc<device_pairing::PairingState>>,
}
/// Build the init-only confidential authorities that sit above the approval engine.
fn configured_confidential(
    connection: &Connection,
    configs: ConfidentialConfigs,
    context: &ConfidentialContext<'_>,
    device: Option<&Arc<tinysecurity::crypto::device_handles::Registry>>,
) -> BusResult<ConfidentialAuthorities> {
    let secret = secret::configured(
        configs.secret,
        secret::Initialization {
            connection,
            peer: context.peer,
            approvals: context.approval_config,
            engine: context.approvals.map(|(_, engine)| engine),
            audit: context.audit_config,
            generation: context.generation,
            clock: Arc::clone(context.clock),
        },
    )?;
    let secret_cipher = cipher::configured(
        configs.cipher,
        connection,
        context.peer,
        secret.as_ref(),
        context.approvals.map(|(_, engine)| engine),
        context.audit,
    )?;
    let crypto = crypto::configured(
        configs.crypto,
        &crypto::Initialization {
            connection,
            peer: context.peer,
            generation: context.generation,
            clock: Arc::clone(context.clock),
        },
    )?;
    let device_pairing = device_pairing::configured(
        configs.device_pairing,
        connection,
        context.peer,
        secret.as_ref(),
        device,
        Arc::clone(context.clock),
        context.generation,
    )?;
    Ok(ConfidentialAuthorities {
        secret,
        secret_cipher,
        crypto,
        device_pairing,
    })
}
#[allow(clippy::too_many_lines)] // Setup validates and atomically wires the module's authorities.
async fn setup(connection: Connection, mut config: ModuleConfig) -> BusResult<()> {
    // Validate before activation. The SDK serializes reinitializations and
    // preserves a fault latch; this adapter never provides retry RPCs.
    let mut device_config =
        tinysecurity::crypto::device_handles::ConfidentialConfig::new(config.device.take());
    let device_clock = default_clock();
    let confidential_configs = ConfidentialConfigs::take(&mut config);
    let judge_config = config.judge.clone();
    let audit_config = config.audit.clone();
    let approval_config = config.approvals.clone();
    let requested_host = config.trusted_host.clone();
    let binding = host_binding(requested_host.as_deref())?;
    let sandbox = sandbox_configured(
        config.sandbox.clone(),
        requested_host.as_deref(),
        audit_config.as_ref(),
        approval_config.as_ref(),
        SANDBOX.get(),
    )
    .await?;
    let candidate = configured_policy(config).await?;
    let (device, device_limits) = device::configured(
        device_config.take(),
        requested_host.as_deref(),
        approval_config.as_ref(),
        audit_config.as_ref(),
        candidate.info().generation,
        device_clock.as_ref(),
    )?;
    let audit = configured_audit(&connection, &binding, audit_config.clone(), &candidate)?;
    let approvals = configured_approvals(
        &connection,
        requested_host.as_deref(),
        approval_config.clone(),
        audit_config.as_ref(),
        &candidate,
        APPROVALS.get(),
    )?;
    let ConfidentialAuthorities {
        secret,
        secret_cipher,
        crypto,
        device_pairing,
    } = configured_confidential(
        &connection,
        confidential_configs,
        &ConfidentialContext {
            peer: requested_host.as_deref(),
            approvals: approvals.as_ref(),
            approval_config: approval_config.as_ref(),
            audit_config: audit_config.as_ref(),
            audit: audit.as_ref(),
            generation: candidate.info().generation,
            clock: &device_clock,
        },
        device.as_ref(),
    )?;
    let judge = configured_automatic(judge_config, approvals.as_ref().map(|(_, e)| e))?;
    if let Some(active) = ACTIVE.get() {
        let generation = candidate.info().generation;
        {
            let mut guard = active
                .write()
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
            activate_authorities(
                device.as_ref(),
                device_limits,
                secret.as_ref(),
                generation,
                || {
                    publish_policy_generation(
                        &connection,
                        &candidate,
                        audit.as_ref(),
                        approvals.as_ref().map(|(_, engine)| engine),
                        judge.clone(),
                    )?;
                    Ok(())
                },
            )?;
            *guard = candidate;
        }
        device_pairing::transition(device_pairing.as_ref(), generation).await?;
        return Ok(());
    }
    let policy = Arc::new(RwLock::new(candidate));
    let mut service = service_for(Arc::clone(&policy), audit.clone());
    service.device.clone_from(&device);
    service.crypto.clone_from(&crypto);
    service.secret.clone_from(&secret);
    service.secret_cipher.clone_from(&secret_cipher);
    service.signals = Some(connection.clone());
    service.sandbox_clock = device_clock;
    service.attach_sandbox(
        sandbox.as_ref().map(|(_, engine)| engine),
        audit_config,
        (&connection, &binding),
    )?;
    service.approvals = approvals.as_ref().map(|(_, engine)| Arc::clone(engine));
    if let Some(engine) = &service.approvals {
        engine.replace_automatic(judge).map_err(approval_failure)?;
    }
    serve_policy(&connection, service, binding.clone()).await?;
    activate_confidential(
        device.as_ref(),
        crypto.as_ref(),
        secret,
        secret_cipher,
        device_pairing,
    )?;
    activate_policy(policy, audit, binding, sandbox, approvals)
}
fn activate_confidential(
    device: Option<&Arc<tinysecurity::crypto::device_handles::Registry>>,
    crypto: Option<&Arc<crypto::CryptoState>>,
    secret: Option<Arc<secret::SecretState>>,
    secret_cipher: Option<Arc<cipher::CipherState>>,
    device_pairing: Option<Arc<device_pairing::PairingState>>,
) -> BusResult<()> {
    device::activate(device)?;
    crypto::activate(crypto)?;
    secret::activate(secret)?;
    cipher::activate(secret_cipher)?;
    device_pairing::activate(device_pairing)
}
async fn serve_policy(
    connection: &Connection,
    service: PolicyService,
    binding: crate::callbacks::PeerBinding,
) -> BusResult<()> {
    connection
        .serve_at(
            names::OBJECT_PATH.try_into()?,
            crate::callbacks::Authenticated::new(service, binding),
        )
        .await?;
    connection.request_name(names::INTERFACE).await?;
    Ok(())
}
fn activate_policy(
    policy: Arc<RwLock<Policy>>,
    audit: Option<Arc<crate::callbacks::AuditClient>>,
    binding: crate::callbacks::PeerBinding,
    sandbox: Option<(
        tinysecurity_bus::SandboxConfig2,
        Arc<tinysecurity::sandbox::Engine>,
    )>,
    approvals: Option<(
        tinysecurity_bus::ApprovalConfig2,
        Arc<tinysecurity::approval::Engine>,
    )>,
) -> BusResult<()> {
    SANDBOX
        .set(sandbox)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    APPROVALS
        .set(approvals)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    AUDIT_CLIENT
        .set(audit)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    HOST_BINDING
        .set(binding)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    ACTIVE
        .set(policy)
        .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?;
    Ok(())
}
tinybus_module::module_export! {
    setup = setup,
    config = ModuleConfig,
    worker_threads = 1,
    provides = ["ai.tinyhumans.tinysecurity.Policy"],
    methods = ["EvaluateSecretCipher2", "ExecuteSecretCipher2", "EvaluateSecret2", "ExecuteSecret2", "PasswordCrypt2", "KeyringAccess2", "PairingControl2", "EvaluateDevice2", "ExecuteDevice2", "DeviceFrame2", "DevicePairing2", "RegisterDevicePairingScope2", "Plan", "Plan2", "EvaluateSandboxApproval2", "ConsumeSandboxPlan2", "ImportApprovalHistory2", "ParseReply", "EvaluateApproval2", "Decide2", "ConsumeApproval2", "RecordExecution2", "ListApprovals2", "ListRecentDecisions2", "PurgeApprovalSession2", "RecordAuditError2", "CancelApproval2", "ExpireApproval2", "PreauthorizeFlow2", "GrantFlowTool2", "RevokeFlowTool2", "ListFlowTrust2", "GrantTool2", "RevokeTool2", "RevokeToolById2", "ListToolTrust2", "ImportTrustSource2", "RegisterApprovalScope2", "ReplaceApprovalScope2", "RetireApprovalScope2", "RegisterSecretScope2", "RegisterSandboxScope2", "RetireSandboxScope2", "Audit2", "RecordAudit2", "Evaluate", "Check", "EvaluateAudited2", "CheckAudited2", "PolicyInfo", "RegisterPolicy", "SupersedePolicy", "EvaluateScoped", "CheckScoped", "ScopedPolicyInfo", "EvaluateScopedAudited", "CheckScopedAudited", "CheckPermissionAudited2", "RegisterPathPolicy", "ValidatePath", "ValidateParent", "CheckPath", "CheckPaths2", "ProtectedPath2", "ProtectedFloor2", "CredentialRoots2", "SpendAction2", "ReserveActionBudgetAudited2", "PeekBudget2", "ClassifyHostAction2", "PrivacyCheck2", "ClassifyProviderEndpoint2", "RegisterCommandPolicy", "ClassifyCommand", "CheckCommand", "CheckCommandAudited2", "RegisterEgressPolicy", "ScopedUrlGuard", "ScopedEgressCheck", "ConsumeEgressAuthorization", "AuthorizeBrowserDial", "ConsumeBrowserDial", "ValidateBrowserDial", "UrlGuard", "EgressCheck", "Redact", "RedactWith", "ScanPrompt", "ScanPrompt2", "ScanToolDefinition"],
    signals = ["PolicyChanged"],
    requires = [],
    optional = ["ai.tinyhumans.tinysecurity.KeyringConsent2", "ai.tinyhumans.tinysecurity.SecretCipherConsumer2", "ai.tinyhumans.tinysecurity.SecretBackend2", "ai.tinyhumans.tinysecurity.DevicePairingHost2", "ai.tinyhumans.tinysecurity.AuditSink2", "ai.tinyhumans.tinysecurity.ApprovalStore2", "ai.tinyhumans.tinysecurity.ApprovalPrompt2"],
    lazy = false,
}
#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;

#[path = "adapter_sandbox.rs"]
mod sandbox;
#[path = "adapter_sandbox_scopes.rs"]
mod sandbox_scopes;
use sandbox::sandbox_configured;

#[path = "adapter_device.rs"]
mod device;

#[path = "adapter_device_pairing.rs"]
mod device_pairing;

#[path = "adapter_crypto.rs"]
mod crypto;

#[path = "adapter_secret.rs"]
pub(crate) mod secret;

#[path = "adapter_secret_cipher.rs"]
mod cipher;
