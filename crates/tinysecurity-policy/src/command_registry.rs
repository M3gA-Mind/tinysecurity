//! Immutable agent scopes with atomic monotonic sliding-window accounting.
use crate::{
    CommandAutonomy, CommandDecision, CommandDenial, CommandGate, CommandPolicy, CommandPolicyId,
    CommandRequest, CommandScope, Error, Result,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
/// Monotonic time source. Implementations must not move backwards.
pub trait CommandClock: std::fmt::Debug + Send + Sync {
    /// Elapsed monotonic time from this clock's fixed origin.
    fn now(&self) -> Duration;
}
#[derive(Debug)]
struct MonotonicClock(Instant);
impl CommandClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}
/// Explicit action ledger for a trusted host's authenticated subject. Reuse it
/// across policy replacement; this engine does not authenticate subject identity.
#[derive(Debug)]
pub struct CommandBudget {
    actions: Mutex<VecDeque<Duration>>,
    clock: Arc<dyn CommandClock>,
}
impl CommandBudget {
    /// Drop reservations older than the sliding hour; returns the current time.
    fn prune(&self, actions: &mut VecDeque<Duration>) -> Duration {
        let now = self.clock.now();
        while actions
            .front()
            .is_some_and(|time| now.saturating_sub(*time) >= Duration::from_secs(3600))
        {
            actions.pop_front();
        }
        now
    }
}
/// An action reserved from a scope's hourly ledger by host-tool admission. Dropping it gives
/// the action back; [`Spent::commit`] keeps it.
#[derive(Debug)]
#[must_use = "a dropped reservation is given back"]
pub struct Spent {
    scope: Arc<RegisteredCommandPolicy>,
    at: Duration,
    committed: bool,
}
impl Spent {
    /// Keep the reservation: the call it was made for is going to run.
    pub fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for Spent {
    fn drop(&mut self) {
        if !self.committed {
            self.scope.release_at(self.at);
        }
    }
}
/// Agent-specific immutable command scope and noncacheable execution budget.
#[derive(Debug)]
pub struct RegisteredCommandPolicy {
    scope: CommandScope,
    budget: Arc<CommandBudget>,
}
impl RegisteredCommandPolicy {
    /// Clone the explicit subject ledger for trusted policy replacement.
    #[must_use]
    pub fn budget(&self) -> Arc<CommandBudget> {
        Arc::clone(&self.budget)
    }
    pub(crate) fn policy(&self) -> &CommandPolicy {
        self.scope.policy()
    }
    /// Informational classification only; never grants permission to execute.
    /// # Errors
    /// Rejects oversized command input.
    pub fn classify(&self, request: &CommandRequest) -> Result<CommandDecision> {
        self.scope.classify(request)
    }
    /// Check actual execution and atomically reserve one action for Allow.
    /// Every retry counts again, including the same command. Prompts/blocks
    /// do not reserve and cannot execute. Reservations are not refunded.
    /// # Errors
    /// Rejects oversized input or poisoned accounting state.
    pub fn check(&self, request: &CommandRequest) -> Result<CommandDecision> {
        let mut decision = self.scope.evaluate(request)?;
        if decision.gate != CommandGate::Allow || !self.scope.policy().enabled {
            return Ok(decision);
        }
        let mut actions = self.budget.actions.lock().map_err(|_| Error::Faulted)?;
        let now = self.budget.prune(&mut actions);
        if actions.len() >= self.scope.policy().max_actions_per_hour as usize {
            decision.gate = CommandGate::Block;
            decision.denial = Some(CommandDenial::RateLimit);
        } else {
            actions.push_back(now);
        }
        Ok(decision)
    }
    /// Check actual execution and return a refundable action reservation for Allow.
    /// Prompts, blocks, disabled scopes and exhausted budgets do not reserve.
    ///
    /// The caller must commit the reservation only when its own pre-execution
    /// requirements have completed. Dropping it refunds the action.
    ///
    /// # Errors
    /// Rejects oversized input or poisoned accounting state.
    pub fn check_guarded(
        self: &Arc<Self>,
        request: &CommandRequest,
    ) -> Result<(CommandDecision, Option<Spent>)> {
        let mut decision = self.scope.evaluate(request)?;
        if decision.gate != CommandGate::Allow || !self.scope.policy().enabled {
            return Ok((decision, None));
        }
        if let Some(spent) = self.reserve_guarded() {
            Ok((decision, Some(spent)))
        } else {
            decision.gate = CommandGate::Block;
            decision.denial = Some(CommandDenial::RateLimit);
            Ok((decision, None))
        }
    }
    /// Gate a command without reserving an action (contract 1.20): the class gate, the
    /// hidden-execution defence, the protected-path floor and the mode's admission
    /// rules, but never the hourly budget. A host asking "may this run" before a human
    /// is consulted uses this, and the run itself reserves through [`Self::check`].
    /// # Errors
    /// Rejects oversized command input.
    pub fn gate(
        &self,
        command: &str,
        declared_class: Option<tinysecurity_bus::CommandClass>,
    ) -> Result<CommandDecision> {
        self.scope.evaluate(&CommandRequest {
            policy_id: CommandPolicyId(String::new()),
            command: command.to_owned(),
            declared_class,
        })
    }
    /// Whether the scope's discretionary enforcement is on.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.scope.policy().enabled
    }
    /// The acting tier fixed at registration.
    #[must_use]
    pub fn autonomy(&self) -> CommandAutonomy {
        self.scope.policy().autonomy
    }
    /// Configured actions per sliding hour.
    #[must_use]
    pub fn max_actions_per_hour(&self) -> u32 {
        self.scope.policy().max_actions_per_hour
    }
    /// Whether the hourly budget is spent, without reserving (contract 1.20). Inert
    /// while enforcement is disabled. An unreadable ledger reads as spent.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        if !self.enabled() {
            return false;
        }
        let Ok(mut actions) = self.budget.actions.lock() else {
            return true;
        };
        self.budget.prune(&mut actions);
        actions.len() >= self.max_actions_per_hour() as usize
    }
    /// Reserve one action from the hourly budget (contract 1.20); `false` when it is
    /// spent or the ledger is unreadable. Always `true` while enforcement is disabled.
    /// Reservations made this way are not refunded.
    #[must_use]
    pub fn reserve(&self) -> bool {
        self.reserve_at().is_some()
    }
    /// Reserve one action and return the instant it was recorded at.
    fn reserve_at(&self) -> Option<Duration> {
        if !self.enabled() {
            return Some(Duration::ZERO);
        }
        let Ok(mut actions) = self.budget.actions.lock() else {
            return None;
        };
        let now = self.budget.prune(&mut actions);
        if actions.len() >= self.max_actions_per_hour() as usize {
            return None;
        }
        actions.push_back(now);
        Some(now)
    }
    /// Reserve one action for host-tool admission (contract 1.20): the returned [`Spent`]
    /// gives it back when dropped, unless [`Spent::commit`]ted, so an early return or an
    /// error after the reservation never consumes quota for a call that cannot run.
    #[must_use]
    pub fn reserve_guarded(self: &Arc<Self>) -> Option<Spent> {
        self.reserve_at().map(|at| Spent {
            scope: Arc::clone(self),
            at,
            committed: false,
        })
    }
    /// Remove the reservation recorded at `at`, not a newer one another call made.
    fn release_at(&self, at: Duration) {
        if !self.enabled() {
            return;
        }
        if let Ok(mut actions) = self.budget.actions.lock()
            && let Some(index) = actions.iter().rposition(|time| *time == at)
        {
            actions.remove(index);
        }
    }
    /// Legacy allowlist diagnostic, independent of class gate and budget.
    #[must_use]
    pub fn is_command_allowed(&self, command: &str) -> bool {
        self.scope.is_command_allowed(command)
    }
}
/// Bounded immutable registry preserved across module reinit. Registration
/// belongs to the trusted host; scope IDs do not authenticate their caller.
#[derive(Debug)]
pub struct CommandPolicyRegistry {
    scopes: Vec<(CommandPolicyId, Arc<RegisteredCommandPolicy>)>,
    clock: Arc<dyn CommandClock>,
}
impl Default for CommandPolicyRegistry {
    fn default() -> Self {
        Self::with_clock(Arc::new(MonotonicClock(Instant::now())))
    }
}
impl CommandPolicyRegistry {
    /// Create a registry with an injected monotonic clock.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn CommandClock>) -> Self {
        Self {
            scopes: Vec::new(),
            clock,
        }
    }
    /// Register a fresh agent budget even when settings equal another agent's.
    /// Never re-register per turn: retain this ID across retries and reinit.
    /// # Errors
    /// Rejects malformed settings, a full registry, or entropy failure/collisions.
    pub fn register(&mut self, policy: CommandPolicy) -> Result<CommandPolicyId> {
        let budget = Arc::new(CommandBudget {
            actions: Mutex::default(),
            clock: Arc::clone(&self.clock),
        });
        self.register_with_budget(policy, budget)
    }
    /// Register replacement settings using a trusted subject's existing ledger.
    /// The host must retain and select the ledger from verified subject identity;
    /// command callers never supply ledger handles on the wire.
    /// # Errors
    /// Rejects malformed settings, registry exhaustion, or entropy failure/collisions.
    pub fn register_with_budget(
        &mut self,
        policy: CommandPolicy,
        budget: Arc<CommandBudget>,
    ) -> Result<CommandPolicyId> {
        let scope = CommandScope::new(policy)?;
        if self.scopes.len() >= 1024 {
            return Err(Error::Unavailable);
        }
        for _ in 0..4 {
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
            let id = CommandPolicyId(
                bytes
                    .iter()
                    .flat_map(|byte| {
                        const HEX: &[u8; 16] = b"0123456789abcdef";
                        [
                            char::from(HEX[usize::from(byte >> 4)]),
                            char::from(HEX[usize::from(byte & 15)]),
                        ]
                    })
                    .collect(),
            );
            if self.scopes.iter().any(|(old, _)| old == &id) {
                continue;
            }
            self.scopes.push((
                id.clone(),
                Arc::new(RegisteredCommandPolicy { scope, budget }),
            ));
            return Ok(id);
        }
        Err(Error::Unavailable)
    }
    /// Clone a registered handle, releasing registry locks before filesystem checks.
    /// # Errors
    /// Rejects unknown or malformed identifiers.
    pub fn get_owned(&self, id: &CommandPolicyId) -> Result<Arc<RegisteredCommandPolicy>> {
        self.scopes
            .iter()
            .find(|(old, _)| old == id)
            .map(|(_, scope)| Arc::clone(scope))
            .ok_or(Error::InvalidArguments)
    }
    /// Classify an existing scope without accounting or execution authorization.
    /// # Errors
    /// Rejects unknown scopes or oversized input.
    pub fn classify(&self, request: &CommandRequest) -> Result<CommandDecision> {
        self.get_owned(&request.policy_id)?.classify(request)
    }
    /// Atomically check and reserve execution under an existing scope.
    /// # Errors
    /// Rejects unknown scopes, oversized input or poisoned accounting state.
    pub fn check(&self, request: &CommandRequest) -> Result<CommandDecision> {
        self.get_owned(&request.policy_id)?.check(request)
    }
}
#[cfg(test)]
#[path = "command_registry_tests.rs"]
mod tests;
