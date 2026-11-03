//! Audit-bound native permission queries; no execution or budget reservation.
use super::{PolicyService, failure};
use tinybus::Result as BusResult;
use tinysecurity_bus::{
    AuditHealth2, AuditResponse2, AuditedResponse2, BudgetDecision2, CommandAutonomy,
    PermissionAuditRequest2, PermissionAuditResponse2, PermissionRequest2, PermissionResult2,
};

impl PolicyService {
    pub(super) async fn audited_permission(
        &self,
        request: PermissionAuditRequest2,
    ) -> BusResult<PermissionAuditResponse2> {
        let snapshot = self.read()?.clone();
        let generation = snapshot.info().generation;
        if request.audit.generation != generation {
            return Ok(AuditedResponse2 {
                decision: None,
                audit: AuditResponse2 {
                    permitted: false,
                    committed: false,
                    health: AuditHealth2::Denied,
                    receipt: None,
                },
            });
        }
        let decision = self.compute_permission(request.request.clone()).await?;
        let audit = self
            .audit_permission(
                serde_json::to_value(&request.request)?,
                serde_json::to_value(&decision)?,
                request.audit,
                generation,
                snapshot.redactor(),
            )
            .await?;
        // Never expose a computed allowance without its own durable receipt.
        // Keep indeterminate/stale evidence so the host can reconcile safely.
        Ok(AuditedResponse2 {
            decision: (audit.permitted && audit.committed).then_some(decision),
            audit,
        })
    }

    async fn compute_permission(
        &self,
        request: PermissionRequest2,
    ) -> BusResult<PermissionResult2> {
        match request {
            PermissionRequest2::ValidatePath(request) => {
                self.run_path(request.policy_id, move |scope| {
                    PermissionResult2::Path(scope.validate(&request.path, false))
                })
                .await
            }
            PermissionRequest2::ValidateParent(request) => {
                self.run_path(request.policy_id, move |scope| {
                    PermissionResult2::Path(scope.validate(&request.path, true))
                })
                .await
            }
            PermissionRequest2::CheckPath(request) => {
                self.run_path(request.policy_id, move |scope| {
                    PermissionResult2::PathAllowed(scope.check_path(&request.path, request.kind))
                })
                .await
            }
            PermissionRequest2::CheckPaths(request) => {
                request.validate().map_err(|error| failure(&error))?;
                self.run_path(request.policy_id, move |scope| {
                    PermissionResult2::Paths(tinysecurity_bus::PathBatchResponse2 {
                        allowed: request
                            .paths
                            .iter()
                            .map(|path| scope.check_path(path, request.kind))
                            .collect(),
                    })
                })
                .await
            }
            PermissionRequest2::GateCommand(request) => {
                let scope = self
                    .commands
                    .lock()
                    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                    .get_owned(&request.policy_id)
                    .map_err(|error| failure(&error))?;
                tokio::task::spawn_blocking(move || {
                    scope
                        .gate(&request.command, request.declared_class)
                        .map(PermissionResult2::Command)
                        .map_err(|error| failure(&error))
                })
                .await
                .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
            }
            PermissionRequest2::PeekBudget(request) => {
                let scope = self
                    .commands
                    .lock()
                    .map_err(|_| failure(&tinysecurity_bus::Error::Faulted))?
                    .get_owned(&request.command_policy)
                    .map_err(|error| failure(&error))?;
                let decision = if !scope.enabled() {
                    BudgetDecision2::Allow
                } else if scope.autonomy() == CommandAutonomy::ReadOnly {
                    BudgetDecision2::ReadOnlyMode
                } else if scope.exhausted() {
                    BudgetDecision2::RateLimited {
                        max_per_hour: scope.max_actions_per_hour(),
                    }
                } else {
                    BudgetDecision2::Allow
                };
                Ok(PermissionResult2::Budget(decision))
            }
            PermissionRequest2::PrivacyCheck(request) => {
                request.validate().map_err(|error| failure(&error))?;
                Ok(PermissionResult2::Privacy(
                    tinysecurity_bus::PrivacyCheckResponse2 {
                        decision: tinysecurity_bus::Decision {
                            generation: self.read()?.info().generation,
                            verdict: tinysecurity::privacy_verdict(&request),
                            cacheable: false,
                        },
                    },
                ))
            }
        }
    }
}
