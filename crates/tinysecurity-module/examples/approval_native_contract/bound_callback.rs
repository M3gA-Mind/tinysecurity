//! Confidential host callbacks for the native approval verifier.
use super::{audit, store::DiskStore};
use async_trait::async_trait;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tinybus::{
    CallContext, Interface, InterfaceName, MemberName,
    module::{HostCallbackGuard, HostCallbackProxy},
};
use tinysecurity_bus::{
    ApprovalCasRequest2, ApprovalChoice2, ApprovalDeliveryRequest2, ApprovalDeliveryResponse2,
    ApprovalLifecycle2, ApprovalLoadRequest2, ApprovalRow2, DecideRequest2, SubjectScope,
    VerifyHumanRequest2, callback_names2, names,
};

#[derive(Clone)]
pub(crate) struct Callback {
    pub(crate) guard: HostCallbackGuard,
    pub(crate) module_proxy: Arc<std::sync::OnceLock<HostCallbackProxy>>,
    pub(crate) interface: InterfaceName,
    pub(crate) scope: SubjectScope,
    pub(crate) store: Arc<Mutex<DiskStore>>,
    pub(crate) reentrant: Arc<AtomicBool>,
    pub(crate) prompt_failure: Arc<AtomicBool>,
}

#[async_trait]
impl Interface for Callback {
    fn name(&self) -> InterfaceName {
        self.interface.clone()
    }

    fn members(&self) -> Vec<MemberName> {
        let names: &[&str] = if self.interface.as_str() == callback_names2::APPROVAL_STORE {
            &[callback_names2::LOAD, callback_names2::CAS]
        } else {
            &[callback_names2::PROMPT, callback_names2::VERIFY_HUMAN]
        };
        names
            .iter()
            .filter_map(|name| (*name).parse().ok())
            .collect()
    }

    async fn call(
        &self,
        _member: &MemberName,
        _args: serde_json::Value,
    ) -> tinybus::Result<serde_json::Value> {
        Err(tinybus::Error::failed("fixture missing provenance"))
    }

    async fn call_with_context(
        &self,
        member: &MemberName,
        args: serde_json::Value,
        context: &CallContext,
    ) -> tinybus::Result<serde_json::Value> {
        if !self.guard.authorizes(context) {
            return Err(tinybus::Error::failed("fixture wrong peer"));
        }
        match member.as_str() {
            callback_names2::LOAD => {
                let (request,): (ApprovalLoadRequest2,) = serde_json::from_value(args)?;
                self.scope(&request.scope)?;
                serde_json::to_value(
                    self.store
                        .lock()
                        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
                        .load(&request)?,
                )
                .map_err(Into::into)
            }
            callback_names2::CAS => {
                let (request,): (ApprovalCasRequest2,) = serde_json::from_value(args)?;
                self.scope(&request.scope)?;
                let response = self
                    .store
                    .lock()
                    .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
                    .cas(request);
                serde_json::to_value(response?).map_err(Into::into)
            }
            callback_names2::VERIFY_HUMAN => {
                let (request,): (VerifyHumanRequest2,) = serde_json::from_value(args)?;
                self.scope(&request.row.binding.scope)?;
                serde_json::to_value(
                    self.store
                        .lock()
                        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
                        .human(&request)?,
                )
                .map_err(Into::into)
            }
            callback_names2::PROMPT => {
                let (request,): (ApprovalDeliveryRequest2,) = serde_json::from_value(args)?;
                self.scope(&request.row.binding.scope)?;
                let saved = self
                    .store
                    .lock()
                    .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
                    .load(&ApprovalLoadRequest2 {
                        scope: self.scope.clone(),
                    })?;
                assert!(
                    saved
                        .records
                        .iter()
                        .any(|row| row.record_id == request.row.request_id),
                    "prompt follows durable pending CAS"
                );
                if self.prompt_failure.load(Ordering::SeqCst) {
                    return Err(tinybus::Error::failed("fixture no human surface"));
                }
                if self.reentrant.swap(false, Ordering::SeqCst) {
                    let ticket = self
                        .store
                        .lock()
                        .map_err(|_| tinybus::Error::failed("fixture state unavailable"))?
                        .human_action(request.row.clone(), ApprovalChoice2::Once)?;
                    let decided: ApprovalRow2 = self
                        .module_proxy
                        .get()
                        .ok_or_else(|| tinybus::Error::failed("fixture module unavailable"))?
                        .clone()
                        .with_timeout(std::time::Duration::from_secs(3))
                        .call(
                            names::methods::DECIDE2,
                            (DecideRequest2 {
                                scope_id: "a".repeat(32),
                                request_id: request.row.request_id.clone(),
                                decision_ticket: ticket,
                                audit: audit(2),
                            },),
                        )
                        .await?;
                    assert_eq!(decided.state, ApprovalLifecycle2::Approved);
                }
                serde_json::to_value(ApprovalDeliveryResponse2 {
                    request_id: request.row.request_id,
                    nonce: request.row.nonce,
                    delivered: true,
                })
                .map_err(Into::into)
            }
            _ => Err(tinybus::Error::failed("fixture unknown callback")),
        }
    }
}

impl Callback {
    fn scope(&self, scope: &SubjectScope) -> tinybus::Result<()> {
        if scope == &self.scope {
            Ok(())
        } else {
            Err(tinybus::Error::failed("fixture wrong scope"))
        }
    }
}
