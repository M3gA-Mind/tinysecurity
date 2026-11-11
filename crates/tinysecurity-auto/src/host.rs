//! Judge credential asked of the host when a judgement first needs it.
//!
//! A host that keeps the credential somewhere only the admitted module can read
//! (its keyring) cannot supply it at load. [`HostClient`] asks a
//! [`CredentialSource`] on the first evaluation instead, reuses the client for
//! [`HOST_CREDENTIAL_TTL_MS`], and drops it as soon as the endpoint rejects the
//! credential, so rotation and sign-out are picked up.
use crate::{Clock, Error, JudgeClient, Result, SdkClient};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tinyinference_decisions::{EvaluationRequest, EvaluationResponse};
use tinysecurity_bus::{JudgeConfig, Secret};

/// How long a host-supplied credential is reused before the host is asked again.
pub const HOST_CREDENTIAL_TTL_MS: u64 = 300_000;

/// The trusted host's current judge credential.
#[async_trait::async_trait]
pub trait CredentialSource: Send + Sync + std::fmt::Debug {
    /// `rejected` says the endpoint refused the last credential. `None`, or any
    /// failure, sends this judgement to a person.
    async fn credential(&self, rejected: bool) -> Option<Secret>;
}

/// Builds the outbound client for one credential.
pub(crate) type Build =
    Arc<dyn Fn(&JudgeConfig, &Secret) -> Result<Arc<dyn JudgeClient>> + Send + Sync>;

/// The production builder: one SDK client per credential.
pub(crate) fn sdk() -> Build {
    Arc::new(|config, credential| Ok(Arc::new(SdkClient::with_credential(config, credential)?)))
}

/// A [`JudgeClient`] whose credential comes from the host on demand.
pub(crate) struct HostClient {
    config: JudgeConfig,
    source: Arc<dyn CredentialSource>,
    clock: Arc<dyn Clock>,
    build: Build,
    // Held across the host callback only, so one ask runs at a time; never
    // across the outbound evaluation.
    held: tokio::sync::Mutex<Option<(Arc<dyn JudgeClient>, u64)>>,
    rejected: AtomicBool,
}
impl std::fmt::Debug for HostClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostClient([REDACTED])")
    }
}
impl HostClient {
    pub(crate) fn new(
        config: JudgeConfig,
        source: Arc<dyn CredentialSource>,
        clock: Arc<dyn Clock>,
        build: Build,
    ) -> Self {
        Self {
            config,
            source,
            clock,
            build,
            held: tokio::sync::Mutex::new(None),
            rejected: AtomicBool::new(false),
        }
    }
    async fn client(&self) -> Result<Arc<dyn JudgeClient>> {
        let mut held = self.held.lock().await;
        let now = self.clock.milliseconds();
        if let Some((client, since)) = held.as_ref()
            && now.saturating_sub(*since) < HOST_CREDENTIAL_TTL_MS
        {
            return Ok(Arc::clone(client));
        }
        *held = None;
        let credential = self
            .source
            .credential(self.rejected.load(Ordering::SeqCst))
            .await
            .filter(|secret| (4..=4096).contains(&secret.0.len()))
            .ok_or(Error::Unavailable)?;
        let client = (self.build)(&self.config, &credential)?;
        self.rejected.store(false, Ordering::SeqCst);
        *held = Some((Arc::clone(&client), now));
        Ok(client)
    }
}
#[async_trait::async_trait]
impl JudgeClient for HostClient {
    async fn evaluate(&self, request: &EvaluationRequest) -> Result<EvaluationResponse> {
        let client = self.client().await?;
        let result = client.evaluate(request).await;
        if matches!(result, Err(Error::Rejected)) {
            // Drop exactly the client that failed; a fresh one may already be held.
            let mut held = self.held.lock().await;
            if held
                .as_ref()
                .is_some_and(|(current, _)| Arc::ptr_eq(current, &client))
            {
                *held = None;
            }
            self.rejected.store(true, Ordering::SeqCst);
        }
        result
    }
}
