//! Judge credential served by the trusted host's `JudgeCredentialHost2`.
//!
//! Used only when the judge is configured without a credential. The module
//! asks after admission, on a judgement, never during load, so a host that
//! reads the credential from this module's own keyring cannot deadlock it.
use std::time::Duration;
use tinysecurity_bus::{
    JudgeCredentialReason2, JudgeCredentialRequest2, JudgeCredentialResponse2, Secret,
    callback_names2,
};

pub(super) struct HostCredential {
    connection: tinybus::Connection,
    peer: String,
    timeout_ms: u32,
    /// Mock-bus unit tests lack confidential module provenance; production never sets it.
    #[cfg(test)]
    ordinary: bool,
}
impl std::fmt::Debug for HostCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostCredential([REDACTED])")
    }
}
impl HostCredential {
    /// The judge's own request deadline also bounds this callback.
    pub(super) fn new(connection: &tinybus::Connection, peer: &str, timeout_ms: u32) -> Self {
        Self {
            connection: connection.clone(),
            peer: peer.to_owned(),
            timeout_ms,
            #[cfg(test)]
            ordinary: false,
        }
    }
}
#[async_trait::async_trait]
impl tinysecurity::auto::CredentialSource for HostCredential {
    async fn credential(&self, rejected: bool) -> Option<Secret> {
        let proxy = self
            .connection
            .proxy(
                self.peer.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::JUDGE_CREDENTIAL_HOST,
            )
            .ok()?
            .with_timeout(Duration::from_millis(u64::from(self.timeout_ms)));
        let args = (JudgeCredentialRequest2 {
            reason: if rejected {
                JudgeCredentialReason2::Rejected
            } else {
                JudgeCredentialReason2::Initial
            },
        },);
        // The credential is a secret: the host serves this member only as a
        // confidential callback.
        #[cfg(test)]
        let confidential = !self.ordinary;
        #[cfg(not(test))]
        let confidential = true;
        let reply: tinybus::Result<JudgeCredentialResponse2> = if confidential {
            proxy
                .call_confidential(callback_names2::CREDENTIAL, args)
                .await
        } else {
            proxy.call(callback_names2::CREDENTIAL, args).await
        };
        reply.ok()?.credential
    }
}

#[cfg(test)]
#[path = "adapter_judge_tests.rs"]
mod tests;
