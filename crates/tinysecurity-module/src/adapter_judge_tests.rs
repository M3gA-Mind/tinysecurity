use super::*;
use std::sync::{Arc, Mutex};
use tinysecurity::auto::CredentialSource;

#[derive(Clone, Default)]
struct Host {
    reasons: Arc<Mutex<Vec<JudgeCredentialReason2>>>,
    credential: Arc<Mutex<Option<String>>>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.JudgeCredentialHost2")]
impl Host {
    async fn credential(
        &self,
        request: JudgeCredentialRequest2,
    ) -> tinybus::Result<JudgeCredentialResponse2> {
        self.reasons
            .lock()
            .map_err(|_| tinybus::Error::failed("reasons"))?
            .push(request.reason);
        let credential = self
            .credential
            .lock()
            .map_err(|_| tinybus::Error::failed("credential"))?
            .clone()
            .map(Secret);
        std::future::ready(Ok(JudgeCredentialResponse2 { credential })).await
    }
}

/// A module connection asking `host`, which serves the callback when `serve`.
async fn fixture(
    host: &Host,
    serve: bool,
) -> Result<(HostCredential, tokio::task::AbortHandle), Box<dyn std::error::Error>> {
    use tinybus::{Connection, broker::Broker, transport::memory::MemoryBus};
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone()).abort_handle();
    let hosting = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let host_peer = hosting.unique_name().ok_or("host")?;
    let module_peer = module.unique_name().ok_or("module")?;
    if serve {
        hosting
            .serve_at(
                callback_names2::OBJECT_PATH.parse()?,
                crate::callbacks::Authenticated::new(
                    host.clone(),
                    crate::callbacks::PeerBinding::new(Some(module_peer.as_str()))?,
                ),
            )
            .await?;
    }
    // Keep the host connection alive for the test body.
    Box::leak(Box::new(hosting));
    let mut source = HostCredential::new(&module, host_peer.as_str(), 1000);
    source.ordinary = true;
    Ok((source, broker))
}

#[tokio::test]
async fn the_host_supplies_the_judge_credential_with_the_reason_it_is_asked()
-> Result<(), Box<dyn std::error::Error>> {
    let host = Host::default();
    *host.credential.lock().map_err(|_| "credential")? = Some("host-held-key".into());
    let (source, broker) = fixture(&host, true).await?;
    assert_eq!(
        source.credential(false).await.map(|secret| secret.0),
        Some("host-held-key".to_owned())
    );
    assert!(source.credential(true).await.is_some());
    assert_eq!(
        *host.reasons.lock().map_err(|_| "reasons")?,
        [
            JudgeCredentialReason2::Initial,
            JudgeCredentialReason2::Rejected
        ]
    );
    // The credential never appears in the source's own diagnostics.
    assert_eq!(format!("{source:?}"), "HostCredential([REDACTED])");
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn no_credential_or_no_serving_host_gives_none() -> Result<(), Box<dyn std::error::Error>> {
    let host = Host::default();
    let (source, broker) = fixture(&host, true).await?;
    assert!(source.credential(false).await.is_none());
    broker.abort();
    let (unserved, broker) = fixture(&host, false).await?;
    assert!(unserved.credential(false).await.is_none());
    broker.abort();
    Ok(())
}
