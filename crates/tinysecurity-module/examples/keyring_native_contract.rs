//! Loaded native keyring access behind the host's confidential consent endpoint.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tinybus::{
    Connection,
    broker::Broker,
    module::{HostCallbackEndpoint, ModuleHost},
    transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    CallerContext, CryptoConfig2, KeyringBackend2, KeyringConfig2, KeyringConsentOutcome2,
    KeyringConsentRequest2, KeyringConsentResponse2, KeyringOperation2, KeyringRequest2,
    KeyringResponse2, ModuleConfig, callback_names2, names,
};

#[derive(Clone)]
struct Consenter {
    allow: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.KeyringConsent2")]
impl Consenter {
    async fn consent(
        &self,
        request: KeyringConsentRequest2,
    ) -> tinybus::Result<KeyringConsentResponse2> {
        assert_eq!(request.name, "session-token");
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(KeyringConsentResponse2 {
            outcome: if self.allow.load(Ordering::SeqCst) {
                KeyringConsentOutcome2::Allowed
            } else {
                KeyringConsentOutcome2::ConsentDenied
            },
            grant: None,
        }))
        .await
    }
}

fn request(operation: KeyringOperation2) -> KeyringRequest2 {
    KeyringRequest2 {
        caller: CallerContext {
            agent: "fixture-agent".into(),
            call_id: "fixture-call".into(),
            ..Default::default()
        },
        purpose: "store the sign-in session".into(),
        operation,
    }
}

async fn wait_owner(host: &Connection) -> Result<tinybus::BusName, Box<dyn std::error::Error>> {
    let peer = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = host.name_owner(names::INTERFACE).await? {
                break tinybus::Result::Ok(peer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(peer)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let library = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: keyring_native_contract <native library>")?,
    )
    .canonicalize()?;
    let name = library
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("native library name")?;
    std::fs::write(
        library
            .parent()
            .ok_or("module directory")?
            .join("modules.toml"),
        format!(
            "\"{name}\" = \"{}\"\n",
            tinybus::module::sha256_file(&library)?
        ),
    )?;
    let store = tempfile::tempdir()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let host = Connection::connect(bus.connect().await?).await?;
    let path: tinybus::ObjectPath = callback_names2::OBJECT_PATH.parse()?;
    // A real binding refuses ordinary calls to a declared callback member.
    let binding = lifecycle
        .prepare_host_callbacks(vec![HostCallbackEndpoint {
            path: path.clone(),
            interface: callback_names2::KEYRING_CONSENT.parse()?,
            members: [callback_names2::CONSENT.parse()?].into(),
        }])
        .await?;
    let consenter = Consenter {
        allow: Arc::new(AtomicBool::new(true)),
        calls: Arc::default(),
    };
    binding.serve_at(path, consenter.clone()).await?;
    let configuration = ModuleConfig {
        trusted_host: Some(binding.unique_name().to_string()),
        crypto: Some(CryptoConfig2 {
            max_payload_bytes: 4096,
            operations_per_minute: 50,
            keyring: Some(KeyringConfig2 {
                service: "tinysecurity-keyring-fixture".into(),
                backend: KeyringBackend2::EncryptedFile {
                    directory: store.path().canonicalize()?.to_string_lossy().into_owned(),
                },
                consent_timeout_ms: 5000,
                read_grant: None,
            }),
            pairing: None,
        }),
        ..ModuleConfig::default()
    };
    lifecycle
        .load_file_with_host_callbacks(&library, serde_json::to_value(&configuration)?, &binding)
        .await?;
    let module = wait_owner(&host).await?;
    let proxy = binding
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));

    let _: KeyringResponse2 = proxy
        .call_confidential(
            names::methods::KEYRING_ACCESS2,
            (request(KeyringOperation2::Set {
                name: "session-token".into(),
                value: b"fixture-session".to_vec(),
            }),),
        )
        .await?;
    let read: KeyringResponse2 = proxy
        .call_confidential(
            names::methods::KEYRING_ACCESS2,
            (request(KeyringOperation2::Get {
                name: "session-token".into(),
            }),),
        )
        .await?;
    assert!(read.found);
    assert_eq!(read.bytes, b"fixture-session");
    assert_eq!(consenter.calls.load(Ordering::SeqCst), 2);

    // A human refusal reaches the module and still withholds the value.
    consenter.allow.store(false, Ordering::SeqCst);
    let denied: tinybus::Result<KeyringResponse2> = proxy
        .call_confidential(
            names::methods::KEYRING_ACCESS2,
            (request(KeyringOperation2::Get {
                name: "session-token".into(),
            }),),
        )
        .await;
    assert!(denied.is_err());
    assert_eq!(consenter.calls.load(Ordering::SeqCst), 3);

    lifecycle.shutdown(Duration::from_secs(5)).await;
    task.abort();
    println!("native keyring: confidential consent callback passed");
    Ok(())
}
