//! Actual hashed native device dispatch, confidential routing and verified callbacks.
#[path = "device_native_contract/bound_callbacks.rs"]
mod bound_callbacks;
#[path = "device_native_contract/fixture.rs"]
mod fixture;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tinybus::{
    Connection,
    broker::Broker,
    module::{HostCallbackEndpoint, HostCallbackProxy, ModuleHost},
    transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    ApprovalConfig2, ApprovalRow2, AuditEventReceipt2, AuditSinkRequest2, AuditSinkResponse2,
    DeviceFrameOperation2, DeviceFrameRequest2, DeviceFrameResponse2, DeviceKeyPurpose2,
    DeviceOperation2, DeviceResponse2, DeviceRole2, EvaluateDeviceRequest2, ExecuteDeviceRequest2,
    ModuleConfig, PolicyInfo, names,
};
#[derive(Clone)]
struct Sink;
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, request: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        std::future::ready(Ok(AuditSinkResponse2 {
            scope: request.scope,
            stream_id: request.stream_id,
            new_tail: request.events[0].sequence,
            events: request
                .events
                .into_iter()
                .map(|event| AuditEventReceipt2 {
                    event_id: event.event_id,
                    sequence: event.sequence,
                })
                .collect(),
        }))
        .await
    }
}

async fn load_bound_module(
    lifecycle: &ModuleHost,
    library: &std::path::Path,
    host: &Connection,
    mut configuration: ModuleConfig,
    store: Arc<Mutex<fixture::store::DiskStore>>,
) -> std::result::Result<
    (
        tinybus::module::HostCallbackBinding,
        HostCallbackProxy,
        String,
        tinybus::BusName,
        ModuleConfig,
    ),
    Box<dyn std::error::Error>,
> {
    let path: tinybus::ObjectPath = tinysecurity_bus::callback_names2::OBJECT_PATH.parse()?;
    let endpoint = |interface: &str, members: &[&str]| -> tinybus::Result<HostCallbackEndpoint> {
        Ok(HostCallbackEndpoint {
            path: path.clone(),
            interface: interface.parse()?,
            members: members
                .iter()
                .map(|member| (*member).parse())
                .collect::<tinybus::Result<_>>()?,
        })
    };
    let binding = lifecycle
        .prepare_host_callbacks(vec![
            endpoint(
                tinysecurity_bus::callback_names2::APPROVAL_STORE,
                &[
                    tinysecurity_bus::callback_names2::LOAD,
                    tinysecurity_bus::callback_names2::CAS,
                ],
            )?,
            endpoint(
                tinysecurity_bus::callback_names2::APPROVAL_PROMPT,
                &[
                    tinysecurity_bus::callback_names2::PROMPT,
                    tinysecurity_bus::callback_names2::VERIFY_HUMAN,
                ],
            )?,
            endpoint(
                tinysecurity_bus::callback_names2::AUDIT_SINK,
                &[tinysecurity_bus::callback_names2::APPEND],
            )?,
        ])
        .await?;
    configuration.trusted_host = Some(binding.unique_name().to_string());
    let guard = binding.guard();
    let module_proxy = Arc::new(std::sync::OnceLock::new());
    let scope = tinysecurity::approval::scope_handle(&fixture::registration().subject)?;
    for interface in [
        tinysecurity_bus::callback_names2::APPROVAL_STORE,
        tinysecurity_bus::callback_names2::APPROVAL_PROMPT,
    ] {
        binding
            .serve_at(
                path.clone(),
                bound_callbacks::callback::Callback {
                    guard: guard.clone(),
                    module_proxy: module_proxy.clone(),
                    interface: interface.parse()?,
                    scope: scope.clone(),
                    store: store.clone(),
                    reentrant: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    prompt_failure: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                },
            )
            .await?;
    }
    binding.serve_at(path, Sink).await?;
    let loaded = lifecycle
        .load_file_with_host_callbacks(library, serde_json::to_value(&configuration)?, &binding)
        .await?;
    let module = wait_owner(host).await?;
    let proxy = binding
        .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
        .with_timeout(Duration::from_secs(10));
    module_proxy
        .set(proxy.clone())
        .map_err(|_| "fixture module proxy already initialized")?;
    assert!(proxy.attestation().await?.is_some());
    Ok((binding, proxy, loaded.name, module, configuration))
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let library = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: device_native_contract <library>")?,
    )
    .canonicalize()?;
    let hash = tinybus::module::sha256_file(&library)?;
    let name = library
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("fixture library name")?;
    std::fs::write(
        library
            .parent()
            .ok_or("fixture library parent")?
            .join("modules.toml"),
        format!("\"{name}\" = \"{hash}\"\n"),
    )?;
    let (_directory, root) = namespace::create()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let lifecycle = ModuleHost::new(broker);
    let host = Connection::connect(bus.connect().await?).await?;
    let configuration = ModuleConfig {
        device: Some(fixture::device_config()),
        trusted_host: host.unique_name().map(|n| n.to_string()),
        approvals: Some(ApprovalConfig2 {
            timeout_ms: 30_000,
            scopes: vec![fixture::registration(), fixture::other_registration()],
        }),
        audit: Some(fixture::audit_config(Some(
            root.join("audit").to_str().ok_or("fixture path")?.into(),
        ))),
        ..Default::default()
    };
    let store = Arc::new(Mutex::new(fixture::store::DiskStore::open(
        &root.join("approvals.journal"),
    )?));
    let (_binding, proxy, loaded_name, module, configuration) =
        load_bound_module(&lifecycle, &library, &host, configuration, store.clone()).await?;
    credential_root_checks(&proxy).await?;
    routing_checks(&proxy, &bus, &module).await?;
    let mut sequence = 1;
    let (key, stale_tunnel) = native_protocols(&proxy, &store, &mut sequence).await?;
    let observer = callback_configuration_fence(
        &lifecycle,
        &loaded_name,
        configuration,
        &proxy,
        &store,
        &mut sequence,
        (key, stale_tunnel),
    )
    .await?;
    let after: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(after.generation, 1);
    verify_journals(&root)?;
    lifecycle.shutdown(Duration::from_secs(5)).await;
    assert!(
        proxy
            .call::<PolicyInfo>(names::methods::POLICY_INFO, ())
            .await
            .is_err()
    );
    let mut correlation = fixture::audit(sequence);
    correlation.generation = 2;
    assert!(
        proxy
            .call_confidential::<DeviceResponse2>(
                names::methods::EXECUTE_DEVICE2,
                (ExecuteDeviceRequest2 {
                    request: fixture::request(
                        sequence,
                        DeviceOperation2::Revoke { handle: observer }
                    ),
                    request_id: "f".repeat(32),
                    audit: correlation
                },)
            )
            .await
            .is_err()
    );
    task.abort();
    assert_eq!(hash, tinybus::module::sha256_file(&library)?);
    println!(
        "native device: SHA256={hash}; verified CredentialRoots2 native resolution + home-none isolation + peer + confidential DeviceFrame2 Seal/Open + no frame approval rows + cross-scope/replay/revoke + callback-bound config mutation refusal + existing approved v2/v3/v4 flows + shutdown passed"
    );
    Ok(())
}

async fn credential_root_checks(
    proxy: &HostCallbackProxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::{CredentialRootsRequest2, CredentialRootsResponse2};

    let home_variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(home_variable)
        .map(std::path::PathBuf::from)
        .ok_or("native fixture home is unavailable")?;
    let response: CredentialRootsResponse2 = proxy
        .call(
            names::methods::CREDENTIAL_ROOTS2,
            CredentialRootsRequest2 {
                home: Some(home.clone()),
            },
        )
        .await?;
    response.validate()?;
    assert!(response.roots.contains(&home.join(".ssh")));
    #[cfg(target_os = "macos")]
    assert!(response.roots.contains(&home.join("Library/Keychains")));
    #[cfg(windows)]
    assert!(
        response
            .roots
            .contains(&home.join("AppData/Roaming/Microsoft/Protect"))
    );
    let absent: CredentialRootsResponse2 = proxy
        .call(
            names::methods::CREDENTIAL_ROOTS2,
            CredentialRootsRequest2 { home: None },
        )
        .await?;
    assert_eq!(absent.roots, Vec::<std::path::PathBuf>::new());
    Ok(())
}
async fn native_tunnel(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    sequence: &mut u64,
    own: &str,
    public: &str,
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    use tinysecurity::crypto::device::{KeyPair, PublicKey, Role, Tunnel};
    let ephemeral = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Ephemeral,
        },
    )
    .await?;
    let ephemeral_public = PublicKey::decode(&ephemeral.public_key.ok_or("fixture public")?)?;
    let peer = KeyPair::generate()?;
    let peer_ephemeral = KeyPair::generate()?;
    let keys = peer.session_keys(
        PublicKey::decode(public)?,
        &peer_ephemeral,
        ephemeral_public,
        ephemeral_public,
        peer_ephemeral.public_key(),
    )?;
    let mut peer_tunnel = Tunnel::new(Role::Server, keys);
    let tunnel = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Tunnel {
            key: own.into(),
            ephemeral: ephemeral.handle.ok_or("fixture ephemeral")?,
            peer_static: peer.public_key().encode(),
            peer_ephemeral: peer_ephemeral.public_key().encode(),
            role: DeviceRole2::Client,
        },
    )
    .await?
    .handle
    .ok_or("fixture tunnel")?;
    let outgoing = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Seal {
            handle: tunnel.clone(),
            plaintext: b"private-secret".to_vec(),
        },
    )
    .await?
    .bytes;
    assert_eq!(&*peer_tunnel.open(&outgoing)?, b"private-secret");
    let incoming = peer_tunnel.seal(b"private-secret")?;
    assert_eq!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::Open {
                handle: tunnel.clone(),
                frame: incoming.clone()
            }
        )
        .await?
        .bytes,
        b"private-secret"
    );
    assert!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::Open {
                handle: tunnel.clone(),
                frame: incoming
            }
        )
        .await
        .is_err()
    );
    verify_frame_dispatch(proxy, store, &tunnel, &mut peer_tunnel).await?;
    verify_revoked_tunnel(proxy, store, sequence, own).await?;
    Ok(tunnel)
}

async fn verify_frame_dispatch(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    tunnel: &str,
    peer_tunnel: &mut tinysecurity::crypto::device::Tunnel,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let before = {
        let store = store
            .lock()
            .map_err(|_| tinybus::Error::failed("fixture store"))?;
        (store.mutations.len(), store.tickets.len())
    };
    let sealed: DeviceFrameResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_FRAME2,
            (DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: tunnel.into(),
                call_id: "module-frame-seal".into(),
                operation: DeviceFrameOperation2::Seal {
                    plaintext: b"private-secret".to_vec(),
                },
            },),
        )
        .await?;
    assert_eq!(sealed.bytes.first(), Some(&2));
    assert_eq!(&*peer_tunnel.open(&sealed.bytes)?, b"private-secret");
    let incoming = peer_tunnel.seal(b"private-secret")?;
    let opened: DeviceFrameResponse2 = proxy
        .call_confidential(
            names::methods::DEVICE_FRAME2,
            (DeviceFrameRequest2 {
                scope_id: "a".repeat(32),
                handle: tunnel.into(),
                call_id: "module-frame-open".into(),
                operation: DeviceFrameOperation2::Open {
                    frame: incoming.clone(),
                },
            },),
        )
        .await?;
    assert_eq!(opened.bytes, b"private-secret");
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "a".repeat(32),
                    handle: tunnel.into(),
                    call_id: "module-frame-replay".into(),
                    operation: DeviceFrameOperation2::Open { frame: incoming },
                },),
            )
            .await
            .is_err()
    );
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "b".repeat(32),
                    handle: tunnel.into(),
                    call_id: "module-frame-cross-scope".into(),
                    operation: DeviceFrameOperation2::Seal {
                        plaintext: b"private-secret".to_vec()
                    },
                },),
            )
            .await
            .is_err()
    );
    let after = {
        let store = store
            .lock()
            .map_err(|_| tinybus::Error::failed("fixture store"))?;
        (store.mutations.len(), store.tickets.len())
    };
    assert_eq!(
        after, before,
        "frame calls must not create approval rows or tickets"
    );
    Ok(())
}

async fn verify_revoked_tunnel(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    sequence: &mut u64,
    own: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity::crypto::device::KeyPair;
    let revoked_ephemeral = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Ephemeral,
        },
    )
    .await?;
    let revoked_peer = KeyPair::generate()?;
    let revoked_peer_ephemeral = KeyPair::generate()?;
    let revoked = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Tunnel {
            key: own.into(),
            ephemeral: revoked_ephemeral.handle.ok_or("fixture ephemeral")?,
            peer_static: revoked_peer.public_key().encode(),
            peer_ephemeral: revoked_peer_ephemeral.public_key().encode(),
            role: DeviceRole2::Client,
        },
    )
    .await?
    .handle
    .ok_or("fixture revoked tunnel")?;
    fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Revoke {
            handle: revoked.clone(),
        },
    )
    .await?;
    assert!(
        proxy
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (DeviceFrameRequest2 {
                    scope_id: "a".repeat(32),
                    handle: revoked,
                    call_id: "module-frame-after-revoke".into(),
                    operation: DeviceFrameOperation2::Seal { plaintext: vec![] },
                },),
            )
            .await
            .is_err()
    );
    Ok(())
}
async fn routing_checks(
    proxy: &HostCallbackProxy,
    bus: &MemoryBus,
    module: &tinybus::BusName,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    assert!(proxy.attestation().await?.is_some());
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert!(
        info.capabilities
            .contains(&names::methods::EXECUTE_DEVICE2.to_owned())
    );
    assert!(
        info.capabilities
            .contains(&names::methods::DEVICE_FRAME2.to_owned())
    );
    assert!(!serde_json::to_string(&info)?.contains("static_secret"));
    let rejected = EvaluateDeviceRequest2 {
        request: fixture::request(1, DeviceOperation2::Cancel),
        audit: fixture::audit(1),
    };
    assert!(
        proxy
            .call::<ApprovalRow2>(names::methods::EVALUATE_DEVICE2, (rejected.clone(),))
            .await
            .is_err()
    );
    let attacker = Connection::connect(bus.connect().await?).await?;
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call_confidential::<ApprovalRow2>(names::methods::EVALUATE_DEVICE2, (rejected,))
            .await
            .is_err()
    );
    let unconfigured_frame = DeviceFrameRequest2 {
        scope_id: "a".repeat(32),
        handle: "missing-tunnel".into(),
        call_id: "untrusted-frame".into(),
        operation: DeviceFrameOperation2::Seal { plaintext: vec![] },
    };
    assert!(
        proxy
            .call::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (unconfigured_frame.clone(),),
            )
            .await
            .is_err(),
        "DeviceFrame2 requires confidential transport"
    );
    assert!(
        attacker
            .proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?
            .call_confidential::<DeviceFrameResponse2>(
                names::methods::DEVICE_FRAME2,
                (unconfigured_frame,),
            )
            .await
            .is_err(),
        "untrusted peers cannot use DeviceFrame2"
    );
    let malformed = serde_json::json!([{"request":{"scope_id":"a","call_id":"private-secret","ttl_ms":1,"operation":{"kind":"seal","handle":"private-secret","plaintext":"private-secret"}},"audit":fixture::audit(1)}]);
    let error = proxy
        .call_confidential::<ApprovalRow2>(names::methods::EVALUATE_DEVICE2, malformed)
        .await
        .err()
        .ok_or("fixture malformed call accepted")?;
    assert!(!error.to_string().contains("private-secret"));
    Ok(())
}
async fn handshake_roundtrip(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    sequence: &mut u64,
    client: &str,
    server: &str,
    core_public: &str,
    client_public: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let handshake = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::SealHandshake {
            handle: client.into(),
            peer: core_public.into(),
            plaintext: b"private-secret".to_vec(),
        },
    )
    .await?
    .bytes;
    let opened = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::OpenHandshake {
            handle: server.into(),
            frame: handshake.clone(),
        },
    )
    .await?;
    assert_eq!(opened.bytes, b"private-secret");
    assert_eq!(opened.public_key, Some(client_public.into()));
    assert!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::OpenHandshake {
                handle: server.into(),
                frame: handshake
            }
        )
        .await
        .is_err()
    );
    Ok(())
}
async fn native_protocols(
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    sequence: &mut u64,
) -> std::result::Result<(String, String), Box<dyn std::error::Error>> {
    let server = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    )
    .await?;
    let client = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Ephemeral,
        },
    )
    .await?;
    let core_public = server.public_key.ok_or("fixture public")?;
    let server = server.handle.ok_or("fixture handle")?;
    let client_public = client.public_key.ok_or("fixture public")?;
    let client = client.handle.ok_or("fixture handle")?;
    handshake_roundtrip(
        proxy,
        store,
        sequence,
        &client,
        &server,
        &core_public,
        &client_public,
    )
    .await?;
    let ack = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::SealAck {
            handle: server.clone(),
            peer: client_public,
            plaintext: b"ack".to_vec(),
        },
    )
    .await?
    .bytes;
    assert_eq!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::OpenAck {
                handle: client,
                peer: core_public.clone(),
                frame: ack
            }
        )
        .await?
        .bytes,
        b"ack"
    );
    native_tunnel(proxy, store, sequence, &server, &core_public).await?;
    fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Revoke {
            handle: server.clone(),
        },
    )
    .await?;
    assert!(
        fixture::run(
            proxy,
            store,
            sequence,
            DeviceOperation2::OpenHandshake {
                handle: server,
                frame: vec![3; 73]
            }
        )
        .await
        .is_err()
    );
    let observer = fixture::run(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
    )
    .await?;
    let observer_public = observer.public_key.ok_or("fixture public")?;
    let observer = observer.handle.ok_or("fixture handle")?;
    let stale_tunnel = native_tunnel(proxy, store, sequence, &observer, &observer_public).await?;
    Ok((observer, stale_tunnel))
}
async fn callback_configuration_fence(
    lifecycle: &ModuleHost,
    name: &str,
    configuration: ModuleConfig,
    proxy: &HostCallbackProxy,
    store: &Arc<Mutex<fixture::store::DiskStore>>,
    sequence: &mut u64,
    handles: (String, String),
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let (_key, _stale_tunnel) = handles;
    let mut changed = configuration.clone();
    for scope in &mut changed.device.as_mut().ok_or("fixture config")?.scopes {
        scope.static_secret = None;
    }
    changed.device.as_mut().ok_or("fixture config")?.max_handles = 16;
    let Err(reinit_error) = lifecycle
        .reinitialize(name, serde_json::to_value(changed)?)
        .await
    else {
        return Err("callback-bound configuration change was accepted".into());
    };
    assert!(
        reinit_error
            .to_string()
            .contains("scoped callback configuration is immutable")
    );
    let info: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    assert_eq!(info.generation, 1);
    let module = lifecycle
        .list()
        .into_iter()
        .find(|module| module.name == name)
        .ok_or("loaded module")?;
    assert!(matches!(module.state, tinybus::module::ModuleState::Ready));
    let current = fixture::run_at(
        proxy,
        store,
        sequence,
        DeviceOperation2::Key {
            purpose: DeviceKeyPurpose2::Static,
        },
        1,
    )
    .await?;
    let observer = current.handle.ok_or("fixture handle")?;
    Ok(observer)
}

fn verify_journals(root: &std::path::Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = std::fs::read(root.join("approvals.journal"))?;
    assert!(!String::from_utf8_lossy(&journal).contains("private-secret"));
    let audit = std::fs::read(root.join("audit.journal"))?;
    if audit.is_empty() {
        return Err("fixture empty audit".into());
    }
    assert!(!String::from_utf8_lossy(&audit).contains("private-secret"));
    Ok(())
}

async fn wait_owner(
    host: &Connection,
) -> std::result::Result<tinybus::BusName, Box<dyn std::error::Error>> {
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
