use super::*;
use tinybus::{broker::Broker, transport::memory::MemoryBus};
use tinysecurity_bus::*;
fn config(required: bool) -> AuditConfig2 {
    AuditConfig2 {
        scope: SubjectScope {
            user: "user".into(),
            workspace: "workspace".into(),
            agent: "agent".into(),
        },
        stream_id: "a".repeat(32),
        timeout_ms: 100,
        required,
        native_path: None,
        max_bytes: 10000,
        max_archives: 3,
        journal_max_bytes: 100_000,
        journal_max_events: 1000,
    }
}
fn batch() -> AuditSinkRequest2 {
    AuditSinkRequest2 {
        scope: config(true).scope,
        stream_id: "a".repeat(32),
        expected_tail: 0,
        events: vec![AuditEvent2 {
            sequence: 1,
            event_id: "b".repeat(32),
            generation: 1,
            kind: AuditKind2::Shell,
            attribution: "bearer private-attribution".into(),
            arguments_json: r#"{"token":"private-secret"}"#.into(),
            rule_ids: vec![],
        }],
    }
}

fn native_namespace()
-> std::result::Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("audit");
        Ok((directory, path))
    }
    #[cfg(windows)]
    {
        let root = std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
            .ok_or("audit test namespace not provisioned")?;
        let directory = tempfile::tempdir_in(root)?;
        // Use the native fixture's .NET installer APIs, independent of cmdlet
        // resolution. Elevated tokens can assign Administrators as the default
        // owner, so both the directory and empty journal need the current user.
        let script = r"
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($identity.User)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity.User, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
    [IO.Directory]::SetAccessControl($env:TINYSECURITY_CALLBACK_DIRECTORY, $acl)
    $journalPath = [IO.Path]::Combine($env:TINYSECURITY_CALLBACK_DIRECTORY, 'audit.journal')
    $rights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $journal = [IO.FileStream]::new($journalPath, [IO.FileMode]::CreateNew, $rights, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::None)
    try {
        $journalAcl = $journal.GetAccessControl()
        $journalAcl.SetOwner($identity.User)
        $journal.SetAccessControl($journalAcl)
        $journal.Flush($true)
    } finally { $journal.Dispose() }
} catch { exit 1 }
";
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("TINYSECURITY_CALLBACK_DIRECTORY", directory.path())
            .output()?;
        // Startup/error streams may contain paths or identities. Never render them.
        if !output.status.success() {
            return Err("callback audit namespace installer failed".into());
        }
        let path = directory.path().join("audit");
        Ok((directory, path))
    }
}
#[tokio::test]
async fn optional_storage_loss_cannot_authorize_a_scope_widening_attempt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let client = AuditClient::new_for_test(
        module,
        binding,
        config(false),
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let mut forged = batch();
    forged.scope.user = "other-user".into();
    let response = client.append(forged).await;
    assert!(
        !response.permitted,
        "optional persistence policy must not make a scope mismatch permissive"
    );
    assert!(!response.committed);
    assert!(response.receipt.is_none());
    task.abort();
    Ok(())
}
#[derive(Clone)]
struct Sink {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    wrong_receipt: bool,
}
#[tinybus::interface(name = "ai.tinyhumans.tinysecurity.AuditSink2")]
impl Sink {
    async fn append(&self, batch: AuditSinkRequest2) -> tinybus::Result<AuditSinkResponse2> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let serialized = std::future::ready(serde_json::to_string(&batch)).await?;
        assert!(!serialized.contains("private-"));
        Ok(AuditSinkResponse2 {
            scope: batch.scope,
            stream_id: if self.wrong_receipt {
                "c".repeat(32)
            } else {
                batch.stream_id
            },
            events: batch
                .events
                .iter()
                .map(|event| AuditEventReceipt2 {
                    sequence: event.sequence,
                    event_id: event.event_id.clone(),
                })
                .collect(),
            new_tail: batch.events.last().map_or(0, |event| event.sequence),
        })
    }
}
#[tokio::test]
async fn exact_sanitized_receipts_required_failure_and_optional_degradation_are_distinct()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let redactor = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    let required = AuditClient::new_for_test(
        module.clone(),
        binding.clone(),
        config(true),
        redactor.clone(),
    )?;
    let optional = AuditClient::new_for_test(
        module.clone(),
        binding.clone(),
        config(false),
        redactor.clone(),
    )?;
    assert_eq!(required.append(batch()).await.health, AuditHealth2::Denied);
    let lost = optional.append(batch()).await;
    assert_eq!(lost.health, AuditHealth2::Degraded);
    assert!(lost.permitted);
    assert!(!lost.committed);
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let module_binding =
        PeerBinding::new(module.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    host.serve_at(
        callback_names2::OBJECT_PATH.try_into()?,
        Authenticated::new(
            Sink {
                calls: calls.clone(),
                wrong_receipt: false,
            },
            module_binding,
        ),
    )
    .await?;
    let verified = required.append(batch()).await;
    assert_eq!(verified.health, AuditHealth2::Healthy);
    assert!(verified.committed);
    assert!(verified.permitted);
    assert!(verified.receipt.is_some());
    let mut malformed = batch();
    malformed.events[0].arguments_json = "private-malformed".into();
    let denied = optional.append(malformed).await;
    assert!(!denied.permitted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // A second bus connection cannot invoke the separately hosted callback.
    let attacker = tinybus::Connection::connect(bus.connect().await?).await?;
    let target = host.unique_name().ok_or("host has a unique name")?;
    assert!(
        attacker
            .proxy(
                target.as_str(),
                callback_names2::OBJECT_PATH,
                callback_names2::AUDIT_SINK
            )?
            .call::<AuditSinkResponse2>(callback_names2::APPEND, (batch(),))
            .await
            .is_err()
    );
    host.close().await?;
    let replacement = tinybus::Connection::connect(bus.connect().await?).await?;
    let replacement_calls = std::sync::Arc::new(AtomicUsize::new(0));
    replacement
        .serve_at(
            callback_names2::OBJECT_PATH.try_into()?,
            Sink {
                calls: replacement_calls.clone(),
                wrong_receipt: false,
            },
        )
        .await?;
    assert!(!required.append(batch()).await.permitted);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn unrelated_success_receipt_never_confirms_a_required_batch()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let task = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    host.serve_at(
        callback_names2::OBJECT_PATH.try_into()?,
        Sink {
            calls: std::sync::Arc::default(),
            wrong_receipt: true,
        },
    )
    .await?;
    let client = AuditClient::new_for_test(
        module,
        binding,
        config(true),
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let response = client.append(batch()).await;
    assert!(!response.permitted);
    assert!(!response.committed);
    assert!(response.receipt.is_none());
    task.abort();
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn native_worker_deadline_returns_before_a_blocked_commit_and_retry_reconciles()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_root, path) = native_namespace()?;
    let sink = std::sync::Arc::new(tinysecurity::audit::JsonlSink::open(&path, 10000, 3)?);
    let (release, blocked) = std::sync::mpsc::channel();
    let (committed, observed) = tokio::sync::oneshot::channel();
    let worker_sink = sink.clone();
    let request = batch();
    let worker = tokio::task::spawn_blocking(move || {
        blocked
            .recv()
            .map_err(|_| tinysecurity::audit::Error::Storage)?;
        let result = worker_sink.append(&request);
        committed
            .send(result.clone())
            .map_err(|_| tinysecurity::audit::Error::Storage)?;
        result
    });
    let waiting = tokio::spawn(async move {
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            await_native_worker(worker, 100),
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_millis(200)).await;
    let result = waiting.await?;
    // Always release before asserting, so the unfixed RED cannot hang runtime shutdown.
    release.send(())?;
    let late = observed.await??;
    assert!(
        result.is_ok(),
        "native deadline must complete before outer watchdog"
    );
    assert!(
        result?.is_err(),
        "timeout must not fabricate a durable receipt"
    );
    assert_eq!(sink.append(&batch())?, late);
    Ok(())
}

#[tokio::test]
async fn audit_initialization_rejects_unbound_authority_and_mutable_configuration()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let connection = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let registry = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    assert!(PeerBinding::new(Some("ai.unverified.Host")).is_err());
    assert!(binding.verify_reinit(Some(":1.999")).is_err());
    binding.verify_reinit(None)?;
    binding.verify_reinit(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    assert!(
        AuditClient::new_for_test(
            connection.clone(),
            PeerBinding::new(None)?,
            config(true),
            registry.clone()
        )
        .is_err()
    );
    for (timeout, stream) in [
        (0, "a".repeat(32)),
        (30_001, "a".repeat(32)),
        (100, "a".repeat(31)),
        (100, "g".repeat(32)),
    ] {
        let mut invalid = config(true);
        invalid.timeout_ms = timeout;
        invalid.stream_id = stream;
        assert!(
            AuditClient::new_for_test(
                connection.clone(),
                binding.clone(),
                invalid,
                registry.clone()
            )
            .is_err()
        );
    }
    let client = AuditClient::new_for_test(connection, binding, config(true), registry)?;
    client.verify_reinit(None)?;
    client.verify_reinit(Some(&config(true)))?;
    let mut replacement = config(true);
    replacement.scope.user = "replacement".into();
    assert!(client.verify_reinit(Some(&replacement)).is_err());
    assert!(client.required());
    assert_eq!(client.scope(), &config(true).scope);
    assert_eq!(client.stream_id(), config(true).stream_id);
    assert_eq!(format!("{client:?}"), "AuditClient([REDACTED])");
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn authenticated_callback_without_transport_context_never_dispatches()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback = Authenticated::new(
        Sink {
            calls: calls.clone(),
            wrong_receipt: false,
        },
        PeerBinding::new(Some(":1.900"))?,
    );
    assert_eq!(callback.name().as_str(), callback_names2::AUDIT_SINK);
    let append: MemberName = callback_names2::APPEND.parse()?;
    assert!(callback.members().contains(&append));
    assert!(!callback.requires_confidential(&append));
    let error = callback
        .call(&append, serde_json::to_value((batch(),))?)
        .await
        .err()
        .ok_or("direct authority must fail")?;
    assert!(!error.to_string().contains("private-"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn native_storage_returns_exact_receipts_and_capacity_denies_without_phantom_commit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let connection = tinybus::Connection::connect(bus.connect().await?).await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let (_root, path) = native_namespace()?;
    let mut native_config = config(true);
    native_config.native_path = Some(path.to_str().ok_or("fixture path")?.into());
    // Capacity and exact receipts must not race real fsync against the synthetic
    // callback budget. The paused-clock blocked-worker test pins timeout semantics.
    native_config.timeout_ms = 30_000;
    native_config.journal_max_events = 1;
    let registry = tinysecurity::Redactor::new(&RedactorConfig::default())?;
    let client = AuditClient::new_for_test(
        connection.clone(),
        binding.clone(),
        native_config.clone(),
        registry.clone(),
    )?;
    let first = client.append(batch()).await;
    assert!(
        first.committed && first.permitted,
        "native receipt committed={} permitted={} health={:?} receipt-present={}",
        first.committed,
        first.permitted,
        first.health,
        first.receipt.is_some()
    );
    assert_eq!(first.health, AuditHealth2::Healthy);
    assert_eq!(client.append(batch()).await, first);
    let stored = std::fs::read(&path)?;
    let mut second = batch();
    second.expected_tail = 1;
    second.events[0].sequence = 2;
    second.events[0].event_id = "d".repeat(32);
    let denied = client.append(second.clone()).await;
    assert!(!denied.committed && !denied.permitted);
    assert_eq!(denied.health, AuditHealth2::Denied);
    assert_eq!(std::fs::read(&path)?, stored);
    native_config.required = false;
    let optional = AuditClient::new_for_test(
        connection.clone(),
        binding.clone(),
        native_config.clone(),
        registry.clone(),
    )?;
    let degraded = optional.append(second).await;
    assert!(degraded.permitted && !degraded.committed);
    assert_eq!(degraded.health, AuditHealth2::Degraded);
    native_config.native_path = Some("relative-untrusted-private-path".into());
    let error = AuditClient::new_for_test(connection, binding, native_config, registry)
        .err()
        .ok_or("unsafe storage must fail initialization")?;
    assert!(!error.to_string().contains("private-path"));
    broker.abort();
    Ok(())
}

#[tokio::test]
async fn cancelled_native_worker_never_returns_a_success_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let worker = tokio::spawn(std::future::pending::<
        tinysecurity::audit::Result<AuditSinkResponse2>,
    >());
    worker.abort();
    assert!(await_native_worker(worker, 100).await.is_err());
    Ok(())
}

#[tokio::test]
async fn registry_replacement_sanitizes_subsequent_callback_without_changing_trusted_scope()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    let broker = Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await?).await?;
    let module = tinybus::Connection::connect(bus.connect().await?).await?;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    host.serve_at(
        callback_names2::OBJECT_PATH.parse()?,
        Sink {
            calls: calls.clone(),
            wrong_receipt: false,
        },
    )
    .await?;
    let binding = PeerBinding::new(host.unique_name().as_ref().map(tinybus::BusName::as_str))?;
    let client = AuditClient::new_for_test(
        module,
        binding,
        config(true),
        tinysecurity::Redactor::new(&RedactorConfig::default())?,
    )?;
    let registry = tinysecurity::Redactor::new(&RedactorConfig {
        secrets: vec![Secret("new-private-credential".into())],
    })?;
    client.replace_registry(registry)?;
    let mut request = batch();
    request.events[0].attribution = "new-private-credential".into();
    let response = client.append(request.clone()).await;
    assert!(response.committed && response.permitted);
    assert_eq!(client.scope(), &config(true).scope);
    let denied = client
        .append_with_registry(
            request,
            Err(tinybus::Error::failed("private-registry-unavailable")),
        )
        .await;
    assert!(!denied.committed && !denied.permitted);
    assert!(!format!("{denied:?}").contains("private-"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    broker.abort();
    Ok(())
}
