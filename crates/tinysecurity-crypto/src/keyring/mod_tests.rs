use super::*;
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;
use tinystoragedrivers::secrets::MemorySecrets;
use tinystoragedrivers::{Result as DriverResult, StorageError};
#[derive(Default)]
struct CountingMint(AtomicUsize);
impl MasterMint for CountingMint {
    fn mint(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new([7; 32]))
    }
}
#[derive(Debug)]
struct Denied;
#[async_trait]
impl SecretStore for Denied {
    async fn get(&self, _: &str) -> DriverResult<Option<Zeroizing<Vec<u8>>>> {
        Err(StorageError::unavailable("private material"))
    }
    async fn set(&self, _: &str, _: &[u8]) -> DriverResult<()> {
        Err(StorageError::backend("unexpected write"))
    }
    async fn delete(&self, _: &str) -> DriverResult<bool> {
        Err(StorageError::backend("unexpected delete"))
    }
    async fn list(&self, _: &str) -> DriverResult<Vec<String>> {
        Err(StorageError::backend("unexpected enumeration"))
    }
    fn backend_name(&self) -> &'static str {
        "denied"
    }
}
#[tokio::test]
async fn legacy_existing_prevents_replacement_and_copies_exact_bytes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(MemorySecrets::new());
    let legacy = Arc::new(MemorySecrets::new());
    let bytes = "AB".repeat(32);
    legacy.set("app:master_key", bytes.as_bytes()).await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(
        target.clone(),
        vec![legacy.clone()],
        &MasterSlot::App,
        mint.clone(),
    )?;
    assert_eq!(resolver.resolve().await?.bytes(), &[0xab; 32]);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        &*target
            .get("app:master_key")
            .await?
            .ok_or("expected entry")?,
        bytes.as_bytes()
    );
    assert_eq!(
        &*legacy
            .get("app:master_key")
            .await?
            .ok_or("expected entry")?,
        bytes.as_bytes()
    );
    Ok(())
}
#[tokio::test]
async fn legacy_denied_blocks_mint_and_target_mutation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(MemorySecrets::new());
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(
        target.clone(),
        vec![Arc::new(Denied)],
        &MasterSlot::App,
        mint.clone(),
    )?;
    assert_eq!(
        resolver.resolve().await.err().ok_or("expected failure")?,
        Error::KeyringUnavailable
    );
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert!(target.get("app:master_key").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn target_valid_wins_without_legacy_lookup_or_mint()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(MemorySecrets::new());
    target
        .set("app:master_key", "11".repeat(32).as_bytes())
        .await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(
        target,
        vec![Arc::new(Denied)],
        &MasterSlot::App,
        mint.clone(),
    )?;
    assert_eq!(resolver.resolve().await?.bytes(), &[0x11; 32]);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert_eq!(format!("{resolver:?}"), "MasterResolver([redacted])");
    Ok(())
}
#[tokio::test]
async fn absence_of_every_source_is_required_to_mint_once()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(MemorySecrets::new());
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(
        target,
        vec![Arc::new(MemorySecrets::new())],
        &MasterSlot::User("fixture".into()),
        mint.clone(),
    )?;
    assert_eq!(resolver.resolve().await?.bytes(), &[7; 32]);
    assert_eq!(resolver.resolve().await?.bytes(), &[7; 32]);
    assert_eq!(mint.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn read_only_resolution_never_mints_or_mutates()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(MemorySecrets::new());
    let legacy = Arc::new(MemorySecrets::new());
    legacy
        .set(".secret_key", b"AB".repeat(32).as_slice())
        .await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new_with_sources(
        target.clone(),
        vec![LegacySource::at_slot(legacy.clone(), MasterSlot::File)],
        &MasterSlot::User("profile".into()),
        mint.clone(),
    )?;

    let key = resolver
        .resolve_existing()
        .await?
        .ok_or("expected existing legacy key")?;
    assert_eq!(key.bytes(), &[0xab; 32]);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert!(
        target
            .get("profile:secretstore.master_key")
            .await?
            .is_none()
    );
    assert!(legacy.get(".secret_key").await?.is_some());

    let absent = MasterResolver::new(
        Arc::new(MemorySecrets::new()),
        vec![Arc::new(MemorySecrets::new())],
        &MasterSlot::App,
        mint.clone(),
    )?;
    assert!(absent.resolve_existing().await?.is_none());
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn malformed_or_ambiguous_legacy_never_mutates_target()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for bytes in [vec![0xff], b"bad".to_vec(), vec![b'x'; 129]] {
        let target = Arc::new(MemorySecrets::new());
        let legacy = Arc::new(MemorySecrets::new());
        legacy.set(".secret_key", &bytes).await?;
        let mint = Arc::new(CountingMint::default());
        let resolver = MasterResolver::new(
            target.clone(),
            vec![legacy.clone()],
            &MasterSlot::File,
            mint.clone(),
        )?;
        assert_eq!(
            resolver.resolve().await.err().ok_or("expected failure")?,
            Error::SecretInvalid
        );
        assert_eq!(mint.0.load(Ordering::SeqCst), 0);
        assert!(target.get(".secret_key").await?.is_none());
        assert_eq!(
            &*legacy.get(".secret_key").await?.ok_or("expected entry")?,
            &bytes
        );
    }
    let target = Arc::new(MemorySecrets::new());
    let a = Arc::new(MemorySecrets::new());
    let b = Arc::new(MemorySecrets::new());
    a.set("app:master_key", "11".repeat(32).as_bytes()).await?;
    b.set("app:master_key", "22".repeat(32).as_bytes()).await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(target.clone(), vec![a, b], &MasterSlot::App, mint.clone())?;
    assert_eq!(
        resolver.resolve().await.err().ok_or("expected failure")?,
        Error::SecretInvalid
    );
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert!(target.get("app:master_key").await?.is_none());
    Ok(())
}
#[tokio::test]
async fn target_denied_or_malformed_blocks_fallback_and_mint()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(Arc::new(Denied), vec![], &MasterSlot::App, mint.clone())?;
    assert_eq!(
        resolver.resolve().await.err().ok_or("expected failure")?,
        Error::KeyringUnavailable
    );
    let target = Arc::new(MemorySecrets::new());
    target.set("app:master_key", b"bad").await?;
    let resolver = MasterResolver::new(
        target,
        vec![Arc::new(Denied)],
        &MasterSlot::App,
        mint.clone(),
    )?;
    assert_eq!(
        resolver.resolve().await.err().ok_or("expected failure")?,
        Error::SecretInvalid
    );
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn inventory_and_slots_are_bounded_distinct_and_redacted()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let make = |slot, legacy| {
        MasterResolver::new(
            Arc::new(MemorySecrets::new()),
            legacy,
            &slot,
            Arc::new(CountingMint::default()),
        )
    };
    assert_eq!(
        make(MasterSlot::User(String::new()), vec![])
            .err()
            .ok_or("expected failure")?,
        Error::InvalidInput
    );
    assert_eq!(
        make(MasterSlot::User("a:b".into()), vec![])
            .err()
            .ok_or("expected failure")?,
        Error::InvalidInput
    );
    assert_eq!(
        make(MasterSlot::User("\0".into()), vec![])
            .err()
            .ok_or("expected failure")?,
        Error::InvalidInput
    );
    assert_eq!(
        make(
            MasterSlot::App,
            (0..4)
                .map(|_| Arc::new(MemorySecrets::new()) as Arc<dyn SecretStore>)
                .collect()
        )
        .err()
        .ok_or("expected failure")?,
        Error::InvalidInput
    );
    assert_eq!(MasterSlot::App.name(), "app:master_key");
    assert_eq!(
        MasterSlot::User("u".into()).name(),
        "u:secretstore.master_key"
    );
    assert_eq!(MasterSlot::File.name(), ".secret_key");
    assert_eq!(SERVICE, "openhuman");
    assert_eq!(
        format!("{:?}", MasterKey(Zeroizing::new([8; 32]))),
        "MasterKey([redacted])"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    Write,
    MissingReadback,
    WrongReadback,
    DeniedReadback,
    Pending,
    PanicWrite,
}
#[derive(Debug)]
struct FaultTarget {
    fault: Fault,
    reads: AtomicUsize,
    writes: AtomicUsize,
}
#[async_trait]
impl SecretStore for FaultTarget {
    async fn get(&self, _: &str) -> DriverResult<Option<Zeroizing<Vec<u8>>>> {
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        if matches!(self.fault, Fault::Pending) {
            return std::future::pending().await;
        }
        if read == 0 {
            return Ok(None);
        }
        match self.fault {
            Fault::DeniedReadback => Err(StorageError::unavailable("private fixture")),
            Fault::WrongReadback => Ok(Some(Zeroizing::new(b"wrong".to_vec()))),
            _ => Ok(None),
        }
    }
    async fn set(&self, _: &str, _: &[u8]) -> DriverResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        assert!(
            !matches!(self.fault, Fault::PanicWrite),
            "fixture write panic"
        );
        if matches!(self.fault, Fault::Write) {
            Err(StorageError::unavailable("private fixture"))
        } else {
            Ok(())
        }
    }
    async fn delete(&self, _: &str) -> DriverResult<bool> {
        Err(StorageError::backend("must preserve source"))
    }
    async fn list(&self, _: &str) -> DriverResult<Vec<String>> {
        Err(StorageError::backend("must not enumerate"))
    }
    fn backend_name(&self) -> &'static str {
        "fixture"
    }
}
#[tokio::test]
async fn failed_copy_or_readback_preserves_legacy_without_mint()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for fault in [
        Fault::Write,
        Fault::MissingReadback,
        Fault::WrongReadback,
        Fault::DeniedReadback,
    ] {
        let target = Arc::new(FaultTarget {
            fault,
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        });
        let source = Arc::new(MemorySecrets::new());
        let original = "aB".repeat(32);
        source.set(".secret_key", original.as_bytes()).await?;
        let mint = Arc::new(CountingMint::default());
        let resolver = MasterResolver::new_with_sources(
            target.clone(),
            vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
            &MasterSlot::User("u".into()),
            mint.clone(),
        )?;
        assert!(resolver.resolve().await.is_err());
        assert_eq!(mint.0.load(Ordering::SeqCst), 0);
        assert_eq!(target.writes.load(Ordering::SeqCst), 1);
        assert!(matches!(
            resolver.resolve().await,
            Err(Error::KeyringUnavailable)
        ));
        assert_eq!(target.writes.load(Ordering::SeqCst), 1);
        assert_eq!(mint.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            &*source.get(".secret_key").await?.ok_or("missing source")?,
            original.as_bytes()
        );
    }
    Ok(())
}
#[tokio::test]
async fn reservation_denies_overlap_and_cancellation_releases_it()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(FaultTarget {
        fault: Fault::Pending,
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(target.clone(), vec![], &MasterSlot::App, mint.clone())?;
    let mut future = Box::pin(resolver.resolve());
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
    assert_eq!(
        resolver
            .resolve()
            .await
            .err()
            .ok_or("expected overlap failure")?,
        Error::KeyringUnavailable
    );
    drop(future);
    assert!(!resolver.reserved.load(Ordering::Acquire));
    assert_eq!(target.writes.load(Ordering::SeqCst), 0);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn a_later_denied_source_blocks_copy_of_an_earlier_valid_master()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let source = Arc::new(MemorySecrets::new());
    source
        .set("app:master_key", "42".repeat(32).as_bytes())
        .await?;
    let target = Arc::new(MemorySecrets::new());
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new(
        target.clone(),
        vec![source, Arc::new(Denied)],
        &MasterSlot::App,
        mint.clone(),
    )?;
    assert_eq!(
        resolver.resolve().await.err().ok_or("expected failure")?,
        Error::KeyringUnavailable
    );
    assert!(target.get("app:master_key").await?.is_none());
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[derive(Debug)]
struct DetachedTarget {
    memory: Arc<MemorySecrets>,
    writes: AtomicUsize,
    reads: AtomicUsize,
    entered: Arc<tokio::sync::Notify>,
    completed: Arc<tokio::sync::Notify>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    readback_gate: bool,
}
#[async_trait]
impl SecretStore for DetachedTarget {
    async fn get(&self, name: &str) -> DriverResult<Option<Zeroizing<Vec<u8>>>> {
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        if self.readback_gate && read == 1 {
            self.entered.notify_one();
            return std::future::pending().await;
        }
        self.memory.get(name).await
    }
    async fn set(&self, name: &str, value: &[u8]) -> DriverResult<()> {
        let write = self.writes.fetch_add(1, Ordering::SeqCst);
        if write != 0 || self.readback_gate {
            return self.memory.set(name, value).await;
        }
        let release = self
            .release
            .lock()
            .map_err(|_| StorageError::unavailable("fixture gate"))?
            .take()
            .ok_or_else(|| StorageError::unavailable("fixture gate"))?;
        let memory = self.memory.clone();
        let name = name.to_owned();
        let value = Zeroizing::new(value.to_vec());
        let entered = self.entered.clone();
        let completed = self.completed.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            entered.notify_one();
            release
                .blocking_recv()
                .map_err(|_| StorageError::unavailable("fixture gate"))?;
            let result = runtime.block_on(memory.set(&name, &value));
            completed.notify_one();
            result
        })
        .await
        .map_err(|_| StorageError::unavailable("fixture worker"))?
    }
    async fn delete(&self, _: &str) -> DriverResult<bool> {
        Err(StorageError::unavailable("must preserve"))
    }
    async fn list(&self, _: &str) -> DriverResult<Vec<String>> {
        Err(StorageError::unavailable("must not enumerate"))
    }
    fn backend_name(&self) -> &'static str {
        "fixture"
    }
}
#[tokio::test]
async fn canceled_detached_write_blocks_retry_until_safe_reconciliation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (release, receiver) = tokio::sync::oneshot::channel();
    let target = Arc::new(DetachedTarget {
        memory: Arc::new(MemorySecrets::new()),
        writes: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        entered: Arc::new(tokio::sync::Notify::new()),
        completed: Arc::new(tokio::sync::Notify::new()),
        release: std::sync::Mutex::new(Some(receiver)),
        readback_gate: false,
    });
    let mint = Arc::new(CountingMint::default());
    let source = Arc::new(MemorySecrets::new());
    source
        .set(".secret_key", "42".repeat(32).as_bytes())
        .await?;
    let resolver = MasterResolver::new_with_sources(
        target.clone(),
        vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
        &MasterSlot::User("u".into()),
        mint.clone(),
    )?;
    let mut future = Box::pin(resolver.resolve());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
    target.entered.notified().await;
    drop(future);
    let retry = resolver.resolve().await;
    release.send(()).map_err(|()| "release gate")?;
    target.completed.notified().await;
    assert!(matches!(retry, Err(Error::KeyringUnavailable)));
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert_eq!(target.writes.load(Ordering::SeqCst), 1);
    assert!(matches!(
        resolver.resolve().await,
        Err(Error::KeyringUnavailable)
    ));
    let stored = target
        .memory
        .get("u:secretstore.master_key")
        .await?
        .ok_or("missing original")?;
    assert!(parse(&stored)?.bytes().eq(&[0x42; 32]));
    assert!(source.get(".secret_key").await?.is_some());
    Ok(())
}
#[tokio::test]
async fn canceled_post_write_readback_retains_uncertain_reservation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(DetachedTarget {
        memory: Arc::new(MemorySecrets::new()),
        writes: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        entered: Arc::new(tokio::sync::Notify::new()),
        completed: Arc::new(tokio::sync::Notify::new()),
        release: std::sync::Mutex::new(None),
        readback_gate: true,
    });
    let mint = Arc::new(CountingMint::default());
    let source = Arc::new(MemorySecrets::new());
    source
        .set(".secret_key", "42".repeat(32).as_bytes())
        .await?;
    let resolver = MasterResolver::new_with_sources(
        target.clone(),
        vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
        &MasterSlot::User("u".into()),
        mint.clone(),
    )?;
    let mut future = Box::pin(resolver.resolve());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
    target.entered.notified().await;
    drop(future);
    assert!(matches!(
        resolver.resolve().await,
        Err(Error::KeyringUnavailable)
    ));
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert_eq!(target.writes.load(Ordering::SeqCst), 1);
    assert!(
        target
            .memory
            .get("u:secretstore.master_key")
            .await?
            .is_some()
    );
    assert!(source.get(".secret_key").await?.is_some());
    Ok(())
}

#[tokio::test]
async fn mutation_panic_latches_without_losing_legacy_key()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(FaultTarget {
        fault: Fault::PanicWrite,
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let source = Arc::new(MemorySecrets::new());
    let original = Zeroizing::new("ab".repeat(32));
    source.set(".secret_key", original.as_bytes()).await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = Arc::new(MasterResolver::new_with_sources(
        target.clone(),
        vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
        &MasterSlot::User("u".into()),
        mint.clone(),
    )?);
    let caller = resolver.clone();
    let task = tokio::spawn(async move { caller.resolve().await });
    assert!(task.await.err().ok_or("expected panic")?.is_panic());
    assert!(matches!(
        resolver.resolve().await,
        Err(Error::KeyringUnavailable)
    ));
    assert_eq!(target.writes.load(Ordering::SeqCst), 1);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    let preserved = source.get(".secret_key").await?.ok_or("missing legacy")?;
    assert!(preserved.as_slice().eq(original.as_bytes()));
    Ok(())
}

#[derive(Debug)]
struct SlotStore {
    slot: &'static str,
    memory: MemorySecrets,
    reads: AtomicUsize,
    writes: AtomicUsize,
    deletes: AtomicUsize,
    lists: AtomicUsize,
}
impl SlotStore {
    fn new(slot: &'static str) -> Self {
        Self {
            slot,
            memory: MemorySecrets::new(),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
            lists: AtomicUsize::new(0),
        }
    }
}
#[async_trait]
impl SecretStore for SlotStore {
    async fn get(&self, name: &str) -> DriverResult<Option<Zeroizing<Vec<u8>>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if name != self.slot {
            return Ok(None);
        }
        self.memory.get(name).await
    }
    async fn set(&self, name: &str, value: &[u8]) -> DriverResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        assert_eq!(name, self.slot);
        self.memory.set(name, value).await
    }
    async fn delete(&self, _: &str) -> DriverResult<bool> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Err(StorageError::backend("unexpected mutation"))
    }
    async fn list(&self, _: &str) -> DriverResult<Vec<String>> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        Err(StorageError::backend("unexpected enumeration"))
    }
    fn backend_name(&self) -> &'static str {
        "fixture"
    }
}
#[tokio::test]
async fn config_user_target_reads_registered_legacy_file_slot()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(SlotStore::new("u:secretstore.master_key"));
    let source = Arc::new(SlotStore::new(".secret_key"));
    let original = Zeroizing::new(format!("  {}\n", "42".repeat(32).to_uppercase()));
    source
        .memory
        .set(".secret_key", original.as_bytes())
        .await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new_with_sources(
        target.clone(),
        vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
        &MasterSlot::User("u".into()),
        mint.clone(),
    )?;
    let key = resolver.resolve().await?;
    assert_eq!(key.bytes(), &[0x42; 32]);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    assert_eq!(target.writes.load(Ordering::SeqCst), 1);
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    assert_eq!(source.writes.load(Ordering::SeqCst), 0);
    assert_eq!(source.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(source.lists.load(Ordering::SeqCst), 0);
    assert_eq!(
        &*target
            .memory
            .get(target.slot)
            .await?
            .ok_or("missing target")?,
        original.as_bytes()
    );
    assert_eq!(
        &*source
            .memory
            .get(source.slot)
            .await?
            .ok_or("missing source")?,
        original.as_bytes()
    );
    let cipher = crate::secretstore::SecretCipher::new(Zeroizing::new(*key.bytes()), true);
    for (line, expected) in include_str!("../../fixtures/enc2_values.txt")
        .lines()
        .zip(["sk-test-fixture-value", "paßword 🔑"])
    {
        assert_eq!(&*cipher.decrypt(line)?, expected);
    }
    let plain = crypto::decrypt(
        key.bytes(),
        include_bytes!("../../fixtures/secrets_enc.bin"),
    )?;
    let map: std::collections::BTreeMap<String, String> = serde_json::from_slice(&plain)?;
    assert_eq!(map.len(), 3);
    assert_eq!(map["user-1:api_key"], "sk-fixture-é中");
    Ok(())
}

#[test]
fn cross_purpose_source_binding_rejected_before_io() {
    let target = Arc::new(SlotStore::new("u:secretstore.master_key"));
    let source = Arc::new(SlotStore::new(".secret_key"));
    let user = MasterSlot::User("u".into());
    for (target_slot, source_slot) in [
        (MasterSlot::App, user.clone()),
        (user.clone(), MasterSlot::App),
        (MasterSlot::App, MasterSlot::File),
        (MasterSlot::File, MasterSlot::App),
        (user.clone(), MasterSlot::User("v".into())),
        (user.clone(), MasterSlot::User("a:b".into())),
        (MasterSlot::User("\0".into()), MasterSlot::File),
        (MasterSlot::File, MasterSlot::User(String::new())),
    ] {
        assert!(matches!(
            MasterResolver::new_with_sources(
                target.clone(),
                vec![LegacySource::at_slot(source.clone(), source_slot)],
                &target_slot,
                Arc::new(CountingMint::default())
            ),
            Err(Error::InvalidInput)
        ));
    }
    assert!(matches!(
        MasterResolver::new_with_sources(
            target.clone(),
            (0..4)
                .map(|_| LegacySource::at_slot(source.clone(), MasterSlot::File))
                .collect(),
            &user,
            Arc::new(CountingMint::default())
        ),
        Err(Error::InvalidInput)
    ));
    assert_eq!(target.reads.load(Ordering::SeqCst), 0);
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(target.writes.load(Ordering::SeqCst), 0);
    assert_eq!(source.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        format!("{:?}", LegacySource::at_slot(source, MasterSlot::File)),
        "LegacySource([redacted])"
    );
}

#[tokio::test]
async fn registered_file_sources_are_all_validated_before_any_publication()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for bad in [
        vec![],
        vec![0xff],
        b"bad".to_vec(),
        vec![b'4'; 63],
        vec![b'4'; 129],
        b"11".repeat(32),
    ] {
        let target = Arc::new(SlotStore::new("u:secretstore.master_key"));
        let first = Arc::new(SlotStore::new(".secret_key"));
        let later = Arc::new(SlotStore::new("u:secretstore.master_key"));
        first
            .memory
            .set(first.slot, b"42".repeat(32).as_slice())
            .await?;
        later.memory.set(later.slot, &bad).await?;
        let mint = Arc::new(CountingMint::default());
        let resolver = MasterResolver::new_with_sources(
            target.clone(),
            vec![
                LegacySource::at_slot(first.clone(), MasterSlot::File),
                LegacySource::at_slot(later.clone(), MasterSlot::User("u".into())),
            ],
            &MasterSlot::User("u".into()),
            mint.clone(),
        )?;
        assert!(matches!(
            resolver.resolve().await,
            Err(Error::SecretInvalid)
        ));
        assert_eq!(target.writes.load(Ordering::SeqCst), 0);
        assert_eq!(mint.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            &*later
                .memory
                .get(later.slot)
                .await?
                .ok_or("missing source")?,
            &bad
        );
        assert_eq!(
            first.deletes.load(Ordering::SeqCst) + later.deletes.load(Ordering::SeqCst),
            0
        );
    }
    let target = Arc::new(SlotStore::new("u:secretstore.master_key"));
    let source = Arc::new(SlotStore::new(".secret_key"));
    source
        .memory
        .set(source.slot, b"42".repeat(32).as_slice())
        .await?;
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new_with_sources(
        target.clone(),
        vec![
            LegacySource::at_slot(source.clone(), MasterSlot::File),
            LegacySource::at_slot(Arc::new(Denied), MasterSlot::User("u".into())),
        ],
        &MasterSlot::User("u".into()),
        mint.clone(),
    )?;
    assert!(matches!(
        resolver.resolve().await,
        Err(Error::KeyringUnavailable)
    ));
    assert_eq!(target.writes.load(Ordering::SeqCst), 0);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn equal_decoded_sources_preserve_first_encoding_and_reverse_binding()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for (slot, source_slot, name, source_name) in [
        (
            MasterSlot::User("u".into()),
            MasterSlot::File,
            "u:secretstore.master_key",
            ".secret_key",
        ),
        (
            MasterSlot::File,
            MasterSlot::User("u".into()),
            ".secret_key",
            "u:secretstore.master_key",
        ),
    ] {
        let target = Arc::new(SlotStore::new(name));
        let first = Arc::new(SlotStore::new(source_name));
        let later = Arc::new(SlotStore::new(name));
        let original = Zeroizing::new(format!(" {}\n", "AB".repeat(32)));
        first.memory.set(first.slot, original.as_bytes()).await?;
        later
            .memory
            .set(later.slot, b"ab".repeat(32).as_slice())
            .await?;
        let mint = Arc::new(CountingMint::default());
        let resolver = MasterResolver::new_with_sources(
            target.clone(),
            vec![
                LegacySource::at_slot(first.clone(), source_slot),
                LegacySource::at_slot(later.clone(), slot.clone()),
            ],
            &slot,
            mint.clone(),
        )?;
        assert_eq!(resolver.resolve().await?.bytes(), &[0xab; 32]);
        assert_eq!(
            &*target.memory.get(name).await?.ok_or("missing target")?,
            original.as_bytes()
        );
        assert_eq!(later.reads.load(Ordering::SeqCst), 1);
        assert_eq!(mint.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            first.writes.load(Ordering::SeqCst) + later.writes.load(Ordering::SeqCst),
            0
        );
    }
    Ok(())
}

#[tokio::test]
async fn valid_target_skips_file_and_only_confirmed_absence_mints()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for value in [Some(b"42".repeat(32)), Some(b"bad".to_vec()), None] {
        let target = Arc::new(SlotStore::new("u:secretstore.master_key"));
        if let Some(bytes) = &value {
            target.memory.set(target.slot, bytes).await?;
        }
        let source = Arc::new(SlotStore::new(".secret_key"));
        let mint = Arc::new(CountingMint::default());
        let resolver = MasterResolver::new_with_sources(
            target.clone(),
            vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
            &MasterSlot::User("u".into()),
            mint.clone(),
        )?;
        match value {
            Some(bytes) if bytes.len() == 64 => {
                assert_eq!(resolver.resolve().await?.bytes(), &[0x42; 32]);
                assert_eq!(source.reads.load(Ordering::SeqCst), 0);
            }
            Some(_) => {
                assert!(matches!(
                    resolver.resolve().await,
                    Err(Error::SecretInvalid)
                ));
                assert_eq!(source.reads.load(Ordering::SeqCst), 0);
            }
            None => {
                assert_eq!(resolver.resolve().await?.bytes(), &[7; 32]);
                assert_eq!(source.reads.load(Ordering::SeqCst), 1);
            }
        }
        assert_eq!(
            mint.0.load(Ordering::SeqCst),
            target.writes.load(Ordering::SeqCst)
        );
        assert_eq!(
            source.writes.load(Ordering::SeqCst)
                + source.deletes.load(Ordering::SeqCst)
                + source.lists.load(Ordering::SeqCst),
            0
        );
    }
    let resolver = MasterResolver::new_with_sources(
        Arc::new(Denied),
        vec![LegacySource::at_slot(Arc::new(Denied), MasterSlot::File)],
        &MasterSlot::User("u".into()),
        Arc::new(CountingMint::default()),
    )?;
    assert!(matches!(
        resolver.resolve().await,
        Err(Error::KeyringUnavailable)
    ));
    Ok(())
}

#[tokio::test]
async fn cancellation_during_cross_slot_source_read_releases_without_writes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let target = Arc::new(SlotStore::new("u:secretstore.master_key"));
    let source = Arc::new(FaultTarget {
        fault: Fault::Pending,
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let mint = Arc::new(CountingMint::default());
    let resolver = MasterResolver::new_with_sources(
        target.clone(),
        vec![LegacySource::at_slot(source.clone(), MasterSlot::File)],
        &MasterSlot::User("u".into()),
        mint.clone(),
    )?;
    for _ in 0..2 {
        let mut future = Box::pin(resolver.resolve());
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
        drop(future);
        assert!(!resolver.reserved.load(Ordering::Acquire));
    }
    assert_eq!(source.reads.load(Ordering::SeqCst), 2);
    assert_eq!(target.writes.load(Ordering::SeqCst), 0);
    assert_eq!(mint.0.load(Ordering::SeqCst), 0);
    Ok(())
}
