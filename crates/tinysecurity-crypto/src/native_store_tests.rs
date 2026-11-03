use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn unique(label: &str) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| "entropy")?;
    let suffix = u64::from_le_bytes(bytes);
    Ok(format!("tinysecurity-test-{label}-{suffix:016x}"))
}

#[tokio::test]
async fn encrypted_file_backend_round_trips_and_deletes() -> TestResult {
    // The driver rejects symlinked components (macOS /var is one); use the real path.
    let dir = std::env::temp_dir().canonicalize()?.join(unique("dir")?);
    std::fs::create_dir_all(&dir)?;
    let store = open("tinysecurity-test", Backend::EncryptedFile(dir.clone()))?;
    assert!(store.get("user:token").await?.is_none());
    store.set("user:token", b"v1").await?;
    assert_eq!(
        store.get("user:token").await?.as_deref().map(Vec::as_slice),
        Some(b"v1".as_slice())
    );
    assert!(store.delete("user:token").await?);
    assert!(!store.delete("user:token").await?);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn relative_directory_and_unbuilt_secret_service_fail_closed() {
    assert_eq!(
        open("s", Backend::EncryptedFile("relative".into())).err(),
        Some(Error::InvalidInput)
    );
    #[cfg(not(all(target_os = "linux", feature = "keyring-secret-service")))]
    assert_eq!(
        open("s", Backend::SecretService).err(),
        Some(Error::KeyringUnavailable)
    );
}

#[cfg(all(target_os = "linux", feature = "keyring-secret-service"))]
#[test]
fn explicit_secret_service_feature_constructs_backend() {
    assert!(open("tinysecurity-test", Backend::SecretService).is_ok());
}

// Real platform credential store (macOS Keychain, Windows Credential Manager,
// Linux kernel keyring). TINYSECURITY_REQUIRE_OS_KEYRING=1 makes an unavailable
// store a failure; otherwise it is reported and skipped. The entry is always
// removed, even when an assertion fails.
struct Cleanup(Arc<dyn SecretStore>, String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let store = Arc::clone(&self.0);
        let name = self.1.clone();
        // Drop may run inside a runtime; clean up on a separate thread.
        let _ = std::thread::spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                let _ = runtime.block_on(store.delete(&name));
            }
        })
        .join();
    }
}

#[tokio::test]
async fn os_keyring_round_trip_cleans_up() -> TestResult {
    let required = std::env::var("TINYSECURITY_REQUIRE_OS_KEYRING").is_ok_and(|v| v == "1");
    let service = unique("svc")?;
    let name = format!("user:{}", unique("entry")?);
    let store = open(&service, Backend::Os)?;
    let _cleanup = Cleanup(Arc::clone(&store), name.clone());
    if let Err(error) = store.set(&name, b"os-secret").await {
        if required {
            return Err(format!("OS keyring required but unavailable: {:?}", error.kind()).into());
        }
        eprintln!("skipping: OS keyring unavailable ({:?})", error.kind());
        return Ok(());
    }
    assert_eq!(
        store.get(&name).await?.as_deref().map(Vec::as_slice),
        Some(b"os-secret".as_slice())
    );
    assert!(store.delete(&name).await?);
    assert!(store.get(&name).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn encrypted_file_services_in_one_directory_are_isolated() -> TestResult {
    let dir = std::env::temp_dir().canonicalize()?.join(unique("shared")?);
    std::fs::create_dir_all(&dir)?;
    let first = open("service-one", Backend::EncryptedFile(dir.clone()))?;
    let second = open("service-two", Backend::EncryptedFile(dir.clone()))?;
    first.set("user:shared-name", b"one").await?;
    assert!(second.get("user:shared-name").await?.is_none());
    assert!(!second.delete("user:shared-name").await?);
    assert_eq!(
        first
            .get("user:shared-name")
            .await?
            .as_deref()
            .map(Vec::as_slice),
        Some(b"one".as_slice())
    );
    assert_eq!(
        open("", Backend::EncryptedFile(dir.clone())).err(),
        Some(Error::InvalidInput)
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
