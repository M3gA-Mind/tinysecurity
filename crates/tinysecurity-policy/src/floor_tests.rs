use super::*;

#[test]
fn concrete_credential_roots_keep_home_none_isolated_and_resolve_native_paths()
-> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    assert_eq!(credential_roots(None)?, Vec::<PathBuf>::new());
    let home = tempfile::tempdir()?;
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh)?;
    let aws = home.path().join(".aws");
    fs::create_dir(&aws)?;
    fs::write(home.path().join(".netrc"), "fixture")?;
    let roots = credential_roots(Some(home.path()))?;
    assert!(roots.contains(&fs::canonicalize(&ssh)?));
    assert!(roots.contains(&fs::canonicalize(&aws)?));
    assert!(roots.contains(&home.path().join(".netrc")));
    assert!(roots.iter().all(|root| root.is_absolute()));
    assert!(roots.len() <= tinysecurity_bus::MAX_CREDENTIAL_ROOTS);

    #[cfg(target_os = "macos")]
    {
        let keychains = home.path().join("Library/Keychains");
        fs::create_dir_all(&keychains)?;
        let roots = credential_roots(Some(home.path()))?;
        assert!(roots.contains(&fs::canonicalize(keychains)?));
    }

    #[cfg(windows)]
    {
        let protect = home.path().join("AppData/Roaming/Microsoft/Protect");
        fs::create_dir_all(&protect)?;
        let roots = credential_roots(Some(home.path()))?;
        assert!(roots.contains(&fs::canonicalize(protect)?));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn credential_roots_include_symlink_alias_and_target_and_fail_closed_on_dangling_links()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let home = tempfile::tempdir()?;
    let target = home.path().join("credential-target");
    std::fs::create_dir(&target)?;
    let alias = home.path().join(".ssh");
    symlink(&target, &alias)?;
    let roots = credential_roots(Some(home.path()))?;
    assert!(roots.contains(&alias));
    assert!(roots.contains(&std::fs::canonicalize(target)?));

    let dangling_home = tempfile::tempdir()?;
    symlink(
        dangling_home.path().join("missing"),
        dangling_home.path().join(".ssh"),
    )?;
    assert!(credential_roots(Some(dangling_home.path())).is_err());
    Ok(())
}

#[test]
fn credential_roots_reject_relative_and_non_directory_homes()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(credential_roots(Some(Path::new("relative-home"))).is_err());
    let file = tempfile::NamedTempFile::new()?;
    assert!(credential_roots(Some(file.path())).is_err());
    Ok(())
}

#[test]
fn windows_credential_candidates_preserve_native_casing_and_match_floor_pairs() {
    let root = Path::new("C:/Users/fixture");
    let candidates = super::windows_credential_candidates(root);
    let stores = ["Protect", "Credentials", "Crypto", "Vault", "Ngc"];
    for app_data in ["AppData/Roaming", "AppData/Local"] {
        for store in stores {
            assert!(
                candidates.contains(&root.join(app_data).join("Microsoft").join(store)),
                "missing native path for {app_data}/Microsoft/{store}"
            );
            assert!(
                CREDENTIAL_PAIRS.iter().any(|&(parent, child)| {
                    parent == "microsoft" && child == store.to_ascii_lowercase()
                }),
                "{store} has no lowercased floor pair"
            );
        }
    }
}
use std::path::PathBuf;

fn floor(path: &str) -> bool {
    lexical_floor(&PathBuf::from(path))
}

#[test]
fn floor_covers_credentials_system_roots_traversal_and_nul() {
    for path in [
        "/home/u/.ssh/id_rsa",
        "/home/u/.AWS/credentials",
        "/home/u/.netrc",
        "/home/u/.docker/config.json",
        "/etc/passwd",
        "/usr/bin/env",
        "/bin",
        "/dev/null",
        "/private/etc/hosts",
        "/work/../x",
        "/work/a\0b",
        r"C:\Windows\System32",
        r"\\?\C:\Program Files\x",
        "D:/ProgramData/x",
    ] {
        assert!(floor(path), "{path}");
    }
}

#[test]
fn floor_protects_windows_ngc_credentials_at_any_depth() {
    assert!(floor("/home/u/AppData/Local/Microsoft/Ngc/secret"));
    assert!(floor(r"C:\Users\u\AppData\Local\Microsoft\Ngc\secret"));
}

#[test]
fn floor_leaves_ordinary_paths_alone() {
    for path in [
        "/home/u/project/src/main.rs",
        "/tmp/x",
        "relative/file",
        "/usrx/a",
    ] {
        assert!(!floor(path), "{path}");
    }
}

#[test]
fn every_vocabulary_entry_is_recognised_by_the_floor() {
    let vocabulary = floor_vocabulary();
    assert!(!vocabulary.components.is_empty() && !vocabulary.files.is_empty());
    for name in vocabulary.components.iter().chain(&vocabulary.files) {
        assert!(floor(&format!("/home/u/{name}")), "{name}");
        assert!(
            floor(&format!("/home/u/{}/deep", name.to_uppercase())),
            "{name}"
        );
    }
    for [parent, child] in &vocabulary.pairs {
        assert!(
            floor(&format!("/home/u/{parent}/{child}")),
            "{parent}/{child}"
        );
    }
    for prefix in &vocabulary.prefixes {
        assert!(prefix.starts_with('/') || prefix.as_bytes().get(1) == Some(&b':'));
        assert_eq!(prefix, &prefix.to_lowercase());
        assert!(floor(prefix), "{prefix}");
        assert!(floor(&format!("{prefix}/child/leaf")), "{prefix}");
    }
}

#[test]
fn vocabulary_splits_directories_from_files_and_keeps_every_constant() {
    let vocabulary = floor_vocabulary();
    for name in [
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".oci",
        ".kube",
        "keychains",
    ] {
        assert!(vocabulary.components.iter().any(|c| c == name), "{name}");
    }
    for name in [".netrc", ".git-credentials", ".pgpass", ".npmrc"] {
        assert!(vocabulary.files.iter().any(|c| c == name), "{name}");
    }
    assert_eq!(
        vocabulary.components.len() + vocabulary.files.len(),
        CREDENTIAL_COMPONENTS.len()
    );
    assert_eq!(vocabulary.pairs.len(), CREDENTIAL_PAIRS.len());
    for prefix in [
        "/etc",
        "/root",
        "/boot",
        "/proc",
        "/sys",
        "/system",
        "/private/etc",
        "/private/var/root",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/usr",
        "/library",
        "/dev",
        "c:/windows",
        "c:/program files",
        "c:/program files (x86)",
        "c:/programdata",
    ] {
        assert!(vocabulary.prefixes.iter().any(|p| p == prefix), "{prefix}");
    }
}

#[test]
fn file_store_subset_stays_within_credential_components() {
    for name in CREDENTIAL_FILE_STORES {
        assert!(CREDENTIAL_COMPONENTS.contains(name), "{name}");
    }
}

#[test]
fn windows_normalized_parent_segments_count_as_traversal() {
    for path in [
        r"C:\safe\.. \Windows\System32",
        r"C:\safe\..\Windows",
        r"C:\safe\... \x",
        r"C:\safe\.. . \x",
        "/work/.. /etc/passwd",
        "/work/.../x",
    ] {
        assert!(floor(path), "{path:?}");
        assert!(crate::protected_path(&PathBuf::from(path)), "{path:?}");
    }
    // Ordinary names that merely contain dots stay usable.
    for path in [
        "/work/my..file.txt",
        "/work/.hidden",
        "/work/a. b",
        "/work/.config.d",
    ] {
        assert!(!floor(path), "{path:?}");
    }
}
