//! Behaviour the host's own path helpers once pinned (injection, traversal, system
//! roots, workspace-internal state, trusted roots, disabled policy), restated against
//! the module's registered scopes. Host-supplied vocabulary (forbidden lists, state
//! reservations) is passed in the policy; the module has no built-in names for it.
use super::*;
use tinysecurity_bus::{PathPolicy, PathReservation, PathReservedPrefix, PathTrustedRoot};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn policy(workspace: &Path, action: &Path) -> PathPolicy {
    PathPolicy {
        enabled: true,
        workspace_only: true,
        workspace_dir: workspace.into(),
        action_dir: action.into(),
        home_dir: Some(workspace.join("home")),
        forbidden_paths: vec![],
        trusted_roots: vec![],
        reserved_paths: vec![],
        reserved_prefixes: vec![],
        readonly_paths: vec![],
        reserved_names: vec![],
    }
}

fn scope_of(policy: PathPolicy) -> Result<std::sync::Arc<PathScope>, Box<dyn std::error::Error>> {
    let mut registry = crate::PathPolicyRegistry::default();
    let id = registry.register(policy)?;
    Ok(registry.get_owned(&id)?)
}

fn string_ok(scope: &PathScope, path: &str) -> bool {
    scope.check_path(Path::new(path), PathCheckKind::StringAllowed)
}

fn root() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let base = dir.path().canonicalize()?;
    Ok((dir, base))
}

#[test]
fn injection_shaped_strings_are_refused_and_double_dots_in_names_are_not() -> TestResult {
    let (_dir, base) = root()?;
    let scope = scope_of(policy(&base, &base))?;
    assert!(string_ok(&scope, "my..file.txt"));
    assert!(string_ok(&scope, "relative/path.txt"));
    for bad in [
        "foo/..%2f..%2fetc/passwd",
        "..%2fetc%2fpasswd",
        "subdir%2f..%2f..%2fetc",
        "../etc/passwd",
        "foo/../etc/passwd",
        "file\0.txt",
        "\0",
        "file\0",
        "safe\0/../../../etc/passwd",
        "/proc/self/root/etc/passwd",
        "~/.ssh/id_rsa",
        "~/.gnupg/secring.gpg",
        "~/.aws/credentials",
    ] {
        assert!(!string_ok(&scope, bad), "{bad:?}");
    }
    Ok(())
}

#[test]
fn workspace_only_blocks_absolute_paths_and_root_and_system_dirs() -> TestResult {
    let (_dir, base) = root()?;
    let scope = scope_of(policy(&base, &base))?;
    assert!(!string_ok(&scope, "/"));
    assert!(!string_ok(&scope, "/any/absolute/path"));
    for dir in [
        "/etc", "/root", "/home", "/usr", "/bin", "/sbin", "/lib", "/opt", "/boot", "/dev",
        "/proc", "/sys", "/var", "/tmp",
    ] {
        assert!(!string_ok(&scope, dir), "{dir}");
        assert!(
            !string_ok(&scope, &format!("{dir}/subpath")),
            "{dir}/subpath"
        );
    }
    Ok(())
}

#[test]
fn host_supplied_forbidden_list_blocks_system_dirs_without_workspace_only() -> TestResult {
    let (_dir, base) = root()?;
    let mut open = policy(&base, &base);
    open.workspace_only = false;
    open.forbidden_paths = ["/home", "/opt", "/var", "/tmp", "/usr", "~/.config"]
        .map(String::from)
        .to_vec();
    open.forbidden_paths.push("~/.ssh".into());
    let scope = scope_of(open)?;
    for path in [
        "/opt/tool/x",
        "/etc/shadow",
        "/root/.bashrc",
        "/usr/bin/env",
    ] {
        assert!(!string_ok(&scope, path), "{path}");
    }
    assert!(!string_ok(&scope, "~/.config/secrets"));
    assert!(!string_ok(&scope, "~/.ssh/id_rsa"));
    Ok(())
}

#[test]
fn sensitive_files_and_directories_are_refused_case_insensitively() {
    for path in [
        "/home/u/.npmrc",
        "/home/u/.NETRC",
        "/home/u/.git-credentials",
        "/home/u/.pgpass",
        "/home/u/.SSH/id_rsa",
        "/home/u/.Gnupg/x",
        "/home/u/.AWS/credentials",
        "/home/u/.kube/config",
        "/home/u/.azure/x",
        "/home/u/.oci/config",
        "/home/u/.OCI/oci_api_key.pem",
        "C:\\Users\\u\\.oci\\oci_api_key.pem",
        "/home/u/.docker/config.json",
        "/home/u/.cargo/credentials.toml",
        "/Users/u/Library/Keychains/login.keychain-db",
        "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Credentials\\x",
        "C:\\Windows\\System32\\config",
        "c:/program files/x",
    ] {
        assert!(protected_path(Path::new(path)), "{path}");
    }
    assert!(!protected_path(Path::new("/home/u/project/notes.txt")));
}

#[test]
fn relative_paths_resolve_under_the_action_dir_not_the_workspace() -> TestResult {
    let (_dir, base) = root()?;
    let workspace = base.join("state");
    let action = base.join("action");
    std::fs::create_dir_all(&workspace)?;
    std::fs::create_dir_all(&action)?;
    std::fs::write(action.join("here.txt"), "x")?;
    let mut policy = policy(&workspace, &action);
    policy.workspace_only = false;
    policy.trusted_roots = vec![PathTrustedRoot {
        path: action.clone(),
        access: PathAccess::ReadWrite,
    }];
    let scope = scope_of(policy)?;
    assert_eq!(
        scope.validate("here.txt", false),
        PathValidationResult::Allowed {
            resolved: action.join("here.txt")
        }
    );
    assert!(!matches!(
        scope.validate("state-only.txt", false),
        PathValidationResult::Allowed { .. }
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn resolved_checks_block_symlink_escapes_and_links_into_forbidden_trees() -> TestResult {
    let (_dir, base) = root()?;
    let workspace = base.join("ws");
    let outside = base.join("outside");
    let secrets = workspace.join("secrets");
    for dir in [&workspace, &outside, &secrets] {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(outside.join("secret.txt"), "s")?;
    std::fs::write(secrets.join("token.txt"), "s")?;
    std::os::unix::fs::symlink(outside.join("secret.txt"), workspace.join("link.txt"))?;
    std::os::unix::fs::symlink(&outside, workspace.join("subdir"))?;
    std::os::unix::fs::symlink(&secrets, workspace.join("to-secrets"))?;
    std::os::unix::fs::symlink("/etc/hostname", workspace.join("to-etc"))?;
    std::fs::write(workspace.join("data.txt"), "hello")?;
    let mut policy = policy(&workspace, &workspace);
    policy.forbidden_paths = vec!["secrets".into(), "/etc".into()];
    let scope = scope_of(policy)?;
    let blocked = |path: &str, parent: bool| {
        !matches!(
            scope.validate(path, parent),
            PathValidationResult::Allowed { .. }
        )
    };
    assert!(blocked("link.txt", false));
    assert!(blocked("subdir/newfile.txt", true));
    assert!(blocked("to-secrets/token.txt", false));
    assert!(blocked("to-etc", false));
    assert!(blocked("does_not_exist.txt", false));
    assert_eq!(
        scope.validate("data.txt", false),
        PathValidationResult::Allowed {
            resolved: workspace.join("data.txt")
        }
    );
    assert!(matches!(
        scope.validate("newfile.txt", true),
        PathValidationResult::Allowed { .. }
    ));
    assert!(!scope.check_path(&workspace.join("link.txt"), PathCheckKind::ResolvedRead));
    assert!(!scope.check_path(&base.join("outside/x"), PathCheckKind::ResolvedWrite));
    assert!(scope.check_path(&workspace.join("src/main.rs"), PathCheckKind::ResolvedRead));
    assert!(!scope.check_path(Path::new("/"), PathCheckKind::ResolvedRead));
    Ok(())
}

fn internal_scope(
    base: &Path,
) -> Result<(PathBuf, std::sync::Arc<PathScope>), Box<dyn std::error::Error>> {
    let account = base.join("users/u1");
    let workspace = account.join("workspace");
    std::fs::create_dir_all(workspace.join("artifacts/abc"))?;
    std::fs::create_dir_all(workspace.join("artifacts/tool-results/s1"))?;
    std::fs::create_dir_all(workspace.join("memory"))?;
    std::fs::create_dir_all(workspace.join("personalities/alice"))?;
    std::fs::create_dir_all(workspace.join("projects/app"))?;
    std::fs::write(account.join("config.toml"), "x")?;
    std::fs::write(account.join("notes.txt"), "hello")?;
    std::fs::write(workspace.join("artifacts/abc/meta.json"), "{}")?;
    std::fs::write(workspace.join("artifacts/tool-results/s1/call-1.txt"), "o")?;
    std::fs::write(workspace.join("personalities/alice/SOUL.md"), "private")?;
    let mut policy = policy(&workspace, &workspace);
    policy.workspace_only = false;
    policy.trusted_roots = vec![PathTrustedRoot {
        path: account.clone(),
        access: PathAccess::ReadWrite,
    }];
    policy.reserved_paths = vec![
        PathReservation {
            path: workspace.join("artifacts"),
            children_only: true,
            exceptions: vec![workspace.join("artifacts/tool-results")],
        },
        PathReservation {
            path: workspace.join("memory"),
            children_only: false,
            exceptions: vec![],
        },
        PathReservation {
            path: workspace.join("personalities"),
            children_only: false,
            exceptions: vec![],
        },
        PathReservation {
            path: workspace.join("core.token"),
            children_only: false,
            exceptions: vec![],
        },
        PathReservation {
            path: account.join("config.toml"),
            children_only: false,
            exceptions: vec![],
        },
    ];
    policy.reserved_prefixes = vec![
        PathReservedPrefix {
            root: workspace.clone(),
            prefix: "memory-".into(),
        },
        PathReservedPrefix {
            root: workspace.clone(),
            prefix: "session_raw-".into(),
        },
    ];
    Ok((account, scope_of(policy)?))
}

#[test]
fn workspace_state_is_internal_but_projects_and_tool_results_are_not() -> TestResult {
    let (_dir, base) = root()?;
    let (account, scope) = internal_scope(&base)?;
    let ws = account.join("workspace");
    for internal in [
        ws.join("memory"),
        ws.join("memory/namespaces"),
        ws.join("memory-alice/memory.db"),
        ws.join("session_raw-alice/1700000000_orchestrator.jsonl"),
        ws.join("personalities/alice/SOUL.md"),
        ws.join("personalities/alice/skills/private/SKILL.md"),
        ws.join("core.token"),
        ws.join("artifacts/abc/meta.json"),
        ws.join("artifacts/abc/args.json"),
        account.join("config.toml"),
    ] {
        assert!(scope.internal(&internal), "{}", internal.display());
        assert!(scope.check_path(&internal, PathCheckKind::Internal));
        assert!(
            !string_ok(&scope, &internal.to_string_lossy()),
            "{}",
            internal.display()
        );
        // `TrustedRead` is pure containment; internal state is refused by the string and
        // validation checks above and below, which is where hosts must ask.
        assert!(!scope.check_path(&internal, PathCheckKind::ResolvedRead));
    }
    for open in [
        ws.join("projects"),
        ws.join("projects/app"),
        ws.join("artifacts/tool-results/s1/call-1.txt"),
        account.join("notes.txt"),
        ws.join("memoryx"),
    ] {
        assert!(!scope.internal(&open), "{}", open.display());
    }
    assert!(string_ok(
        &scope,
        &ws.join("artifacts/tool-results/s1/call-1.txt")
            .to_string_lossy()
    ));
    assert!(matches!(
        scope.validate(
            &ws.join("artifacts/tool-results/s1/call-1.txt")
                .to_string_lossy(),
            false
        ),
        PathValidationResult::Allowed { .. }
    ));
    // A trusted root over the account dir never exposes internal state.
    for internal in [
        ws.join("personalities/alice/SOUL.md"),
        account.join("config.toml"),
    ] {
        assert!(!matches!(
            scope.validate(&internal.to_string_lossy(), false),
            PathValidationResult::Allowed { .. }
        ));
        assert!(!matches!(
            scope.validate(&internal.to_string_lossy(), true),
            PathValidationResult::Allowed { .. }
        ));
    }
    assert!(!matches!(
        scope.validate(
            &ws.join("session_raw-alice/new.jsonl").to_string_lossy(),
            true
        ),
        PathValidationResult::Allowed { .. }
    ));
    assert!(matches!(
        scope.validate(&account.join("notes.txt").to_string_lossy(), false),
        PathValidationResult::Allowed { .. }
    ));
    Ok(())
}

#[test]
fn trusted_roots_never_reach_credential_stores_and_respect_access() -> TestResult {
    let (_dir, base) = root()?;
    let granted = base.join("granted");
    std::fs::create_dir_all(granted.join(".ssh"))?;
    std::fs::write(granted.join(".ssh/id_rsa"), "k")?;
    std::fs::write(granted.join(".npmrc"), "t")?;
    std::fs::write(granted.join("ok.txt"), "o")?;
    let workspace = base.join("ws");
    std::fs::create_dir_all(&workspace)?;
    let mut read_only = policy(&workspace, &workspace);
    read_only.trusted_roots = vec![PathTrustedRoot {
        path: granted.clone(),
        access: PathAccess::ReadOnly,
    }];
    let scope = scope_of(read_only)?;
    assert!(scope.check_path(&granted.join("ok.txt"), PathCheckKind::TrustedRead));
    assert!(!scope.check_path(&granted.join("ok.txt"), PathCheckKind::TrustedWrite));
    assert!(scope.check_path(&granted.join("ok.txt"), PathCheckKind::ResolvedRead));
    assert!(!scope.check_path(&granted.join("ok.txt"), PathCheckKind::ResolvedWrite));
    for secret in [granted.join(".ssh/id_rsa"), granted.join(".npmrc")] {
        for kind in [
            PathCheckKind::TrustedRead,
            PathCheckKind::ResolvedRead,
            PathCheckKind::StringAllowed,
        ] {
            assert!(
                !scope.check_path(&secret, kind),
                "{kind:?} {}",
                secret.display()
            );
        }
        assert!(scope.check_path(&secret, PathCheckKind::Protected));
    }
    Ok(())
}

#[test]
fn disabled_policy_keeps_the_floor_and_nothing_discretionary() -> TestResult {
    let (_dir, base) = root()?;
    let mut off = policy(&base.join("ws"), &base.join("act"));
    off.enabled = false;
    let elsewhere = base.join("somewhere");
    off.forbidden_paths = vec![elsewhere.to_string_lossy().into_owned()];
    let scope = scope_of(off)?;
    assert!(string_ok(
        &scope,
        &elsewhere.join("else/notes.md").to_string_lossy()
    ));
    for path in [
        "/home/u/.ssh/id_rsa",
        "/home/u/.gnupg/secring.gpg",
        "/home/u/.aws/credentials",
        "/etc/shadow",
        "/root/.bashrc",
        "../../etc/passwd",
        "out/note\0.md",
    ] {
        assert!(!string_ok(&scope, path), "{path}");
        assert!(
            !scope.check_path(Path::new(path), PathCheckKind::ResolvedRead),
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn floor_is_never_bypassed_by_prefixing_or_suffixing() -> TestResult {
    let (_dir, base) = root()?;
    let mut open = policy(&base, &base);
    open.enabled = false;
    let scope = scope_of(open)?;
    let cores = [
        "/etc/passwd",
        "/root/.bashrc",
        "/home/u/.ssh/id_rsa",
        "/home/u/.aws/credentials",
    ];
    for core in cores {
        assert!(protected_path(Path::new(core)), "{core}");
        assert!(
            !scope.check_path(Path::new(core), PathCheckKind::StringAllowed),
            "{core}"
        );
        for suffix in ["", "/", "/x", "/x/../y", "\0", "/.."] {
            let path = format!("{core}{suffix}");
            assert!(
                !scope.check_path(Path::new(&path), PathCheckKind::StringAllowed),
                "{path:?}"
            );
        }
        for prefix in ["/./", "//", "/x/..", "/proc/self/root"] {
            let path = format!("{prefix}{core}");
            assert!(
                !scope.check_path(Path::new(&path), PathCheckKind::StringAllowed),
                "{path:?}"
            );
        }
    }
    // Arbitrary text never panics.
    for text in [
        "",
        ".",
        "..",
        "~",
        "\\",
        "é/ü",
        "a\u{202e}b",
        "%00",
        "\u{0}",
    ] {
        let _ = scope.check_path(Path::new(text), PathCheckKind::StringAllowed);
        let _ = protected_path(Path::new(text));
    }
    Ok(())
}

#[test]
fn installation_roots_are_host_configurable_for_acting_scopes_but_in_the_unscoped_floor()
-> TestResult {
    let (_dir, base) = root()?;
    let mut open = policy(&base, &base);
    open.workspace_only = false;
    let scope = scope_of(open)?;
    // The acting scope leaves /usr to the host's forbidden list (documented on
    // `protected_path`), while the unscoped floor (`ProtectedPath2`) includes it.
    assert!(!scope.check_path(Path::new("/usr/bin/env"), PathCheckKind::Protected));
    assert!(crate::lexical_floor(Path::new("/usr/bin/env")));
    Ok(())
}
