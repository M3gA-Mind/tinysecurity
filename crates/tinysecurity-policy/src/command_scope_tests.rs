use super::*;
use tinysecurity_bus::CommandPolicyId;
fn policy(enabled: bool, autonomy: CommandAutonomy) -> std::io::Result<CommandPolicy> {
    Ok(CommandPolicy {
        enabled,
        autonomy,
        execution_mode: CommandExecutionMode::HarnessGated,
        shell_dialect: tinysecurity_bus::ShellDialect::Posix,
        allowed_commands: ["ls", "cat", "git", "echo", "find", "date"]
            .map(str::to_string)
            .to_vec(),
        max_actions_per_hour: 2,
        require_approval_for_medium_risk: true,
        block_high_risk_commands: true,
        action_dir: std::env::current_dir()?,
        home_dir: None,
    })
}
type GateDecision = CommandGate;
struct Characterization(CommandScope);
impl Characterization {
    fn classify_command(&self, command: &str) -> Result<CommandClass> {
        self.0
            .classify(&CommandRequest {
                policy_id: CommandPolicyId(String::new()),
                command: command.into(),
                declared_class: None,
            })
            .map(|decision| decision.class)
    }
    fn gate_decision(&self, class: CommandClass) -> CommandGate {
        self.0.gate(class)
    }
    fn is_command_allowed(&self, command: &str) -> bool {
        self.0.is_command_allowed(command)
    }
}
fn default_policy() -> std::result::Result<Characterization, Box<dyn std::error::Error>> {
    Ok(Characterization(CommandScope::new(policy(
        true,
        CommandAutonomy::Supervised,
    )?)?))
}
fn readonly_policy() -> std::result::Result<Characterization, Box<dyn std::error::Error>> {
    Ok(Characterization(CommandScope::new(policy(
        true,
        CommandAutonomy::ReadOnly,
    )?)?))
}
fn full_policy() -> std::result::Result<Characterization, Box<dyn std::error::Error>> {
    Ok(Characterization(CommandScope::new(policy(
        true,
        CommandAutonomy::Full,
    )?)?))
}

#[test]
fn classify_reads_are_read() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    for c in [
        "ls -la",
        "cat f",
        "grep x f",
        "git status",
        "git log --oneline",
        "pwd",
        "wc -l f",
        "head f",
        "find . -name '*.rs'",
        "cargo tree",
        "npm ls",
        "dir",
        "type f.txt",
        "Get-Content f",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Read, "{c}");
    }
    Ok(())
}

#[test]
fn command_vocabulary_matches_host_policy_regressions()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    for (command, expected) in [
        ("printf '%s\\n' hi", CommandClass::Read),
        ("php -r 'echo 1;'", CommandClass::Write),
        ("lua -e 'print(1)'", CommandClass::Write),
        ("env FOO=1 curl https://example.test", CommandClass::Network),
        ("timeout 5 ls", CommandClass::Read),
        ("nohup env FOO=1 sudo reboot", CommandClass::Destructive),
        ("nice -n 5 curl https://example.test", CommandClass::Network),
        ("command curl https://example.test", CommandClass::Network),
        ("exec curl https://example.test", CommandClass::Network),
        ("time curl https://example.test", CommandClass::Network),
        (
            "stdbuf -oL curl https://example.test",
            CommandClass::Network,
        ),
        ("xargs -I{} curl {}", CommandClass::Network),
        ("c''url https://example.test", CommandClass::Network),
        ("env -S 'curl https://example.test'", CommandClass::Network),
        ("env -S'ls -la'", CommandClass::Write),
        ("GIT_CONFIG_COUNT=1 git status", CommandClass::Write),
        ("PATH=/tmp git status", CommandClass::Write),
        ("GIT_PAGER=cat git status", CommandClass::Write),
        ("git remote -v", CommandClass::Read),
        (
            "git remote add origin https://example.test",
            CommandClass::Write,
        ),
        ("git remote remove origin", CommandClass::Write),
        (
            "git remote set-url origin https://example.test",
            CommandClass::Write,
        ),
        ("git remote update", CommandClass::Write),
        ("git reflog expire --all", CommandClass::Write),
        ("git reflog delete HEAD@{1}", CommandClass::Write),
        ("git --config-env=key=ENV status", CommandClass::Write),
        ("git --config-env key=ENV status", CommandClass::Write),
        ("git diff --output=/tmp/diff", CommandClass::Write),
        ("git diff --output /tmp/diff", CommandClass::Write),
        ("git log --output=/tmp/log", CommandClass::Write),
        ("git log --output /tmp/log", CommandClass::Write),
        ("git diff --ext-diff", CommandClass::Write),
        ("npm audit", CommandClass::Read),
        ("npm audit fix", CommandClass::Write),
        ("pnpm audit fix", CommandClass::Write),
        ("yarn audit fix", CommandClass::Write),
        ("rg --pre cat pattern", CommandClass::Write),
        ("tree -o /tmp/tree", CommandClass::Write),
        ("hostname -F /tmp/hostname", CommandClass::Write),
        ("hostname example.test", CommandClass::Write),
        ("find . '-fprint' /tmp/list", CommandClass::Write),
        // `&>` is a Bash output redirect; `${HOME}` is structurally denied.
        ("printf hi &>out.txt", CommandClass::Write),
        ("echo ${HOME}", CommandClass::Read),
    ] {
        assert_eq!(p.classify_command(command)?, expected, "{command}");
    }
    #[cfg(windows)]
    let protected_file_url = "file:///C:/Users/test/.ssh/id_ed25519";
    #[cfg(not(windows))]
    let protected_file_url = "file:///home/test/.ssh/id_ed25519";
    let file_url = p.0.classify(&CommandRequest {
        policy_id: CommandPolicyId(String::new()),
        command: format!("cat {protected_file_url}"),
        declared_class: None,
    })?;
    assert_eq!(file_url.gate, CommandGate::Block);
    assert_eq!(file_url.denial, Some(CommandDenial::Protected));
    let dollar_expansion = p.0.evaluate(&CommandRequest {
        policy_id: CommandPolicyId(String::new()),
        command: "echo ${HOME}".into(),
        declared_class: None,
    })?;
    assert_eq!(dollar_expansion.denial, Some(CommandDenial::Command));
    let amp_redirect = p.0.evaluate(&CommandRequest {
        policy_id: CommandPolicyId(String::new()),
        command: "printf hi &>out.txt".into(),
        declared_class: None,
    })?;
    assert_eq!(amp_redirect.class, CommandClass::Write);
    assert_eq!(amp_redirect.denial, None);
    Ok(())
}

#[test]
fn matches_openhuman_command_class_corpus() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/openhuman_security_command_corpus.json"
    ))?;
    let rows = corpus.as_array().ok_or("corpus must be an array")?;
    let mut checked = 0;
    for row in rows {
        if row.get("op").and_then(serde_json::Value::as_str) != Some("class") {
            continue;
        }
        let command = row
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or("class row needs command")?;
        let expected = match row
            .get("expect")
            .and_then(serde_json::Value::as_str)
            .ok_or("class row needs expected class")?
        {
            "Read" => CommandClass::Read,
            "Write" => CommandClass::Write,
            "Network" => CommandClass::Network,
            "Install" => CommandClass::Install,
            "Destructive" => CommandClass::Destructive,
            other => return Err(format!("unknown command class {other}").into()),
        };
        assert_eq!(p.classify_command(command)?, expected, "{command}");
        checked += 1;
    }
    assert_eq!(
        checked, 13,
        "update parity corpus count when host corpus changes"
    );
    Ok(())
}

#[test]
fn classify_unknown_is_write_fail_closed() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // The whole point: a command we don't recognize is NOT treated as read.
    assert_eq!(p.classify_command("./deploy.sh")?, CommandClass::Write);
    assert_eq!(
        p.classify_command("some-random-binary --go")?,
        CommandClass::Write
    );
    assert_eq!(p.classify_command("git")?, CommandClass::Write); // bare git
    Ok(())
}

#[test]
fn classify_writes_are_write() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    for c in [
        "touch f",
        "mkdir d",
        "mv a b",
        "rm -rf build",
        "git commit -m x",
        "git push",
        "npm install",
        "cargo build",
        "node script.js",
        "python3 x.py",
        "bash -lc 'id'",
        "Remove-Item x",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Write, "{c}");
    }
    Ok(())
}

#[test]
fn classify_find_file_write_actions_are_write()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // -fprintf / -fprint / -fprint0 / -fls write find's output to a named
    // file (an arbitrary-path write side-channel), so they must be gated as
    // Write rather than slipping through as a read-only search.
    for c in [
        "find . -maxdepth 0 -fprintf /tmp/out.txt '%p\\n'",
        "find . -name '*.rs' -fprint /tmp/list.txt",
        "find . -fprint0 /tmp/list0.txt",
        "find . -fls /tmp/ls.txt",
        "find . -delete",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Write, "{c}");
    }
    // Quoting the predicate must not slip the write past the gate — the shell
    // strips the quotes before find runs, so `'-fprint'` is the same write.
    for c in [
        "find . '-fprint' /tmp/list.txt",
        "find . \"-fprintf\" /tmp/out.txt '%p\\n'",
        "find . '-delete'",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Write, "{c}");
    }
    // A plain search stays read-only.
    assert_eq!(
        p.classify_command("find . -name '*.rs' -print")?,
        CommandClass::Read
    );
    Ok(())
}

#[test]
fn classify_network_is_network() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    for c in [
        "curl http://x",
        "wget http://x",
        "ssh host",
        "scp a b",
        "nc -l 1",
        "Invoke-WebRequest http://x",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Network, "{c}");
    }
    Ok(())
}

#[test]
fn classify_destructive_is_destructive() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    for c in [
        "sudo rm f",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs /dev/sda1",
        "shutdown -h now",
        "rm -rf /",
        "format C:",
        "diskpart",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Destructive, "{c}");
    }
    Ok(())
}

#[test]
fn classify_highest_segment_wins() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert_eq!(
        p.classify_command("ls | curl http://x")?,
        CommandClass::Network
    );
    assert_eq!(
        p.classify_command("cat f && sudo reboot")?,
        CommandClass::Destructive
    );
    assert_eq!(p.classify_command("ls && mkdir d")?, CommandClass::Write);
    Ok(())
}

#[test]
fn classify_redirect_lifts_read_to_write() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // `cat` is read, but the redirect writes a file.
    assert_eq!(p.classify_command("cat f")?, CommandClass::Read);
    assert_eq!(p.classify_command("cat f > out.txt")?, CommandClass::Write);
    assert_eq!(
        p.classify_command("echo hi | tee out.txt")?,
        CommandClass::Write
    );
    Ok(())
}

#[test]
fn gate_decision_readonly_blocks_acts() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = readonly_policy()?;
    assert_eq!(p.gate_decision(CommandClass::Read), GateDecision::Allow);
    assert_eq!(p.gate_decision(CommandClass::Write), GateDecision::Block);
    assert_eq!(p.gate_decision(CommandClass::Network), GateDecision::Block);
    assert_eq!(
        p.gate_decision(CommandClass::Destructive),
        GateDecision::Block
    );
    Ok(())
}

#[test]
fn gate_decision_supervised_prompts_every_act()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?; // Supervised
    assert_eq!(p.gate_decision(CommandClass::Read), GateDecision::Allow);
    assert_eq!(p.gate_decision(CommandClass::Write), GateDecision::Prompt);
    assert_eq!(p.gate_decision(CommandClass::Network), GateDecision::Prompt);
    assert_eq!(
        p.gate_decision(CommandClass::Destructive),
        GateDecision::Prompt
    );
    Ok(())
}

#[test]
fn gate_decision_full_runs_write_but_prompts_network_and_destructive()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = full_policy()?;
    assert_eq!(p.gate_decision(CommandClass::Read), GateDecision::Allow);
    assert_eq!(p.gate_decision(CommandClass::Write), GateDecision::Allow);
    assert_eq!(p.gate_decision(CommandClass::Network), GateDecision::Prompt);
    assert_eq!(
        p.gate_decision(CommandClass::Destructive),
        GateDecision::Prompt
    );
    Ok(())
}

// -- install chokepoint (Phase C) ---------------------------------

#[test]
fn classify_installs_are_install_bucket() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    for c in [
        "apt install jq",
        "apt-get install -y curl",
        "brew install ripgrep",
        "pacman -S vim",
        "pacman -Sy",
        "pacman -Syu",
        "apk add bash",
        "dnf install nginx",
        "pip install requests",
        "pip3 install x",
        "pipx install black",
        "gem install rails",
        "cargo install ripgrep",
        "go install ./cmd/x",
        "npm install -g typescript",
        "pnpm add -g eslint",
        "yarn global add prettier",
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Install, "{c}");
    }
    Ok(())
}

#[test]
fn classify_local_installs_are_write_not_install()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // Project-local installs are ordinary writes (run in Full), not the
    // host-modifying Install bucket.
    assert_eq!(p.classify_command("npm install")?, CommandClass::Write);
    assert_eq!(
        p.classify_command("npm install lodash")?,
        CommandClass::Write
    );
    assert_eq!(p.classify_command("cargo add serde")?, CommandClass::Write);
    Ok(())
}

#[test]
fn classify_pacman_readonly_queries_are_not_install()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // pacman's `-S` family includes read-only queries (search/info/list/groups/
    // print). A blanket `starts_with("-s")` mis-bucketed these as always-ask
    // Install; they must fall through to the fail-closed Write default instead.
    for c in [
        "pacman -Ss firefox", // search
        "pacman -Si vim",     // info
        "pacman -Sl core",    // list a repo
        "pacman -Sg",         // list groups
        "pacman -Sp vim",     // print download URLs
    ] {
        assert_eq!(p.classify_command(c)?, CommandClass::Write, "{c}");
    }
    Ok(())
}

#[test]
fn gate_decision_install_always_asks_even_in_full()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        full_policy()?.gate_decision(CommandClass::Install),
        GateDecision::Prompt
    );
    assert_eq!(
        default_policy()?.gate_decision(CommandClass::Install),
        GateDecision::Prompt
    );
    assert_eq!(
        readonly_policy()?.gate_decision(CommandClass::Install),
        GateDecision::Block
    );
    Ok(())
}

#[test]
fn command_injection_background_chain_blocked()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert!(!p.is_command_allowed("ls & rm -rf /"));
    assert!(!p.is_command_allowed("ls&rm -rf /"));
    assert!(!p.is_command_allowed("echo ok & python3 -c 'print(1)'"));
    Ok(())
}

#[test]
fn command_injection_redirect_blocked() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert!(!p.is_command_allowed("echo secret > /etc/crontab"));
    assert!(!p.is_command_allowed("ls >> /tmp/exfil.txt"));
    Ok(())
}

#[test]
fn quoted_ampersand_and_redirect_literals_are_not_treated_as_operators()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert!(p.is_command_allowed("echo \"A&B\""));
    assert!(p.is_command_allowed("echo \"A>B\""));
    Ok(())
}

#[test]
fn command_argument_injection_blocked() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // find -exec is a common bypass
    assert!(!p.is_command_allowed("find . -exec rm -rf {} +"));
    assert!(!p.is_command_allowed("find / -ok cat {} \\;"));
    // -execdir / -okdir have identical command-execution semantics — same cwd
    // bypass class, different option spelling.
    assert!(!p.is_command_allowed("find /tmp -maxdepth 1 -name poc_proof.txt -execdir whoami \\;"));
    assert!(!p.is_command_allowed("find /etc -name passwd -okdir head -3 {} \\;"));
    // git config/alias can execute commands
    assert!(!p.is_command_allowed("git config core.editor \"rm -rf /\""));
    assert!(!p.is_command_allowed("git alias.st status"));
    assert!(!p.is_command_allowed("git -c core.editor=calc.exe commit"));
    // Legitimate commands should still work
    assert!(p.is_command_allowed("find . -name '*.txt'"));
    assert!(p.is_command_allowed("git status"));
    assert!(p.is_command_allowed("git add ."));
    Ok(())
}

#[test]
fn dangerous_env_var_prefix_blocked() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // GIT_PAGER / PAGER / GIT_SSH_COMMAND / GIT_EXTERNAL_DIFF / EDITOR all
    // cause git or other allowed binaries to spawn the assigned value as a
    // subprocess. The bare command (`git log`, `git status`, `git diff`)
    // is allowlisted, but the env prefix shifts execution to an arbitrary
    // command.
    assert!(!p.is_command_allowed("GIT_PAGER=/tmp/payload.sh git log"));
    assert!(!p.is_command_allowed("PAGER=calc.exe git log"));
    assert!(!p.is_command_allowed("GIT_SSH_COMMAND=/tmp/x git fetch"));
    assert!(!p.is_command_allowed("GIT_EXTERNAL_DIFF=/tmp/x git diff"));
    assert!(!p.is_command_allowed("EDITOR=/tmp/x git commit"));
    assert!(!p.is_command_allowed("VISUAL=/tmp/x git commit"));
    assert!(!p.is_command_allowed("LESS=/tmp/x cat /etc/passwd"));
    assert!(!p.is_command_allowed("LESSOPEN=/tmp/x cat /etc/passwd"));
    assert!(!p.is_command_allowed("MANPAGER=/tmp/x man bash"));
    assert!(!p.is_command_allowed("BAT_PAGER=/tmp/x bat file"));
    assert!(!p.is_command_allowed("BROWSER=/tmp/x git status"));
    // Loader-override variables let an attacker inject a library into the
    // next process.
    assert!(!p.is_command_allowed("LD_PRELOAD=/tmp/x.so git status"));
    assert!(!p.is_command_allowed("LD_LIBRARY_PATH=/tmp git status"));
    assert!(!p.is_command_allowed("LD_AUDIT=/tmp/x.so git status"));
    assert!(!p.is_command_allowed("DYLD_INSERT_LIBRARIES=/tmp/x.dylib git status"));
    assert!(!p.is_command_allowed("DYLD_LIBRARY_PATH=/tmp git status"));
    assert!(!p.is_command_allowed("DYLD_FORCE_FLAT_NAMESPACE=1 git status"));
    // Shell-evaluation variables.
    assert!(!p.is_command_allowed("BASH_ENV=/tmp/x git status"));
    assert!(!p.is_command_allowed("ENV=/tmp/x git status"));
    assert!(!p.is_command_allowed("PROMPT_COMMAND=/tmp/x git status"));
    assert!(!p.is_command_allowed("IFS=$'\\n' git status"));
    // Python startup hook + path override.
    assert!(!p.is_command_allowed("PYTHONSTARTUP=/tmp/x python3 -V"));
    assert!(!p.is_command_allowed("PYTHONPATH=/tmp python3 -V"));
    // PATH / SHELL overrides redirect resolution of the next binary.
    assert!(!p.is_command_allowed("PATH=/tmp git status"));
    assert!(!p.is_command_allowed("SHELL=/tmp/x git status"));
    // Lower-case spellings still match (env names are case-insensitive
    // by convention here — most shells uppercase them, but the matcher
    // should not be fooled by case folding).
    assert!(!p.is_command_allowed("git_pager=/tmp/x git log"));
    // Case-insensitive: should also catch mixed-case names.
    assert!(!p.is_command_allowed("Ld_PrElOaD=/tmp/x.so git status"));

    // All leading env-var assignments are now rejected — including
    // previously-benign-looking ones (TZ, LANG, LC_ALL, custom names).
    // The allowlist already names every command we want to permit, and
    // none need an operator-set env var at invoke time, so the broader
    // gate has no false-positive surface on the approved path.
    assert!(!p.is_command_allowed("TZ=UTC git log"));
    assert!(!p.is_command_allowed("LANG=en_US.UTF-8 git log"));
    assert!(!p.is_command_allowed("LC_ALL=C git status"));
    assert!(!p.is_command_allowed("FOO=bar git status"));
    // No env prefix at all — unchanged.
    assert!(p.is_command_allowed("git status"));
    Ok(())
}

#[test]
fn command_injection_dollar_brace_blocked() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert!(!p.is_command_allowed("echo ${IFS}cat${IFS}/etc/passwd"));
    Ok(())
}

#[test]
fn command_injection_tee_blocked() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert!(!p.is_command_allowed("echo secret | tee /etc/crontab"));
    assert!(!p.is_command_allowed("ls | /usr/bin/tee outfile"));
    assert!(!p.is_command_allowed("tee file.txt"));
    Ok(())
}

#[test]
fn command_injection_process_substitution_blocked()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    assert!(!p.is_command_allowed("cat <(echo pwned)"));
    assert!(!p.is_command_allowed("ls >(cat /etc/passwd)"));
    Ok(())
}

#[test]
fn command_env_var_prefix_is_always_rejected() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let p = default_policy()?;
    // ANY env assignment is rejected — including in front of an
    // otherwise-allowed command. Helper-style exec primitives
    // (GIT_SSH=, SSH_ASKPASS=, LD_PRELOAD=) and benign-looking
    // overrides (FOO=, LANG=) both go through the same gate so the
    // policy doesn't have to enumerate every shape of every
    // downstream tool's hook surface.
    assert!(!p.is_command_allowed("FOO=bar ls"));
    assert!(!p.is_command_allowed("LANG=C grep pattern file"));
    assert!(!p.is_command_allowed("FOO=bar rm -rf /"));
    Ok(())
}

#[test]
fn validate_command_rejects_leading_env_var_assignment()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let p = default_policy()?;
    // Helper-style exec primitives that mutate which binary the
    // approved command actually runs as: rejected.
    assert!(!p.is_command_allowed("GIT_SSH=./wrapper.sh git ls-remote ssh://x"));
    assert!(!p.is_command_allowed("SSH_ASKPASS=./y ssh user@host"));
    assert!(!p.is_command_allowed("LD_PRELOAD=./libx.so ls"));
    // Negative: same command without the env prefix passes the
    // structural guard (it may still fail later on its own merits,
    // but the env-prefix gate doesn't fire).
    assert!(p.is_command_allowed("git ls-remote ssh://example.com"));
    Ok(())
}

fn decision(p: CommandPolicy, command: &str) -> Result<CommandDecision> {
    CommandScope::new(p)?.evaluate(&CommandRequest {
        policy_id: CommandPolicyId(String::new()),
        command: command.into(),
        declared_class: Some(CommandClass::Read),
    })
}

#[test]
fn partial_quoted_heredoc_keeps_following_executable_visible()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let command = "cat <<'EOF'x\nbody\nEOFx\ncat ~/.ssh/id_rsa";
    assert_eq!(
        decision(policy(false, CommandAutonomy::Full)?, command)?.denial,
        Some(CommandDenial::Protected)
    );
    assert_eq!(
        decision(
            policy(true, CommandAutonomy::Supervised)?,
            "cat <<'EOF'x\nbody\nEOFx\ntouch review-proof"
        )?
        .gate,
        CommandGate::Prompt
    );
    #[cfg(unix)]
    {
        let root = tempfile::tempdir()?;
        let status = std::process::Command::new("bash")
            .args(["-c", "cat <<'EOF'x\nbody\nEOFx\ntouch review-proof"])
            .current_dir(root.path())
            .status()?;
        assert!(status.success());
        assert!(root.path().join("review-proof").exists());
    }
    Ok(())
}

#[test]
fn allowlisted_execution_uses_risk_independently_of_class()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut p = policy(true, CommandAutonomy::Supervised)?;
    p.execution_mode = CommandExecutionMode::Allowlisted;
    p.allowed_commands.extend(["curl".into(), "sudo".into()]);
    assert_eq!(decision(p.clone(), "git add .")?.gate, CommandGate::Allow);
    p.require_approval_for_medium_risk = false;
    assert_eq!(
        decision(p.clone(), "curl https://example.test")?.gate,
        CommandGate::Allow
    );
    p.require_approval_for_medium_risk = true;
    assert_eq!(
        decision(p.clone(), "curl https://example.test")?.gate,
        CommandGate::Prompt
    );
    p.block_high_risk_commands = false;
    assert_eq!(
        decision(p.clone(), "sudo echo safe")?.gate,
        CommandGate::Prompt
    );
    p.block_high_risk_commands = true;
    p.autonomy = CommandAutonomy::Full;
    assert_eq!(
        decision(p.clone(), "curl https://example.test")?.gate,
        CommandGate::Allow
    );
    assert_eq!(
        decision(p.clone(), "sudo echo safe")?.denial,
        Some(CommandDenial::HighRisk)
    );
    p.block_high_risk_commands = false;
    assert_eq!(
        decision(p.clone(), "sudo echo safe")?.gate,
        CommandGate::Allow
    );
    p.autonomy = CommandAutonomy::ReadOnly;
    assert_eq!(decision(p, "cat safe")?.gate, CommandGate::Block);
    Ok(())
}

#[test]
fn native_shell_execution_and_escaping_cannot_bypass_policy()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut ps = policy(true, CommandAutonomy::Supervised)?;
    ps.shell_dialect = tinysecurity_bus::ShellDialect::PowerShell;
    assert_eq!(
        decision(ps, "echo (Remove-Item review-proof)")?.gate,
        CommandGate::Block
    );
    let mut cmd = policy(false, CommandAutonomy::Full)?;
    cmd.shell_dialect = tinysecurity_bus::ShellDialect::Cmd;
    assert_eq!(
        decision(cmd, r"type C:\Users\u\.s^sh\id_rsa")?.denial,
        Some(CommandDenial::Protected)
    );
    Ok(())
}

#[test]
fn native_quoted_and_escaped_parentheses_remain_literal_data()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::ShellDialect;
    for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
        let mut p = policy(true, CommandAutonomy::Supervised)?;
        p.shell_dialect = dialect;
        for mode in [
            CommandExecutionMode::HarnessGated,
            CommandExecutionMode::Allowlisted,
        ] {
            p.execution_mode = mode;
            assert_eq!(
                decision(p.clone(), "echo \"(Remove-Item file)\"")?.gate,
                CommandGate::Allow
            );
            let escaped = if dialect == ShellDialect::PowerShell {
                "echo `(Remove-Item file`)"
            } else {
                "echo ^(Remove-Item file^)"
            };
            assert_eq!(decision(p.clone(), escaped)?.gate, CommandGate::Allow);
            assert_eq!(
                decision(p.clone(), "echo (Remove-Item file)")?.gate,
                CommandGate::Block
            );
        }
    }
    Ok(())
}

#[test]
fn native_escape_decoding_preserves_credential_floor_and_ordinary_paths()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::ShellDialect;
    for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
        for enabled in [false, true] {
            for autonomy in [
                CommandAutonomy::ReadOnly,
                CommandAutonomy::Supervised,
                CommandAutonomy::Full,
            ] {
                let mut p = policy(enabled, autonomy)?;
                p.shell_dialect = dialect;
                let protected = if dialect == ShellDialect::Cmd {
                    r"type C:\Users\u\.s^sh\id_rsa"
                } else {
                    r"Get-Content C:\Users\u\.s`sh\id_rsa"
                };
                assert_eq!(
                    decision(p.clone(), protected)?.denial,
                    Some(CommandDenial::Protected)
                );
                for command in [
                    r#"type "C:\Users\Some Person\.ssh\id_rsa""#,
                    r#"type "\\server\share\Some Person\.ssh\id_rsa""#,
                ] {
                    assert_eq!(
                        decision(p.clone(), command)?.denial,
                        Some(CommandDenial::Protected)
                    );
                }
                for command in [
                    r#"type "C:\Users\Some Person\ordinary file""#,
                    r#"type "\\server\share\ordinary file""#,
                ] {
                    assert_eq!(decision(p.clone(), command)?.gate, CommandGate::Allow);
                }
            }
        }
    }
    let mut ps = policy(false, CommandAutonomy::Full)?;
    ps.shell_dialect = ShellDialect::PowerShell;
    assert_eq!(
        decision(ps.clone(), r#"Get-Content "C:\Users\u\.s`sh\id_rsa""#)?.denial,
        Some(CommandDenial::Protected)
    );
    assert_eq!(
        decision(ps, r"Get-Content 'C:\Users\u\.s`sh\id_rsa'")?.denial,
        None
    );
    let mut cmd = policy(false, CommandAutonomy::Full)?;
    cmd.shell_dialect = ShellDialect::Cmd;
    assert_eq!(
        decision(cmd, r#"type "C:\Users\u\.s^sh\id_rsa""#)?.denial,
        None
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn native_windows_shells_execute_the_reported_grammar()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("review-proof"), "safe fixture")?;
    let result = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "echo (Remove-Item review-proof)",
        ])
        .current_dir(root.path())
        .output()?;
    assert!(result.status.success());
    assert!(!root.path().join("review-proof").exists());
    std::fs::create_dir(root.path().join(".ssh"))?;
    std::fs::write(root.path().join(".ssh").join("id_rsa"), "safe fixture")?;
    let result = std::process::Command::new("cmd.exe")
        .args(["/D", "/C", r"type .s^sh\id_rsa"])
        .current_dir(root.path())
        .output()?;
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)?.contains("safe fixture"));
    Ok(())
}

#[test]
fn native_dialects_never_treat_posix_heredocs_as_data()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for dialect in [
        tinysecurity_bus::ShellDialect::PowerShell,
        tinysecurity_bus::ShellDialect::Cmd,
    ] {
        let mut p = policy(false, CommandAutonomy::Full)?;
        p.shell_dialect = dialect;
        assert_eq!(
            decision(p, "echo <<'EOF'\ncat ~/.ssh/id_rsa\nEOF")?.denial,
            Some(CommandDenial::Protected)
        );
    }
    Ok(())
}

#[test]
fn script_blocks_are_powershell_execution_but_cmd_braces_are_data()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut p = policy(true, CommandAutonomy::Supervised)?;
    p.shell_dialect = tinysecurity_bus::ShellDialect::PowerShell;
    assert_eq!(
        decision(p.clone(), "echo {Remove-Item file}")?.gate,
        CommandGate::Block
    );
    p.shell_dialect = tinysecurity_bus::ShellDialect::Cmd;
    assert_eq!(decision(p, "echo {ordinary}")?.gate, CommandGate::Allow);
    Ok(())
}

#[test]
fn every_expanded_heredoc_body_remains_live() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    for command in [
        "cat <<A <<'cat'\n$(touch review-proof)\nA\nbody\ncat",
        "cat <<'cat' <<A\nbody\ncat\n$(touch review-proof)\nA",
        "cat <<A <<'cat' <<B\n$(touch first)\nA\nbody\ncat\n$(touch second)\nB",
    ] {
        assert_eq!(
            decision(policy(true, CommandAutonomy::Supervised)?, command)?.gate,
            CommandGate::Block,
            "{command}"
        );
        let command = command
            .replace("touch review-proof", "cat ~/.ssh/id_rsa")
            .replace("touch first", "cat ~/.ssh/id_rsa")
            .replace("touch second", "cat ~/.ssh/id_rsa");
        assert_eq!(
            decision(policy(false, CommandAutonomy::Full)?, &command)?.denial,
            Some(CommandDenial::Protected),
            "{command}"
        );
    }
    Ok(())
}

#[test]
fn attached_redirect_targets_enforce_the_protected_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for dialect in [
        tinysecurity_bus::ShellDialect::Posix,
        tinysecurity_bus::ShellDialect::PowerShell,
        tinysecurity_bus::ShellDialect::Cmd,
    ] {
        let mut p = policy(false, CommandAutonomy::Full)?;
        p.shell_dialect = dialect;
        for command in [
            "cat</etc/shadow",
            "cat< /etc/shadow",
            "cat 0</etc/shadow",
            "echo>/etc/shadow",
            "echo 2>>/etc/shadow",
            "cat<~/.ssh/id_rsa",
            "cat<../outside",
            "echo>>../outside",
            "cat<\"/etc/shadow\"",
        ] {
            assert_eq!(
                decision(p.clone(), command)?.denial,
                Some(CommandDenial::Protected),
                "{dialect:?}: {command}"
            );
        }
        for command in [
            "echo 'cat</etc/shadow'",
            "echo \"cat>/etc/shadow\"",
            "echo>ordinary",
            "cat<ordinary",
        ] {
            if dialect == tinysecurity_bus::ShellDialect::Cmd && command.contains('\'') {
                continue;
            }
            assert_eq!(
                decision(p.clone(), command)?.gate,
                CommandGate::Allow,
                "{dialect:?}: {command}"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn bash_expands_each_heredoc_even_when_later_stdin_overwrites_it()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let command = "cat <<-A <<-'B'x <<-C\n\t$(touch first)\n\tA\n\t$(touch literal) <<'fake'\n\tBx\n\t$(touch last)\n\tC";
    let output = std::process::Command::new("bash")
        .args(["-c", command])
        .current_dir(root.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join("first").exists());
    assert!(root.path().join("last").exists());
    assert!(!root.path().join("literal").exists());
    assert_eq!(
        decision(policy(true, CommandAutonomy::Supervised)?, command)?.gate,
        CommandGate::Block
    );
    Ok(())
}

#[test]
fn redirect_targets_preserve_native_path_and_escape_rules()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinysecurity_bus::ShellDialect;
    for dialect in [
        ShellDialect::Posix,
        ShellDialect::PowerShell,
        ShellDialect::Cmd,
    ] {
        let mut p = policy(false, CommandAutonomy::Full)?;
        p.shell_dialect = dialect;
        for command in [
            r#"cat<"C:\Users\Some Person\.ssh\id_rsa""#,
            r#"echo>>"\\server\share\.ssh\id_rsa""#,
        ] {
            assert_eq!(
                decision(p.clone(), command)?.denial,
                Some(CommandDenial::Protected),
                "{dialect:?}: {command}"
            );
        }
        for command in [
            r#"cat<"C:\Users\Some Person\ordinary file""#,
            r#"echo>>"\\server\share\ordinary file""#,
        ] {
            assert_eq!(
                decision(p.clone(), command)?.gate,
                CommandGate::Allow,
                "{dialect:?}: {command}"
            );
        }
        let command = match dialect {
            ShellDialect::Posix => r"echo cat\</etc/shadow",
            ShellDialect::PowerShell => r"echo cat`>/etc/shadow",
            ShellDialect::Cmd => r"echo cat^>/etc/shadow",
        };
        assert_eq!(decision(p.clone(), command)?.gate, CommandGate::Allow);
        let command = match dialect {
            ShellDialect::Posix => r"cat<~/.s\sh/id_rsa",
            ShellDialect::PowerShell => r"cat<C:\Users\u\.s`sh\id_rsa",
            ShellDialect::Cmd => r"cat<C:\Users\u\.s^sh\id_rsa",
        };
        assert_eq!(decision(p, command)?.denial, Some(CommandDenial::Protected));
    }
    Ok(())
}

#[test]
fn commented_heredocs_preserve_following_live_commands()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    assert_ne!(
        decision(
            policy(true, CommandAutonomy::Supervised)?,
            "echo ok # <<'EOF'\ntouch review-proof"
        )?
        .gate,
        CommandGate::Allow
    );
    Ok(())
}

#[test]
fn commented_heredocs_preserve_the_disabled_credential_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        decision(
            policy(false, CommandAutonomy::Full)?,
            "echo ok # <<'EOF'\ncat ~/.ssh/id_rsa"
        )?
        .denial,
        Some(CommandDenial::Protected)
    );
    Ok(())
}

#[test]
fn continued_heredoc_headers_preserve_protected_arguments()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for command in [
        "cat <<'EOF' \\\n~/.ssh/id_rsa\nbody\nEOF",
        "cat <<'EOF' \\\n<~/.ssh/id_rsa\nbody\nEOF",
    ] {
        assert_eq!(
            decision(policy(false, CommandAutonomy::Full)?, command)?.denial,
            Some(CommandDenial::Protected),
            "{command}"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn bash_comments_and_continued_headers_keep_live_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let output = std::process::Command::new("bash")
        .args(["-c", "echo ok # <<'EOF'\ntouch comment-proof"])
        .current_dir(root.path())
        .output()?;
    assert!(output.status.success());
    assert!(root.path().join("comment-proof").exists());
    for quote in ["", "'", "\""] {
        let command =
            format!("printf '%s\\n' <<'EOF' \\\n{quote}continued-argument{quote}\nbody\nEOF");
        let output = std::process::Command::new("bash")
            .args(["-c", &command])
            .current_dir(root.path())
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"continued-argument\n");
    }
    Ok(())
}

#[test]
fn expanded_body_continuations_preserve_the_disabled_credential_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let command = "cat <<EOF <<'B'\nE\\\nOF\nliteral\nB\nEOF\ncat ~/.ssh/id_rsa\nB";
    assert_eq!(
        decision(policy(false, CommandAutonomy::Full)?, command)?.denial,
        Some(CommandDenial::Protected)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn bash_expanded_body_continuation_can_form_its_terminator()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let output = std::process::Command::new("bash")
        .args([
            "-c",
            "cat <<EOF <<'B'\nE\\\nOF\nliteral\nB\nEOF\ntouch continued-body-proof\nB",
        ])
        .current_dir(root.path())
        .output()?;
    assert!(
        root.path().join("continued-body-proof").exists(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"literal\n");
    Ok(())
}

#[test]
fn literal_delimiter_whitespace_preserves_the_disabled_credential_floor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for literal in ['\u{a0}', '\r', '\u{b}', '\u{c}'] {
        let command =
            format!("cat <<'A'{literal}x\nA\ncat <<'C'\nA{literal}x\ncat ~/.ssh/id_rsa\nC");
        assert_eq!(
            decision(policy(false, CommandAutonomy::Full)?, &command)?.denial,
            Some(CommandDenial::Protected)
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn bash_preserves_nonblank_whitespace_in_heredoc_delimiters()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for literal in ['\u{a0}', '\r', '\u{b}', '\u{c}'] {
        let root = tempfile::tempdir()?;
        let command = format!(
            "cat <<'A'{literal}x\nA\ncat <<'C'\nA{literal}x\ntouch literal-delimiter-proof\nC"
        );
        let output = std::process::Command::new("bash")
            .args(["-c", &command])
            .current_dir(root.path())
            .output()?;
        assert!(
            root.path().join("literal-delimiter-proof").exists(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"A\ncat <<'C'\n");
    }
    Ok(())
}
