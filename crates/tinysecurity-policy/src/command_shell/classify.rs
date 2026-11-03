//! Base-command classification: the read/write/network/install/destructive
//! bucket lists, verb-sensitive VCS / package-manager handling, and the
//! structural "hidden execution" guard for the harness-gated command flow.

use super::executor::is_command_executor;
use super::scan::{contains_unquoted_background_ampersand, strip_quoted_heredoc_bodies};

use tinysecurity_bus::CommandClass;

/// Provably read-only command bases (cross-platform union). A base **not** in
/// this set — and not a recognized network/destructive/executor command, nor a
/// read-only verb of git/npm/cargo — falls through to [`CommandClass::Write`]
/// (the classifier is fail-closed). Conservative on purpose: anything that can
/// write a file under a common flag is intentionally omitted (`sort -o`, `tee`).
const READ_ONLY_BASES: &[&str] = &[
    // POSIX inspection / read-only coreutils
    "ls",
    "cat",
    "pwd",
    "echo",
    "printf",
    "wc",
    "head",
    "tail",
    "date",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "which",
    "whoami",
    "id",
    "hostname",
    "uname",
    "printenv",
    "stat",
    "file",
    "du",
    "df",
    "tree",
    "realpath",
    "readlink",
    "dirname",
    "basename",
    "cmp",
    "true",
    "false",
    "sleep",
    "seq",
    "tty",
    "groups",
    "locale",
    "ps",
    "top",
    "free",
    "uptime",
    "lsblk",
    "lscpu",
    "cut",
    // NOTE: OS-native launchers (`open`, `xdg-open`, `start`) are deliberately
    // NOT in the read-only set. `classify_command` only sees the base command,
    // not its args, and these launchers can open arbitrary `https://` URLs and
    // custom URI handlers — i.e. trigger outbound network / system actions — so
    // treating them as `Read` (no approval) is too broad. App launching now
    // goes through the dedicated `launch_app` tool, which is scoped to named
    // applications only and carries no shell-arg ambiguity.
    // Windows cmd / PowerShell read verbs + common aliases
    "dir",
    "type",
    "where",
    "whereis",
    "get-childitem",
    "gci",
    "get-content",
    "gc",
    "get-location",
    "gl",
    "select-string",
    "sls",
    "measure-object",
    "get-item",
    "gi",
    "test-path",
    "resolve-path",
    "get-command",
    "gcm",
    "get-process",
];

/// Commands that reach the network. Always-ask in every acting tier.
const NETWORK_BASES: &[&str] = &[
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ftp",
    "tftp",
    "socat",
    // Windows / PowerShell
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "start-bitstransfer",
    "bitsadmin",
];

/// Catastrophic / irreversible / privilege / system-control bases. Always-ask
/// in every acting tier (Full included). Coarse on the broad Windows verbs
/// (`reg`/`net`/`sc`) — over-prompting there is the safe default.
const DESTRUCTIVE_BASES: &[&str] = &[
    // POSIX privilege / disk / system-control
    "sudo",
    "su",
    "doas",
    "dd",
    "mkfs",
    "fdisk",
    "sfdisk",
    "parted",
    "wipefs",
    "shred",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init",
    "telinit",
    "mount",
    "umount",
    "swapoff",
    "iptables",
    "ip6tables",
    "nft",
    "ufw",
    "firewall-cmd",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "passwd",
    "chpasswd",
    "visudo",
    "modprobe",
    "insmod",
    "rmmod",
    // Windows / PowerShell
    "format",
    "diskpart",
    "bcdedit",
    "takeown",
    "cipher",
    "vssadmin",
    "reg",
    "regedit",
    "runas",
    "sc",
    "net",
    "set-executionpolicy",
    "stop-computer",
    "restart-computer",
    "clear-disk",
    "format-volume",
    "remove-partition",
    "disable-computerrestore",
];

/// Git subcommands that only read repository state. Anything else — including
/// `commit`/`push`/`branch`/`config`/unknown/bare `git` — is fail-closed to
/// `Write`.
const GIT_READ_VERBS: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "remote",
    "describe",
    "blame",
    "ls-files",
    "ls-tree",
    "rev-parse",
    "cat-file",
    "shortlog",
    "reflog",
    "rev-list",
    "name-rev",
    "var",
    "check-ignore",
    "check-attr",
    "verify-commit",
    "count-objects",
    "fsck",
    "whatchanged",
    "grep",
    "version",
    "help",
];

const DANGEROUS_ENV_NAMES: &[&str] = &[
    "BASH_ENV",
    "BAT_PAGER",
    "BROWSER",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "EDITOR",
    "ENV",
    "GIT_EDITOR",
    "GIT_EXTERNAL_DIFF",
    "GIT_EXTERNAL_FILTER",
    "GIT_PAGER",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "IFS",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LESS",
    "LESSCLOSE",
    "LESSOPEN",
    "MANOPT",
    "MANPAGER",
    "PAGER",
    "PATH",
    "PROMPT_COMMAND",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "SHELL",
    "VISUAL",
];

fn shell_unquote(word: &str) -> String {
    let (mut out, mut quote, mut escaped) = (String::with_capacity(word.len()), None, false);
    for c in word.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(open), _) if c == open => quote = None,
            (Some('"') | None, '\\') => escaped = true,
            _ => out.push(c),
        }
    }
    out
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn shell_words(source: &str) -> Vec<&str> {
    let (mut words, mut start, mut quote, mut escaped) = (Vec::new(), None, None, false);
    for (index, c) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (_, '\\') => escaped = true,
            (None, '\'' | '"') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if let Some(begin) = start.take() {
                    words.push(&source[begin..index]);
                }
                continue;
            }
            (Some(_) | None, _) => {}
        }
        start.get_or_insert(index);
    }
    if let Some(begin) = start {
        words.push(&source[begin..]);
    }
    words
}

fn launcher_value_options(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "env" => &["-u", "--unset", "-C", "--chdir"],
        "timeout" => &["-s", "--signal", "-k", "--kill-after"],
        "nice" => &["-n", "--adjustment"],
        "stdbuf" => &["-i", "-o", "-e"],
        "xargs" => &["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"],
        "time" => &["-f", "-o"],
        "exec" => &["-a"],
        "nohup" | "command" => &[],
        _ => return None,
    })
}

fn effective_command<'a, 'w>(words: &'a [&'w str]) -> (String, &'a [&'w str]) {
    let (mut name, mut args, mut rest) = (String::new(), &words[..0], words);
    while let Some((first, tail)) = rest.split_first() {
        if is_assignment(first) {
            rest = tail;
            continue;
        }
        name = super::scan::normalized_command_name(&shell_unquote(first));
        args = tail;
        let Some(options) = launcher_value_options(&name) else {
            break;
        };
        let mut operand = 0;
        while let Some(word) = tail.get(operand) {
            if options.contains(word) {
                operand += 2;
            } else if word.starts_with('-') || is_assignment(word) {
                operand += 1;
            } else {
                break;
            }
        }
        if name == "timeout" {
            operand += 1;
        }
        rest = tail.get(operand..).unwrap_or_default();
    }
    (name, args)
}

fn env_split_string(words: &[&str]) -> Option<String> {
    let position = words
        .iter()
        .position(|word| !is_assignment(word))
        .filter(|&i| super::scan::normalized_command_name(&shell_unquote(words[i])) == "env")?;
    let mut rest = words[position + 1..].iter();
    while let Some(word) = rest.next() {
        let unquoted = shell_unquote(word);
        let split = if unquoted == "-S" || unquoted == "--split-string" {
            rest.next().map(|v| shell_unquote(v))
        } else if let Some(value) = unquoted.strip_prefix("--split-string=") {
            Some(value.to_owned())
        } else if let Some(value) = unquoted.strip_prefix("-S") {
            Some(value.to_owned())
        } else if launcher_value_options("env").is_some_and(|options| options.contains(word)) {
            rest.next();
            continue;
        } else if unquoted.starts_with('-') || is_assignment(word) {
            continue;
        } else {
            return None;
        };
        return split
            .map(|command| format!("{command} {}", rest.copied().collect::<Vec<_>>().join(" ")));
    }
    None
}

/// Classify the command actually launched by one shell segment, including env
/// assignments, env split-string and standard command launchers.
pub(crate) fn classify_segment_source(source: &str) -> CommandClass {
    let words = shell_words(source);
    if let Some(command) = env_split_string(&words) {
        return classify_segment_source(&command).max(CommandClass::Write);
    }
    let (base, args) = effective_command(&words);
    let args = args
        .iter()
        .map(|w| shell_unquote(w).to_ascii_lowercase())
        .collect::<Vec<_>>();
    let joined = source.replace(['\'', '"'], "").to_ascii_lowercase();
    let mut class = classify_segment(&base, &args, &joined);
    if words.iter().any(|word| {
        is_assignment(word)
            && word.split_once('=').is_some_and(|(name, _)| {
                let upper = name.to_ascii_uppercase();
                DANGEROUS_ENV_NAMES.contains(&upper.as_str()) || upper.starts_with("GIT_CONFIG")
            })
    }) {
        class = class.max(CommandClass::Write);
    }
    class
}

/// npm/pnpm/yarn read-only subcommands. `install`/`run`/`test`/`exec` (which
/// run arbitrary scripts) and unknown verbs are fail-closed to `Write`.
const NODE_PKG_READ_VERBS: &[&str] = &[
    "ls", "list", "view", "info", "outdated", "ping", "whoami", "help", "why", "audit", "doctor",
];

/// cargo read-only subcommands. `build`/`run`/`test`/`check` compile and may
/// run build scripts, so they are fail-closed to `Write`.
const CARGO_READ_VERBS: &[&str] = &["tree", "metadata", "search", "info", "version", "help"];

/// Detect a pacman *install/upgrade* from its bundled operation flag.
///
/// pacman packs its operation and modifiers into a single flag (`-Syu`, `-Ss`),
/// and `args` reach us already lowercased — so the `-S` (sync) operation is
/// indistinguishable from a literal `-s` by case alone. We therefore key off
/// the *modifier* letters instead of a blanket `starts_with("-s")`, which would
/// over-match every read-only `-S` query: a `-S`-family flag mutates the host
/// only when it carries none of pacman's read-only query modifiers — search
/// (`s`), info (`i`), list (`l`), groups (`g`) or print (`p`). So `-S pkg`,
/// `-Sy`, `-Syu` are installs while `-Ss`/`-Si`/`-Sl`/`-Sg`/`-Sp` are reads.
fn is_pacman_install(args: &[String]) -> bool {
    args.iter().any(|a| {
        a.strip_prefix("-s")
            .is_some_and(|modifiers| !modifiers.contains(['s', 'i', 'l', 'g', 'p']))
    })
}

/// Detect a package-manager *install* invocation. These mutate the host /
/// global environment, so they are the always-ask `Install` bucket (even in
/// Full) — the same gate the dedicated `install_tool` enforces, applied to the
/// shell escape hatch. Project-local installs (`npm install` without `-g`,
/// `cargo add`) are ordinary `Write`s and are deliberately NOT matched here.
/// `args` are already lowercased by the caller.
fn is_install_command(base: &str, args: &[String]) -> bool {
    let has = |needle: &str| args.iter().any(|a| a == needle);
    let first_is = |verb: &str| args.first().map(String::as_str) == Some(verb);
    match base {
        // System package managers.
        "pacman" => is_pacman_install(args),
        "apk" => has("add"),
        "apt" | "apt-get" | "dnf" | "yum" | "zypper" | "brew" | "snap" | "flatpak" | "winget"
        | "choco" | "scoop" => has("install"),
        // Language package managers — host/global-modifying installs only.
        "pip" | "pip3" | "pipx" | "gem" | "go" | "cargo" => first_is("install"),
        "npm" | "pnpm" => {
            (has("install") || has("i") || has("add")) && (has("-g") || has("--global"))
        }
        "yarn" => has("global"),
        _ => false,
    }
}

/// Classify a single already-split shell segment. `base` is the normalized
/// (lowercased, `.exe`-stripped, basename-only) program name; `args` are the
/// lowercased remaining words; `joined` is the lowercased segment used for
/// pattern matching. Fail-closed: an unrecognized base resolves to `Write`.
#[must_use]
pub(crate) fn classify_segment(base: &str, args: &[String], joined: &str) -> CommandClass {
    // Catastrophic patterns first — they win regardless of the base command.
    if joined.contains("rm -rf /") || joined.contains("rm -fr /") || joined.contains(":(){:|:&};:")
    {
        return CommandClass::Destructive;
    }
    if DESTRUCTIVE_BASES.contains(&base) {
        return CommandClass::Destructive;
    }
    if NETWORK_BASES.contains(&base) {
        return CommandClass::Network;
    }
    // Package installs mutate the host → always-ask Install bucket (closes the
    // shell escape hatch around `install_tool`).
    if is_install_command(base, args) {
        return CommandClass::Install;
    }
    // Interpreters / code executors run arbitrary code. Fail-closed to Write
    // (not Destructive) so Full can still run code while Supervised prompts.
    if is_command_executor(base) {
        return CommandClass::Write;
    }
    // `find` is read-only unless it executes commands, deletes, or writes
    // files. -fprintf / -fprint / -fprint0 / -fls write their output to a
    // named file rather than stdout — an arbitrary-path write that side-steps
    // the gated file-write tools (and their workspace confinement), so they
    // must be classified Write (approval-gated) alongside -delete.
    //
    // `args` is built with `split_whitespace()`, which keeps shell quotes that
    // the shell itself strips before `find` runs — `find . '-fprint' out`
    // arrives as the literal `'-fprint'`. Trim surrounding single/double quotes
    // before matching so a quoted predicate cannot slip the write past the gate.
    if base == "find" {
        if args.iter().any(|a| {
            matches!(
                a.trim_matches(|c| c == '\'' || c == '"'),
                "-exec"
                    | "-execdir"
                    | "-ok"
                    | "-okdir"
                    | "-delete"
                    | "-fprintf"
                    | "-fprint"
                    | "-fprint0"
                    | "-fls"
            )
        }) {
            return CommandClass::Write;
        }
        return CommandClass::Read;
    }
    if base == "git" {
        let sub = args.get(1).map(String::as_str);
        if matches!(args.first().map(String::as_str), Some("remote"))
            && sub.is_some_and(|s| !matches!(s, "-v" | "--verbose" | "show" | "get-url"))
            || matches!(args.first().map(String::as_str), Some("reflog"))
                && matches!(sub, Some("expire" | "delete"))
            || args
                .iter()
                .any(|a| a == "--config-env" || a.starts_with("--config-env=") || a == "--ext-diff")
            || matches!(args.first().map(String::as_str), Some("diff" | "log"))
                && args
                    .iter()
                    .any(|a| a == "--output" || a.starts_with("--output="))
        {
            return CommandClass::Write;
        }
    }
    if matches!(base, "npm" | "pnpm" | "yarn")
        && args.first().is_some_and(|a| a == "audit")
        && args.iter().any(|a| a == "fix")
    {
        return CommandClass::Write;
    }
    if base == "rg" && args.iter().any(|a| a == "--pre" || a.starts_with("--pre="))
        || base == "tree" && args.iter().any(|a| a == "-o")
        || base == "hostname"
            && args
                .iter()
                .any(|a| !a.starts_with('-') || a.starts_with("--file"))
    {
        return CommandClass::Write;
    }
    // Verb-sensitive VCS / package tools.
    if base == "git" {
        return verb_class(args, GIT_READ_VERBS);
    }
    if matches!(base, "npm" | "pnpm" | "yarn") {
        return verb_class(args, NODE_PKG_READ_VERBS);
    }
    if base == "cargo" {
        return verb_class(args, CARGO_READ_VERBS);
    }
    if READ_ONLY_BASES.contains(&base) {
        return CommandClass::Read;
    }
    // Fail closed: unknown or known-mutating base → Write.
    CommandClass::Write
}

/// `Read` when the first subcommand word is in `read_verbs`, else fail-closed
/// `Write`. Mirrors the `args.first()` verb check used by `command_risk_level`.
fn verb_class(args: &[String], read_verbs: &[&str]) -> CommandClass {
    match args.first().map(String::as_str) {
        Some(verb) if read_verbs.contains(&verb) => CommandClass::Read,
        _ => CommandClass::Write,
    }
}

/// Structural-safety guard for the harness-gated command flow (Option 2). Even
/// after a human approves a command, a hidden subshell / command substitution /
/// output redirect / `tee` / background `&` could smuggle a *different* command
/// past the approval summary, so these are refused outside Full (which is
/// trusted to use redirects and pipes). Mirrors the structural checks in
/// `SecurityPolicy::is_command_allowed`.
/// `$()` and `${…}` are refused; simple `$NAME` expansion remains allowed.
/// Bash `&>` is treated as an output redirect (classified `Write`), not as a
/// background operator, and can run after the class gate is approved.
/// Detect shell structure that can **hide execution** from `classify_command`,
/// which only inspects the base command of each `;`/`&&`/`|` segment. Command
/// and process substitution and backticks run an *inner* command classification
/// can't see (`echo $(rm -rf ~)` classifies as `echo` = Read and would run
/// unprompted), and a trailing `&` detaches a process past the gate — so these
/// stay hard-blocked outside Full.
///
/// Deliberately NOT flagged here: plain redirects (`>`, `2>&1`, `2>/dev/null`),
/// `&>` output redirection, and `tee`. `classify_command` already lifts a redirect /
/// `tee` to `Write`, so the gate prompts and — once the human approves — the
/// command MUST actually run. Re-blocking an approved `… 2>&1` here was the bug
/// that made Supervised mode unusable: every command the agent wrote carried a
/// `2>&1`, got approved, then silently failed this in-tool guard and never ran.
#[must_use]
pub(crate) fn has_hidden_execution(command: &str) -> bool {
    // A quoted heredoc body (`<< 'EOF' … EOF`) is data, not shell: the shell
    // performs no expansion inside it, so an `&`, a backtick or a `$(` there
    // cannot run anything. Scanning it as live text refused ordinary documents
    // — the life-scenario `meal-plan` write was blocked because four recipe
    // titles read "Chicken & Spinach". An *unquoted* delimiter is left in place
    // by the helper, because expansion IS live in that body.
    let command = &strip_quoted_heredoc_bodies(command);
    has_hidden_execution_lexical(command)
}

/// Inspect already normalized source; the caller owns dialect-specific data removal.
pub(crate) fn has_hidden_execution_lexical(command: &str) -> bool {
    // The backtick check is deliberately NOT quote-aware: any backtick in the
    // command string is blocked, even inside a double-quoted literal. Over-
    // blocking is the safe direction here. (By contrast the `&` case below is
    // quote-aware via `contains_unquoted_background_ampersand`, because that one
    // must still allow benign fd-dup redirects like `2>&1`.)
    command.contains('`')
        || command.contains("$(")
        || command.contains("${")
        || command.contains("<(")
        || command.contains(">(")
        || contains_unquoted_background_ampersand(command)
}
