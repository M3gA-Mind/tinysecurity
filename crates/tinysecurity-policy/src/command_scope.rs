//! Immutable command classification and both host execution-policy flows.
use crate::command_shell::{
    classify::{classify_segment_source, has_hidden_execution, has_hidden_execution_lexical},
    env_guard::has_dangerous_env_prefix,
    executor::is_command_executor,
    scan::{
        command_basename, command_words, contains_unquoted_char,
        contains_unquoted_single_ampersand, encoded_command_words, has_leading_env_assignment,
        native_command, normalized_command_name, skip_env_assignments, split_unquoted_segments,
        strip_quoted_heredoc_bodies,
    },
};
use crate::{protected_path, resolve_ancestor};
use std::path::{Path, PathBuf};
use tinysecurity_bus::{
    CommandAutonomy, CommandClass, CommandDecision, CommandDenial, CommandExecutionMode,
    CommandGate, CommandPolicy, CommandRequest, CommandRisk, Error, Result,
};
/// Immutable settings; action accounting lives in the registry, not this diagnostic scope.
#[derive(Debug)]
pub struct CommandScope {
    policy: CommandPolicy,
}
impl CommandScope {
    pub(crate) fn new(policy: CommandPolicy) -> Result<Self> {
        if !policy.action_dir.is_absolute()
            || policy.home_dir.as_ref().is_some_and(|p| !p.is_absolute())
            || policy.allowed_commands.len() > 1024
            || policy
                .allowed_commands
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_whitespace))
        {
            return Err(Error::InvalidArguments);
        }
        Ok(Self { policy })
    }
    pub(crate) fn policy(&self) -> &CommandPolicy {
        &self.policy
    }
    /// Classify without reserving an action or authorizing execution.
    /// # Errors
    /// Rejects oversized command input.
    pub fn classify(&self, request: &CommandRequest) -> Result<CommandDecision> {
        if request.command.len() > 1_048_576 {
            return Err(Error::InvalidArguments);
        }
        let native = native_command(&request.command, self.policy.shell_dialect);
        let command = self.shell_source(&native);
        let mut class = CommandClass::Read;
        for segment in split_unquoted_segments(&command) {
            class = class.max(classify_segment_source(&segment));
        }
        if contains_unquoted_char(&command, '>')
            || command
                .split_whitespace()
                .any(|w| w == "tee" || w.ends_with("/tee"))
        {
            class = class.max(CommandClass::Write);
        }
        if let Some(declared) = request.declared_class {
            class = class.max(declared);
        }
        let risk = self.risk(&command);
        let mut result = CommandDecision {
            class,
            risk,
            gate: self.gate(class),
            denial: None,
        };
        if !self.literals_allowed(&command) {
            result.gate = CommandGate::Block;
            result.denial = Some(CommandDenial::Protected);
        }
        Ok(result)
    }
    pub(crate) fn evaluate(&self, request: &CommandRequest) -> Result<CommandDecision> {
        let mut result = self.classify(request)?;
        if result.denial.is_some() || !self.policy.enabled {
            return Ok(result);
        }
        let native = native_command(&request.command, self.policy.shell_dialect);
        let command = self.shell_source(&native);
        let hidden = (if self.policy.shell_dialect == tinysecurity_bus::ShellDialect::Posix {
            has_hidden_execution(&command)
        } else {
            has_hidden_execution_lexical(&command)
        }) || self.has_native_execution(&command);
        let denial = if self.policy.execution_mode == CommandExecutionMode::Allowlisted {
            // Legacy admission is deliberately independent of the harness class
            // gate. Only the configured risk restrictions raise its allow result.
            result.gate = CommandGate::Allow;
            if !self.is_command_allowed(&request.command) {
                Some(if self.policy.autonomy == CommandAutonomy::ReadOnly {
                    CommandDenial::ReadOnly
                } else {
                    CommandDenial::Command
                })
            } else if result.risk == CommandRisk::High && self.policy.block_high_risk_commands {
                Some(CommandDenial::HighRisk)
            } else {
                if self.policy.autonomy == CommandAutonomy::Supervised
                    && (result.risk == CommandRisk::High
                        || (result.risk == CommandRisk::Medium
                            && self.policy.require_approval_for_medium_risk))
                {
                    result.gate = CommandGate::Prompt;
                }
                None
            }
        } else if result.gate == CommandGate::Block {
            Some(CommandDenial::ReadOnly)
        } else if self.policy.autonomy != CommandAutonomy::Full && hidden {
            Some(CommandDenial::Command)
        } else {
            None
        };
        if let Some(denial) = denial {
            result.gate = CommandGate::Block;
            result.denial = Some(denial);
        }
        Ok(result)
    }
    fn gate(&self, class: CommandClass) -> CommandGate {
        if !self.policy.enabled || class == CommandClass::Read {
            return CommandGate::Allow;
        }
        match self.policy.autonomy {
            CommandAutonomy::ReadOnly => CommandGate::Block,
            CommandAutonomy::Supervised => CommandGate::Prompt,
            CommandAutonomy::Full => {
                if class == CommandClass::Write {
                    CommandGate::Allow
                } else {
                    CommandGate::Prompt
                }
            }
        }
    }
    fn has_native_execution(&self, command: &str) -> bool {
        use tinysecurity_bus::ShellDialect;
        match self.policy.shell_dialect {
            ShellDialect::Posix => false,
            ShellDialect::PowerShell => {
                contains_unquoted_char(command, '(') || contains_unquoted_char(command, '{')
            }
            ShellDialect::Cmd => contains_unquoted_char(command, '('),
        }
    }
    fn shell_source<'a>(&self, command: &'a str) -> std::borrow::Cow<'a, str> {
        if self.policy.shell_dialect == tinysecurity_bus::ShellDialect::Posix {
            strip_quoted_heredoc_bodies(command)
        } else {
            std::borrow::Cow::Borrowed(command)
        }
    }
    fn words(&self, command: &str) -> Option<Vec<String>> {
        if self.policy.shell_dialect == tinysecurity_bus::ShellDialect::Posix {
            command_words(command)
        } else {
            encoded_command_words(command)
        }
    }
    fn literals_allowed(&self, command: &str) -> bool {
        // Raw source literals protect interpreter strings. Decoded shell words
        // protect quoted/escaped argument paths, including native paths with spaces.
        let raw_allowed = command
            .split(|c: char| {
                c.is_whitespace()
                    || matches!(c, '\'' | '"' | '(' | ')' | '[' | ']' | ',' | ';' | '=')
            })
            .all(|word| self.literal_allowed(word));
        raw_allowed
            && split_unquoted_segments(command).iter().all(|segment| {
                self.words(segment)
                    .is_none_or(|words| words.iter().all(|word| self.literal_allowed(word)))
            })
    }
    fn literal_allowed(&self, word: &str) -> bool {
        let word = word.trim_matches(|c| matches!(c, ':' | '<' | '>' | '&' | '|'));
        if word.is_empty() {
            return true;
        }
        let file_url_path = word
            .strip_prefix("file://")
            .and_then(|_| url::Url::parse(word).ok())
            .and_then(|url| url.to_file_path().ok());
        if word.contains("://") && file_url_path.is_none() {
            return true;
        }
        let word = file_url_path.as_ref().map_or_else(
            || word.to_owned(),
            |path| path.to_string_lossy().into_owned(),
        );
        let word = ["${HOME}", "$HOME", "%USERPROFILE%"]
            .iter()
            .find_map(|prefix| word.strip_prefix(prefix).map(|rest| format!("~{rest}")))
            .unwrap_or(word);
        if protected_path(Path::new(&word)) {
            return false;
        }
        let candidate = word
            .strip_prefix("~/")
            .and_then(|tail| self.policy.home_dir.as_ref().map(|home| home.join(tail)))
            .unwrap_or_else(|| PathBuf::from(&word));
        let candidate = if candidate.is_absolute() {
            candidate
        } else {
            self.policy.action_dir.join(candidate)
        };
        !protected_path(&candidate)
            && !resolve_ancestor(&candidate).is_ok_and(|p| protected_path(&p))
    }
    fn risk(&self, command: &str) -> CommandRisk {
        let mut saw_medium = false;

        for segment in split_unquoted_segments(command) {
            let Some(words) = self.words(&segment) else {
                saw_medium = true;
                continue;
            };
            let Some(base_raw) = words.first() else {
                continue;
            };
            let base = normalized_command_name(base_raw);
            let args: Vec<String> = words
                .iter()
                .skip(1)
                .map(|word| word.to_ascii_lowercase())
                .collect();
            let joined_segment = words.join(" ").to_ascii_lowercase();

            if matches!(
                base.as_str(),
                "mkfs"
                    | "dd"
                    | "shutdown"
                    | "reboot"
                    | "halt"
                    | "poweroff"
                    | "sudo"
                    | "su"
                    | "mount"
                    | "umount"
                    | "iptables"
                    | "ufw"
                    | "firewall-cmd"
                    | "useradd"
                    | "userdel"
                    | "usermod"
                    | "passwd"
            ) {
                return CommandRisk::High;
            }

            if joined_segment.contains("rm -rf /")
                || joined_segment.contains("rm -fr /")
                || joined_segment.contains(":(){:|:&};:")
            {
                return CommandRisk::High;
            }

            let medium = match base.as_str() {
                "git" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "commit"
                            | "push"
                            | "reset"
                            | "clean"
                            | "rebase"
                            | "merge"
                            | "cherry-pick"
                            | "revert"
                            | "branch"
                            | "checkout"
                            | "switch"
                            | "tag"
                    )
                }),
                "npm" | "pnpm" | "yarn" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "install" | "add" | "remove" | "uninstall" | "update" | "publish"
                    )
                }),
                "cargo" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "add" | "remove" | "install" | "clean" | "publish"
                    )
                }),
                "touch" | "mkdir" | "mv" | "cp" | "ln" | "rm" | "chmod" | "chown" | "curl"
                | "wget" | "nc" | "ncat" | "netcat" | "scp" | "ssh" | "ftp" | "telnet" => true,
                _ => false,
            };

            let medium = medium || is_command_executor(base.as_str());

            saw_medium |= medium;
        }

        if saw_medium {
            CommandRisk::Medium
        } else {
            CommandRisk::Low
        }
    }

    /// Legacy supervised allowlist query; never authorizes execution or consumes a budget.
    #[must_use]
    pub fn is_command_allowed(&self, command: &str) -> bool {
        if !self.policy.enabled {
            return true;
        }
        if self.policy.autonomy == CommandAutonomy::ReadOnly {
            return false;
        }
        let native = native_command(command, self.policy.shell_dialect);
        let command = &self.shell_source(&native);

        if self.policy.autonomy == CommandAutonomy::Full {
            return true;
        }

        if self.has_native_execution(command) {
            return false;
        }
        if command.contains('`')
            || command.contains("$(")
            || command.contains("${")
            || command.contains("<(")
            || command.contains(">(")
        {
            return false;
        }

        if contains_unquoted_char(command, '>') {
            return false;
        }

        if command
            .split_whitespace()
            .any(|w| w == "tee" || w.ends_with("/tee"))
        {
            return false;
        }

        if contains_unquoted_single_ampersand(command) {
            return false;
        }

        let segments = split_unquoted_segments(command);
        for segment in &segments {
            if has_leading_env_assignment(segment) || has_dangerous_env_prefix(segment) {
                return false;
            }

            let Some(words) = self.words(segment) else {
                return false;
            };
            let base_raw = words.first().map_or("", String::as_str);
            let base_cmd = command_basename(base_raw);

            if base_cmd.is_empty() {
                continue;
            }

            if !self
                .policy
                .allowed_commands
                .iter()
                .any(|allowed| allowed == base_cmd)
            {
                return false;
            }

            let args: Vec<String> = words
                .iter()
                .skip(1)
                .map(|word| word.to_ascii_lowercase())
                .collect();
            if !Self::is_args_safe(base_cmd, &args) {
                return false;
            }
        }

        segments.iter().any(|s| {
            let s = skip_env_assignments(s.trim());
            s.split_whitespace().next().is_some_and(|w| !w.is_empty())
        })
    }

    fn is_args_safe(base: &str, args: &[String]) -> bool {
        let base = base.to_ascii_lowercase();
        if is_command_executor(base.as_str()) {
            return false;
        }

        match base.as_str() {
            "find" => !args
                .iter()
                .any(|arg| arg == "-exec" || arg == "-ok" || arg == "-execdir" || arg == "-okdir"),
            "git" => !args.iter().any(|arg| {
                arg == "config"
                    || arg.starts_with("config.")
                    || arg == "alias"
                    || arg.starts_with("alias.")
                    || arg == "-c"
            }),
            "date" => args.is_empty(),
            _ => true,
        }
    }
}

#[cfg(test)]
#[path = "command_scope_tests.rs"]
mod tests;
