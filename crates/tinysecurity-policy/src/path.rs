//! Native ancestor resolution and unconditional floor ported from `OpenHuman`.
use crate::{DenialReason, PolicyConfig};
use std::path::{Path, PathBuf};
pub(super) const CRITICAL_ROOTS: &[&str] = &[
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/system",
    "/private/etc",
    "/private/var/root",
];
pub(super) const INSTALLATION_ROOTS: &[&str] = &[
    "/bin", "/sbin", "/lib", "/lib64", "/usr", "/library", "/dev",
];
pub(super) const CREDENTIAL_COMPONENTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".oci",
    ".kube",
    "keychains",
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".npmrc",
];
/// Members of [`CREDENTIAL_COMPONENTS`] that name a single credential file rather
/// than a credential directory. A subset, so the two views cannot drift.
pub(super) const CREDENTIAL_FILE_STORES: &[&str] =
    &[".netrc", ".git-credentials", ".pgpass", ".npmrc"];
pub(super) const CREDENTIAL_PAIRS: &[(&str, &str)] = &[
    ("microsoft", "protect"),
    ("microsoft", "credentials"),
    ("microsoft", "crypto"),
    ("microsoft", "vault"),
    ("microsoft", "ngc"),
    (".docker", "config.json"),
    (".cargo", "credentials.toml"),
];
/// Windows system directories, matched under every drive letter by
/// [`windows_system_root`]; the exported vocabulary derives from this list.
pub(super) const WINDOWS_SYSTEM_ROOTS: &[&str] = &[
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
];
/// A parent-directory segment, including conservative cross-platform forms with
/// trailing spaces or dots (such as `.. ` or `...`). Windows treats exact `..`
/// as a parent component; some Windows path APIs separately normalize trailing
/// spaces or periods, while `...` can remain a distinct name. Checked on every OS.
pub(super) fn parent_segment(segment: &str) -> bool {
    segment.starts_with("..") && segment.trim_end_matches([' ', '.']).is_empty()
}
pub(super) fn denial_segment(segment: &str) -> &str {
    segment
        .split(':')
        .next()
        .unwrap_or(segment)
        .trim_end_matches([' ', '.'])
}
pub(super) fn floor(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    // Windows canonicalize emits an extended-length prefix. It must not hide
    // the system-root floor when this engine runs natively on Windows.
    let normalized = strip_native_namespace(&normalized);
    let segments: Vec<_> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    // Both slash dialects are checked on every OS. The additional macOS
    // /private aliases are protected before canonicalization too.
    if path.contains('\0')
        || segments.iter().any(|segment| parent_segment(segment))
        || credential_store(&segments)
    {
        return true;
    }
    CRITICAL_ROOTS
        .iter()
        .chain(INSTALLATION_ROOTS)
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
        || windows_system_root(normalized)
}
pub(super) fn strip_native_namespace(path: &str) -> &str {
    path.strip_prefix("//?/")
        .or_else(|| path.strip_prefix("//./"))
        .or_else(|| path.strip_prefix("/??/"))
        .unwrap_or(path)
}
pub(super) fn credential_store(segments: &[&str]) -> bool {
    let normalized: Vec<_> = segments
        .iter()
        .map(|segment| denial_segment(segment))
        .collect();
    normalized
        .iter()
        .any(|component| CREDENTIAL_COMPONENTS.contains(component))
        || normalized.windows(2).any(|pair| {
            CREDENTIAL_PAIRS
                .iter()
                .any(|&(parent, child)| pair == [parent, child])
        })
}

// Match Windows system roots on every drive, including native/extended aliases.
// This is lexical on every OS so a foreign path cannot evade the floor.
pub(super) fn windows_system_root(path: &str) -> bool {
    let components: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    let components = components
        .strip_prefix(&["globalroot"])
        .unwrap_or(&components);
    let components = components.strip_prefix(&["unc"]).unwrap_or(components);
    let admin_share = |component: &&str| {
        let bytes = component.trim_end_matches([' ', '.']).as_bytes();
        bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b'$'
    };
    let root_index = if components.get(1).is_some_and(admin_share) {
        // UNC server + administrative drive share; canonical UNC retains this form.
        2
    } else if components.first().is_some_and(|part| {
        let bytes = part.as_bytes();
        (bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
            || part.starts_with("volume{")
    }) {
        1
    } else if components.first() == Some(&"device")
        && components
            .get(1)
            .is_some_and(|part| part.starts_with("harddiskvolume"))
    {
        2
    } else {
        0
    };
    components.get(root_index).is_some_and(|part| {
        let root = part
            .split(':')
            .next()
            .unwrap_or(part)
            .trim_end_matches([' ', '.']);
        WINDOWS_SYSTEM_ROOTS.contains(&root)
    })
}
pub(super) fn valid_root(root: &str) -> bool {
    Path::new(root).is_absolute()
        && !floor(root)
        && Path::new(root)
            .canonicalize()
            .is_ok_and(|p| !floor(&p.to_string_lossy()) && p.is_dir())
}
fn resolved(path: &Path) -> std::io::Result<PathBuf> {
    // Canonicalize the nearest existing ancestor for prospective file writes.
    // A broken symlink or permission error is not treated as a missing suffix.
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for segment in suffix.iter().rev() {
                    canonical.push(segment);
                }
                return Ok(canonical);
            }
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound
                    || ancestor.symlink_metadata().is_ok()
                {
                    return Err(error);
                }
                let name = ancestor.file_name().ok_or(error)?.to_os_string();
                suffix.push(name);
                if !ancestor.pop() {
                    return Err(std::io::Error::other("no resolvable ancestor"));
                }
            }
        }
    }
}
pub(super) fn check(
    config: &PolicyConfig,
    path: &str,
    _write: bool,
) -> std::result::Result<(), DenialReason> {
    if floor(path) {
        return Err(DenialReason::Floor);
    }
    // Tilde and foreign OS paths cannot be interpreted securely on this host.
    if path.is_empty()
        || path.starts_with('~')
        || (cfg!(unix) && (path.contains('\\') || path.as_bytes().get(1) == Some(&b':')))
    {
        return Err(DenialReason::PathResolution);
    }
    let input = Path::new(path);
    // The host must resolve against the operation's real working directory.
    // Module cwd/action roots cannot stand in for that execution context.
    if !input.is_absolute() {
        return Err(DenialReason::PathResolution);
    }
    let absolute = input.to_path_buf();
    if floor(&absolute.to_string_lossy()) {
        return Err(DenialReason::Floor);
    }
    let canonical = resolved(&absolute).map_err(|_| DenialReason::PathResolution)?;
    if floor(&canonical.to_string_lossy()) {
        return Err(DenialReason::Floor);
    }
    if !config.enabled {
        return Ok(());
    }
    let action = Path::new(&config.action_dir)
        .canonicalize()
        .map_err(|_| DenialReason::PathResolution)?;
    let workspace = Path::new(&config.workspace_dir)
        .canonicalize()
        .map_err(|_| DenialReason::PathResolution)?;
    if !canonical.starts_with(action) || canonical.starts_with(workspace) {
        return Err(DenialReason::PathScope);
    }
    for forbidden in &config.forbidden_paths {
        let forbidden = resolved(Path::new(forbidden)).map_err(|_| DenialReason::PathResolution)?;
        if canonical.starts_with(forbidden) {
            return Err(DenialReason::PathScope);
        }
    }
    Ok(())
}
