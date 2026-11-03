//! Canonical grant admission reuses the native owner filesystem policy.
use std::path::Path;
use tinysecurity_bus::{
    MAX_CREDENTIAL_ROOT_BYTES, MAX_CREDENTIAL_ROOTS, PathGrant, PathValidationResult,
    SandboxDenial2, SandboxPlanRequest2, SandboxScope2,
};
use tinysecurity_policy::{PathScope, protected_path, resolve_ancestor};
fn floor(root: &Path, scope: &SandboxScope2) -> bool {
    tinysecurity_policy::protected_subtree(root, scope.paths.home_dir.as_deref())
}
pub(crate) fn admit(
    scope: &SandboxScope2,
    paths: &PathScope,
    grants: &[PathGrant],
) -> std::result::Result<Vec<PathGrant>, SandboxDenial2> {
    let mut result = Vec::new();
    for grant in grants {
        let raw = Path::new(&grant.path);
        if !raw.is_absolute() || protected_path(raw) || floor(raw, scope) {
            return Err(SandboxDenial2::Floor);
        }
        let PathValidationResult::Allowed { resolved } =
            paths.validate_grant(&grant.path, grant.write)
        else {
            return Err(SandboxDenial2::Path);
        };
        if !scope.grant_ceiling.iter().any(|ceiling| {
            (!grant.write || ceiling.write)
                && resolve_ancestor(Path::new(&ceiling.path))
                    .is_ok_and(|root| resolved.starts_with(root))
        }) {
            return Err(SandboxDenial2::Ceiling);
        }
        result.push(PathGrant {
            path: resolved.to_str().ok_or(SandboxDenial2::Path)?.into(),
            write: grant.write,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path).then(a.write.cmp(&b.write)));
    result.dedup();
    Ok(result)
}

/// Produce the canonical deny-read list for an allow-default folder jail.
///
/// Native credential roots are derived from the registered home using the same policy
/// vocabulary as path checks. Additional roots come from the trusted host's credential
/// stores (for example, an application profile file outside home). A workspace or
/// writable grant inside a denied store cannot be confined safely and denies the plan.
pub(crate) fn credential_denials(
    scope: &SandboxScope2,
    request: &SandboxPlanRequest2,
    grants: &[PathGrant],
) -> std::result::Result<Vec<std::path::PathBuf>, SandboxDenial2> {
    use std::collections::BTreeSet;

    if request.credential_denials.len() > MAX_CREDENTIAL_ROOTS
        || request.credential_denials.iter().any(|path| {
            !path.is_absolute()
                || path.as_os_str().len() > MAX_CREDENTIAL_ROOT_BYTES
                || path.to_string_lossy().contains('\0')
                || path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
        })
    {
        return Err(SandboxDenial2::InvalidRequest);
    }

    let mut roots: BTreeSet<_> =
        tinysecurity_policy::credential_roots(scope.paths.home_dir.as_deref())
            .map_err(|_| SandboxDenial2::Floor)?
            .into_iter()
            .collect();
    for path in &request.credential_denials {
        let resolved = resolve_ancestor(path).map_err(|_| SandboxDenial2::Floor)?;
        roots.insert(path.clone());
        roots.insert(resolved);
        if roots.len() > MAX_CREDENTIAL_ROOTS * 2 {
            return Err(SandboxDenial2::InvalidRequest);
        }
    }

    let mut granted =
        vec![resolve_ancestor(&scope.paths.workspace_dir).map_err(|_| SandboxDenial2::Floor)?];
    granted.extend(
        grants
            .iter()
            .filter(|grant| grant.write)
            .map(|grant| resolve_ancestor(Path::new(&grant.path)))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| SandboxDenial2::Floor)?,
    );
    if roots
        .iter()
        .any(|root| granted.iter().any(|path| path.starts_with(root)))
    {
        return Err(SandboxDenial2::Floor);
    }

    Ok(roots.into_iter().collect())
}
#[cfg(test)]
#[path = "grants_tests.rs"]
mod tests;
