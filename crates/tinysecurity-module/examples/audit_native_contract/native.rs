//! Loaded permissions tied to the actual OS sink, including precommit rotation denial.
use super::{audit_config, module_peer};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::Duration,
};
use tinybus::{
    Connection,
    broker::Broker,
    module::{ModuleHost, ModuleState},
    transport::memory::MemoryBus,
};
use tinysecurity_bus::{
    AccessTier, AuditCorrelation2, AuditedRequest2, CallerContext, Check, CheckAuditedResponse2,
    CheckRequest, ModuleConfig, Verdict, names,
};

fn namespace() -> std::result::Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let directory = tempfile::tempdir()?;
    #[cfg(windows)]
    let directory = tempfile::tempdir_in(
        std::env::var_os("TINYSECURITY_AUDIT_TEST_ROOT")
            .ok_or("audit namespace not provisioned")?,
    )?;
    #[cfg(windows)]
    provision(directory.path())?;
    #[cfg(unix)]
    let path = directory.path().canonicalize()?.join("audit");
    #[cfg(windows)]
    let path = directory.path().join("audit");
    #[cfg(unix)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(unix)]
    options
        .open(path.with_file_name("audit.journal"))?
        .sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path.with_file_name("audit.journal"))?
            .permissions()
            .mode()
            & 0o777;
        eprintln!("audit-stage=native-journal-installer mode={mode}");
        assert_eq!(
            mode, 0o600,
            "the fixture must restrict the authority before module initialization"
        );
    }
    Ok((directory, path))
}

#[cfg(windows)]
const NAMESPACE_INSTALL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
function Get-ExceptionKind {
    param($exception)
    switch ($exception.GetType().FullName) {
        'System.UnauthorizedAccessException' { 1 }
        'System.ArgumentException' { 2 }
        'System.InvalidOperationException' { 3 }
        'System.Management.Automation.CommandNotFoundException' { 4 }
        'System.Management.Automation.MethodInvocationException' { 5 }
        'System.Management.Automation.PSArgumentException' { 6 }
        'System.ComponentModel.Win32Exception' { 7 }
        'System.Management.Automation.ProviderInvocationException' { 9 }
        'System.Management.Automation.CmdletInvocationException' { 10 }
        'System.Management.Automation.ActionPreferenceStopException' { 11 }
        'System.Management.Automation.ParameterBindingException' { 12 }
        'System.Management.Automation.ItemNotFoundException' { 13 }
        'System.Management.Automation.DriveNotFoundException' { 14 }
        'System.Management.Automation.RuntimeException' { 15 }
        'System.Management.Automation.SessionStateUnauthorizedAccessException' { 16 }
        'System.Security.AccessControl.PrivilegeNotHeldException' { 17 }
        'System.Security.SecurityException' { 18 }
        'System.NotSupportedException' { 19 }
        'System.Management.Automation.PSInvalidOperationException' { 20 }
        'System.Management.Automation.ParentContainsErrorRecordException' { 21 }
        'System.Management.Automation.PSNotSupportedException' { 22 }
        'System.Management.Automation.ParameterBindingValidationException' { 23 }
        'System.Management.Automation.ParameterBindingArgumentTransformationException' { 24 }
        'System.Management.Automation.PSArgumentNullException' { 25 }
        'System.Management.Automation.PSArgumentOutOfRangeException' { 26 }
        'System.IO.IOException' { 27 }
        'System.IO.DirectoryNotFoundException' { 28 }
        'System.IO.FileNotFoundException' { 29 }
        'System.Management.Automation.PSInvalidCastException' { 30 }
        'System.SystemException' { 31 }
        default { 8 }
    }
}
$stage = 1
try {
    Write-Output "audit-native-installer stage=$stage"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $stage = 2; Write-Output "audit-native-installer stage=$stage"
    $stage = 3; Write-Output "audit-native-installer stage=$stage"
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $stage = 4; Write-Output "audit-native-installer stage=$stage"
    $stage = 5; Write-Output "audit-native-installer stage=$stage"
    $acl.SetOwner($identity.User)
    $stage = 6; Write-Output "audit-native-installer stage=$stage"
    $stage = 7; Write-Output "audit-native-installer stage=$stage"
    $acl.SetAccessRuleProtection($true, $false)
    $stage = 8; Write-Output "audit-native-installer stage=$stage"
    $stage = 9; Write-Output "audit-native-installer stage=$stage"
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity.User, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $stage = 10; Write-Output "audit-native-installer stage=$stage"
    $stage = 11; Write-Output "audit-native-installer stage=$stage"
    [void]$acl.AddAccessRule($rule)
    $stage = 12; Write-Output "audit-native-installer stage=$stage"
    $stage = 13; Write-Output "audit-native-installer stage=$stage"
    # Do not depend on PowerShell cmdlet resolution to persist this ACL.
    # The .NET API persists the identical owner and protected access rules.
    [System.IO.Directory]::SetAccessControl($env:TINYSECURITY_NATIVE_DIRECTORY, $acl)
    # An elevated token can default a new file's owner to Administrators.
    # Install the empty authority with the actual user owner before any bytes;
    # retain the directory's restricted inherited access rule unchanged.
    $journalPath = [IO.Path]::Combine($env:TINYSECURITY_NATIVE_DIRECTORY, 'audit.journal')
    # Generic read/write does not grant WRITE_OWNER to SetAccessControl.
    # The rights overload grants TakeOwnership on this create-new handle only.
    $journalRights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $journal = [IO.FileStream]::new($journalPath, [IO.FileMode]::CreateNew, $journalRights, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::None)
    try {
        $journalAcl = $journal.GetAccessControl()
        $journalAcl.SetOwner($identity.User)
        $journal.SetAccessControl($journalAcl)
        $journal.Flush($true)
    } finally { $journal.Dispose() }
    $stage = 14; Write-Output "audit-native-installer stage=$stage"
} catch {
    # Never render the error record: messages may contain paths or identities.
    $exception = $_.Exception
    $wrapper = Get-ExceptionKind $exception
    # PowerShell can wrap provider errors in ErrorRecord instead of InnerException.
    # Inspect only bounded exception links; no record or message is rendered.
    for ($depth = 0; $depth -lt 8; $depth++) {
        $candidate = $exception.InnerException
        if ($null -eq $candidate -and $exception -is [System.Management.Automation.RuntimeException]) {
            $candidate = $exception.ErrorRecord.Exception
        }
        if ($null -eq $candidate -or [object]::ReferenceEquals($candidate, $exception)) {
            break
        }
        $exception = $candidate
    }
    $kind = Get-ExceptionKind $exception
    $category = [int]$_.CategoryInfo.Category
    if ($category -lt 0 -or $category -gt 31) { $category = 31 }
    $native = 0
    if ($exception -is [System.ComponentModel.Win32Exception]) {
        $native = $exception.NativeErrorCode
    }
    $command = 0
    if ($kind -eq 4 -and $_.CategoryInfo.TargetName -eq 'Set-Acl') {
        $command = 1
    }
    if ($command -eq 0 -and $_.InvocationInfo.MyCommand.Name -eq 'Set-Acl') {
        $command = 2
    }
    $hresult = $exception.HResult
    Write-Output "audit-native-installer stage=$stage error=$kind hresult=$hresult native=$native command=$command wrapper=$wrapper category=$category"
    exit 1
}
"#;

#[cfg(windows)]
fn provision(path: &Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    provision_with_script(path, NAMESPACE_INSTALL_SCRIPT)
}

#[cfg(windows)]
fn provision_with_script(
    path: &Path,
    script: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("TINYSECURITY_NATIVE_DIRECTORY", path)
        .output()?;
    for line in installer_diagnostics(&output.stdout)? {
        eprintln!("{line}");
    }
    if !output.status.success() {
        return Err("native audit namespace installer failed".into());
    }
    Ok(())
}

// Validate the complete stream before displaying any child output. Even a
// PowerShell startup error must never expose an unrecognized record.
#[cfg(any(windows, test))]
fn installer_diagnostics(stdout: &[u8]) -> Result<Vec<&str>, &'static str> {
    if stdout.len() > 4096 {
        return Err("native audit installer diagnostics invalid");
    }
    let text =
        std::str::from_utf8(stdout).map_err(|_| "native audit installer diagnostics invalid")?;
    let lines: Vec<_> = text.lines().collect();
    if lines.is_empty() || lines.len() > 15 {
        return Err("native audit installer diagnostics invalid");
    }
    for line in &lines {
        let fields: Vec<_> = line.split(' ').collect();
        if !matches!(fields.len(), 2 | 8) || fields[0] != "audit-native-installer" {
            return Err("native audit installer diagnostics invalid");
        }
        let number = |field: &str, key: &str, min: i32, max: i32| {
            field
                .strip_prefix(key)
                .and_then(|value| {
                    value.parse::<i32>().ok().filter(|parsed| {
                        (min..=max).contains(parsed) && parsed.to_string() == value
                    })
                })
                .is_some()
        };
        if !number(fields[1], "stage=", 1, 14)
            || (fields.len() == 8
                && (!number(fields[2], "error=", 1, 31)
                    || !number(fields[3], "hresult=", i32::MIN, i32::MAX)
                    || !number(fields[4], "native=", 0, i32::MAX)
                    || !number(fields[5], "command=", 0, 2)
                    || !number(fields[6], "wrapper=", 1, 31)
                    || !number(fields[7], "category=", 0, 31)))
        {
            return Err("native audit installer diagnostics invalid");
        }
    }
    Ok(lines)
}

fn request(tail: u64) -> AuditedRequest2<CheckRequest> {
    AuditedRequest2 {
        request: CheckRequest {
            caller: CallerContext {
                agent: "agent".into(),
                call_id: format!("bearer private-native-operation-{tail}"),
                tier: AccessTier::Full,
                ..Default::default()
            },
            checks: vec![Check::LocalDiagnostic {}],
        },
        audit: AuditCorrelation2 {
            event_id: format!("{:032x}", tail + 1),
            expected_tail: tail,
            generation: 1,
        },
    }
}

// Diagnostic categories contain no SDK reason strings or serialized identities.
fn init_category(state: &ModuleState) -> u8 {
    match state {
        ModuleState::Discovered => 1,
        ModuleState::Rejected { .. } => 2,
        ModuleState::Unresolved { .. } => 3,
        ModuleState::Resolved => 4,
        ModuleState::Initializing => 5,
        ModuleState::Ready => 6,
        ModuleState::Serving => 7,
        ModuleState::Faulted { .. } => 8,
        ModuleState::Failed { .. } => 9,
        ModuleState::Stopped => 10,
        ModuleState::Disabled => 11,
    }
}

#[cfg(all(windows, test))]
fn engine_category(error: tinysecurity::audit::Error) -> u8 {
    use tinysecurity::audit::Error;
    match error {
        Error::Sanitation => 1,
        Error::Conflict => 2,
        Error::Permissions => 3,
        Error::Busy => 4,
        Error::Storage => 5,
        Error::Unsupported => 6,
    }
}

pub(super) async fn verify(library: &Path) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = namespace()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let client = Connection::connect(bus.connect().await?).await?;
    let mut audit = audit_config(true);
    // This fixture verifies real durable receipts and OS access controls, not
    // a synthetic short deadline. Dedicated worker tests cover timeout behavior.
    audit.timeout_ms = 30_000;
    audit.native_path = Some(path.to_str().ok_or("native fixture path encoding")?.into());
    audit.max_bytes = 2048;
    host.load_file_with_config(
        library,
        serde_json::to_value(ModuleConfig {
            trusted_host: client.unique_name().map(|peer| peer.as_str().to_owned()),
            audit: Some(audit),
            ..Default::default()
        })?,
    )?;
    let module = match module_peer(&client).await {
        Ok(module) => module,
        Err(error) => {
            // The SDK faults asynchronously when setup fails. Observe only its
            // typed state; never print the associated reason or module identity.
            for module in host.list() {
                println!(
                    "audit-native-init stage=1 category={}",
                    init_category(&module.state)
                );
            }
            return Err(error);
        }
    };
    let proxy = client.proxy(module.as_str(), names::OBJECT_PATH, names::INTERFACE)?;
    assert!(proxy.attestation().await?.is_some());
    verify_stale_native_permission(&proxy).await?;
    let first: CheckAuditedResponse2 = proxy
        .call_confidential(names::methods::CHECK_AUDITED2, (request(0),))
        .await?;
    let health = match first.audit.health {
        tinysecurity_bus::AuditHealth2::Healthy => 1,
        tinysecurity_bus::AuditHealth2::Degraded => 2,
        tinysecurity_bus::AuditHealth2::Denied => 3,
    };
    let verdict = match first.decision.decisions[0].verdict {
        Verdict::Allow => 1,
        Verdict::RequireApproval { .. } => 2,
        Verdict::Deny { .. } => 3,
    };
    eprintln!(
        "audit-native-stage=first permitted={} committed={} health={health} receipt={} verdict={verdict}",
        u8::from(first.audit.permitted),
        u8::from(first.audit.committed),
        u8::from(first.audit.receipt.is_some()),
    );
    assert!(
        first.audit.permitted
            && first.audit.committed
            && matches!(first.decision.decisions[0].verdict, Verdict::Allow)
    );
    assert_eq!(
        proxy
            .call::<CheckAuditedResponse2>(names::methods::CHECK_AUDITED2, (request(0),))
            .await?,
        first
    );
    let journal = path.with_file_name("audit.journal");
    assert!(std::fs::metadata(&journal)?.len() > 0);
    assert!(
        std::fs::read(&journal)?
            .windows(b"private-native-operation".len())
            .all(|part| part != b"private-native-operation"),
        "the actual authority must contain sanitized data only"
    );
    #[cfg(windows)]
    verify_rename_denial(&proxy, &path).await?;
    #[cfg(unix)]
    verify_permissions_denial(&proxy, &journal).await?;
    host.shutdown(Duration::from_secs(1)).await;
    task.abort();
    println!("loaded required permission is backed by the actual restricted native journal");
    Ok(())
}

#[cfg(unix)]
async fn verify_permissions_denial(
    proxy: &tinybus::Proxy,
    journal: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let before = std::fs::read(journal)?;
    std::fs::set_permissions(journal, std::fs::Permissions::from_mode(0o644))?;
    let result = proxy
        .call::<CheckAuditedResponse2>(names::methods::CHECK_AUDITED2, (request(1),))
        .await;
    // Restore the installer fixture even when the real loaded call fails.
    std::fs::set_permissions(journal, std::fs::Permissions::from_mode(0o600))?;
    let denied = result?;
    assert!(!denied.audit.permitted && !denied.audit.committed);
    assert!(denied.audit.receipt.is_none());
    assert!(
        denied
            .decision
            .decisions
            .iter()
            .all(|decision| !matches!(decision.verdict, Verdict::Allow))
    );
    assert_eq!(std::fs::read(journal)?, before);
    let permitted: CheckAuditedResponse2 = proxy
        .call(names::methods::CHECK_AUDITED2, (request(1),))
        .await?;
    assert!(permitted.audit.permitted && permitted.audit.committed);
    assert_eq!(
        permitted
            .audit
            .receipt
            .as_ref()
            .ok_or("native retry receipt absent")?
            .new_tail,
        2
    );
    assert_eq!(
        proxy
            .call::<CheckAuditedResponse2>(names::methods::CHECK_AUDITED2, (request(1),))
            .await?,
        permitted
    );
    Ok(())
}

#[cfg(windows)]
async fn verify_rename_denial(
    proxy: &tinybus::Proxy,
    path: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::fs::OpenOptionsExt;
    let pin = OpenOptions::new().read(true).share_mode(3).open(path)?;
    let journal = path.with_file_name("audit.journal");
    let mut blocked = None;
    for tail in 1..16 {
        let before = std::fs::read(&journal)?;
        let response: CheckAuditedResponse2 = proxy
            .call(names::methods::CHECK_AUDITED2, (request(tail),))
            .await?;
        if !response.audit.permitted {
            assert!(!response.audit.committed && response.audit.receipt.is_none());
            assert!(
                response
                    .decision
                    .decisions
                    .iter()
                    .all(|decision| !matches!(decision.verdict, Verdict::Allow))
            );
            assert_eq!(
                std::fs::read(&journal)?,
                before,
                "required denied rename must not journal the candidate"
            );
            blocked = Some(tail);
            break;
        }
        assert!(response.audit.committed);
    }
    let tail = blocked.ok_or("required permission never reached blocked rotation")?;
    drop(pin);
    let permitted: CheckAuditedResponse2 = proxy
        .call(names::methods::CHECK_AUDITED2, (request(tail),))
        .await?;
    assert!(permitted.audit.permitted && permitted.audit.committed);
    let receipt = permitted
        .audit
        .receipt
        .as_ref()
        .ok_or("native exact receipt absent")?;
    assert_eq!(receipt.new_tail, tail + 1);
    assert_eq!(receipt.events[0].event_id, request(tail).audit.event_id);
    assert_eq!(
        proxy
            .call::<CheckAuditedResponse2>(names::methods::CHECK_AUDITED2, (request(tail),))
            .await?,
        permitted
    );
    Ok(())
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;

async fn verify_stale_native_permission(
    proxy: &tinybus::Proxy,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let query = tinysecurity_bus::PermissionRequest2::PrivacyCheck(
        tinysecurity_bus::PrivacyCheckRequest2 {
            privacy: tinysecurity_bus::PrivacyMode::Standard,
            external: true,
            class: tinysecurity_bus::PrivacyDataClass2::Metadata,
            destination_label: "private-native-permission-destination".into(),
            risk: None,
        },
    );
    assert_eq!(format!("{query:?}"), "PermissionRequest2([REDACTED])");
    let stale: tinysecurity_bus::PermissionAuditResponse2 = proxy
        .call_confidential(
            names::methods::CHECK_PERMISSION_AUDITED2,
            (AuditedRequest2 {
                request: query,
                audit: AuditCorrelation2 {
                    event_id: "e".repeat(32),
                    expected_tail: 0,
                    generation: 0,
                },
            },),
        )
        .await?;
    assert!(stale.decision.is_none());
    assert!(!stale.audit.permitted && !stale.audit.committed);
    assert!(stale.audit.receipt.is_none());
    Ok(())
}
