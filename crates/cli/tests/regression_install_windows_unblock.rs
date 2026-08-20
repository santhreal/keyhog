//! Windows installs should clear Mark-of-the-Web after staging keyhog.exe.

fn ps_function<'a>(script: &'a str, name: &str) -> &'a str {
    let marker = format!("function {name}");
    let start = script
        .find(&marker)
        .unwrap_or_else(|| panic!("install.ps1 missing {marker}"));
    let tail = &script[start..];
    let end = tail.find("\nfunction ").unwrap_or(tail.len());
    &tail[..end]
}

fn assert_in_order(haystack: &str, needles: &[&str]) {
    let mut offset = 0;
    for needle in needles {
        let rest = &haystack[offset..];
        let found = rest
            .find(needle)
            .unwrap_or_else(|| panic!("missing `{needle}` after byte {offset}"));
        offset += found + needle.len();
    }
}

#[test]
fn powershell_installer_unblocks_staged_binary() {
    let script = include_str!("../../../install.ps1");
    assert!(
        script.contains("function Clear-MarkOfTheWeb"),
        "install.ps1 must define a single Mark-of-the-Web cleanup helper"
    );
    assert!(
        script.contains("Get-Command Unblock-File"),
        "cleanup helper must use PowerShell's Unblock-File when available"
    );
    assert!(
        script.contains("Clear-MarkOfTheWeb -Path $dest"),
        "Stage-Install must unblock the final keyhog.exe path after Move-Item"
    );
}

#[test]
fn powershell_installer_explains_smartscreen_if_unblock_fails() {
    let script = include_str!("../../../install.ps1");
    assert!(
        script.contains("SmartScreen prompts"),
        "install.ps1 must explain what to do if Windows still shows SmartScreen"
    );
    assert!(
        script.contains("verify the SHA256 above"),
        "SmartScreen guidance must tie the operator back to the checksum proof"
    );
}

#[test]
fn powershell_upgrade_path_backs_up_before_overwrite() {
    let script = include_str!("../../../install.ps1");
    let stage_install = ps_function(script, "Stage-Install");

    assert_in_order(
        stage_install,
        &[
            "$Script:InstallBackup = $null",
            "if (Test-Path $dest)",
            "Copy-Item -Force $dest $backup",
            "$Script:InstallBackup = $backup",
            "Move-Item -Force $tmp $dest",
        ],
    );
    assert!(
        stage_install
            .contains("Refusing to overwrite it - your current install is left untouched.")
            && stage_install.contains("Remove-Item -Force $tmp -ErrorAction SilentlyContinue"),
        "backup failure must abort before touching the existing keyhog.exe"
    );
}

#[test]
fn powershell_finalize_restores_or_removes_after_failed_health_check() {
    let script = include_str!("../../../install.ps1");
    let finalize_install = ps_function(script, "Finalize-Install");
    let restore_install = ps_function(script, "Restore-PreviousInstallOrRemove");

    assert_in_order(
        finalize_install,
        &[
            "if (-not (Invoke-AutorouteCalibration -BinPath $BinPath))",
            "Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote \"Removed the uncalibrated binary; no working keyhog was overwritten.\"",
            "return $false",
            "if ($Script:InstallBackup) { Remove-Item -Force $Script:InstallBackup",
            "return $true",
            "Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote \"Removed the non-runnable download; no working keyhog was overwritten.\"",
        ],
    );
    assert_in_order(
        restore_install,
        &[
            "if ($Script:InstallBackup -and (Test-Path $Script:InstallBackup))",
            "Move-Item -Force $Script:InstallBackup $BinPath",
            "Rolled back to your previous working keyhog",
            "} else {",
            "Remove-Item -Force $BinPath -ErrorAction SilentlyContinue",
            "Warn $RemovedNote",
        ],
    );
}

#[test]
fn powershell_calibration_cleanup_runs_from_finally() {
    let script = include_str!("../../../install.ps1");
    let calibration = ps_function(script, "Invoke-AutorouteCalibration");

    assert_in_order(
        calibration,
        &[
            "$tmpDir = Join-Path",
            "New-Item -ItemType Directory -Force -Path $tmpDir",
            "$dockerImagesToRemove = @()",
            "$webJobsToStop = @()",
            "} finally {",
            "foreach ($job in $webJobsToStop)",
            "Stop-Job -Job $job -ErrorAction SilentlyContinue",
            "Remove-Job -Job $job -Force -ErrorAction SilentlyContinue",
            "foreach ($image in $dockerImagesToRemove)",
            "& $dockerPath image rm -f $image *> $null",
            "} finally {",
            "Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue",
        ],
    );
    assert!(
        !calibration.contains("KEYHOG_AUTOROUTE_CALIBRATE")
            && !calibration.contains("KEYHOG_BATCH_PIPELINE")
            && !calibration.contains("KEYHOG_GPU_AUTOROUTE"),
        "PowerShell calibration must use explicit scan flags, not ambient env state that must be restored"
    );
}

#[test]
fn powershell_calibration_scan_help_inspection_fails_loud() {
    let script = include_str!("../../../install.ps1");
    let calibration = ps_function(script, "Invoke-AutorouteCalibration");

    assert!(
        !calibration.contains("scan --help 2>$null") && !calibration.contains("catch { '' }"),
        "PowerShell calibration must not hide scan --help failures and guess supported flags"
    );
    assert_in_order(
        calibration,
        &[
            "$scanHelpErr = Join-Path $tmpDir 'scan-help.err'",
            "& $BinPath scan --help 2> $scanHelpErr",
            "$scanHelpExit = $LASTEXITCODE",
            "if ($scanHelpExit -ne 0)",
            "Could not inspect installed keyhog scan --help before autoroute calibration.",
            "scan --help error: $realErr",
            "Installed keyhog scan --help returned no output; refusing to guess calibration flags.",
        ],
    );
}

#[test]
fn powershell_uninstall_delegates_then_removes_installer_integrations() {
    let script = include_str!("../../../install.ps1");
    let uninstall = ps_function(script, "Do-Uninstall");

    assert_in_order(
        uninstall,
        &[
            "Invoke-InstalledBinaryUninstall -BinPath $bin",
            "Remove-Item -Force $bin",
            "Ok \"Removed $bin\"",
            "Remove-WindowsInstallerOwnedIntegrations",
        ],
    );
    assert!(
        !uninstall.contains("Shell profile entries and completions, if any, are left in place."),
        "Windows uninstall must not claim installer-owned PATH/completion artifacts are left behind"
    );
}

#[test]
fn powershell_uninstall_helpers_clean_user_path_and_completion_files() {
    let script = include_str!("../../../install.ps1");
    let binary_uninstall = ps_function(script, "Invoke-InstalledBinaryUninstall");
    let path_cleanup = ps_function(script, "Remove-UserPathEntry");
    let completion_cleanup = ps_function(script, "Remove-InstallerOwnedPowerShellCompletion");
    let integration_cleanup = ps_function(script, "Remove-WindowsInstallerOwnedIntegrations");

    assert!(
        binary_uninstall.contains("& $BinPath uninstall --yes 2> $errFile")
            && binary_uninstall.contains("Test-WizardCommandUnavailable")
            && binary_uninstall.contains("keyhog uninstall --yes failed"),
        "PowerShell uninstall must attempt the binary-owned state cleanup and surface failures"
    );
    assert!(
        path_cleanup.contains("[Environment]::GetEnvironmentVariable(\"Path\", \"User\")")
            && path_cleanup.contains("[Environment]::SetEnvironmentVariable(\"Path\",")
            && path_cleanup.contains("[StringComparison]::OrdinalIgnoreCase"),
        "PowerShell uninstall must remove the installer-owned User PATH entry idempotently"
    );
    assert!(
        completion_cleanup.contains("Documents\\PowerShell\\Completions\\keyhog.ps1")
            && completion_cleanup.contains("Documents\\WindowsPowerShell\\Completions\\keyhog.ps1")
            && completion_cleanup.contains("Remove-Item -Force $path"),
        "PowerShell uninstall must remove known completion files from both PowerShell profile roots"
    );
    assert!(
        integration_cleanup.contains("Remove-UserPathEntry -Path $InstallDir")
            && integration_cleanup.contains("Remove-InstallerOwnedPowerShellCompletion"),
        "PowerShell uninstall integration cleanup must own PATH and completion artifacts"
    );
}

/// WHY: the sidecar seeds the compiled-matcher cache, so an unverified or
/// hostile archive plants files outside it, and a half-seeded cache is worse
/// than none. Ordering IS the contract: verify -> validate -> backup -> seed
/// -> finalize, with a cache restore on every failure edge.
#[test]
fn powershell_installer_verifies_and_seeds_the_local_gpu_literal_sidecar() {
    let script = include_str!("../../../install.ps1");
    let sidecar_stage = ps_function(script, "Stage-LocalGpuLiteralSidecar");
    let sidecar_check = ps_function(script, "Test-GpuLiteralSidecarArchive");
    let sidecar_install = ps_function(script, "Install-VerifiedGpuLiteralSidecar");
    let cache_backup = ps_function(script, "Backup-GpuProgramsCacheForInstall");
    let cache_restore = ps_function(script, "Restore-GpuProgramsCacheBackup");
    let stage_install = ps_function(script, "Stage-Install");
    let do_install = ps_function(script, "Do-Install");

    assert_in_order(
        sidecar_stage,
        &[
            "$FromFile.gpu-literals.tar.gz",
            // A missing sidecar is no longer fatal: nothing ships one, so the
            // installer compiles the matchers from the installed binary. Order
            // still matters for a sidecar that IS supplied.
            "$Script:GpuLiteralsFromBinary = $true",
            "Verify-LocalSignature",
            "Verify-LocalChecksum",
            "No local checksum file found beside -FromFile GPU literal sidecar",
            "Test-GpuLiteralSidecarArchive -ArchivePath $sidecarPath",
        ],
    );
    assert!(
        sidecar_check.contains("tar.exe")
            && sidecar_check.contains("$tarPath = $tar.Path")
            && !sidecar_check.contains("$tar.Source")
            && sidecar_check.contains("-tzf $ArchivePath")
            && sidecar_check.contains("^[A-Za-z]:")
            && sidecar_check.contains("(^|[\\\\/])\\.\\.[\\s\\.]*([\\\\/]|$)")
            && sidecar_check.contains("-tvzf $ArchivePath")
            && sidecar_check.contains("$global:LASTEXITCODE = 0")
            && sidecar_check.contains("if (-not $? -or $LASTEXITCODE -ne 0)")
            && sidecar_check.contains("$entryKind -eq 'l' -or $entryKind -eq 'h'"),
        "PowerShell sidecar archive validation must reject traversal plus symlink/hardlink tar entries"
    );
    assert!(
        sidecar_install.contains("Get-GpuProgramsCacheDirForInstall")
            && sidecar_install.contains("keyhog-gpu-literals")
            && sidecar_install.contains("Get-ChildItem -Path $extractDir -Filter '*.bin'")
            && sidecar_install.contains("Move-Item -Force -Path $tmpTarget"),
        "PowerShell sidecar install must seed verified .bin artifacts into the runtime program cache"
    );
    assert!(
        cache_backup.contains("Copy-Item -Recurse -Force -Path $programsDir")
            && cache_backup.contains("$Script:GpuProgramsCacheWasMissing = $true")
            && cache_restore.contains("Remove-Item -Recurse -Force $programsDir")
            && cache_restore.contains(
                "Move-Item -Force -Path (Join-Path $Script:GpuProgramsCacheBackupPath 'programs')"
            )
            && cache_restore.contains("Clear-GpuProgramsCacheBackup"),
        "PowerShell installer must be able to roll back GPU literal cache state when final verification fails"
    );
    assert_in_order(
        stage_install,
        &[
            "Verify-LocalSignature",
            "Verify-LocalChecksum -BinaryPath $tmp -SumFile $localSum",
            "Stage-LocalGpuLiteralSidecar",
            "Remove-Item -Force $tmp -ErrorAction SilentlyContinue",
            "Clear-GpuLiteralSidecarTemp",
            "exit 1",
            "New-Item -ItemType Directory -Force -Path $InstallDir",
        ],
    );
    assert_in_order(
        do_install,
        &[
            "$bin = Stage-Install",
            "Backup-GpuProgramsCacheForInstall",
            "Install-VerifiedGpuLiteralSidecar",
            "Restore-GpuProgramsCacheBackup",
            "Rollback-StagedInstallAfterSidecarFailure -BinPath $bin",
            "Install failed while seeding shipped GPU literal artifacts.",
            "Finalize-Install -BinPath $bin",
            "Restore-GpuProgramsCacheBackup",
            "Clear-GpuLiteralSidecarTemp",
            "Install failed verification; see above.",
            "Clear-GpuProgramsCacheBackup",
            "Ensure-OnPath",
        ],
    );
}

/// WHY: install.sh verifies a sibling `.minisig` against the pinned key before
/// it overwrites anything. install.ps1 must do the same, or Windows silently
/// gets a weaker install path than Linux and macOS for the identical bundle.
/// Does not catch a correct signature over the wrong artifact; the checksum
/// binding covers that.
#[test]
fn powershell_installer_verifies_a_local_signature_with_the_pinned_key() {
    let script = include_str!("../../../install.ps1");
    let verify = ps_function(script, "Verify-LocalSignature");

    assert!(
        verify.contains("-P $Script:ReleasePublicKey"),
        "local signature verification must use the pinned release key"
    );
    assert!(
        verify.contains(
            "Refusing to install an artifact signed by the wrong key or modified after signing."
        ),
        "a failed signature must refuse the install, not warn"
    );
    assert!(
        verify.contains("minisign is required to verify the supplied local signature"),
        "a missing minisign must fail closed with remediation, not skip verification"
    );
}
