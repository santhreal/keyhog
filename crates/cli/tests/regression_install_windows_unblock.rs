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

    assert_in_order(
        finalize_install,
        &[
            "if (-not (Invoke-AutorouteCalibration -BinPath $BinPath))",
            "Move-Item -Force $Script:InstallBackup $BinPath",
            "Rolled back to your previous working keyhog",
            "Remove-Item -Force $BinPath -ErrorAction SilentlyContinue",
            "Removed the uncalibrated binary; no working keyhog was overwritten.",
        ],
    );
    assert_in_order(
        finalize_install,
        &[
            "if ($Script:InstallBackup) { Remove-Item -Force $Script:InstallBackup",
            "return $true",
            "if ($Script:InstallBackup -and (Test-Path $Script:InstallBackup))",
            "Move-Item -Force $Script:InstallBackup $BinPath",
            "Rolled back to your previous working keyhog",
            "Remove-Item -Force $BinPath -ErrorAction SilentlyContinue",
            "Removed the non-runnable download; no working keyhog was overwritten.",
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

#[test]
fn powershell_default_install_resolves_concrete_latest_before_download() {
    let script = include_str!("../../../install.ps1");
    let resolve_tag = ps_function(script, "Resolve-Tag");
    let resolve_tag_from_api = ps_function(script, "Resolve-TagFromApi");
    let resolve_redirect = ps_function(script, "Resolve-TagFromLatestRedirect");
    let resolve_operator_tag = ps_function(script, "Resolve-OperatorReleaseTag");
    let release_label = ps_function(script, "Get-ReleaseTagLabel");
    let show_summary = ps_function(script, "Show-Summary");
    let asset_url = ps_function(script, "Get-ReleaseAssetUrl");
    let download_asset = ps_function(script, "Download-Asset");
    let verify_checksum = ps_function(script, "Verify-Checksum");
    let stage_install = ps_function(script, "Stage-Install");
    let do_install = ps_function(script, "Do-Install");
    let do_repair = ps_function(script, "Do-Repair");
    let do_diagnose = ps_function(script, "Do-Diagnose");
    let github_api = ps_function(script, "Invoke-GitHubApi");

    assert!(
        resolve_tag.contains("$Script:Tag = 'latest'") && !resolve_tag.contains("api.github.com"),
        "Resolve-Tag should only normalize the requested tag; operator paths own concrete latest resolution"
    );
    assert_in_order(
        resolve_operator_tag,
        &[
            "Resolve-Tag",
            "$Script:Tag -eq 'latest'",
            "Resolve-TagFromLatestRedirect",
            "$Script:LatestReleaseAlias = $true",
            "return",
            "checking recent releases",
            "Resolve-TagFromApi",
            "$Script:LatestReleaseAlias = $true",
        ],
    );
    assert!(
        resolve_redirect.contains("Invoke-WebRequest")
            && resolve_redirect.contains("-Method Head")
            && resolve_redirect.contains("-MaximumRedirection 0")
            && resolve_redirect.contains("Headers.Location")
            && resolve_redirect.contains("releases/latest/download")
            && resolve_redirect.contains("/releases/download/([^/]+)/"),
        "PowerShell latest resolution must read the first non-API redirect before the GitHub releases API"
    );
    assert!(
        release_label.contains("$($Script:Tag) (latest)")
            && show_summary.contains("Get-ReleaseTagLabel")
            && show_summary.contains("Show-InstalledReleaseRelation"),
        "PowerShell summaries must display the concrete tag while preserving that it came from latest"
    );
    assert!(
        asset_url.contains("releases/latest/download/$Name")
            && asset_url.contains("releases/download/$($Script:Tag)/$Name"),
        "PowerShell release asset URL owner must support latest redirects and pinned tags"
    );
    assert!(
        download_asset.contains("$url = Get-ReleaseAssetUrl -Name $Name")
            && verify_checksum.contains("Get-ReleaseAssetUrl -Name \"$AssetName.sha256\""),
        "asset, signature, and checksum downloads must share the release URL owner"
    );
    assert!(
        !stage_install.contains("Latest release asset redirect did not provide")
            && !stage_install.contains("Resolve-TagFromApi"),
        "Stage-Install must not own a second late latest-resolution route"
    );
    assert_in_order(
        do_install,
        &[
            "Resolve-Asset",
            "Resolve-OperatorReleaseTag",
            "Show-Summary",
        ],
    );
    assert_in_order(do_repair, &["Resolve-Asset", "Resolve-OperatorReleaseTag"]);
    assert_in_order(
        do_diagnose,
        &[
            "Resolve-Asset",
            "Resolve-OperatorReleaseTag",
            "Would install",
        ],
    );
    assert!(
        resolve_tag_from_api.contains("api.github.com/repos/$Repo/releases?per_page=10"),
        "PowerShell API release walk must choose the newest release with assets when the latest redirect cannot prove a tag"
    );
    assert!(
        github_api.contains("$env:GITHUB_TOKEN")
            && github_api.contains("Authorization")
            && github_api.contains("Bearer $env:GITHUB_TOKEN"),
        "PowerShell release-resolution API request must honor optional GITHUB_TOKEN"
    );
}
