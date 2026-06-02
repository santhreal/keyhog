# KeyHog installer (Windows, PowerShell 5+).
#
# Curl-pipe-iwr quick install:
#   iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex
#
# Interactive install (recommended when you want post-install wizard):
#   iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -OutFile keyhog-install.ps1
#   .\keyhog-install.ps1
#
# Modes:
#   (default)        install or upgrade keyhog
#   -Repair          detect a broken install and re-download
#   -Diagnose        print full host + binary status, make no changes
#   -Uninstall       remove the binary
#
# Common flags:
#   -Version v0.5.37      pin a release tag (default: latest release with assets)
#   -FromFile PATH        install a pre-built/pre-downloaded keyhog.exe instead
#                         of querying GitHub (offline / air-gapped / CI proving).
#                         A sibling PATH.sha256 is checksum-verified if present.
#   -InstallDir PATH      override $env:KEYHOG_INSTALL
#   -Yes                  non-interactive: accept defaults, no prompts
#   -NoColor              disable ANSI colors
#
# Env overrides (same effect as the flags):
#   $env:KEYHOG_VERSION, $env:KEYHOG_FROM_FILE, $env:KEYHOG_INSTALL, $env:NO_COLOR

[CmdletBinding()]
param(
    [switch]$Repair,
    [switch]$Diagnose,
    [switch]$Uninstall,
    [switch]$Yes,
    [switch]$NoColor,
    [string]$Version = $env:KEYHOG_VERSION,
    [string]$FromFile = $env:KEYHOG_FROM_FILE,
    [string]$InstallDir = $(if ($env:KEYHOG_INSTALL) { $env:KEYHOG_INSTALL } else { Join-Path $env:LOCALAPPDATA 'keyhog\bin' })
)

$ErrorActionPreference = 'Stop'
$Repo = 'santhsecurity/keyhog'

# ============================================================
# colors + i/o helpers
# ============================================================

$Script:UseColor = -not $NoColor -and -not $env:NO_COLOR -and ($Host.UI.SupportsVirtualTerminal)
$Script:Interactive = [Environment]::UserInteractive

function Use-Color { param($Text, $Color)
    if ($Script:UseColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Say  { param($t) Write-Host $t }
function Info { param($t) Use-Color $t 'Cyan' }
function Ok   { param($t) Use-Color $t 'Green' }
function Warn { param($t) Use-Color $t 'Yellow' }
function Err  { param($t) Use-Color $t 'Red' }
function Dim  { param($t) Use-Color $t 'DarkGray' }

function Show-Banner {
    if ($Script:Interactive) {
        Write-Host ""
        Use-Color "   KeyHog installer" 'White'
        Dim "   (secret scanner, $Repo)"
        Write-Host ""
    } else {
        Say "keyhog installer (non-interactive)"
    }
}

function Confirm-Choice {
    param($Question, [string]$Default = 'Y')
    if ($Yes) { return $true }
    if (-not $Script:Interactive) { return ($Default -in @('Y','y')) }
    $hint = if ($Default -in @('Y','y')) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $ans = Read-Host "$Question $hint"
        if ([string]::IsNullOrWhiteSpace($ans)) { $ans = $Default }
        switch -Regex ($ans) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default { Warn "Please answer y or n." }
        }
    }
}

# ============================================================
# detection
# ============================================================

function Get-Arch {
    $a = (Get-CimInstance -ClassName Win32_Processor).Architecture
    # 9 = AMD64 / x86_64.  0 = x86, 5 = ARM, 12 = ARM64.
    if ($a -eq 9) { return 'x86_64' }
    return "unsupported-$a"
}

function Get-GpuInfo {
    try {
        $gpus = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
    } catch {
        $gpus = @()
    }
    return $gpus
}

function Resolve-Asset {
    $arch = Get-Arch
    if ($arch -ne 'x86_64') {
        Err "Only Windows x86_64 is supported. (Win32 arch code: $($arch -replace 'unsupported-',''))"
        Err "ARM64 Windows native binaries are not produced by the keyhog release workflow yet."
        exit 1
    }
    $Script:Asset = 'keyhog-windows-x86_64.exe'

    $gpus = Get-GpuInfo
    $nv = $gpus | Where-Object { $_ -match 'NVIDIA' } | Select-Object -First 1
    if ($nv) {
        $Script:GpuNote = "Detected NVIDIA GPU ($nv). Installing the WGPU + SIMD Windows build. A dedicated CUDA-on-Windows variant (significantly faster on large scans) is on the roadmap."
    } elseif ($gpus.Count -gt 0) {
        $Script:GpuNote = "Detected non-NVIDIA GPU(s): $($gpus -join ', '). Installing the WGPU + SIMD Windows build."
    } else {
        $Script:GpuNote = "No GPU detected. Installing the WGPU + SIMD Windows build."
    }
}

function Resolve-Tag {
    if ($Version) { $Script:Tag = $Version; return }
    # /releases/latest can return a release with zero assets (a release
    # workflow that built but failed to upload). Walk the recent
    # releases list, take the newest tag whose assets array is non-empty.
    # This is the Windows mirror of install.sh's resolve_tag fallback.
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=10"
    } catch {
        Err "Could not query GitHub releases API: $_"
        Err "Try -Version v0.5.37 (or another known tag) explicitly."
        exit 1
    }
    foreach ($r in $releases) {
        if ($r.assets -and $r.assets.Count -gt 0) {
            $Script:Tag = $r.tag_name
            return
        }
    }
    Err "No GitHub release in the last 10 has any assets uploaded."
    Err "Try -Version v0.5.37 (or another known tag) explicitly."
    exit 1
}

function Get-CurrentBinary {
    $candidate = Join-Path $InstallDir 'keyhog.exe'
    if (Test-Path $candidate) { return $candidate }
    $cmd = Get-Command keyhog -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-CurrentVersion {
    $bin = Get-CurrentBinary
    if (-not $bin) { return $null }
    try { return (& $bin --version 2>&1 | Select-Object -First 1) } catch { return $null }
}

# ============================================================
# install flow
# ============================================================

function Download-Asset {
    param($Name, $OutPath)
    $url = "https://github.com/$Repo/releases/download/$($Script:Tag)/$Name"
    if ($Script:Interactive) { Info "Downloading $Name from $($Script:Tag)..." }
    else { Say "keyhog: downloading $url" }
    # Retry transient network failures. GitHub's CDN occasionally drops a
    # multi-MB transfer mid-stream ("The connection was closed unexpectedly"),
    # which failed the Windows install-from-scratch smoke even though the asset
    # was present and correctly named. A single Invoke-WebRequest with no retry
    # turns one flaky connection into a failed install.
    $attempts = 5
    for ($i = 1; $i -le $attempts; $i++) {
        try {
            Invoke-WebRequest -Uri $url -OutFile $OutPath -UseBasicParsing
            return
        } catch {
            if ($i -ge $attempts) { throw }
            $delay = [math]::Min(2 * $i, 10)
            Warn "  download attempt $i/$attempts failed: $($_.Exception.Message)"
            Dim  "  retrying in ${delay}s..."
            Start-Sleep -Seconds $delay
        }
    }
}

function Verify-Checksum {
    param($BinaryPath, $AssetName)
    $checksumUrl = "https://github.com/$Repo/releases/download/$($Script:Tag)/$AssetName.sha256"
    $expected = $null
    try {
        $line = Invoke-RestMethod -Uri $checksumUrl -ErrorAction Stop
        if ($line) {
            $expected = ($line -split '\s+')[0]
        }
    } catch {
        Dim "  (no .sha256 file for $($Script:Tag), skipping checksum verification)"
        return $true
    }
    if (-not $expected) {
        Dim "  (no .sha256 file for $($Script:Tag), skipping checksum verification)"
        return $true
    }
    $hash = (Get-FileHash -Algorithm SHA256 -Path $BinaryPath).Hash.ToLower()
    if ($hash -eq $expected.ToLower()) {
        Ok "SHA256 verified ($expected)."
        return $true
    }
    Err "SHA256 mismatch on $AssetName!"
    Err "  Expected: $expected"
    Err "  Got:      $hash"
    Err "Refusing to install. The download may have been corrupted or tampered with."
    return $false
}

# Verify $BinaryPath against a LOCAL checksum file $SumFile (a `<sha256>  <name>`
# line, as written by `Get-FileHash ... | Format-Table` or shipped beside a
# release asset). Used by -FromFile installs so an offline/CI install can still
# integrity-check the artifact. Returns $true on match or when the file is
# empty; $false only on an actual mismatch. Mirrors install.sh
# verify_local_checksum.
function Verify-LocalChecksum {
    param($BinaryPath, $SumFile)
    $expected = $null
    try {
        $line = (Get-Content -Path $SumFile -TotalCount 1 -ErrorAction Stop)
        if ($line) { $expected = ($line -split '\s+')[0] }
    } catch {
        Dim "  ($SumFile could not be read; skipping checksum verification)"
        return $true
    }
    if (-not $expected) {
        Dim "  ($SumFile is empty; skipping checksum verification)"
        return $true
    }
    $hash = (Get-FileHash -Algorithm SHA256 -Path $BinaryPath).Hash.ToLower()
    if ($hash -eq $expected.ToLower()) {
        Ok "SHA256 verified ($expected)."
        return $true
    }
    Err "SHA256 mismatch against $SumFile!"
    Err "  Expected: $expected"
    Err "  Got:      $hash"
    Err "Refusing to install the local binary."
    return $false
}

# Holds the path to the pre-upgrade binary backup so a failed verification can
# roll back to the previously-working binary instead of leaving the user with a
# broken one. $null when there was nothing to back up (fresh install).
$Script:InstallBackup = $null

function Stage-Install {
    $tmp = [System.IO.Path]::GetTempFileName()
    if ($FromFile) {
        # Local-binary source: install a pre-built/pre-downloaded artifact
        # instead of a GitHub release. Everything below (empty-file guard,
        # backup, atomic swap, Finalize-Install/doctor, rollback) is identical
        # to the download path - only the origin of $tmp differs. Mirrors
        # install.sh's --from-file branch.
        if (-not (Test-Path -PathType Leaf $FromFile)) {
            Err "-FromFile: no such file: $FromFile"
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            exit 1
        }
        try {
            Copy-Item -Force -Path $FromFile -Destination $tmp
        } catch {
            Err "-FromFile: could not read $FromFile : $_"
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            exit 1
        }
    } else {
        try {
            Download-Asset -Name $Script:Asset -OutPath $tmp
        } catch {
            Err "Download failed. Is the release published yet? Browse https://github.com/$Repo/releases"
            Err "Underlying error: $_"
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            exit 1
        }
    }
    # Empty-source guard (parity with install.sh): a 0-byte file would still
    # be "installed" as a do-nothing stub. This and the checksum check run
    # BEFORE any overwrite, so a pre-existing working binary is never touched.
    if ((Get-Item $tmp).Length -eq 0) {
        if ($FromFile) {
            Err "-FromFile source $FromFile is empty (0 bytes)."
        } else {
            Err "Downloaded asset $($Script:Asset) is empty (0 bytes)."
            Err "The release asset may be missing or the download was interrupted."
        }
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        exit 1
    }
    # Checksum is verified BEFORE we overwrite, so a corrupt artifact can never
    # replace a working binary. Downloads check against the release's per-asset
    # .sha256; a -FromFile install checks a sibling PATH.sha256 if the caller
    # staged one, otherwise trusts the local artifact (provenance is theirs).
    if ($FromFile) {
        $localSum = "$FromFile.sha256"
        if (Test-Path -PathType Leaf $localSum) {
            if (-not (Verify-LocalChecksum -BinaryPath $tmp -SumFile $localSum)) {
                Remove-Item -Force $tmp -ErrorAction SilentlyContinue
                exit 1
            }
        } else {
            Dim "  (no $localSum beside the binary; skipping checksum for local install)"
        }
    } elseif (-not (Verify-Checksum -BinaryPath $tmp -AssetName $Script:Asset)) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        exit 1
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir 'keyhog.exe'

    # Recoverability invariant: never destroy a working binary before the
    # replacement has proven itself. Back the current one up; Finalize-Install
    # restores it if the new binary fails to run.
    $Script:InstallBackup = $null
    if (Test-Path $dest) {
        $backup = Join-Path $InstallDir (".keyhog.bak.$PID.exe")
        try {
            Copy-Item -Force $dest $backup
            $Script:InstallBackup = $backup
        } catch {
            Err "Could not back up the existing binary at $dest."
            Err "Refusing to overwrite it - your current install is left untouched."
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            exit 1
        }
    }
    try {
        Move-Item -Force $tmp $dest
    } catch {
        Err "Could not write $dest (file in use or directory not writable?): $_"
        if ($Script:InstallBackup) { Remove-Item -Force $Script:InstallBackup -ErrorAction SilentlyContinue; $Script:InstallBackup = $null }
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        exit 1
    }
    return $dest
}

# Returns $true iff the binary runs `--version` and exits 0. The old
# Verify-Install only caught a launch failure (a thrown exception); a binary
# that launched but exited nonzero - the common corrupt / wrong-build case -
# slipped through and was reported as "Installed". Check $LASTEXITCODE too.
function Test-Binary {
    param($BinPath)
    try {
        $out = & $BinPath --version 2>&1
    } catch {
        Err "Installed binary at $BinPath could not be launched."
        Err "  $_"
        return $false
    }
    if ($LASTEXITCODE -ne 0) {
        Err "Installed binary at $BinPath ran but exited $LASTEXITCODE (--version failed)."
        Err "  output: $out"
        Err "The download may be corrupt or the wrong build for this machine."
        return $false
    }
    Ok "Installed $($out | Select-Object -First 1)"
    return $true
}

# Verify the freshly-staged binary; on failure restore the previous working
# binary (upgrade) or remove the broken download (fresh install). Returns
# $true on success. Mirrors install.sh's finalize_install.
function Finalize-Install {
    param($BinPath)
    if (Test-Binary -BinPath $BinPath) {
        if ($Script:InstallBackup) { Remove-Item -Force $Script:InstallBackup -ErrorAction SilentlyContinue; $Script:InstallBackup = $null }
        # Native post-install health check (parity with install.sh): reuses the
        # scanner's own hw_probe and runs an end-to-end scan self-test, proving
        # the binary actually detects a secret on this host. Non-fatal; a PATH
        # note shouldn't fail an otherwise-working install.
        Say ""
        try {
            # Out-Host: doctor prints to the console but its stdout must NOT
            # land on this function's output stream, or it would contaminate
            # the boolean return value (Finalize-Install is used as a predicate).
            & $BinPath doctor | Out-Host
            if ($LASTEXITCODE -ne 0) {
                Warn "keyhog doctor reported issues above; the binary is installed but may not be fully healthy."
            }
        } catch {
            Warn "Could not run 'keyhog doctor' for post-install verification: $_"
        }
        return $true
    }
    if ($Script:InstallBackup -and (Test-Path $Script:InstallBackup)) {
        Move-Item -Force $Script:InstallBackup $BinPath
        $Script:InstallBackup = $null
        Warn "Rolled back to your previous working keyhog at $BinPath."
    } else {
        Remove-Item -Force $BinPath -ErrorAction SilentlyContinue
        Warn "Removed the non-runnable download; no working keyhog was overwritten."
    }
    return $false
}

function Show-Summary {
    Info "Host: windows-$(Get-Arch)"
    Say  "  GPU note: $($Script:GpuNote)"
    Say  "  Picked asset:  $($Script:Asset)"
    Say  "  Install dir:   $InstallDir"
    Say  "  Release tag:   $($Script:Tag)"
    $existing = Get-CurrentVersion
    if ($existing) { Say "  Existing:      $existing" }
}

function Post-Install-Wizard {
    if (-not $Script:Interactive -or $Yes) { return }
    Write-Host ""
    Use-Color "Optional post-install steps" 'White'

    $pathEntries = $env:PATH -split ';'
    if ($pathEntries -notcontains $InstallDir) {
        if (Confirm-Choice "Add $InstallDir to your User PATH (persistent)?" 'Y') {
            $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if (-not $userPath) { $userPath = "" }
            if (($userPath -split ';') -notcontains $InstallDir) {
                $newPath = if ($userPath) { "$InstallDir;$userPath" } else { $InstallDir }
                [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
                Ok "  Added. Open a new shell to pick up the change."
            } else {
                Dim "  Already in User PATH."
            }
        } else {
            Dim "  Skipped. Add manually with: setx PATH `"$InstallDir;`$env:PATH`""
        }
    }

    if (Confirm-Choice "Install PowerShell completions?" 'N') {
        $dir = Join-Path $env:USERPROFILE 'Documents\PowerShell\Completions'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $file = Join-Path $dir 'keyhog.ps1'
        try {
            & (Join-Path $InstallDir 'keyhog.exe') completion powershell > $file
            Ok "  Completions at $file. Add 'Import-Module $file' to your `$PROFILE."
        } catch {
            Warn "  completions subcommand not in this build, skipping (upgrade to v0.5.30+)."
            Remove-Item -Force $file -ErrorAction SilentlyContinue
        }
    }

    if (Confirm-Choice "Install a git pre-commit hook in the current directory?" 'N') {
        try { & (Join-Path $InstallDir 'keyhog.exe') hook install }
        catch { Warn "  hook subcommand not in this build, skipping (upgrade to v0.5.30+)." }
    }
}

# ============================================================
# modes
# ============================================================

function Do-Install {
    if ($FromFile) {
        # Local-binary install: no GitHub release lookup, no network.
        # Asset/Tag are populated for Show-Summary and the verify messages only.
        $Script:Asset = [System.IO.Path]::GetFileName($FromFile)
        $Script:Tag = '(local file)'
        $Script:GpuNote = "installing local binary: $FromFile"
    } else {
        Resolve-Asset
        Resolve-Tag
    }
    Show-Summary
    if ($Script:Interactive -and -not $Yes) {
        if (-not (Confirm-Choice "Proceed with this install?" 'Y')) { Warn "Aborted."; return }
    }
    $bin = Stage-Install
    if (-not (Finalize-Install -BinPath $bin)) {
        Err "Install failed verification; see above."
        exit 1
    }
    Post-Install-Wizard
    Write-Host ""
    Use-Color "Next steps:" 'White'
    Say "  keyhog scan .            # scan the current directory"
    Say "  keyhog scan --help       # full options"
    Say "  keyhog --version         # verify"
}

function Do-Repair {
    Info "Repair mode."
    Resolve-Asset
    Resolve-Tag
    $bin = Get-CurrentBinary
    if (-not $bin) {
        Warn "No existing keyhog binary found. Installing fresh."
        $bin = Stage-Install
        if (-not (Finalize-Install -BinPath $bin)) {
            Err "Repair failed; see above."
            exit 1
        }
        Ok "Repair complete."
        return
    }
    Say "Found existing binary: $bin"
    & $bin --version > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Ok "Binary runs cleanly. Re-downloading $($Script:Asset) anyway (--repair)."
    } else {
        Warn "Existing binary does not run. Replacing with $($Script:Asset)."
    }
    $newBin = Stage-Install
    if (-not (Finalize-Install -BinPath $newBin)) {
        Err "Repair failed; your previous binary was preserved where possible (see above)."
        exit 1
    }
    Ok "Repair complete."
}

function Do-Diagnose {
    Info "Diagnostic report ($(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'))"
    Write-Host ""
    Use-Color "Host" 'White'
    Say "  OS:    windows"
    Say "  Arch:  $(Get-Arch)"
    $gpus = Get-GpuInfo
    if ($gpus.Count -gt 0) {
        Say "  GPUs:  $($gpus -join ', ')"
    } else {
        Say "  GPUs:  (none detected)"
    }
    Write-Host ""
    Use-Color "Existing install" 'White'
    $bin = Get-CurrentBinary
    if ($bin) {
        Say "  Path:    $bin"
        Say "  Version: $((Get-CurrentVersion) -or '(does not run)')"
    } else {
        Say "  (no keyhog found on PATH or in $InstallDir)"
    }
    Write-Host ""
    Use-Color "PATH" 'White'
    $pathEntries = $env:PATH -split ';'
    if ($pathEntries -contains $InstallDir) {
        Ok "  $InstallDir is on PATH."
    } else {
        Warn "  $InstallDir is NOT on PATH."
    }
    Write-Host ""
    Use-Color "Latest release" 'White'
    Resolve-Tag
    Say "  Tag: $($Script:Tag)"
    Resolve-Asset
    Say "  Would install: $($Script:Asset)"
}

function Do-Uninstall {
    $bin = Get-CurrentBinary
    if (-not $bin) { Warn "No keyhog binary found. Nothing to remove."; return }
    if (-not (Confirm-Choice "Remove $bin?" 'Y')) { Warn "Aborted."; return }
    Remove-Item -Force $bin
    Ok "Removed $bin"
    Dim "  (Shell profile entries and completions, if any, are left in place.)"
}

# ============================================================
# main
# ============================================================

Show-Banner

if ($Repair)         { Do-Repair }
elseif ($Diagnose)   { Do-Diagnose }
elseif ($Uninstall)  { Do-Uninstall }
else                 { Do-Install }
