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
#   -Version v0.5.30      pin a release tag
#   -InstallDir PATH      override $env:KEYHOG_INSTALL
#   -Yes                  non-interactive: accept defaults, no prompts
#   -NoColor              disable ANSI colors
#
# Env overrides (same effect as the flags):
#   $env:KEYHOG_VERSION, $env:KEYHOG_INSTALL, $env:NO_COLOR

[CmdletBinding()]
param(
    [switch]$Repair,
    [switch]$Diagnose,
    [switch]$Uninstall,
    [switch]$Yes,
    [switch]$NoColor,
    [string]$Version = $env:KEYHOG_VERSION,
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
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
        $Script:Tag = $release.tag_name
    } catch {
        Err "Could not resolve latest release tag from GitHub API: $_"
        Err "Try -Version v0.5.30 (or another known tag) explicitly."
        exit 1
    }
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
    Invoke-WebRequest -Uri $url -OutFile $OutPath -UseBasicParsing
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

function Stage-Install {
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Download-Asset -Name $Script:Asset -OutPath $tmp
    } catch {
        Err "Download failed. Is the release published yet? Browse https://github.com/$Repo/releases"
        Err "Underlying error: $_"
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        exit 1
    }
    if (-not (Verify-Checksum -BinaryPath $tmp -AssetName $Script:Asset)) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        exit 1
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir 'keyhog.exe'
    Move-Item -Force $tmp $dest
    return $dest
}

function Verify-Install {
    param($BinPath)
    try {
        $v = & $BinPath --version 2>&1
        Ok "Installed $v"
    } catch {
        Err "Installed binary at $BinPath does not run. The download may be corrupt."
        exit 1
    }
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
            & (Join-Path $InstallDir 'keyhog.exe') completions powershell > $file
            Ok "  Completions at $file. Add 'Import-Module $file' to your `$PROFILE."
        } catch {
            Warn "  completions subcommand not in this build, skipping (upgrade to v0.5.30+)."
            Remove-Item -Force $file -ErrorAction SilentlyContinue
        }
    }

    if (Confirm-Choice "Wire keyhog into a Claude Code pre-tool hook?" 'N') {
        try { & (Join-Path $InstallDir 'keyhog.exe') hook install --agent claude-code }
        catch { Warn "  hook subcommand not in this build, skipping (upgrade to v0.5.30+)." }
    }
}

# ============================================================
# modes
# ============================================================

function Do-Install {
    Resolve-Asset
    Resolve-Tag
    Show-Summary
    if ($Script:Interactive -and -not $Yes) {
        if (-not (Confirm-Choice "Proceed with this install?" 'Y')) { Warn "Aborted."; return }
    }
    $bin = Stage-Install
    Verify-Install -BinPath $bin
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
        Verify-Install -BinPath $bin
        return
    }
    Say "Found existing binary: $bin"
    try {
        & $bin --version > $null 2>&1
        Ok "Binary runs cleanly. Re-downloading $($Script:Asset) anyway (--repair)."
    } catch {
        Warn "Existing binary does not run. Replacing with $($Script:Asset)."
    }
    $newBin = Stage-Install
    Verify-Install -BinPath $newBin
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
