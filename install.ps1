# keyhog install script - Windows (PowerShell 5+).
#
# Usage:
#   iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex
#
# Or with explicit install location:
#   $env:KEYHOG_INSTALL = "C:\Tools\keyhog"
#   iwr ... | iex
#
# Detects CPU arch (x86_64 only for now - Windows ARM64 native builds
# are not produced by the release workflow yet), fetches the
# corresponding binary from the latest GitHub release, drops it in
# $env:KEYHOG_INSTALL (default: %LOCALAPPDATA%\keyhog\bin), and
# verifies the install by running --version.
#
# Daemon mode is unix-only and refuses to start on Windows with a
# clear error; everything else (scan, detectors, watch, hook, etc.)
# works the same way.

$ErrorActionPreference = 'Stop'

$Repo = 'santhsecurity/keyhog'

$InstallDir = if ($env:KEYHOG_INSTALL) {
    $env:KEYHOG_INSTALL
} else {
    Join-Path $env:LOCALAPPDATA 'keyhog\bin'
}

$Arch = (Get-CimInstance -ClassName Win32_Processor).Architecture
# 9 = AMD64 / x86_64. Other Win32 architecture codes:
#   0 = x86, 5 = ARM, 12 = ARM64. We only ship x86_64 today.
if ($Arch -ne 9) {
    Write-Host "ERROR: only Windows x86_64 is supported. (CIM arch code: $Arch.)" -ForegroundColor Red
    Write-Host "       ARM64 Windows native binaries are not produced by the keyhog release workflow yet." -ForegroundColor Red
    exit 1
}
$Asset = 'keyhog-windows-x86_64.exe'

# Pick the tag. $env:KEYHOG_VERSION = 'v0.5.29' pins a specific
# release; otherwise we ask the GitHub API for the latest published
# tag. Unauthenticated API calls are rate-limited at 60/hour per IP.
if ($env:KEYHOG_VERSION) {
    $Tag = $env:KEYHOG_VERSION
} else {
    try {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
        $Tag = $Release.tag_name
    } catch {
        Write-Host "ERROR: could not resolve latest release tag from GitHub API: $_" -ForegroundColor Red
        Write-Host "       Set `$env:KEYHOG_VERSION = 'v0.5.29' (or another known tag) explicitly." -ForegroundColor Red
        exit 1
    }
}

$Url = "https://github.com/$Repo/releases/download/$Tag/$Asset"
$Dest = Join-Path $InstallDir 'keyhog.exe'

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "keyhog: downloading $Url"
try {
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
} catch {
    Write-Host "ERROR: download failed. Is the release published yet?" -ForegroundColor Red
    Write-Host "       Browse https://github.com/$Repo/releases to confirm the asset exists." -ForegroundColor Red
    Write-Host "       Underlying error: $_" -ForegroundColor Red
    exit 1
}

Write-Host "keyhog: installed $Tag to $Dest"
& $Dest --version

# Friendly PATH hint - don't touch the user's registry/profile, just
# tell them what to do.
$pathEntries = $env:PATH -split ';'
if ($pathEntries -notcontains $InstallDir) {
    Write-Host
    Write-Host "NOTE: $InstallDir is not in your PATH."
    Write-Host "      Add it for the current session:"
    Write-Host "        `$env:PATH = `"$InstallDir;`$env:PATH`""
    Write-Host "      Or persistently (User-level):"
    Write-Host "        setx PATH `"$InstallDir;`$env:PATH`""
}
