# KeyHog installer (Windows, PowerShell 5+).
#
# Curl-pipe-iwr quick install:
#   iwr https://raw.githubusercontent.com/santhreal/keyhog/main/install.ps1 -useb | iex
#
# Interactive install (recommended when you want post-install wizard):
#   iwr https://raw.githubusercontent.com/santhreal/keyhog/main/install.ps1 -OutFile keyhog-install.ps1
#   .\keyhog-install.ps1
#
# Modes:
#   (default)        install or upgrade keyhog
#   -Repair          detect a broken install and re-download
#   -Diagnose        print full host + binary status, make no changes
#   -Calibrate       rerun visible autoroute calibration for the installed binary
#   -Uninstall       remove the binary
#
# Common flags:
#   -Version vX.Y.Z       pin a release tag (default: latest stable complete bundle)
#   -FromFile PATH        install a pre-built/pre-downloaded keyhog.exe instead
#                         of querying GitHub (offline / air-gapped / CI proving).
#                         Requires PATH.sha256, PATH.gpu-literals.tar.gz, and
#                         PATH.gpu-literals.tar.gz.sha256 unless -Insecure is explicit.
#   -InstallDir PATH      override the default install directory
#   -Yes                  non-interactive: accept defaults, no prompts
#   -Insecure             allow install only when release signature/checksum
#                         proof is unavailable; fetched mismatches still fail
#   -NoColor              disable ANSI colors
#
# Env overrides:
#   $env:KEYHOG_VERSION, $env:GITHUB_TOKEN, $env:NO_COLOR

[CmdletBinding()]
param(
    [switch]$Repair,
    [switch]$Diagnose,
    [switch]$Calibrate,
    [switch]$Uninstall,
    [switch]$Yes,
    [switch]$NoColor,
    [switch]$Insecure,
    [string]$Version = $env:KEYHOG_VERSION,
    [string]$FromFile,
    [string]$InstallDir = $(Join-Path $env:LOCALAPPDATA 'keyhog\bin')
)

$ErrorActionPreference = 'Stop'
$Repo = 'santhreal/keyhog'
$Script:ReleasePublicKey = 'RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
$Script:InsecureInstall = [bool]$Insecure
$Script:LatestReleaseAlias = $false
$Script:GpuLiteralSidecarPath = $null
$Script:GpuProgramsCacheBackupPath = $null
$Script:GpuProgramsCacheWasMissing = $false

# ============================================================
# colors + i/o helpers
# ============================================================

$Script:UseColor = -not $NoColor -and -not $env:NO_COLOR -and ($Host.UI.SupportsVirtualTerminal)
$Script:Interactive = [Environment]::UserInteractive

function Use-Color { param($Text, $Color)
    if ($Script:UseColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Say  { param($t) Write-Host $t }
function Write-Status { param($Label, $Text, $Color) Use-Color "$Label $Text" $Color }
function Info { param($t) Write-Status 'INFO' $t 'Cyan' }
function Ok   { param($t) Write-Status 'PASS' $t 'Green' }
function Warn { param($t) Write-Status 'WARN' $t 'Yellow' }
function Err  { param($t) Write-Status 'FAIL' $t 'Red' }
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

function Get-FirstErrorLine {
    param([string]$Path, [string]$Fallback)
    $line = $null
    if ($Path -and (Test-Path $Path)) {
        $line = Get-Content -Path $Path -TotalCount 1 -ErrorAction SilentlyContinue
    }
    if ($line) { return [string]$line }
    return $Fallback
}

function Test-WizardCommandUnavailable {
    param([string]$Reason)
    return ($Reason -match '(?i)(unknown|unrecognized|invalid|no such)\s+subcommand')
}

function Warn-WizardCommandFailure {
    param(
        [string]$Label,
        [string]$ErrFile,
        [string]$UnavailableMessage,
        [string]$DirectHint,
        [string]$Fallback
    )
    $reason = Get-FirstErrorLine $ErrFile $Fallback
    if ($UnavailableMessage -and (Test-WizardCommandUnavailable $reason)) {
        Warn $UnavailableMessage
    } elseif ($reason) {
        Warn "  $Label failed: $reason"
    } else {
        Warn "  $Label failed without stderr. Run '$DirectHint' directly for details."
    }
}

function Invoke-InstalledBinaryUninstall {
    param([string]$BinPath)
    if (-not (Test-Path -PathType Leaf $BinPath)) { return }
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        & $BinPath uninstall --yes 2> $errFile
        if ($LASTEXITCODE -eq 0) { return }
        $reason = Get-FirstErrorLine $errFile ""
        if (Test-WizardCommandUnavailable $reason) {
            Warn "  installed keyhog has no uninstall subcommand; removing installer-owned files directly."
        } elseif ($reason) {
            Warn "  keyhog uninstall --yes failed: $reason"
        } else {
            Warn "  keyhog uninstall --yes failed without stderr; removing installer-owned files directly."
        }
    } catch {
        Warn "  keyhog uninstall --yes failed: $($_.Exception.Message)"
    } finally {
        Remove-Item -Force $errFile -ErrorAction SilentlyContinue
    }
}

function Normalize-PathForUserPath {
    param([string]$Path)
    try {
        return ([System.IO.Path]::GetFullPath($Path)).TrimEnd('\')
    } catch {
        return $Path.TrimEnd('\')
    }
}

function Remove-UserPathEntry {
    param([string]$Path)
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { return }
    $target = Normalize-PathForUserPath $Path
    $kept = New-Object System.Collections.Generic.List[string]
    $removed = $false
    foreach ($entry in ($userPath -split ';')) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $current = Normalize-PathForUserPath $entry
        if ([string]::Equals($current, $target, [StringComparison]::OrdinalIgnoreCase)) {
            $removed = $true
        } else {
            $kept.Add($entry)
        }
    }
    if ($removed) {
        [Environment]::SetEnvironmentVariable("Path", ($kept -join ';'), "User")
        Ok "  Removed $Path from User PATH."
    }
}

function Remove-InstallerOwnedPowerShellCompletion {
    $paths = @(
        (Join-Path $env:USERPROFILE 'Documents\PowerShell\Completions\keyhog.ps1'),
        (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Completions\keyhog.ps1')
    )
    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }
        try {
            Remove-Item -Force $path
            Ok "  Removed PowerShell completion: $path"
        } catch {
            Warn "  Could not remove PowerShell completion ${path}: $($_.Exception.Message)"
        }
    }
}

function Remove-WindowsInstallerOwnedIntegrations {
    Remove-UserPathEntry -Path $InstallDir
    Remove-InstallerOwnedPowerShellCompletion
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
        $Script:GpuNote = "Detected NVIDIA GPU ($nv). Installing the portable no-system-library Windows build (no Hyperscan, WGPU, or CUDA asset in the current release)."
    } elseif ($gpus.Count -gt 0) {
        $Script:GpuNote = "Detected non-NVIDIA GPU(s): $($gpus -join ', '). Installing the portable no-system-library Windows build (no Hyperscan, WGPU, or CUDA asset in the current release)."
    } else {
        $Script:GpuNote = "No GPU detected. Installing the portable no-system-library Windows build (no Hyperscan, WGPU, or CUDA asset in the current release)."
    }
}

function Resolve-Tag {
    if ($Version) {
        # keyhog release tags are all v-prefixed (vX.Y.Z). Accept a bare
        # semver too (`-Version X.Y.Z`): a download URL built from the
        # un-prefixed tag 404s. Normalise a digit-leading
        # version to the v-prefixed tag; leave an explicit v… or any other
        # ref untouched.
        if ($Version -match '^[0-9]') { $Script:Tag = "v$Version" } else { $Script:Tag = $Version }
        return
    }
    $Script:Tag = 'latest'
}

function Invoke-GitHubApi {
    param([string]$Uri)
    $headers = @{}
    if ($env:GITHUB_TOKEN) {
        $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN"
        $headers['X-GitHub-Api-Version'] = '2022-11-28'
    }
    if ($headers.Count -gt 0) {
        return Invoke-RestMethod -Uri $Uri -Headers $headers -ErrorAction Stop
    }
    return Invoke-RestMethod -Uri $Uri -ErrorAction Stop
}

function Resolve-TagFromApi {
    # Select the newest stable, published release with the complete signed
    # Windows bundle. Any-asset admission can choose a partial or other-host
    # release and fail after claiming it was installable.
    # This is the Windows mirror of install.sh's resolve_tag_from_api fallback.
    try {
        $releases = Invoke-GitHubApi -Uri "https://api.github.com/repos/$Repo/releases?per_page=10"
    } catch {
        Err "Could not query GitHub releases API: $_"
        Err "Try -Version vX.Y.Z with a known published release tag explicitly."
        exit 1
    }
    $required = @(
        $Script:Asset,
        "$($Script:Asset).sha256",
        "$($Script:Asset).minisig",
        "$($Script:Asset).gpu-literals.tar.gz",
        "$($Script:Asset).gpu-literals.tar.gz.sha256",
        "$($Script:Asset).gpu-literals.tar.gz.minisig"
    )
    foreach ($r in $releases) {
        if ($r.draft -or $r.prerelease) { continue }
        $names = @($r.assets | ForEach-Object { $_.name })
        $complete = $true
        foreach ($name in $required) {
            if ($names -notcontains $name) { $complete = $false; break }
        }
        if ($complete) {
            $Script:Tag = $r.tag_name
            return
        }
    }
    Err "No stable GitHub release in the last 10 has the complete signed bundle for $($Script:Asset)."
    Err "Required: binary, SHA-256, minisign, GPU literal sidecar, sidecar SHA-256, and sidecar minisign."
    Err "Try -Version vX.Y.Z with a known published release tag explicitly."
    exit 1
}

function Test-ReleaseBundleComplete {
    param([string]$Tag)
    $required = @(
        $Script:Asset,
        "$($Script:Asset).sha256",
        "$($Script:Asset).minisig",
        "$($Script:Asset).gpu-literals.tar.gz",
        "$($Script:Asset).gpu-literals.tar.gz.sha256",
        "$($Script:Asset).gpu-literals.tar.gz.minisig"
    )
    foreach ($name in $required) {
        $url = "https://github.com/$Repo/releases/download/$Tag/$name"
        try {
            Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -ErrorAction Stop | Out-Null
        } catch {
            return $false
        }
    }
    return $true
}

function Resolve-TagFromLatestRedirect {
    param([string]$Name)
    if (-not $Name) { return $false }
    $url = "https://github.com/$Repo/releases/latest/download/$Name"
    $location = $null
    try {
        $response = Invoke-WebRequest -Uri $url -Method Head -MaximumRedirection 0 -UseBasicParsing -ErrorAction Stop
        if ($response.Headers -and $response.Headers.Location) {
            $location = [string]$response.Headers.Location
        }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { return $false }
        if ($resp.Headers -and $resp.Headers.Location) {
            $location = [string]$resp.Headers.Location
        }
    }
    if ($location -and $location -match '/releases/download/([^/]+)/') {
        $candidate = $Matches[1]
        if (-not (Test-ReleaseBundleComplete -Tag $candidate)) { return $false }
        $Script:Tag = $candidate
        return $true
    }
    return $false
}

function Resolve-OperatorReleaseTag {
    Resolve-Tag
    $Script:LatestReleaseAlias = $false
    if (-not $Version -and $Script:Tag -eq 'latest') {
        if (Resolve-TagFromLatestRedirect -Name $Script:Asset) {
            $Script:LatestReleaseAlias = $true
            return
        }
        Warn "Latest release redirect did not prove a complete signed host bundle; checking recent stable releases."
        Resolve-TagFromApi
        $Script:LatestReleaseAlias = $true
    }
}

function Get-ReleaseTagLabel {
    if ($Script:LatestReleaseAlias) { return "$($Script:Tag) (latest)" }
    return $Script:Tag
}

function Get-VersionTagFromText {
    param([string]$Text)
    if ($Text -match '(v[0-9][0-9A-Za-z._-]*)') { return $Matches[1] }
    return $null
}

function Show-InstalledReleaseRelation {
    param([string]$Existing)
    if (-not $Script:LatestReleaseAlias -or -not $Existing) { return }
    $existingTag = Get-VersionTagFromText -Text $Existing
    if (-not $existingTag) { return }
    if ($existingTag -eq $Script:Tag) {
        Say "  Update:        up to date"
    } else {
        Say "  Update:        update available ($existingTag -> $($Script:Tag))"
    }
}

function Get-ReleaseAssetUrl {
    param([string]$Name)
    if ($Script:Tag -eq 'latest') {
        return "https://github.com/$Repo/releases/latest/download/$Name"
    }
    return "https://github.com/$Repo/releases/download/$($Script:Tag)/$Name"
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
    $url = Get-ReleaseAssetUrl -Name $Name
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
            Invoke-WebRequest -Uri $url -OutFile $OutPath -UseBasicParsing -ErrorAction Stop
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

function Allow-UnverifiedInstall {
    param([string]$Reason)
    if ($Script:InsecureInstall) {
        Warn "  INSECURE: $Reason"
        Warn "  Proceeding without full release verification because -Insecure is set."
        return $true
    }
    Err $Reason
    Err "Refusing to install an unverified keyhog binary."
    if ($Reason -like '*minisign is not installed*') {
        Show-MinisignInstallHint
    } else {
        Err "Fix: ensure the .minisig and .sha256 files are published, minisign is installed, and Get-FileHash is available."
    }
    Err "Only for emergency/local diagnostics, rerun with -Insecure to accept an unverified binary."
    return $false
}

function Show-MinisignInstallHint {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Err "Fix: install minisign with: winget install -e --id jedisct1.minisign"
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        Err "Fix: install minisign with: scoop install minisign"
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        Err "Fix: install minisign with: choco install minisign"
    } else {
        Err "Fix: install minisign with Scoop (scoop install minisign), Chocolatey (choco install minisign), or cargo install minisign."
    }
}

function Find-Minisign {
    $cmd = Get-Command minisign.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $cmd = Get-Command minisign -ErrorAction SilentlyContinue
    }
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-HttpStatusCode {
    # Extract the HTTP status code from a terminating web-request error, or 0 if
    # the failure carried no HTTP response (a DNS/timeout/connection transport
    # error). Works across Windows PowerShell 5.1 (System.Net.WebException) and
    # PowerShell 7+ (HttpResponseException): both expose Exception.Response.StatusCode.
    param($ErrorRecord)
    $resp = $null
    try { $resp = $ErrorRecord.Exception.Response } catch { $resp = $null }
    if ($null -ne $resp) {
        try { return [int]$resp.StatusCode } catch { }
    }
    try {
        if ($null -ne $ErrorRecord.Exception.PSObject.Properties['StatusCode']) {
            return [int]$ErrorRecord.Exception.StatusCode
        }
    } catch { }
    return 0
}

function Verify-ReleaseSignature {
    param($BinaryPath, $AssetName)
    $sigPath = [System.IO.Path]::GetTempFileName()
    try {
        try {
            Download-Asset -Name "$AssetName.minisig" -OutPath $sigPath
        } catch {
            # Classify the failure: a genuine HTTP 404 means the signature is
            # absent, but a network/transport error must NOT be silently
            # downgraded to "no signature published" and skipped (fail closed
            # for security controls). Download-Asset already retried transients.
            $code = Get-HttpStatusCode $_
            if ($code -eq 404) {
                return (Allow-UnverifiedInstall "No .minisig signature was published for $AssetName at $($Script:Tag).")
            }
            return (Allow-UnverifiedInstall "Could not fetch the .minisig signature for $AssetName ($($_.Exception.Message)): a network/transport failure, not a missing signature. A retry may succeed.")
        }
        if ((Get-Item $sigPath).Length -eq 0) {
            return (Allow-UnverifiedInstall "No .minisig signature was published for $AssetName at $($Script:Tag).")
        }

        $minisign = Find-Minisign
        if (-not $minisign) {
            return (Allow-UnverifiedInstall "minisign is not installed, so the $AssetName release signature cannot be verified.")
        }

        $output = & $minisign -Vm $BinaryPath -P $Script:ReleasePublicKey -x $sigPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            Ok "Minisign signature verified."
            return $true
        }
        Err "Minisign signature verification failed for $AssetName."
        if ($output) { Err "  $output" }
        Err "Refusing to install. The release asset may have been tampered with or signed by the wrong key."
        return $false
    } finally {
        Remove-Item -Force $sigPath -ErrorAction SilentlyContinue
    }
}

function Verify-Checksum {
    param($BinaryPath, $AssetName)
    $checksumUrl = Get-ReleaseAssetUrl -Name "$AssetName.sha256"
    $expected = $null
    # Fetch the published checksum with transient-retry, classifying failures so
    # a network/transport error is never silently downgraded to "no checksum
    # published" and skipped (fail closed for security controls). A genuine HTTP
    # 404 (asset absent) fails fast; only non-404 transport errors are retried,
    # matching Download-Asset's policy, and a persistent one is surfaced honestly.
    $attempts = 5
    for ($i = 1; $i -le $attempts; $i++) {
        try {
            $line = Invoke-RestMethod -Uri $checksumUrl -ErrorAction Stop
            if ($line) { $expected = ($line -split '\s+')[0] }
            break
        } catch {
            $code = Get-HttpStatusCode $_
            if ($code -eq 404) {
                return (Allow-UnverifiedInstall "No .sha256 checksum was published for $AssetName at $($Script:Tag).")
            }
            if ($i -ge $attempts) {
                return (Allow-UnverifiedInstall "Could not fetch the .sha256 checksum for $AssetName ($($_.Exception.Message)): a network/transport failure, not a missing checksum. A retry may succeed.")
            }
            $delay = [math]::Min(2 * $i, 10)
            Warn "  checksum fetch attempt $i/$attempts failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $delay
        }
    }
    if (-not $expected) {
        return (Allow-UnverifiedInstall "No .sha256 checksum was published for $AssetName at $($Script:Tag).")
    }
    try {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $BinaryPath -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        return (Allow-UnverifiedInstall "Get-FileHash could not verify ${AssetName}: $($_.Exception.Message)")
    }
    if ($hash -eq $expected.ToLowerInvariant()) {
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
# integrity-check the artifact. Returns $true on match. Missing proof fails
# closed unless the operator explicitly chooses -Insecure.
function Verify-LocalChecksum {
    param($BinaryPath, $SumFile)
    $expected = $null
    try {
        $line = (Get-Content -Path $SumFile -TotalCount 1 -ErrorAction Stop)
        if ($line) { $expected = ($line -split '\s+')[0] }
    } catch {
        return (Allow-UnverifiedInstall "Local checksum file $SumFile could not be read.")
    }
    if (-not $expected) {
        return (Allow-UnverifiedInstall "Local checksum file $SumFile is empty or unreadable.")
    }
    try {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $BinaryPath -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        return (Allow-UnverifiedInstall "Get-FileHash could not verify $BinaryPath against ${SumFile}: $($_.Exception.Message)")
    }
    if ($hash -eq $expected.ToLowerInvariant()) {
        Ok "SHA256 verified ($expected)."
        return $true
    }
    Err "SHA256 mismatch against $SumFile!"
    Err "  Expected: $expected"
    Err "  Got:      $hash"
    Err "Refusing to install the local binary."
    return $false
}

function Clear-MarkOfTheWeb {
    param([string]$Path)
    $unblock = Get-Command Unblock-File -ErrorAction SilentlyContinue
    if (-not $unblock) {
        Warn "Could not remove Windows Mark-of-the-Web because Unblock-File is unavailable."
        Warn "If SmartScreen prompts on first run, verify the SHA256 above before allowing keyhog.exe."
        return
    }
    try {
        Unblock-File -Path $Path -ErrorAction Stop
    } catch {
        Warn "Could not remove Windows Mark-of-the-Web from ${Path}: $($_.Exception.Message)"
        Warn "If SmartScreen prompts on first run, verify the SHA256 above before allowing keyhog.exe."
    }
}

function Get-AutorouteCachePathForInstall {
    $root = $env:LOCALAPPDATA
    if (-not $root) {
        $root = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    }
    if (-not $root) { return $null }
    return (Join-Path (Join-Path $root 'keyhog') 'autoroute.json')
}

function Get-GpuProgramsCacheDirForInstall {
    $root = $env:LOCALAPPDATA
    if (-not $root) {
        $root = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    }
    if (-not $root) { return $null }
    return (Join-Path (Join-Path $root 'keyhog') 'programs')
}

function Clear-GpuLiteralSidecarTemp {
    if ($Script:GpuLiteralSidecarPath) {
        Remove-Item -Force $Script:GpuLiteralSidecarPath -ErrorAction SilentlyContinue
        $Script:GpuLiteralSidecarPath = $null
    }
}

function Clear-GpuProgramsCacheBackup {
    if ($Script:GpuProgramsCacheBackupPath) {
        Remove-Item -Recurse -Force $Script:GpuProgramsCacheBackupPath -ErrorAction SilentlyContinue
        $Script:GpuProgramsCacheBackupPath = $null
    }
    $Script:GpuProgramsCacheWasMissing = $false
}

function Backup-GpuProgramsCacheForInstall {
    Clear-GpuProgramsCacheBackup
    $programsDir = Get-GpuProgramsCacheDirForInstall
    if (-not $programsDir) {
        Err "GPU literal cache directory is unavailable because LocalAppData could not be resolved."
        return $false
    }
    $backupRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("keyhog-gpu-programs-backup-{0}" -f ([System.Guid]::NewGuid().ToString('N')))
    try {
        New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
        if (Test-Path -PathType Container $programsDir) {
            Copy-Item -Recurse -Force -Path $programsDir -Destination (Join-Path $backupRoot 'programs')
            $Script:GpuProgramsCacheWasMissing = $false
        } else {
            $Script:GpuProgramsCacheWasMissing = $true
        }
        $Script:GpuProgramsCacheBackupPath = $backupRoot
        return $true
    } catch {
        Remove-Item -Recurse -Force $backupRoot -ErrorAction SilentlyContinue
        Err "Could not back up GPU literal cache directory at ${programsDir}: $($_.Exception.Message)"
        return $false
    }
}

function Restore-GpuProgramsCacheBackup {
    if (-not $Script:GpuProgramsCacheBackupPath) { return $true }
    $programsDir = Get-GpuProgramsCacheDirForInstall
    if (-not $programsDir) {
        Err "GPU literal cache directory is unavailable because LocalAppData could not be resolved."
        return $false
    }
    try {
        Remove-Item -Recurse -Force $programsDir -ErrorAction SilentlyContinue
        if (-not $Script:GpuProgramsCacheWasMissing) {
            $parent = Split-Path -Parent $programsDir
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
            Move-Item -Force -Path (Join-Path $Script:GpuProgramsCacheBackupPath 'programs') -Destination $programsDir
        }
        Clear-GpuProgramsCacheBackup
        return $true
    } catch {
        Err "Could not restore GPU literal cache directory at ${programsDir}: $($_.Exception.Message)"
        return $false
    }
}

function Download-VerifiedGpuLiteralSidecar {
    $sidecarName = if ($FromFile) { [System.IO.Path]::GetFileName("$FromFile.gpu-literals.tar.gz") } else { "$($Script:Asset).gpu-literals.tar.gz" }
    $sidecarPath = [System.IO.Path]::GetTempFileName()
    try {
        if ($FromFile) {
            $localSidecar = "$FromFile.gpu-literals.tar.gz"
            $localSum = "$localSidecar.sha256"
            if (-not (Test-Path -PathType Leaf $localSidecar)) {
                Err "-FromFile requires a sibling GPU literal sidecar: $localSidecar"
                Err "Refusing to install a local binary that would recompile shipped detector matchers at runtime."
                return $false
            }
            if ((Get-Item $localSidecar).Length -eq 0) {
                Err "GPU literal artifact sidecar $localSidecar is empty."
                return $false
            }
            if (Test-Path -PathType Leaf $localSum) {
                if (-not (Verify-LocalChecksum -BinaryPath $localSidecar -SumFile $localSum)) {
                    return $false
                }
            } else {
                if (-not (Allow-UnverifiedInstall "No local checksum file found beside -FromFile GPU literal sidecar: $localSum")) {
                    return $false
                }
            }
            try {
                Copy-Item -Force -Path $localSidecar -Destination $sidecarPath
            } catch {
                Err "-FromFile: could not read GPU literal sidecar ${localSidecar}: $_"
                return $false
            }
        } else {
            try {
                Download-Asset -Name $sidecarName -OutPath $sidecarPath
            } catch {
                # Classify the fetch failure (Law 10: never conflate a transport
                # failure with a missing asset). Only a real 404 means the sidecar
                # was not published; a network/DNS/transport error (status 0 or
                # 5xx) must NOT tell the operator to rebuild the release workflow
                # for an asset that may well be present.
                $code = Get-HttpStatusCode $_
                if ($code -eq 404) {
                    Err "No GPU literal artifact sidecar was published for $($Script:Asset) at $($Script:Tag)."
                    Err "Refusing to install a release that would recompile shipped detector matchers at runtime."
                    Err "Fix: rebuild the release workflow so $sidecarName, $sidecarName.sha256, and $sidecarName.minisig are uploaded."
                } else {
                    Err "Could not download the GPU literal artifact sidecar $sidecarName (network/transport error $code, not a missing asset): $($_.Exception.Message)"
                    Err "This is a network/transport failure, so the sidecar may well be published; a retry may succeed."
                    Err "Refusing to install a release whose shipped detector matchers could not be fetched (they must not be recompiled at runtime)."
                }
                return $false
            }
            if (-not (Verify-ReleaseSignature -BinaryPath $sidecarPath -AssetName $sidecarName)) {
                return $false
            }
            if (-not (Verify-Checksum -BinaryPath $sidecarPath -AssetName $sidecarName)) {
                return $false
            }
        }
        if ((Get-Item $sidecarPath).Length -eq 0) {
            Err "GPU literal artifact sidecar $sidecarName is empty."
            return $false
        }
        if (-not (Test-GpuLiteralSidecarArchive -ArchivePath $sidecarPath)) {
            Err "Refusing GPU literal sidecar with unsafe archive contents."
            return $false
        }
        Clear-GpuLiteralSidecarTemp
        $Script:GpuLiteralSidecarPath = $sidecarPath
        return $true
    } finally {
        if ($Script:GpuLiteralSidecarPath -ne $sidecarPath) {
            Remove-Item -Force $sidecarPath -ErrorAction SilentlyContinue
        }
    }
}

function Test-GpuLiteralSidecarArchive {
    param([string]$ArchivePath)
    $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
    if (-not $tar) {
        Err "tar.exe is required to install GPU literal artifact sidecars."
        Err "Fix: use a supported Windows build with bsdtar/tar.exe on PATH, then rerun install.ps1."
        return $false
    }
    $tarPath = $tar.Path
    $global:LASTEXITCODE = 0
    $entries = & $tarPath -tzf $ArchivePath 2>$null
    if (-not $? -or $LASTEXITCODE -ne 0) {
        Err "GPU literal artifact sidecar is not a readable tar.gz archive."
        return $false
    }
    foreach ($entry in @($entries)) {
        if ([string]::IsNullOrWhiteSpace($entry) -or
            $entry.StartsWith('/') -or
            $entry.StartsWith('\') -or
            $entry -match '^[A-Za-z]:' -or
            $entry -match '(^|[\\/])\.\.[\s\.]*([\\/]|$)') {
            Err "GPU literal artifact sidecar contains an unsafe archive path: $entry"
            return $false
        }
    }
    $global:LASTEXITCODE = 0
    $listings = & $tarPath -tvzf $ArchivePath 2>$null
    if (-not $? -or $LASTEXITCODE -ne 0) {
        Err "GPU literal artifact sidecar contents could not be inspected for link entries."
        return $false
    }
    foreach ($listing in @($listings)) {
        if ([string]::IsNullOrWhiteSpace($listing)) { continue }
        $entryKind = $listing.Substring(0, 1)
        if ($entryKind -eq 'l' -or $entryKind -eq 'h') {
            Err "GPU literal artifact sidecar contains a link entry: $listing"
            return $false
        }
    }
    return $true
}

function Install-VerifiedGpuLiteralSidecar {
    if (-not $Script:GpuLiteralSidecarPath) { return $true }
    if (-not (Test-GpuLiteralSidecarArchive -ArchivePath $Script:GpuLiteralSidecarPath)) {
        Clear-GpuLiteralSidecarTemp
        return $false
    }
    $programsDir = Get-GpuProgramsCacheDirForInstall
    if (-not $programsDir) {
        Clear-GpuLiteralSidecarTemp
        Err "GPU literal cache directory is unavailable because LocalAppData could not be resolved."
        return $false
    }
    $extractDir = Join-Path ([System.IO.Path]::GetTempPath()) ("keyhog-gpu-literals-{0}" -f ([System.Guid]::NewGuid().ToString('N')))
    try {
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        New-Item -ItemType Directory -Force -Path $programsDir | Out-Null
        $tar = (Get-Command tar.exe -ErrorAction Stop).Path
        $global:LASTEXITCODE = 0
        & $tar -xzf $Script:GpuLiteralSidecarPath -C $extractDir
        if (-not $? -or $LASTEXITCODE -ne 0) {
            Err "Could not extract GPU literal artifact sidecar."
            return $false
        }
        $artifacts = @(Get-ChildItem -Path $extractDir -Filter '*.bin' -File -Recurse -ErrorAction Stop)
        if ($artifacts.Count -eq 0) {
            Err "GPU literal artifact sidecar contained no matcher .bin files."
            return $false
        }
        foreach ($artifact in $artifacts) {
            $tmpTarget = Join-Path $programsDir (".{0}.{1}" -f $artifact.Name, $PID)
            Copy-Item -Force -Path $artifact.FullName -Destination $tmpTarget
            Move-Item -Force -Path $tmpTarget -Destination (Join-Path $programsDir $artifact.Name)
        }
        Ok "Installed $($artifacts.Count) GPU literal matcher artifact(s) into $programsDir."
        return $true
    } catch {
        Err "Could not install GPU literal artifacts into ${programsDir}: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue
        Clear-GpuLiteralSidecarTemp
    }
}

function Rollback-StagedInstallAfterSidecarFailure {
    param([string]$BinPath)
    Clear-GpuLiteralSidecarTemp
    if ($Script:InstallBackup -and (Test-Path $Script:InstallBackup)) {
        Move-Item -Force $Script:InstallBackup $BinPath
        $Script:InstallBackup = $null
        Warn "Rolled back to your previous working keyhog at $BinPath."
    } else {
        Remove-Item -Force $BinPath -ErrorAction SilentlyContinue
        Warn "Removed the binary because shipped GPU literal artifacts could not be seeded."
    }
}

function Format-AutorouteByteCount {
    param([UInt64]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N1}GiB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1}MiB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1}KiB' -f ($Bytes / 1KB)) }
    return ("${Bytes}B")
}

function Format-AutorouteMs {
    param($Value)
    if ($null -eq $Value) { return '-' }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return '-' }
    return "${text}ms"
}

function Format-AutorouteMargin {
    param($Value)
    if ($null -eq $Value) { return 'tie' }
    $ns = [double]$Value
    if ($ns -le 0) { return 'tie' }
    if ($ns -lt 1000) { return ('{0:N0}ns' -f $ns) }
    if ($ns -lt 1000000) { return ('{0:N1}us' -f ($ns / 1000)) }
    if ($ns -lt 1000000000) { return ('{0:N1}ms' -f ($ns / 1000000)) }
    return ('{0:N2}s' -f ($ns / 1000000000))
}

function Show-AutorouteCalibrationSummary {
    param([int]$ProbeCount, [datetime]$StartedAt)
    $cachePath = Get-AutorouteCachePathForInstall
    if (-not $cachePath) {
        Warn "Autoroute calibration summary unavailable: platform cache directory is unavailable."
        return $false
    }
    if (-not (Test-Path -PathType Leaf $cachePath)) {
        Warn "Autoroute calibration summary unavailable: no readable cache at $cachePath."
        return $false
    }

    try {
        $cache = Get-Content -Raw -Path $cachePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Warn "Autoroute calibration summary unavailable: could not parse persisted cache at ${cachePath}: $($_.Exception.Message)"
        return $false
    }

    $rows = @()
    foreach ($pair in @($cache.decisions)) {
        $items = @($pair)
        if ($items.Count -lt 2) { continue }
        $decision = $items[1]
        if (-not $decision.backend) { continue }
        $sampleBytes = if ($null -ne $decision.sample_bytes) { [UInt64]$decision.sample_bytes } else { [UInt64]0 }
        $sampleChunks = if ($null -ne $decision.sample_chunks) { [int]$decision.sample_chunks } else { 0 }
        $sample = '{0} / {1}ch' -f (Format-AutorouteByteCount $sampleBytes), $sampleChunks
        $rows += ('  {0,-18} {1,-16} {2,-9} {3,-7} {4,-7} {5,-7}' -f `
            $sample, `
            ([string]$decision.backend), `
            (Format-AutorouteMargin $decision.selected_margin_ns), `
            (Format-AutorouteMs $decision.simd_ms), `
            (Format-AutorouteMs $decision.cpu_ms), `
            (Format-AutorouteMs $decision.gpu_ms))
    }
    if ($rows.Count -eq 0) {
        Warn "Autoroute calibration summary unavailable: persisted cache at $cachePath has no decisions."
        return $false
    }

    $elapsed = [math]::Max(0, [math]::Round(((Get-Date) - $StartedAt).TotalSeconds, 1))
    Say ""
    Info "Autoroute calibration decisions"
    Dim "  cache: $cachePath"
    Say ('  probes: {0} in {1}s; decisions persisted: {2}' -f $ProbeCount, $elapsed, $rows.Count)
    Say '  sample/chunks       selected backend margin    simd    cpu     gpu'
    foreach ($row in $rows) { Say $row }
    return $true
}

function Test-DockerDaemonResponsive {
    param($DockerPath)
    # `docker info` round-trips to the daemon and exits non-zero when the engine
    # is not running (e.g. Docker Desktop installed but not started). Used to
    # distinguish "docker installed AND usable" from "docker present but dead"
    # so calibration can skip the docker workload instead of failing the whole
    # install. All streams suppressed; only the exit code matters.
    try {
        & $DockerPath info *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Invoke-AutorouteCalibration {
    param($BinPath)
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("keyhog-autoroute-prime-{0}" -f ([System.Guid]::NewGuid()))
    try {
        New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    } catch {
        Err "Could not create autoroute calibration workspace ${tmpDir}: $_"
        return $false
    }
    try {
        Say ""
        Info "Autoroute calibration"
        Dim "  visible install phase; persistent until you run install.ps1 -Calibrate again"
        $calibrationStartedAt = Get-Date
        $failed = $false
        $dockerImagesToRemove = @()
        $webJobsToStop = @()
        try {
            $scanHelpErr = Join-Path $tmpDir 'scan-help.err'
            $scanHelpException = $null
            try {
                $scanHelp = (& $BinPath scan --help 2> $scanHelpErr | Out-String)
                $scanHelpExit = $LASTEXITCODE
            } catch {
                $scanHelp = ''
                $scanHelpExit = 1
                $scanHelpException = $_.Exception.Message
            }
            if ($scanHelpExit -ne 0) {
                $realErr = Get-FirstErrorLine $scanHelpErr $scanHelpException
                Err "Could not inspect installed keyhog scan --help before autoroute calibration."
                if ($realErr) { Err "scan --help error: $realErr" }
                return $false
            }
            if ([string]::IsNullOrWhiteSpace($scanHelp)) {
                Err "Installed keyhog scan --help returned no output; refusing to guess calibration flags."
                return $false
            }
            if ($scanHelp -notmatch '--autoroute-calibrate') {
                # This build does not expose autoroute calibration. The portable
                # Windows/macOS builds gate it out (only the Linux build ships
                # it), so the binary routes with its compiled-in defaults and has
                # no cache to prime -- calibration is a no-op here. Passing
                # --autoroute-calibrate to a binary that lacks it makes EVERY
                # probe fail with "unexpected argument", which (before this guard)
                # rolled back the entire install on Windows/macOS. Skip
                # calibration and report success so the install completes.
                Warn "  Autoroute calibration not supported by this build (no --autoroute-calibrate flag); using the binary's compiled-in routing."
                Dim "  Install is complete; this is expected on portable (Windows/macOS) builds."
                return $true
            }
            $configArgs = if ($scanHelp -match '--no-config') {
                @('--no-config')
            } else {
                $emptyConfig = Join-Path $tmpDir 'empty-config.toml'
                New-Item -ItemType File -Force -Path $emptyConfig | Out-Null
                @('--config', $emptyConfig)
            }
            # Candidate admission is calibration-only identity: --autoroute-gpu is
            # excluded from the resolved scan digest, so its winner is consumed by
            # later normal auto scans. --batch-pipeline changes execution identity
            # and remains absent. Keep this in parity with install.sh.
            $batchArgs = @('--autoroute-calibrate', '--autoroute-gpu')
            # Calibrate the documented scan-policy presets too: each changes scanner
            # fields hashed into the config digest, so `keyhog scan . --fast` resolves a
            # DIFFERENT digest than the default and needs its own decisions or it fails
            # closed. The current multi-config cache lets the default + every preset coexist;
            # only presets this build's `scan --help` actually exposes are calibrated.
            $autoroutePresets = @()
            foreach ($presetFlag in @('--fast', '--deep', '--precision')) {
                if ($scanHelp -match [regex]::Escape($presetFlag)) {
                    $autoroutePresets += $presetFlag
                }
            }
            $unavailableCalibrations = @()
            $gitCalibration = $false
            $gitPath = $null
            if (($scanHelp -match '--git-history') -and ($scanHelp -match '--git-diff')) {
                $gitCmd = Get-Command git -ErrorAction SilentlyContinue
                if (-not $gitCmd) {
                    Warn "  Git source calibration unavailable: git was not found on PATH."
                    Warn "  Filesystem/stdin calibration will continue; install git and rerun install.ps1 -Calibrate before relying on git-source autorouting."
                    $unavailableCalibrations += 'git'
                } else {
                    $gitPath = $gitCmd.Source
                    $gitCalibration = $true
                }
            }
            $dockerCalibration = $false
            $dockerPath = $null
            if ($scanHelp -match '--docker-image') {
                $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
                if (-not $dockerCmd) {
                    Warn "  Docker image calibration unavailable: docker was not found on PATH."
                    Warn "  Filesystem/stdin calibration will continue; install Docker and rerun install.ps1 -Calibrate before relying on Docker image autorouting."
                    $unavailableCalibrations += 'docker'
                } elseif (-not (Test-DockerDaemonResponsive $dockerCmd.Source)) {
                    # docker is installed but the daemon is not responding -- the
                    # common Windows case (Docker Desktop not started). Without
                    # this guard the `docker build` calibration probe below failed
                    # and rolled back the ENTIRE install, so keyhog could not be
                    # installed on any host whose Docker engine was merely stopped.
                    # Treat a dead daemon exactly like missing docker: skip the
                    # docker workload and continue, don't brick the install.
                    Warn "  Docker image calibration unavailable: the Docker daemon is not responding (is Docker Desktop running?)."
                    Warn "  Filesystem/stdin calibration will continue; start Docker and rerun install.ps1 -Calibrate before relying on Docker image autorouting."
                    $unavailableCalibrations += 'docker'
                } else {
                    $dockerPath = $dockerCmd.Source
                    $dockerCalibration = $true
                }
            }
            $webCalibration = $false
            if ($scanHelp -match '--url') {
                $webCalibration = $true
            }
            $workloads = @()
            $emptyStdin = Join-Path $tmpDir 'probe-stdin-empty.txt'
            New-Item -ItemType File -Force -Path $emptyStdin | Out-Null
            $workloads += [pscustomobject]@{
                Label = 'empty stdin workload'
                Target = $emptyStdin
                Mode = 'stdin'
                Out = Join-Path $tmpDir 'out-stdin-empty.json'
                Stdout = Join-Path $tmpDir 'stdout-stdin-empty.txt'
                Stderr = Join-Path $tmpDir 'stderr-stdin-empty.txt'
            }
            $stdin64 = Join-Path $tmpDir 'probe-stdin-64kib.txt'
            New-CalibrationProbeKiB -Path $stdin64 -KiB 64
            $workloads += [pscustomobject]@{
                Label = 'stdin 64 KiB workload'
                Target = $stdin64
                Mode = 'stdin'
                Out = Join-Path $tmpDir 'out-stdin-64kib.json'
                Stdout = Join-Path $tmpDir 'stdout-stdin-64kib.txt'
                Stderr = Join-Path $tmpDir 'stderr-stdin-64kib.txt'
            }
            # One representative for every power-of-two file-size band from
            # 1 B through 32 MiB. Autoroute never interpolates an unmeasured band.
            foreach ($bytes in @(1, 2, 4, 8, 16, 32, 64, 128, 256, 512)) {
                $probe = Join-Path $tmpDir "probe-${bytes}b.txt"
                New-CalibrationProbeBytes -Path $probe -Bytes $bytes
                $workloads += [pscustomobject]@{
                    Label = "${bytes} B workload"
                    Target = $probe
                    Mode = 'path'
                    Out = Join-Path $tmpDir "out-${bytes}b.json"
                    Stdout = Join-Path $tmpDir "stdout-${bytes}b.txt"
                    Stderr = Join-Path $tmpDir "stderr-${bytes}b.txt"
                }
            }
            foreach ($kib in @(1, 2, 4, 8, 16, 32, 64, 128, 256, 512)) {
                $probe = Join-Path $tmpDir "probe-${kib}kib.txt"
                New-CalibrationProbeKiB -Path $probe -KiB $kib
                $workloads += [pscustomobject]@{
                    Label = "${kib} KiB workload"
                    Target = $probe
                    Mode = 'path'
                    Out = Join-Path $tmpDir "out-${kib}kib.json"
                    Stdout = Join-Path $tmpDir "stdout-${kib}kib.txt"
                    Stderr = Join-Path $tmpDir "stderr-${kib}kib.txt"
                }
            }
            foreach ($mib in @(1, 2, 4, 8, 16, 32)) {
                $probe = Join-Path $tmpDir "probe-${mib}mib.txt"
                New-CalibrationProbe -Path $probe -MiB $mib
                $workloads += [pscustomobject]@{
                    Label = "${mib} MiB workload"
                    Target = $probe
                    Mode = 'path'
                    Out = Join-Path $tmpDir "out-${mib}mib.json"
                    Stdout = Join-Path $tmpDir "stdout-${mib}mib.txt"
                    Stderr = Join-Path $tmpDir "stderr-${mib}mib.txt"
                }
            }
            $decodeHeavy = Join-Path $tmpDir 'probe-decode-heavy-256kib.txt'
            New-DecodeHeavyCalibrationProbeKiB -Path $decodeHeavy -KiB 256
            $workloads += [pscustomobject]@{
                Label = 'decode-heavy 256 KiB workload'
                Target = $decodeHeavy
                Mode = 'path'
                Out = Join-Path $tmpDir 'out-decode-heavy-256kib.json'
                Stdout = Join-Path $tmpDir 'stdout-decode-heavy-256kib.txt'
                Stderr = Join-Path $tmpDir 'stderr-decode-heavy-256kib.txt'
            }
            foreach ($fileCount in @(2, 4, 8, 16, 32)) {
                $tree = Join-Path $tmpDir "many-${fileCount}x4k"
                New-CalibrationTreeKiB -Path $tree -Files $fileCount -KiB 4
                $workloads += [pscustomobject]@{
                    Label = "${fileCount} x 4 KiB files workload"
                    Target = $tree
                    Mode = 'path'
                    Out = Join-Path $tmpDir "out-many-${fileCount}x4k.json"
                    Stdout = Join-Path $tmpDir "stdout-many-${fileCount}x4k.txt"
                    Stderr = Join-Path $tmpDir "stderr-many-${fileCount}x4k.txt"
                }
            }
            if ($gitCalibration) {
                $gitRepo = Join-Path $tmpDir 'git-source'
                New-CalibrationGitRepository -Path $gitRepo -GitPath $gitPath
                $workloads += [pscustomobject]@{
                    Label = 'git history 4 KiB source workload'
                    Target = $gitRepo
                    Mode = 'git-history'
                    Out = Join-Path $tmpDir 'out-git-history.json'
                    Stdout = Join-Path $tmpDir 'stdout-git-history.txt'
                    Stderr = Join-Path $tmpDir 'stderr-git-history.txt'
                }
                $workloads += [pscustomobject]@{
                    Label = 'git blobs head/history source workload'
                    Target = $gitRepo
                    Mode = 'git-blobs'
                    Out = Join-Path $tmpDir 'out-git-blobs.json'
                    Stdout = Join-Path $tmpDir 'stdout-git-blobs.txt'
                    Stderr = Join-Path $tmpDir 'stderr-git-blobs.txt'
                }
                $workloads += [pscustomobject]@{
                    Label = 'git diff 12 KiB source workload'
                    Target = $gitRepo
                    Mode = 'git-diff'
                    Out = Join-Path $tmpDir 'out-git-diff.json'
                    Stdout = Join-Path $tmpDir 'stdout-git-diff.txt'
                    Stderr = Join-Path $tmpDir 'stderr-git-diff.txt'
                }
            }
            if ($dockerCalibration) {
                $dockerImage = 'keyhog-autoroute-calibration:{0}-{1}' -f $PID, ([System.Guid]::NewGuid().ToString('N').Substring(0, 12))
                New-CalibrationDockerImage -Path (Join-Path $tmpDir 'docker-source') -Image $dockerImage -DockerPath $dockerPath
                $dockerImagesToRemove += $dockerImage
                $workloads += [pscustomobject]@{
                    Label = 'docker image 4 KiB source workload'
                    Target = $dockerImage
                    Mode = 'docker-image'
                    Out = Join-Path $tmpDir 'out-docker-image.json'
                    Stdout = Join-Path $tmpDir 'stdout-docker-image.txt'
                    Stderr = Join-Path $tmpDir 'stderr-docker-image.txt'
                }
            }
            if ($webCalibration) {
                $webRoot = Join-Path $tmpDir 'web-source'
                New-CalibrationWebFixture -Path $webRoot
                $webServer = Start-CalibrationWebServer -Path $webRoot -PortFile (Join-Path $tmpDir 'web-source.port')
                $webJobsToStop += $webServer.Job
                $workloads += [pscustomobject]@{
                    Label = 'web URL 4 KiB source workload'
                    Target = $webServer.Url
                    Mode = 'url'
                    Out = Join-Path $tmpDir 'out-web-url.json'
                    Stdout = Join-Path $tmpDir 'stdout-web-url.txt'
                    Stderr = Join-Path $tmpDir 'stderr-web-url.txt'
                }
            }

            # Core stdin + filesystem workloads calibrate once per scan-policy preset
            # (default policy first, then each supported preset); external-source
            # workloads (git/docker/web) calibrate the default policy only, mirrors
            # the install.sh `for autoroute_scan_flags in "" $autoroute_presets` loop.
            $coreModes = @('stdin', 'path')
            $presetPasses = @('') + $autoroutePresets
            $probePlan = @()
            foreach ($pass in $presetPasses) {
                foreach ($w in $workloads) {
                    if ($coreModes -contains $w.Mode) {
                        $probePlan += [pscustomobject]@{ Workload = $w; Preset = $pass }
                    }
                }
            }
            foreach ($w in $workloads) {
                if ($coreModes -notcontains $w.Mode) {
                    $probePlan += [pscustomobject]@{ Workload = $w; Preset = '' }
                }
            }
            for ($i = 0; $i -lt $probePlan.Count; $i++) {
                $workload = $probePlan[$i].Workload
                $presetArgs = if ($probePlan[$i].Preset) { @($probePlan[$i].Preset) } else { @() }
                $passSuffix = if ($probePlan[$i].Preset) { " [$($probePlan[$i].Preset)]" } else { '' }
                $label = "  [{0}/{1}] {2}{3}" -f ($i + 1), $probePlan.Count, $workload.Label, $passSuffix
                switch ($workload.Mode) {
                    'stdin' {
                        $args = @('scan', '--stdin') + $batchArgs + $presetArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'path' {
                        $args = @('scan', $workload.Target) + $batchArgs + $presetArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'git-history' {
                        $args = @('scan', '--git-history', $workload.Target, '--max-commits', '1') + $batchArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'git-blobs' {
                        $args = @('scan', '--git-blobs', $workload.Target, '--max-commits', '2') + $batchArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'git-diff' {
                        $args = @('scan', '--git-diff', 'HEAD', '--git-diff-path', $workload.Target) + $batchArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'url' {
                        $args = @('scan', '--url', $workload.Target) + $batchArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'docker-image' {
                        $args = @('scan', '--docker-image', $workload.Target) + $batchArgs + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    default {
                        throw "unsupported autoroute calibration mode: $($workload.Mode)"
                    }
                }
                $argList = ($args | ForEach-Object { Quote-ProcessArgument $_ }) -join ' '
                $startArgs = @{
                    FilePath = $BinPath
                    ArgumentList = $argList
                    RedirectStandardOutput = $workload.Stdout
                    RedirectStandardError = $workload.Stderr
                    NoNewWindow = $true
                    PassThru = $true
                }
                if ($workload.Mode -eq 'stdin') {
                    $startArgs.RedirectStandardInput = $workload.Target
                }
                $probeStartedAt = Get-Date
                $proc = Start-Process @startArgs
                $frames = @('-', '\', '|', '/')
                $frame = 0
                while (-not $proc.HasExited) {
                    Write-Host ("`rINFO {0} {1}" -f $label, $frames[$frame]) -NoNewline
                    $frame = ($frame + 1) % $frames.Count
                    Start-Sleep -Milliseconds 150
                    $proc.Refresh()
                }
                $proc.WaitForExit()
                $elapsedMs = [int][math]::Max(0, [math]::Round(((Get-Date) - $probeStartedAt).TotalMilliseconds))
                if ($proc.ExitCode -eq 0) {
                    Write-Host ("`rPASS {0} ({1}ms)" -f $label, $elapsedMs)
                } else {
                    Write-Host ("`rFAIL {0} ({1}ms)" -f $label, $elapsedMs)
                    $reason = Get-FirstNonEmptyLine -Paths @($workload.Stderr, $workload.Stdout)
                    if ($reason) { Dim "    reason: $reason" }
                    Err "Autoroute calibration probe failed for $($workload.Label)."
                    $failed = $true
                }
            }
            if ($failed) {
                Err "Autoroute calibration phase failed; persisted auto routing was not updated for every required workload."
                return $false
            }
            if ($unavailableCalibrations.Count -gt 0) {
                Warn ("Autoroute calibration incomplete for unavailable source classes: {0}." -f ($unavailableCalibrations -join ', '))
                Warn "Install the required source tools and rerun install.ps1 -Calibrate before using those source routes."
            }
            if (-not (Show-AutorouteCalibrationSummary -ProbeCount $probePlan.Count -StartedAt $calibrationStartedAt)) {
                Err "Autoroute calibration completed but persisted decisions could not be read back."
                return $false
            }
            Ok "Autoroute calibration phase complete."
            return $true
        } finally {
            foreach ($job in $webJobsToStop) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }
            if ($dockerPath) {
                foreach ($image in $dockerImagesToRemove) {
                    & $dockerPath image rm -f $image *> $null
                    if ($LASTEXITCODE -ne 0) {
                        Dim "  Docker calibration image cleanup failed for $image"
                    }
                }
            }
        }
    } catch {
        Err "Autoroute calibration probe failed: $_"
        return $false
    } finally {
        Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    }
}

function Get-FirstNonEmptyLine {
    param([string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path $path)) { continue }
        foreach ($line in Get-Content -Path $path -ErrorAction SilentlyContinue) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                return $line
            }
        }
    }
    return $null
}

function Quote-ProcessArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function New-CalibrationProbe {
    param([string]$Path, [int]$MiB)
    New-CalibrationProbeKiB -Path $Path -KiB ($MiB * 1024)
}

function New-CalibrationProbeKiB {
    param([string]$Path, [int]$KiB)
    $chunk = New-PlainCalibrationBlock
    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.Encoding]::ASCII)
    try {
        for ($i = 0; $i -lt $KiB; $i++) { $writer.Write($chunk) }
    } finally {
        $writer.Dispose()
    }
}

function New-CalibrationProbeBytes {
    param([string]$Path, [int]$Bytes)
    $chunk = New-PlainCalibrationBlock
    if ($Bytes -lt 0 -or $Bytes -gt $chunk.Length) {
        throw "Calibration byte probe size must be between 0 and $($chunk.Length); got $Bytes."
    }
    [System.IO.File]::WriteAllText(
        $Path,
        $chunk.Substring(0, $Bytes),
        [System.Text.Encoding]::ASCII
    )
}

function New-DecodeHeavyCalibrationProbeKiB {
    param([string]$Path, [int]$KiB)
    $chunk = New-DecodeHeavyCalibrationBlock
    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.Encoding]::ASCII)
    try {
        for ($i = 0; $i -lt $KiB; $i++) { $writer.Write($chunk) }
    } finally {
        $writer.Dispose()
    }
}

function New-RepeatedCalibrationBlock {
    param([string]$Seed)
    $block = $Seed
    while ($block.Length -lt 1024) {
        $block += $Seed
    }
    return $block.Substring(0, 1024)
}

function New-PlainCalibrationBlock {
    New-RepeatedCalibrationBlock -Seed 'src path one. scan text two. keyhog route plain. config value sample. '
}

function New-DecodeHeavyCalibrationBlock {
    New-RepeatedCalibrationBlock -Seed 'apiVersion:v1 kind:Secret data token:QUtJQUlPU0ZPRE5ON0VYQU1QTEVBS0lBSU9TRk9ETk43RVhBTVBMRT0= payload:c2stcHJvai1BQkNkZWZHSElKS0xtbm9QUVJTVFVWV1hZWjAxMjM0NTY3ODkwPQ== '
}

function Invoke-GitCalibrationCommand {
    param([string]$GitPath, [string[]]$Arguments)
    & $GitPath @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') exited with code $LASTEXITCODE"
    }
}

function New-CalibrationGitRepository {
    param([string]$Path, [string]$GitPath)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('init', '-q', $Path)
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'config', 'user.email', 'keyhog-calibration@example.invalid')
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'config', 'user.name', 'KeyHog Autoroute Calibration')
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'config', 'commit.gpgsign', 'false')
    New-CalibrationProbeKiB -Path (Join-Path $Path 'probe.txt') -KiB 4
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'add', 'probe.txt')
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'commit', '-q', '-m', 'keyhog autoroute calibration baseline')
    New-CalibrationProbeKiB -Path (Join-Path $Path 'probe.txt') -KiB 8
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'add', 'probe.txt')
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'commit', '-q', '-m', 'keyhog autoroute calibration head')
    New-CalibrationProbeKiB -Path (Join-Path $Path 'probe.txt') -KiB 12
}

function Invoke-DockerCalibrationCommand {
    param([string]$DockerPath, [string[]]$Arguments)
    & $DockerPath @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') exited with code $LASTEXITCODE"
    }
}

function New-CalibrationDockerImage {
    param([string]$Path, [string]$Image, [string]$DockerPath)
    $context = Join-Path $Path 'context'
    New-Item -ItemType Directory -Force -Path $context | Out-Null
    New-CalibrationProbeKiB -Path (Join-Path $context 'probe.txt') -KiB 4
    Set-Content -Path (Join-Path $context 'Dockerfile') -Encoding ASCII -Value @(
        'FROM scratch',
        'COPY probe.txt /keyhog-autoroute-probe.txt'
    )
    Invoke-DockerCalibrationCommand -DockerPath $DockerPath -Arguments @('build', '-q', '-t', $Image, $context)
}

function New-CalibrationWebFixture {
    param([string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    New-CalibrationProbeKiB -Path (Join-Path $Path 'probe.js') -KiB 4
}

function Start-CalibrationWebServer {
    param([string]$Path, [string]$PortFile)
    $job = Start-Job -ScriptBlock {
        param([string]$Root, [string]$PortPath, [int]$ParentPid, [int]$MaxSeconds)
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 0)
        $listener.Start()
        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            Set-Content -Path $PortPath -Encoding ASCII -Value $port
            # Lifetime bound (parity with install.sh, whose server is reaped by
            # the parent's cleanup trap): a raw `while ($true) AcceptTcpClient()`
            # blocks forever and would LEAK a listener holding a loopback port if
            # the installer died between Start-Job and Stop-Job. Poll() with a
            # 500ms window lets the loop re-check its guards between connections
            # and exit if the parent installer is gone or the calibration
            # deadline passed. The happy path is unchanged: a pending connection
            # makes Poll return $true immediately, so AcceptTcpClient never
            # blocks.
            $deadline = [DateTime]::UtcNow.AddSeconds($MaxSeconds)
            while ($true) {
                if (-not $listener.Server.Poll(500000, [System.Net.Sockets.SelectMode]::SelectRead)) {
                    if ([DateTime]::UtcNow -gt $deadline) { break }
                    if ($ParentPid -gt 0 -and -not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { break }
                    continue
                }
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
                    do {
                        $line = $reader.ReadLine()
                    } while ($null -ne $line -and $line.Length -gt 0)
                    $body = [System.IO.File]::ReadAllBytes((Join-Path $Root 'probe.js'))
                    $header = "HTTP/1.1 200 OK`r`nContent-Type: application/javascript`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
                    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
                    $stream.Write($headerBytes, 0, $headerBytes.Length)
                    $stream.Write($body, 0, $body.Length)
                } finally {
                    $client.Close()
                }
            }
        } finally {
            $listener.Stop()
        }
    } -ArgumentList $Path, $PortFile, $PID, 600

    for ($i = 0; $i -lt 100; $i++) {
        if (Test-Path -PathType Leaf $PortFile) {
            $port = (Get-Content -Path $PortFile -TotalCount 1).Trim()
            if ($port) {
                return [pscustomobject]@{
                    Job = $job
                    Url = "http://127.0.0.1:$port/probe.js"
                }
            }
        }
        if ($job.State -in @('Failed', 'Stopped', 'Completed')) {
            $reason = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            throw "loopback Web URL calibration server exited before publishing a port. $reason"
        }
        Start-Sleep -Milliseconds 50
    }
    Stop-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    throw "loopback Web URL calibration server did not publish a port"
}

function New-CalibrationTreeKiB {
    param([string]$Path, [int]$Files, [int]$KiB)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    for ($i = 0; $i -lt $Files; $i++) {
        New-CalibrationProbeKiB -Path (Join-Path $Path "file-$i.txt") -KiB $KiB
    }
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
    # Release verification happens BEFORE we overwrite, so a corrupt or unsigned
    # artifact can never replace a working binary. Downloads check the release's
    # per-asset .minisig and .sha256; a -FromFile install requires a sibling
    # PATH.sha256 unless the operator explicitly accepts an unverified local
    # artifact.
    if ($FromFile) {
        $localSum = "$FromFile.sha256"
        if (Test-Path -PathType Leaf $localSum) {
            if (-not (Verify-LocalChecksum -BinaryPath $tmp -SumFile $localSum)) {
                Remove-Item -Force $tmp -ErrorAction SilentlyContinue
                exit 1
            }
        } else {
            if (-not (Allow-UnverifiedInstall "No local checksum file found beside -FromFile binary: $localSum")) {
                Remove-Item -Force $tmp -ErrorAction SilentlyContinue
                exit 1
            }
        }
        if (-not (Download-VerifiedGpuLiteralSidecar)) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            Clear-GpuLiteralSidecarTemp
            exit 1
        }
    } else {
        if (-not (Verify-ReleaseSignature -BinaryPath $tmp -AssetName $Script:Asset)) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            exit 1
        }
        if (-not (Verify-Checksum -BinaryPath $tmp -AssetName $Script:Asset)) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            exit 1
        }
        if (-not (Download-VerifiedGpuLiteralSidecar)) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            Clear-GpuLiteralSidecarTemp
            exit 1
        }
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
        Clear-MarkOfTheWeb -Path $dest
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
    $firstLine = $out | Select-Object -First 1
    if ($Script:Tag -and $Script:Tag -ne 'latest' -and $Script:Tag -ne '(local file)') {
        $observedTag = Get-VersionTagFromText -Text ($out | Out-String)
        if (-not $observedTag) {
            Err "Installed binary did not report a version tag; refusing to trust release $($Script:Tag)."
            return $false
        }
        if ($observedTag -ne $Script:Tag) {
            Err "Candidate binary version does not match release tag: binary reports $observedTag but release resolved $($Script:Tag)."
            Err "Refusing to install a mismatched binary (possible substitution or downgrade attack)."
            return $false
        }
    }
    Ok "Installed $firstLine"
    return $true
}

# Roll back a failed post-install verification: restore the pre-install backup
# if one exists (upgrade/repair over a binary that worked), otherwise remove the
# freshly-staged binary (fresh install). Single owner so the doctor / autoroute
# / non-runnable failure paths cannot drift apart (ONE PLACE - mirrors
# install.sh's finalize_install rollback block).
function Restore-PreviousInstallOrRemove {
    param(
        [Parameter(Mandatory)] [string]$BinPath,
        [string]$RemovedNote = "Removed the failed install; no working keyhog was overwritten."
    )
    if ($Script:InstallBackup -and (Test-Path $Script:InstallBackup)) {
        Move-Item -Force $Script:InstallBackup $BinPath
        $Script:InstallBackup = $null
        Warn "Rolled back to your previous working keyhog at $BinPath."
    } else {
        Remove-Item -Force $BinPath -ErrorAction SilentlyContinue
        $Script:InstallBackup = $null
        Warn $RemovedNote
    }
}

# Verify the freshly-staged binary; on failure restore the previous working
# binary (upgrade) or remove the broken download (fresh install). Returns
# $true on success. Mirrors install.sh's finalize_install.
function Finalize-Install {
    param($BinPath)
    if (Test-Binary -BinPath $BinPath) {
        # Native post-install health check (parity with install.sh): reuses the
        # scanner's own hw_probe and runs an end-to-end scan self-test, proving
        # the binary actually detects a secret on this host. doctor exits 4
        # (EXIT_HEALTH_FAILURE) iff it deems the binary UNHEALTHY - the planted
        # secret was NOT detected, the detector corpus is missing, or (on a GPU
        # host) the fail-closed DEFAULT GPU scan route is dead - and 0 otherwise
        # (PATH-only notices are exit-0 warnings; GPU self-tests are skipped on
        # no-GPU/headless hosts). A non-zero exit means the binary we just
        # installed cannot do its primary job on the route it will actually use:
        # fail closed and roll back rather than report "installed" (Law 10 - no
        # silent fallback past a failed self-test).
        Say ""
        try {
            # Out-Host: doctor prints to the console but its stdout must NOT
            # land on this function's output stream, or it would contaminate
            # the boolean return value (Finalize-Install is used as a predicate).
            & $BinPath doctor | Out-Host
            $doctorExit = $LASTEXITCODE
            if ($doctorExit -eq 4) {
                Err "keyhog doctor reports the freshly-installed binary is UNHEALTHY (exit 4): it failed its own end-to-end scan self-test above."
                Err "Refusing to leave a scanner that cannot detect secrets on its default route; rolling back this install."
                Err "  If only the GPU route is broken, the CPU/SIMD paths still work - reinstall, then scan with an explicit '--backend cpu' or '--backend simd' override."
                Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote "Removed the unhealthy binary; no working keyhog was overwritten."
                return $false
            } elseif ($doctorExit -ne 0) {
                Err "keyhog doctor did not complete (exit $doctorExit): the installed binary could not even run its own health self-test."
                Err "Rolling back rather than leaving an install whose health is unknown."
                Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote "Removed the binary that could not self-test; no working keyhog was overwritten."
                return $false
            }
        } catch {
            Err "Could not run 'keyhog doctor' for post-install verification: $_"
            Err "Rolling back rather than reporting success with unknown scanner health."
            Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote "Removed the binary whose health could not be verified; no working keyhog was overwritten."
            return $false
        }
        if (-not (Invoke-AutorouteCalibration -BinPath $BinPath)) {
            Err "Autoroute calibration failed; refusing to leave an install whose default auto route is not usable."
            Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote "Removed the uncalibrated binary; no working keyhog was overwritten."
            return $false
        }
        if ($Script:InstallBackup) { Remove-Item -Force $Script:InstallBackup -ErrorAction SilentlyContinue; $Script:InstallBackup = $null }
        return $true
    }
    Restore-PreviousInstallOrRemove -BinPath $BinPath -RemovedNote "Removed the non-runnable download; no working keyhog was overwritten."
    return $false
}

function Show-Summary {
    Info "Host: windows-$(Get-Arch)"
    Say  "  GPU note: $($Script:GpuNote)"
    Say  "  Picked asset:  $($Script:Asset)"
    Say  "  Install dir:   $InstallDir"
    Say  "  Release tag:   $(Get-ReleaseTagLabel)"
    $existing = Get-CurrentVersion
    if ($existing) {
        Say "  Existing:      $existing"
        Show-InstalledReleaseRelation -Existing $existing
    }
}

function Test-PathContainsDir {
    # Windows PATH entries compare case-insensitively and accumulate formatting
    # noise (trailing backslashes, stray spaces) AND are frequently stored
    # unexpanded as REG_EXPAND_SZ (`%LOCALAPPDATA%\...`, `%USERPROFILE%\...`). A
    # raw compare on the split misses `C:\keyhog\` vs `C:\keyhog` and, worse,
    # misses `%LOCALAPPDATA%\Programs\keyhog` vs its expansion - re-appending a
    # DUPLICATE entry on every re-install. One normalized, ENV-EXPANDED
    # comparison, used by every PATH check (Windows analog of install.sh's
    # $HOME/~ spelling match).
    param([string]$PathString, [string]$Dir)
    if (-not $PathString) { return $false }
    $needle = [Environment]::ExpandEnvironmentVariables($Dir).Trim().TrimEnd('\')
    foreach ($entry in ($PathString -split ';')) {
        $normalized = [Environment]::ExpandEnvironmentVariables($entry).Trim().TrimEnd('\')
        if ($normalized -and ($normalized -ieq $needle)) { return $true }
    }
    return $false
}

function Ensure-OnPath {
    # PATH wiring runs in EVERY install mode -- not only the interactive wizard.
    # The canonical quick install (`iwr ... | iex`) and `-Yes` are
    # non-interactive, and Confirm-Choice auto-approves the Yes-default there, so
    # keyhog lands on PATH automatically instead of being installed-but-
    # uninvokable. (Previously the only PATH-wiring lived inside the wizard, which
    # early-returns for `-not Interactive -or $Yes` -- so the documented quick
    # install left `keyhog` off PATH and unrunnable, a silent config gap.)
    # Interactive runs still prompt; a decline prints the exact manual command --
    # never a silent skip.
    if (Test-PathContainsDir $env:PATH $InstallDir) { return }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    if (Test-PathContainsDir $userPath $InstallDir) {
        Dim "  $InstallDir already in your User PATH (open a new shell to pick it up)."
        return
    }
    if (Confirm-Choice "Add $InstallDir to your User PATH (persistent)?" 'Y') {
        $newPath = if ($userPath) { "$InstallDir;$userPath" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Ok "  Added $InstallDir to your User PATH. Open a new shell to pick up the change."
    } else {
        Warn "  $InstallDir is NOT on PATH. Add it with: setx PATH `"$InstallDir;`$env:PATH`""
    }
}

function Post-Install-Wizard {
    if (-not $Script:Interactive -or $Yes) { return }
    Write-Host ""
    Use-Color "Optional post-install steps" 'White'

    if (Confirm-Choice "Install PowerShell completions?" 'N') {
        $dir = Join-Path $env:USERPROFILE 'Documents\PowerShell\Completions'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $file = Join-Path $dir 'keyhog.ps1'
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            & (Join-Path $InstallDir 'keyhog.exe') completion powershell > $file 2> $errFile
            $exit = $LASTEXITCODE
            if ($exit -eq 0) {
                Ok "  Completions at $file. Add 'Import-Module $file' to your `$PROFILE."
            } else {
                Warn-WizardCommandFailure `
                    "completion generation" `
                    $errFile `
                    "  completion subcommand not in this build, skipping (upgrade keyhog and rerun install)." `
                    "keyhog.exe completion powershell" `
                    "exit code $exit"
                Remove-Item -Force $file -ErrorAction SilentlyContinue
            }
        } catch {
            Warn-WizardCommandFailure `
                "completion generation" `
                $errFile `
                "  completion subcommand not in this build, skipping (upgrade keyhog and rerun install)." `
                "keyhog.exe completion powershell" `
                $_.Exception.Message
            Remove-Item -Force $file -ErrorAction SilentlyContinue
        } finally {
            Remove-Item -Force $errFile -ErrorAction SilentlyContinue
        }
    }

    if (Confirm-Choice "Install a git pre-commit hook in the current directory?" 'N') {
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            & (Join-Path $InstallDir 'keyhog.exe') hook install 2> $errFile
            $exit = $LASTEXITCODE
            if ($exit -eq 0) {
                Ok "  Pre-commit hook installed in the current directory."
            } else {
                Warn-WizardCommandFailure `
                    "pre-commit hook install" `
                    $errFile `
                    "  hook subcommand not in this build, skipping (upgrade keyhog and rerun install)." `
                    "keyhog.exe hook install" `
                    "exit code $exit"
            }
        } catch {
            Warn-WizardCommandFailure `
                "pre-commit hook install" `
                $errFile `
                "  hook subcommand not in this build, skipping (upgrade keyhog and rerun install)." `
                "keyhog.exe hook install" `
                $_.Exception.Message
        } finally {
            Remove-Item -Force $errFile -ErrorAction SilentlyContinue
        }
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
        Resolve-OperatorReleaseTag
    }
    Show-Summary
    if ($Script:Interactive -and -not $Yes) {
        if (-not (Confirm-Choice "Proceed with this install?" 'Y')) { Warn "Aborted."; return }
    }
    $bin = Stage-Install
    if (-not (Backup-GpuProgramsCacheForInstall)) {
        Rollback-StagedInstallAfterSidecarFailure -BinPath $bin
        Err "Install failed while backing up GPU literal cache state."
        exit 1
    }
    if (-not (Install-VerifiedGpuLiteralSidecar)) {
        Restore-GpuProgramsCacheBackup | Out-Null
        Rollback-StagedInstallAfterSidecarFailure -BinPath $bin
        Err "Install failed while seeding shipped GPU literal artifacts."
        exit 1
    }
    if (-not (Finalize-Install -BinPath $bin)) {
        Restore-GpuProgramsCacheBackup | Out-Null
        Clear-GpuLiteralSidecarTemp
        Err "Install failed verification; see above."
        exit 1
    }
    Clear-GpuProgramsCacheBackup
    Ensure-OnPath
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
    Resolve-OperatorReleaseTag
    $bin = Get-CurrentBinary
    if (-not $bin) {
        Warn "No existing keyhog binary found. Installing fresh."
        $bin = Stage-Install
        if (-not (Backup-GpuProgramsCacheForInstall)) {
            Rollback-StagedInstallAfterSidecarFailure -BinPath $bin
            Err "Repair failed while backing up GPU literal cache state."
            exit 1
        }
        if (-not (Install-VerifiedGpuLiteralSidecar)) {
            Restore-GpuProgramsCacheBackup | Out-Null
            Rollback-StagedInstallAfterSidecarFailure -BinPath $bin
            Err "Repair failed while seeding shipped GPU literal artifacts."
            exit 1
        }
        if (-not (Finalize-Install -BinPath $bin)) {
            Restore-GpuProgramsCacheBackup | Out-Null
            Clear-GpuLiteralSidecarTemp
            Err "Repair failed; see above."
            exit 1
        }
        Clear-GpuProgramsCacheBackup
        Ok "Repair complete."
        return
    }
    Say "Found existing binary: $bin"
    & $bin --version > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Ok "Binary runs cleanly. Repair will download and verify $($Script:Asset) before replacing it (-Repair)."
    } else {
        Warn "Existing binary does not run. Replacing with $($Script:Asset)."
    }
    $newBin = Stage-Install
    if (-not (Backup-GpuProgramsCacheForInstall)) {
        Rollback-StagedInstallAfterSidecarFailure -BinPath $newBin
        Err "Repair failed while backing up GPU literal cache state."
        exit 1
    }
    if (-not (Install-VerifiedGpuLiteralSidecar)) {
        Restore-GpuProgramsCacheBackup | Out-Null
        Rollback-StagedInstallAfterSidecarFailure -BinPath $newBin
        Err "Repair failed while seeding shipped GPU literal artifacts."
        exit 1
    }
    if (-not (Finalize-Install -BinPath $newBin)) {
        Restore-GpuProgramsCacheBackup | Out-Null
        Clear-GpuLiteralSidecarTemp
        Err "Repair failed; your previous binary was preserved where possible (see above)."
        exit 1
    }
    Clear-GpuProgramsCacheBackup
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
        # NOT `-or`: PowerShell `-or` is a BOOLEAN operator, so
        # `$version -or '(does not run)'` coerces the version STRING to $true
        # and the report printed "Version: True". Use an explicit empty check.
        $version = Get-CurrentVersion
        if ([string]::IsNullOrWhiteSpace($version)) { $version = '(does not run)' }
        Say "  Version: $version"
    } else {
        Say "  (no keyhog found on PATH or in $InstallDir)"
    }
    Write-Host ""
    Use-Color "PATH" 'White'
    if (Test-PathContainsDir $env:PATH $InstallDir) {
        Ok "  $InstallDir is on PATH."
    } else {
        Warn "  $InstallDir is NOT on PATH."
    }
    Write-Host ""
    Use-Color "Latest release" 'White'
    Resolve-Asset
    Resolve-OperatorReleaseTag
    Say "  Tag: $(Get-ReleaseTagLabel)"
    $existing = Get-CurrentVersion
    Show-InstalledReleaseRelation -Existing $existing
    Say "  Would install: $($Script:Asset)"
}

function Do-Uninstall {
    $bin = Get-CurrentBinary
    if (-not $bin) { Warn "No keyhog binary found. Nothing to remove."; return }
    if (-not (Confirm-Choice "Remove $bin?" 'Y')) { Warn "Aborted."; return }
    Invoke-InstalledBinaryUninstall -BinPath $bin
    try {
        if (Test-Path $bin) {
            Remove-Item -Force $bin
        }
    } catch {
        Err "Could not remove ${bin}: $($_.Exception.Message)"
        Err "Fix: close running keyhog processes or shells using keyhog.exe, then rerun install.ps1 -Uninstall."
        exit 1
    }
    Ok "Removed $bin"
    Remove-WindowsInstallerOwnedIntegrations
}

function Do-Calibrate {
    $bin = Get-CurrentBinary
    if (-not $bin) {
        Err "No installed keyhog binary found to calibrate. Run install first."
        exit 1
    }
    if (-not (Invoke-AutorouteCalibration -BinPath $bin)) {
        exit 1
    }
}

# ============================================================
# main
# ============================================================

Show-Banner

if ($Repair)         { Do-Repair }
elseif ($Diagnose)   { Do-Diagnose }
elseif ($Calibrate)  { Do-Calibrate }
elseif ($Uninstall)  { Do-Uninstall }
else                 { Do-Install }
