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
#   -Calibrate       rerun visible autoroute calibration for the installed binary
#   -Uninstall       remove the binary
#
# Common flags:
#   -Version v0.5.37      pin a release tag (default: latest release with assets)
#   -FromFile PATH        install a pre-built/pre-downloaded keyhog.exe instead
#                         of querying GitHub (offline / air-gapped / CI proving).
#                         Requires a sibling PATH.sha256 unless -Insecure is explicit.
#   -InstallDir PATH      override $env:KEYHOG_INSTALL
#   -Yes                  non-interactive: accept defaults, no prompts
#   -Insecure             allow install only when checksum proof is unavailable;
#                         checksum mismatches still fail
#   -NoColor              disable ANSI colors
#
# Env overrides:
#   $env:KEYHOG_VERSION, $env:KEYHOG_FROM_FILE, $env:KEYHOG_INSTALL,
#   $env:NO_COLOR

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
    [string]$FromFile = $env:KEYHOG_FROM_FILE,
    [string]$InstallDir = $(if ($env:KEYHOG_INSTALL) { $env:KEYHOG_INSTALL } else { Join-Path $env:LOCALAPPDATA 'keyhog\bin' })
)

$ErrorActionPreference = 'Stop'
$Repo = 'santhsecurity/keyhog'
$Script:InsecureInstall = [bool]$Insecure

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
    if ($Version) {
        # keyhog release tags are all v-prefixed (v0.5.37). Accept a bare
        # semver too (`-Version 0.5.37`): a download URL built from the
        # un-prefixed tag 404s, which is exactly what broke the Windows
        # install smoke (it passed "0.5.37"). Normalise a digit-leading
        # version to the v-prefixed tag; leave an explicit v… or any other
        # ref untouched.
        if ($Version -match '^[0-9]') { $Script:Tag = "v$Version" } else { $Script:Tag = $Version }
        return
    }
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

function Allow-UnverifiedInstall {
    param([string]$Reason)
    if ($Script:InsecureInstall) {
        Warn "  INSECURE: $Reason"
        Warn "  Proceeding without checksum verification because -Insecure is set."
        return $true
    }
    Err $Reason
    Err "Refusing to install an unverified keyhog binary."
    Err "Fix: provide the .sha256 file and ensure Get-FileHash is available."
    Err "Only for emergency/local diagnostics, rerun with -Insecure to accept an unverified binary."
    return $false
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
        return (Allow-UnverifiedInstall "No .sha256 checksum was published for $AssetName at $($Script:Tag).")
    }
    if (-not $expected) {
        return (Allow-UnverifiedInstall "No .sha256 checksum was published for $AssetName at $($Script:Tag).")
    }
    try {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $BinaryPath -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        return (Allow-UnverifiedInstall "Get-FileHash could not verify $AssetName: $($_.Exception.Message)")
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

function Get-AutorouteCachePathForInstall {
    $raw = [Environment]::GetEnvironmentVariable('KEYHOG_AUTOROUTE_CACHE')
    if ($null -ne $raw) {
        $trimmed = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.ToLowerInvariant() -in @('0', 'off')) {
            return $null
        }
        if ($trimmed -match '^[A-Za-z]:[\\/]' -or $trimmed -match '^\\\\') {
            return $trimmed
        }
        Warn "Autoroute cache summary cannot use KEYHOG_AUTOROUTE_CACHE=$trimmed; the binary requires an absolute cache path."
        return $null
    }

    $root = $env:LOCALAPPDATA
    if (-not $root) {
        $root = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    }
    if (-not $root) { return $null }
    return (Join-Path (Join-Path $root 'keyhog') 'autoroute.json')
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
        Warn "Autoroute calibration summary unavailable: persistent autoroute cache is disabled or invalid."
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
        $oldCal = $env:KEYHOG_AUTOROUTE_CALIBRATE
        $oldBatch = $env:KEYHOG_BATCH_PIPELINE
        $oldGpu = $env:KEYHOG_GPU_AUTOROUTE
        $failed = $false
        $dockerImagesToRemove = @()
        $webJobsToStop = @()
        try {
            $env:KEYHOG_AUTOROUTE_CALIBRATE = '1'
            $env:KEYHOG_BATCH_PIPELINE = '1'
            $env:KEYHOG_GPU_AUTOROUTE = '1'
            $scanHelp = try { (& $BinPath scan --help 2>$null | Out-String) } catch { '' }
            $configArgs = if ($scanHelp -match '--no-config') {
                @('--no-config')
            } else {
                $emptyConfig = Join-Path $tmpDir 'empty-config.toml'
                New-Item -ItemType File -Force -Path $emptyConfig | Out-Null
                @('--config', $emptyConfig)
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
            foreach ($kib in @(4, 64)) {
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
            foreach ($mib in @(1, 8, 32)) {
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
            $tree = Join-Path $tmpDir 'many-4k'
            New-CalibrationTreeKiB -Path $tree -Files 32 -KiB 4
            $workloads += [pscustomobject]@{
                Label = '32 x 4 KiB files workload'
                Target = $tree
                Mode = 'path'
                Out = Join-Path $tmpDir 'out-many-4k.json'
                Stdout = Join-Path $tmpDir 'stdout-many-4k.txt'
                Stderr = Join-Path $tmpDir 'stderr-many-4k.txt'
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

            for ($i = 0; $i -lt $workloads.Count; $i++) {
                $workload = $workloads[$i]
                $label = "  [{0}/{1}] {2}" -f ($i + 1), $workloads.Count, $workload.Label
                switch ($workload.Mode) {
                    'stdin' {
                        $args = @('scan', '--stdin') + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'path' {
                        $args = @('scan', $workload.Target) + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'git-history' {
                        $args = @('scan', '--git-history', $workload.Target, '--max-commits', '1') + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'git-blobs' {
                        $args = @('scan', '--git-blobs', $workload.Target, '--max-commits', '2') + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'git-diff' {
                        $args = @('scan', '--git-diff', 'HEAD', '--git-diff-path', $workload.Target) + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'url' {
                        $args = @('scan', '--url', $workload.Target) + $configArgs + @('--format', 'json', '-o', $workload.Out)
                    }
                    'docker-image' {
                        $args = @('scan', '--docker-image', $workload.Target) + $configArgs + @('--format', 'json', '-o', $workload.Out)
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
                $proc = Start-Process @startArgs
                $frames = @('-', '\', '|', '/')
                $frame = 0
                while (-not $proc.HasExited) {
                    Write-Host ("`r{0} {1}" -f $label, $frames[$frame]) -NoNewline
                    $frame = ($frame + 1) % $frames.Count
                    Start-Sleep -Milliseconds 150
                    $proc.Refresh()
                }
                $proc.WaitForExit()
                if ($proc.ExitCode -eq 0) {
                    Write-Host ("`r{0} OK" -f $label)
                } else {
                    Write-Host ("`r{0} FAILED" -f $label)
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
            if (-not (Show-AutorouteCalibrationSummary -ProbeCount $workloads.Count -StartedAt $calibrationStartedAt)) {
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
            if ($null -eq $oldCal) { Remove-Item Env:KEYHOG_AUTOROUTE_CALIBRATE -ErrorAction SilentlyContinue } else { $env:KEYHOG_AUTOROUTE_CALIBRATE = $oldCal }
            if ($null -eq $oldBatch) { Remove-Item Env:KEYHOG_BATCH_PIPELINE -ErrorAction SilentlyContinue } else { $env:KEYHOG_BATCH_PIPELINE = $oldBatch }
            if ($null -eq $oldGpu) { Remove-Item Env:KEYHOG_GPU_AUTOROUTE -ErrorAction SilentlyContinue } else { $env:KEYHOG_GPU_AUTOROUTE = $oldGpu }
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
    Invoke-GitCalibrationCommand -GitPath $GitPath -Arguments @('-C', $Path, 'config', 'user.name', 'Keyhog Autoroute Calibration')
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
        param([string]$Root, [string]$PortPath)
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 0)
        $listener.Start()
        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            Set-Content -Path $PortPath -Encoding ASCII -Value $port
            while ($true) {
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
    } -ArgumentList $Path, $PortFile

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
    # Checksum is verified BEFORE we overwrite, so a corrupt artifact can never
    # replace a working binary. Downloads check against the release's per-asset
    # .sha256; a -FromFile install requires a sibling PATH.sha256 unless the
    # operator explicitly accepts an unverified local artifact.
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
        if (-not (Invoke-AutorouteCalibration -BinPath $BinPath)) {
            Err "Autoroute calibration failed; refusing to leave an install whose default auto route is not usable."
            if ($Script:InstallBackup -and (Test-Path $Script:InstallBackup)) {
                Move-Item -Force $Script:InstallBackup $BinPath
                $Script:InstallBackup = $null
                Warn "Rolled back to your previous working keyhog at $BinPath."
            } else {
                Remove-Item -Force $BinPath -ErrorAction SilentlyContinue
                Warn "Removed the uncalibrated binary; no working keyhog was overwritten."
            }
            return $false
        }
        if ($Script:InstallBackup) { Remove-Item -Force $Script:InstallBackup -ErrorAction SilentlyContinue; $Script:InstallBackup = $null }
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
