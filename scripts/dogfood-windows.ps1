#requires -Version 5
<#
.SYNOPSIS
  Deep Windows dogfood for keyhog: build the Windows-shippable binary, then
  exercise the real CLI on real inputs and assert exit codes + findings.

.DESCRIPTION
  Building directly from the NFS share (Z:) fails on Windows: the shared
  Cargo.lock takes a byte-range lock from the desktop's auto-backup and the
  Windows NFS client hard-fails (os error 33). So this syncs the source to a
  LOCAL build dir first. It also removes crates\core\detectors -- on Linux that
  is a symlink to ..\..\detectors, which robocopy/tar flatten into an empty dir,
  tripping core/build.rs ("contains no .toml"); removing it lets build.rs fall
  through to the workspace detectors/.

  Windows ships the `portable` feature set (no hyperscan / CUDA / GPU system
  libs), which is the cargo-install profile real Windows users get.

.EXAMPLE
  pwsh scripts\dogfood-windows.ps1                       # from Z: (interactive session)
  pwsh scripts\dogfood-windows.ps1 -Source C:\src\keyhog # from an already-local copy
#>
param(
  [string]$Source   = 'Z:\software\keyhog',
  [string]$BuildDir = 'C:\keyhog-dogfood\build',
  [string]$Target   = 'C:\cargo-target',
  [string]$Profile  = 'release-fast'
)
$ErrorActionPreference = 'Stop'
$script:fail = 0
function Check($name, $cond) { if ($cond) { Write-Output "  PASS $name" } else { Write-Output "  FAIL $name"; $script:fail = 1 } }

Write-Output "== keyhog Windows dogfood =="
Write-Output "   source=$Source  build=$BuildDir  target=$Target  profile=$Profile"

# 1. Sync source -> local build dir (skip if already building in place).
if ($Source -ne $BuildDir) {
  New-Item -ItemType Directory -Force $BuildDir | Out-Null
  robocopy "$Source\crates"    "$BuildDir\crates"    /E /XD target .git /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null
  robocopy "$Source\detectors" "$BuildDir\detectors" /E             /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null
  Copy-Item "$Source\Cargo.toml","$Source\Cargo.lock" $BuildDir -Force
  # install.ps1 is dogfooded below (the installer phase). Copy it in so the
  # ssh/ship path (dogfood-all-os.sh run_win) has it locally on C:.
  if (Test-Path "$Source\install.ps1") { Copy-Item "$Source\install.ps1" $BuildDir -Force }
}
$coreDet = Join-Path $BuildDir 'crates\core\detectors'
if (Test-Path $coreDet) { Remove-Item $coreDet -Recurse -Force }

$detCount = (Get-ChildItem "$BuildDir\detectors\*.toml" -ErrorAction SilentlyContinue).Count
Check "source synced ($detCount detectors)" ($detCount -gt 0)

# 2. Build the portable profile.
$env:CARGO_TARGET_DIR = $Target
& cargo build --profile $Profile -p keyhog --no-default-features --features portable --manifest-path "$BuildDir\Cargo.toml"
Check "cargo build (portable)" ($LASTEXITCODE -eq 0)
# cargo's `dev` profile emits to target\debug; custom profiles use their own name.
$pdir = $Profile; if ($Profile -eq 'dev') { $pdir = 'debug' }
$kh = Join-Path $Target "$pdir\keyhog.exe"
Check "binary produced" (Test-Path $kh)
if (-not (Test-Path $kh)) { Write-Output "WINDOWS DOGFOOD: FAIL (no binary)"; exit 1 }

# 3. Dogfood the real CLI on real inputs.
$t = Join-Path $env:TEMP ("kh-dog-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force $t | Out-Null
try {
  "aws_access_key_id = AKIAZ4RNVT5QW3MXK7PD`r`ngithub_token = ghp_0123456789abcdefghijklmnopqrstuvwxyz" |
    Set-Content "$t\leak.env" -Encoding ascii
  "nothing secret here, just prose" | Set-Content "$t\clean.txt" -Encoding ascii
  "aws_access_key_id = AKIAZ4RNVT5QW3MXK7PD" | Set-Content "$t\stdin.txt" -Encoding ascii

  # Invoke via `cmd /c ... 2>nul`: PowerShell 5.1 merges a native exe's stderr
  # into its own error stream under `*>`, which trips $ErrorActionPreference='Stop'
  # (keyhog writes a WARN to stderr on the git-history path). cmd swallows stderr
  # so only the real exit code ($LASTEXITCODE) reaches us.
  cmd /c "`"$kh`" --version >nul 2>nul";                            Check "version"               ($LASTEXITCODE -eq 0)
  $out = cmd /c "`"$kh`" scan `"$t\leak.env`" --format json 2>nul"; $rc = $LASTEXITCODE
  Check "planted secret -> exit 1"                                  ($rc -eq 1)
  Check "planted secret -> aws-access-key detector"                 ($out -match 'aws-access-key')
  cmd /c "`"$kh`" scan `"$t\clean.txt`" >nul 2>nul";                Check "clean tree -> exit 0"  ($LASTEXITCODE -eq 0)
  cmd /c "`"$kh`" scan --git-history `"$t`" >nul 2>nul";            Check "git-history non-repo -> exit 2 (fail-closed)" ($LASTEXITCODE -eq 2)
  cmd /c "`"$kh`" scan --stdin < `"$t\stdin.txt`" >nul 2>nul";      Check "stdin secret -> exit 1" ($LASTEXITCODE -eq 1)
} finally {
  Remove-Item $t -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. Installer dogfood: drive install.ps1's local-binary path (-FromFile) into a
#    throwaway prefix, then prove the INSTALLED binary runs and `keyhog doctor`
#    passes. Mirrors the unix install proof (tests/install/install_from_local_
#    build.sh). The removed terminal dashboard has no Windows dogfood branch;
#    this proof stays on the supported scan/doctor surfaces.
$installScript = Join-Path $BuildDir 'install.ps1'
if (-not (Test-Path $installScript)) { $installScript = Join-Path $Source 'install.ps1' }
if (Test-Path $installScript) {
  $prefix = Join-Path $env:TEMP ("kh-install-" + [System.IO.Path]::GetRandomFileName())
  try {
    # Invoke as a child process and read $LASTEXITCODE; *>$null keeps the
    # installer's own banner/doctor output from tripping ErrorActionPreference.
    & powershell -NoProfile -ExecutionPolicy Bypass -File $installScript `
        -FromFile $kh -InstallDir $prefix -Yes -NoColor *> $null
    Check "install.ps1 -FromFile exit 0" ($LASTEXITCODE -eq 0)
    $installed = Join-Path $prefix 'keyhog.exe'
    Check "installed binary present" (Test-Path $installed)
    if (Test-Path $installed) {
      cmd /c "`"$installed`" --version >nul 2>nul"; Check "installed --version exit 0" ($LASTEXITCODE -eq 0)
      cmd /c "`"$installed`" doctor >nul 2>nul";    Check "installed doctor exit 0"    ($LASTEXITCODE -eq 0)
    }
  } finally {
    Remove-Item $prefix -Recurse -Force -ErrorAction SilentlyContinue
  }
} else {
  Check "install.ps1 present beside source/build" $false
}

# 5. `uninstall` exit-code contract -- the ONE deliberate cross-OS divergence.
#    On Unix the kernel unlinks a running executable, so `uninstall --yes` exits
#    0 and the file is gone (proven on macOS). Windows refuses to delete a
#    running .exe, so `remove_binary` FAILS CLOSED with an anyhow error that
#    main.rs maps to EXIT_USER_ERROR = 2, and the binary STAYS. We assert that
#    Windows contract here on a throwaway COPY (so the real build survives).
#    crates/cli/tests/target_spec/cross_os_contracts.rs pins the same divergence
#    at the source level; this is the live end-to-end proof.
$ut = Join-Path $env:TEMP ("kh-uninst-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force $ut | Out-Null
try {
  $copy = Join-Path $ut 'keyhog-copy.exe'
  Copy-Item $kh $copy
  cmd /c "`"$copy`" uninstall >nul 2>nul";        Check "uninstall dry-run -> exit 0"               ($LASTEXITCODE -eq 0)
  cmd /c "`"$copy`" uninstall --yes >nul 2>nul";  Check "uninstall --yes -> exit 2 (Windows fail-closed)" ($LASTEXITCODE -eq 2)
  Check "uninstall --yes leaves the running .exe in place (Windows)" (Test-Path $copy)
} finally {
  Remove-Item $ut -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:fail -ne 0) { Write-Output "WINDOWS DOGFOOD: FAIL"; exit 1 }
Write-Output "WINDOWS DOGFOOD: PASS"; exit 0
