#!/usr/bin/env bash
# Static analysis for installer and trust-root shell/PowerShell scripts.
#
# Local runs loud-skip missing optional linters so a developer box without
# PowerShell can still run source gates. CI sets REQUIRE_INSTALL_LINTERS=1 so
# missing ShellCheck, shfmt, pwsh, or PSScriptAnalyzer is a hard failure.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

rc=0
REQUIRE_INSTALL_LINTERS="${REQUIRE_INSTALL_LINTERS:-0}"

run() {
    local label="$1"
    shift
    echo "== ${label} =="
    "$@" || rc=1
    echo
}

need_tool() {
    local tool="$1"
    if command -v "$tool" > /dev/null 2>&1; then
        return 0
    fi
    echo "SKIP (loud): ${tool} is not installed."
    if [ "$REQUIRE_INSTALL_LINTERS" = "1" ]; then
        echo "  REQUIRE_INSTALL_LINTERS=1 - treating this skip as a FAILURE." >&2
        rc=1
    fi
    return 1
}

shell_dialect() {
    local file="$1"
    case "$file" in
        install.sh) echo "sh" ;;
        *) echo "bash" ;;
    esac
}

shellcheck_targets=(install.sh)
shfmt_parse_targets=(install.sh)
shfmt_diff_targets=(scripts/gates/install_static_analysis.sh)

for file in "${shellcheck_targets[@]}"; do
    case "$(shell_dialect "$file")" in
        sh) run "POSIX syntax: ${file}" sh -n "$file" ;;
        bash) run "bash syntax: ${file}" bash -n "$file" ;;
    esac
done

if need_tool shellcheck; then
    for file in "${shellcheck_targets[@]}"; do
        run "ShellCheck: ${file}" shellcheck -x -s "$(shell_dialect "$file")" "$file"
    done
fi

if need_tool shfmt; then
    for file in "${shfmt_parse_targets[@]}"; do
        run "shfmt parse: ${file}" sh -c \
            'shfmt --to-json -ln "$1" --filename "$2" < "$2" >/dev/null' \
            sh "$(shell_dialect "$file")" "$file"
    done
    for file in "${shfmt_diff_targets[@]}"; do
        run "shfmt diff: ${file}" shfmt -d -i 4 -ci -sr -kp -ln "$(shell_dialect "$file")" "$file"
    done
fi

run_powershell_gate() {
    pwsh -NoLogo -NoProfile -NonInteractive -File - << 'PS1'
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ./install.ps1), [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
  $errors | ForEach-Object {
    Write-Host "ERROR: $($_.Message) @ line $($_.Extent.StartLineNumber)"
  }
  exit 1
}
Import-Module PSScriptAnalyzer -ErrorAction Stop
$issues = Invoke-ScriptAnalyzer -Path ./install.ps1 -Severity Error,Warning
if ($issues.Count -gt 0) {
  $issues | Format-Table -AutoSize | Out-String | Write-Host
  exit 1
}
Write-Host "install.ps1 parsed cleanly and passed PSScriptAnalyzer."
PS1
}

if need_tool pwsh; then
    run "PowerShell parse + PSScriptAnalyzer: install.ps1" run_powershell_gate
fi

exit "$rc"
