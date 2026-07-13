//! Regression: `keyhog completion <shell>` must emit the *exact* shell-specific
//! marker that a real completion loader recognizes, for every supported shell,
//! and reject unknown shells with the clap usage-error exit code.
//!
//! These assertions are concrete: each shell generator in `clap_complete` 4.6.0
//! writes a fixed anchor line keyed on the binary name (`keyhog`). If the
//! subcommand ever pipes the wrong shell, drops the generator, or renames the
//! binary out from under the completion header, exactly one of these markers
//! disappears and the corresponding test fails with a precise diff.
//!
//! Anchors verified against the vendored generator source
//! (`clap_complete-4.6.0/src/aot/shells/*.rs`):
//!   bash       -> `_keyhog() {`   and   `complete -F _keyhog`
//!   zsh        -> `#compdef keyhog` (first line)
//!   fish       -> `complete -c keyhog`
//!   powershell -> `Register-ArgumentCompleter -Native -CommandName 'keyhog' -ScriptBlock {`
//!   elvish     -> `set edit:completion:arg-completer[keyhog] = {`

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog completion <shell>` and return (exit_code, stdout, stderr).
fn run_completion(shell: &str) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .arg("completion")
        .arg(shell)
        .output()
        .expect("spawn keyhog completion");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Positive: each shell emits its exact marker with exit code 0.
// ---------------------------------------------------------------------------

#[test]
fn bash_emits_keyhog_function_marker() {
    let (code, stdout, stderr) = run_completion("bash");
    assert_eq!(code, Some(0), "bash exit code; stderr={stderr}");
    assert!(
        stdout.contains("_keyhog() {"),
        "bash completion must define the `_keyhog() {{` function; got head: {}",
        &stdout[..stdout.len().min(300)]
    );
}

#[test]
fn bash_registers_completion_via_complete_dash_f() {
    // The bash-*unique* registration line (`complete -F _keyhog ...`), this is
    // what distinguishes a bash script from zsh, which also defines `_keyhog()`.
    let (code, stdout, _stderr) = run_completion("bash");
    assert_eq!(code, Some(0));
    assert!(
        stdout.contains("complete -F _keyhog"),
        "bash completion must register with `complete -F _keyhog`; got tail: {}",
        &stdout[stdout.len().saturating_sub(300)..]
    );
}

#[test]
fn zsh_first_line_is_compdef_keyhog() {
    let (code, stdout, stderr) = run_completion("zsh");
    assert_eq!(code, Some(0), "zsh exit code; stderr={stderr}");
    // clap_complete writes `#compdef {name}` as the very first bytes.
    assert!(
        stdout.starts_with("#compdef keyhog"),
        "zsh completion must begin with `#compdef keyhog`; got head: {:?}",
        &stdout[..stdout.len().min(40)]
    );
}

#[test]
fn fish_emits_complete_dash_c_keyhog() {
    let (code, stdout, stderr) = run_completion("fish");
    assert_eq!(code, Some(0), "fish exit code; stderr={stderr}");
    assert!(
        stdout.contains("complete -c keyhog"),
        "fish completion must use `complete -c keyhog`; got head: {}",
        &stdout[..stdout.len().min(300)]
    );
}

#[test]
fn powershell_emits_register_argument_completer_for_keyhog() {
    let (code, stdout, stderr) = run_completion("powershell");
    assert_eq!(code, Some(0), "powershell exit code; stderr={stderr}");
    assert!(
        stdout.contains("Register-ArgumentCompleter -Native -CommandName 'keyhog' -ScriptBlock {"),
        "powershell completion must register for CommandName 'keyhog'; got head: {}",
        &stdout[..stdout.len().min(300)]
    );
}

#[test]
fn elvish_emits_arg_completer_binding_for_keyhog() {
    let (code, stdout, stderr) = run_completion("elvish");
    assert_eq!(code, Some(0), "elvish exit code; stderr={stderr}");
    assert!(
        stdout.contains("set edit:completion:arg-completer[keyhog] = {"),
        "elvish completion must bind `edit:completion:arg-completer[keyhog]`; got head: {}",
        &stdout[..stdout.len().min(300)]
    );
}

// ---------------------------------------------------------------------------
// Cross-shell distinctness (negative twins): a shell's script must NOT carry a
// different shell's anchor. This catches a mis-wired `args.shell` dispatch that
// would emit the wrong generator while still exiting 0.
// ---------------------------------------------------------------------------

#[test]
fn bash_script_has_no_zsh_or_powershell_markers() {
    let (code, stdout, _stderr) = run_completion("bash");
    assert_eq!(code, Some(0));
    assert!(
        !stdout.contains("#compdef keyhog"),
        "bash script must not contain the zsh `#compdef keyhog` marker"
    );
    assert!(
        !stdout.contains("Register-ArgumentCompleter"),
        "bash script must not contain the powershell `Register-ArgumentCompleter` marker"
    );
}

#[test]
fn zsh_script_has_no_bash_register_or_powershell_markers() {
    let (code, stdout, _stderr) = run_completion("zsh");
    assert_eq!(code, Some(0));
    assert!(
        !stdout.contains("complete -F _keyhog"),
        "zsh script must not contain the bash `complete -F _keyhog` registration"
    );
    assert!(
        !stdout.contains("Register-ArgumentCompleter"),
        "zsh script must not contain the powershell `Register-ArgumentCompleter` marker"
    );
}

#[test]
fn fish_script_has_no_powershell_or_elvish_markers() {
    let (code, stdout, _stderr) = run_completion("fish");
    assert_eq!(code, Some(0));
    assert!(
        !stdout.contains("Register-ArgumentCompleter"),
        "fish script must not contain the powershell marker"
    );
    assert!(
        !stdout.contains("edit:completion:arg-completer"),
        "fish script must not contain the elvish arg-completer marker"
    );
}

// ---------------------------------------------------------------------------
// Success path writes the script to stdout, not stderr.
// ---------------------------------------------------------------------------

#[test]
fn successful_completion_leaves_stderr_empty() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let (code, stdout, stderr) = run_completion(shell);
        assert_eq!(code, Some(0), "{shell} exit code");
        assert_eq!(
            stderr, "",
            "{shell} completion must not write to stderr on success; stderr={stderr}"
        );
        assert!(
            stdout.contains("keyhog"),
            "{shell} completion script must reference the binary name"
        );
    }
}

// ---------------------------------------------------------------------------
// Negative / boundary: unknown or malformed shell arguments.
// ---------------------------------------------------------------------------

#[test]
fn unknown_shell_exits_with_usage_error_code_two() {
    let (code, stdout, stderr) = run_completion("tcsh");
    assert_eq!(
        code,
        Some(2),
        "unknown shell must exit 2 (clap usage error); stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.is_empty(),
        "no completion script should be printed for an invalid shell; stdout={stdout}"
    );
    assert!(
        stderr.contains("tcsh"),
        "usage error must name the rejected shell `tcsh`; stderr={stderr}"
    );
}

#[test]
fn uppercase_shell_name_is_rejected_case_sensitively() {
    // clap_complete's Shell::from_str matches case-sensitively (ignore_case=false),
    // so `BASH` is not a valid value and must be a usage error, not a bash script.
    let (code, stdout, stderr) = run_completion("BASH");
    assert_eq!(
        code,
        Some(2),
        "uppercase `BASH` must be rejected with exit 2; stdout={stdout} stderr={stderr}"
    );
    assert!(
        !stdout.contains("_keyhog() {"),
        "uppercase `BASH` must not produce a bash completion script"
    );
}

#[test]
fn missing_shell_argument_exits_with_usage_error_code_two() {
    let output = Command::new(binary())
        .arg("completion")
        .output()
        .expect("spawn keyhog completion (no shell)");
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing required <shell> arg must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "no script should print when the shell argument is missing; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// Help surface enumerates every supported shell as a possible value.
// ---------------------------------------------------------------------------

#[test]
fn help_lists_all_five_supported_shells() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("--help")
        .output()
        .expect("spawn keyhog completion --help");
    assert_eq!(output.status.code(), Some(0), "completion --help exit code");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        assert!(
            stdout.contains(shell),
            "completion --help must list `{shell}` as a possible value; got:\n{stdout}"
        );
    }
}
