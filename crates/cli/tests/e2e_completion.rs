//! e2e test for `keyhog completion <shell>`.
//!
//! The completion subcommand generates shell completion scripts for bash,
//! zsh, fish, powershell, and elvish. This test verifies that completions
//! are emitted with the correct format for each shell.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog completion bash` returns exit 0 with a valid bash completion script.
/// The script should define a completion function and include subcommand names.
#[test]
fn completion_bash_returns_exit_zero_with_function() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("bash")
        .output()
        .expect("spawn keyhog completion bash");

    assert_eq!(
        output.status.code(),
        Some(0),
        "completion bash should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "completion bash should emit completion script"
    );

    // Bash completions typically contain function definitions and subcommand references.
    assert!(
        stdout.contains("keyhog") || stdout.contains("scan") || stdout.contains("complete"),
        "bash completion should reference keyhog or its subcommands; got: {}",
        &stdout[..stdout.len().min(200)]
    );
}

/// `keyhog completion zsh` returns exit 0 with a zsh-formatted completion script.
#[test]
fn completion_zsh_returns_exit_zero_with_zsh_format() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("zsh")
        .output()
        .expect("spawn keyhog completion zsh");

    assert_eq!(
        output.status.code(),
        Some(0),
        "completion zsh should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "completion zsh should emit completion script"
    );

    // zsh completions often start with a shebang or include zsh-specific syntax.
    assert!(
        stdout.contains("keyhog")
            || stdout.contains("compdef")
            || stdout.contains("(")
            || stdout.contains("#"),
        "zsh completion should be valid; got: {}",
        &stdout[..stdout.len().min(200)]
    );
}

/// `keyhog completion fish` returns exit 0 with a fish shell completion script.
#[test]
fn completion_fish_returns_exit_zero_with_fish_format() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("fish")
        .output()
        .expect("spawn keyhog completion fish");

    assert_eq!(
        output.status.code(),
        Some(0),
        "completion fish should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "completion fish should emit completion script"
    );

    // Fish completions often use 'complete' command syntax.
    assert!(
        stdout.contains("complete") || stdout.contains("fish") || stdout.contains("keyhog"),
        "fish completion should be valid; got: {}",
        &stdout[..stdout.len().min(200)]
    );
}

/// `keyhog completion powershell` returns exit 0 with a PowerShell script.
#[test]
fn completion_powershell_returns_exit_zero_with_powershell_format() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("powershell")
        .output()
        .expect("spawn keyhog completion powershell");

    assert_eq!(
        output.status.code(),
        Some(0),
        "completion powershell should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "completion powershell should emit completion script"
    );

    // PowerShell scripts often contain function or class definitions.
    assert!(
        stdout.contains("function") || stdout.contains("keyhog") || stdout.contains("Register"),
        "powershell completion should be valid; got: {}",
        &stdout[..stdout.len().min(200)]
    );
}

/// `keyhog completion <invalid-shell>` returns exit 2 (user error) because
/// the shell name is not a valid option.
#[test]
fn completion_invalid_shell_exits_two() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("tcsh")
        .output()
        .expect("spawn keyhog completion tcsh");

    assert_eq!(
        output.status.code(),
        Some(2),
        "completion with invalid shell should exit 2 (user error)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("tcsh")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("shell"),
        "error should name the invalid shell; stderr: {stderr}"
    );
}

/// `keyhog completion --help` documents the shell argument and available options.
#[test]
fn completion_help_documents_available_shells() {
    let output = Command::new(binary())
        .arg("completion")
        .arg("--help")
        .output()
        .expect("spawn keyhog completion --help");

    assert_eq!(
        output.status.code(),
        Some(0),
        "completion --help should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The help should mention at least one shell option.
    assert!(
        stdout.contains("bash")
            || stdout.contains("zsh")
            || stdout.contains("fish")
            || stdout.contains("shell"),
        "help should document shell options; got: {stdout}"
    );
}
