//! `cargo xtask check-cat-a` — one-shot gate that runs every
//! pre-merge CI step a Cat-A author cares about:
//!
//! 1. `cargo check --workspace --all-features --all-targets`
//! 2. `cargo clippy --workspace --all-features --all-targets -- -D warnings`
//! 3. `cargo test -p vyre-libs --all-features`
//! 4. `cargo test -p vyre-foundation --all-features` (region-inline + wire)
//! 5. `cargo test -p vyre-reference --all-features` (assign + lifetime)
//! 6. `scripts/check_parity_testing_not_leaked.sh`
//! 7. `scripts/check_op_names.sh`
//! 8. `cargo doc --workspace --all-features --no-deps`
//!
//! Exits non-zero on the first failure; prints a pass summary on
//! success. Designed to be the single command a Cat-A author runs
//! before opening a PR.

use std::path::PathBuf;
use std::process::{Command, ExitStatus};

fn repo_root() -> PathBuf {
    // xtask binary is invoked via `cargo xtask`, whose CWD is the
    // workspace root — use that directly.
    std::env::current_dir().expect("xtask must run in a cwd")
}

fn run_step(label: &str, mut cmd: Command) -> ExitStatus {
    println!("\n==> {label}");
    println!("    $ {cmd:?}");
    let status = cmd.status().unwrap_or_else(|err| {
        panic!("Fix: `{label}` could not launch: {err}");
    });
    if !status.success() {
        eprintln!("==> FAIL: {label} (exit {})", status.code().unwrap_or(-1));
    }
    status
}

pub fn run(_args: &[String]) {
    let root = repo_root();
    let mut failed = Vec::<&str>::new();

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let mut check = Command::new(&cargo);
    check
        .args(["check", "--workspace", "--all-features", "--all-targets"])
        .current_dir(&root);
    if !run_step("check (all-features, all-targets)", check).success() {
        failed.push("cargo check");
    }

    let mut clippy = Command::new(&cargo);
    clippy
        .args([
            "clippy",
            "--workspace",
            "--all-features",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(&root);
    if !run_step("clippy -D warnings", clippy).success() {
        failed.push("cargo clippy");
    }

    for crate_name in &["vyre-libs", "vyre-foundation", "vyre-reference"] {
        let mut test = Command::new(&cargo);
        test.args(["test", "-p", crate_name, "--all-features"])
            .current_dir(&root);
        if !run_step(&format!("test -p {crate_name}"), test).success() {
            failed.push("cargo test");
        }
    }

    for script in &[
        "scripts/check_parity_testing_not_leaked.sh",
        "scripts/check_op_names.sh",
    ] {
        let mut sh = Command::new("bash");
        sh.arg(script).current_dir(&root);
        if !run_step(script, sh).success() {
            failed.push(script);
        }
    }

    let mut doc = Command::new(&cargo);
    doc.args(["doc", "--workspace", "--all-features", "--no-deps"])
        .current_dir(&root);
    if !run_step("doc (no-deps)", doc).success() {
        failed.push("cargo doc");
    }

    if !failed.is_empty() {
        eprintln!("\n==> check-cat-a FAILED on: {failed:?}");
        std::process::exit(1);
    }
    println!("\n==> check-cat-a: all gates passed.");
}
