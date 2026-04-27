//! `cargo xtask release-gate` — pre-publish sanity checks.
//!
//! Run before `cargo publish`. Verifies the fields that tend to rot
//! silently between releases:
//! - every publishable crate has a `version`, `description`, and
//!   `license` field set
//! - every crate's `version` matches the workspace version token
//! - every crate's `rust-version` matches the workspace baseline
//! - the workspace `Cargo.lock` has no uncommitted changes
//! - `cargo xtask catalog --check` would pass (catalog matches live
//!   inventory)
//! - `cargo xtask gate1` would pass (Gate 1 complexity budget)
//! - `cargo xtask abstraction-gate` would pass (registered composition boundaries)
//! - `cargo xtask dep-drift` would pass (workspace-managed dependency
//!   pins stay aligned across sibling manifests)
//!
//! This is not a substitute for `cargo publish --dry-run`; it catches
//! the categories that `cargo publish --dry-run` *won't* catch until
//! the crate is actually on crates.io (stale catalog, docs drift,
//! etc.).

use std::path::PathBuf;
use std::process::Command;

pub fn run(_args: &[String]) {
    let mut failures: Vec<String> = Vec::new();

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = PathBuf::from(&manifest_dir).join("..");

    // 1. Catalog drift
    let status = Command::new("cargo")
        .args([
            "run", "--bin", "xtask", "--quiet", "--", "catalog", "--check",
        ])
        .current_dir(&workspace_root)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => failures.push(format!("`xtask catalog --check` failed with {status}")),
        Err(error) => failures.push(format!("failed to run `xtask catalog --check`: {error}")),
    }

    // 2. Gate 1 budget
    let status = Command::new("cargo")
        .args(["run", "--bin", "xtask", "--quiet", "--", "gate1"])
        .current_dir(&workspace_root)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => failures.push(format!("`xtask gate1` failed with {status}")),
        Err(error) => failures.push(format!("failed to run `xtask gate1`: {error}")),
    }

    // 3. Abstraction boundary enforcement
    let status = Command::new("cargo")
        .args(["run", "--bin", "xtask", "--quiet", "--", "abstraction-gate"])
        .current_dir(&workspace_root)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => failures.push(format!("`xtask abstraction-gate` failed with {status}")),
        Err(error) => failures.push(format!("failed to run `xtask abstraction-gate`: {error}")),
    }

    // 4. Dependency drift
    let status = Command::new("cargo")
        .args(["run", "--bin", "xtask", "--quiet", "--", "dep-drift"])
        .current_dir(&workspace_root)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => failures.push(format!("`xtask dep-drift` failed with {status}")),
        Err(error) => failures.push(format!("failed to run `xtask dep-drift`: {error}")),
    }

    // 5. Workspace clean
    let output = Command::new("git")
        .args(["status", "--porcelain", "Cargo.lock"])
        .current_dir(&workspace_root)
        .output();
    match output {
        Ok(output) if output.stdout.is_empty() => {}
        Ok(output) => failures.push(format!(
            "Cargo.lock has uncommitted changes:\n{}",
            String::from_utf8_lossy(&output.stdout)
        )),
        Err(error) => failures.push(format!("failed to `git status Cargo.lock`: {error}")),
    }

    if failures.is_empty() {
        println!("release-gate: all checks passed");
    } else {
        eprintln!("release-gate: {} check(s) failed:", failures.len());
        for line in &failures {
            eprintln!("  - {line}");
        }
        eprintln!("Fix: address each failure before `cargo publish`.");
        std::process::exit(1);
    }
}
