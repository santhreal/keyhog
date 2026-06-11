//! Contract: Rust test sources must be real Rust, never Git LFS pointers.
//!
//! Background: `*.rs` test files had been LFS-tracked (`readme_claims.rs`,
//! `diagnose_*.rs`). In a checkout without Git LFS those files materialize as
//! pointer text (`version https://git-lfs.github.com/spec/v1` ...), which Cargo
//! tries to parse as Rust, so `cargo check --all-targets` fails before a single
//! test runs. This guard fails loudly if that misconfiguration ever returns —
//! and it catches the root cause two ways, so it fires regardless of whether
//! THIS checkout has LFS installed:
//!
//!   1. content check  — no `tests/**/*.rs` is an LFS pointer (catches an
//!      actual pointer in a non-LFS checkout);
//!   2. attribute check — `.gitattributes` assigns `filter=lfs` to no `.rs`
//!      path (catches the root cause in an LFS checkout, where the content is
//!      smudged to real source and the content check would pass).

use std::path::{Path, PathBuf};

const LFS_POINTER_SIGNATURE: &str = "version https://git-lfs.github.com/spec/v1";

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn scanner_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Collect every `*.rs` under `dir`, recursively.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_rust_test_source_is_an_lfs_pointer() {
    let mut sources = Vec::new();
    rust_sources(&scanner_tests_dir(), &mut sources);
    assert!(
        !sources.is_empty(),
        "found no .rs test sources under {} — the walk is broken",
        scanner_tests_dir().display(),
    );

    let pointers: Vec<&PathBuf> = sources
        .iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.starts_with(LFS_POINTER_SIGNATURE))
                .unwrap_or(false)
        })
        .collect();

    assert!(
        pointers.is_empty(),
        "Rust test sources are committed as Git LFS pointers (a non-LFS checkout \
         cannot compile them): {pointers:?}. Remove the matching `filter=lfs` rule \
         from .gitattributes and re-add the files as normal text.",
    );
}

#[test]
fn gitattributes_does_not_lfs_track_rust_sources() {
    let gitattributes = repo_root().join(".gitattributes");
    let Ok(text) = std::fs::read_to_string(&gitattributes) else {
        // No .gitattributes => nothing can be LFS-tracked. Pass.
        return;
    };

    let offenders: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.contains("filter=lfs"))
        .filter(|line| {
            // The pattern is the first whitespace-delimited token.
            line.split_whitespace()
                .next()
                .is_some_and(|pat| pat.ends_with(".rs"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        ".gitattributes LFS-tracks Rust source(s) — this breaks `cargo check` in \
         non-LFS checkouts: {offenders:?}. Rust sources must be normal text.",
    );
}
