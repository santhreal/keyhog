//! Contract: nothing under `crates/scanner/tests/` may be a Git LFS pointer.
//!
//! Test sources (`*.rs`) and fixtures (`*.toml`, `*.proptest-regressions`) had
//! been LFS-tracked via `.gitattributes`. In a checkout without Git LFS those
//! files materialize as pointer text (`version https://git-lfs.github.com/...`):
//!   - an LFS-tracked `*.rs` is parsed by Cargo as Rust, so
//!     `cargo check --all-targets` fails before a single test runs;
//!   - an LFS-tracked contract `*.toml` is parsed by `contracts_runner` as
//!     TOML, so `load_contracts()` panics.
//!
//! This guard fails loudly if that misconfiguration ever returns, and catches
//! the root cause two ways so it fires regardless of whether THIS checkout has
//! LFS installed:
//!   1. content check   — no test source/fixture is an LFS pointer (catches an
//!      actual pointer in a non-LFS checkout);
//!   2. attribute check — `.gitattributes` assigns `filter=lfs` to no path under
//!      the scanner test tree (catches the root cause in an LFS checkout, where
//!      the content is smudged to real text and the content check would pass).

use std::path::{Path, PathBuf};

const LFS_POINTER_SIGNATURE: &str = "version https://git-lfs.github.com/spec/v1";
const FIXTURE_EXTS: [&str; 3] = ["rs", "toml", "proptest-regressions"];

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn scanner_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Collect every text source/fixture under `dir`, recursively.
fn fixture_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            fixture_sources(&path, out);
            continue;
        }
        // `*.proptest-regressions` has no conventional extension split, so match
        // on the file name suffix rather than Path::extension.
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if FIXTURE_EXTS
            .iter()
            .any(|ext| name.ends_with(&format!(".{ext}")))
        {
            out.push(path);
        }
    }
}

#[test]
fn no_test_source_or_fixture_is_an_lfs_pointer() {
    let mut sources = Vec::new();
    fixture_sources(&scanner_tests_dir(), &mut sources);
    assert!(
        sources.len() > 100,
        "found only {} test sources/fixtures under {} — the walk is broken \
         (the contract corpus alone is ~900 files)",
        sources.len(),
        scanner_tests_dir().display(),
    );

    let pointers: Vec<&PathBuf> = sources
        .iter()
        .filter(|p| {
            let source = std::fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("failed to read Rust test source {}: {e}", p.display()));
            source.starts_with(LFS_POINTER_SIGNATURE)
        })
        .collect();

    assert!(
        pointers.is_empty(),
        "test sources/fixtures are committed as Git LFS pointers (a non-LFS \
         checkout cannot compile/parse them): {pointers:?}. Remove the matching \
         `filter=lfs` rule from .gitattributes and re-add the files as normal text.",
    );
}

#[test]
fn gitattributes_does_not_lfs_track_the_test_tree() {
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
            line.split_whitespace()
                .next()
                .is_some_and(|pat| pat.contains("crates/scanner/tests"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        ".gitattributes LFS-tracks files under the scanner test tree — this breaks \
         `cargo check` / contracts_runner in non-LFS checkouts: {offenders:?}. \
         Test sources and fixtures must be normal text.",
    );
}
