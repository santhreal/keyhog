//! Shared invariant for the LR2-A8 harness: a test suite's `mod.rs` must
//! register exactly the set of sibling `*.rs` test files — no orphans (a file
//! on disk with no `mod` declaration is never compiled or run) and no phantoms
//! (a `mod` declaration with no matching file).
//!
//! This replaces two brittle magic-count gates (`gap_mod_has_ten_modules`,
//! `contract_mod_has_ten_modules`). A hardcoded module count breaks on every
//! legitimate add/remove AND — worse — silently tolerates an orphan test file
//! whenever the count happens to match. That is the exact failure that let four
//! `gap/` oracles (two of them registered findings, KH-GAP-177/178) and two
//! SARIF `contract/` tests sit un-wired: written, even tracked as "green" in the
//! registry, yet never compiled or executed. A correspondence check has no
//! magic number to drift and fails loudly the moment a file is added without
//! wiring it (or a `mod` line outlives its file).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Module names declared in a `mod.rs` via `pub mod NAME;` or `mod NAME;`.
fn declared_modules(mod_rs_src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in mod_rs_src.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        let rest = line
            .strip_prefix("pub mod ")
            .or_else(|| line.strip_prefix("mod "));
        if let Some(name) = rest.and_then(|r| r.strip_suffix(';')) {
            out.insert(name.trim().to_string());
        }
    }
    out
}

/// Sibling Rust module stems in a suite directory: `foo.rs` and `foo/mod.rs`
/// both require a `mod foo;` / `pub mod foo;` declaration from the parent.
fn sibling_module_stems(suite_dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let entries = std::fs::read_dir(suite_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", suite_dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.join("mod.rs").exists() {
                let stem = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .expect("utf8 dir stem")
                    .to_string();
                out.insert(stem);
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("utf8 stem")
            .to_string();
        if stem == "mod" {
            continue;
        }
        out.insert(stem);
    }
    out
}

fn module_dirs_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if !path.is_dir() {
            continue;
        }
        if path.join("mod.rs").exists() {
            out.push(path.clone());
        }
        module_dirs_under(&path, out);
    }
}

/// Assert that `<crate>/tests/<suite_rel>/mod.rs` registers exactly its sibling
/// test files. `suite_rel` is relative to the crate manifest dir (e.g. "gap").
pub fn assert_suite_fully_wired(suite_rel: &str) {
    let suite_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(suite_rel);
    let mod_rs = suite_dir.join("mod.rs");
    let src = std::fs::read_to_string(&mod_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", mod_rs.display()));

    let files = sibling_module_stems(&suite_dir);
    let declared = declared_modules(&src);

    assert!(
        !files.is_empty(),
        "no sibling Rust modules found under {} — the walk is broken",
        suite_dir.display()
    );

    let orphans: Vec<&String> = files.difference(&declared).collect();
    assert!(
        orphans.is_empty(),
        "{}: test files on disk are not registered in mod.rs, so they are never \
         compiled or run (orphans): {orphans:?}. Add `pub mod <name>;` for each, \
         or delete the dead file.",
        suite_dir.display()
    );

    let phantoms: Vec<&String> = declared.difference(&files).collect();
    assert!(
        phantoms.is_empty(),
        "{}: declares modules with no matching .rs file (phantoms): {phantoms:?}.",
        mod_rs.display()
    );
}

/// Assert every `tests/**/mod.rs` manifest in the crate declares exactly the
/// sibling Rust module files/directories it can compile.
pub fn assert_all_test_module_manifests_wired() {
    let tests_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut module_dirs = Vec::new();
    module_dirs_under(&tests_root, &mut module_dirs);
    module_dirs.sort();

    let mut failures = Vec::new();
    for dir in module_dirs {
        let mod_rs = dir.join("mod.rs");
        let src = std::fs::read_to_string(&mod_rs)
            .unwrap_or_else(|e| panic!("read {}: {e}", mod_rs.display()));
        let files = sibling_module_stems(&dir);
        let declared = declared_modules(&src);
        let orphans: Vec<&String> = files.difference(&declared).collect();
        let phantoms: Vec<&String> = declared.difference(&files).collect();
        if !orphans.is_empty() || !phantoms.is_empty() {
            failures.push(format!(
                "{}: orphans={orphans:?}; phantoms={phantoms:?}",
                mod_rs
                    .strip_prefix(&tests_root)
                    .unwrap_or(&mod_rs)
                    .display()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "core test module manifest drift; orphaned tests are invisible coverage loss:\n{}",
        failures.join("\n")
    );
}
