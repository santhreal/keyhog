//! Verifier test-directory wiring guard.
//!
//! Cargo does not auto-discover files below `tests/<dir>/`. A sibling `.rs`
//! file next to a `mod.rs` only compiles when that manifest declares it. This
//! guard keeps verifier gap/adversarial/unit shards from becoming invisible
//! coverage while `all_tests` still looks green.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn declared_modules(manifest: &Path) -> BTreeSet<String> {
    let src = std::fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("read module manifest {}: {e}", manifest.display()));
    src.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") {
                return None;
            }
            let rest = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))?;
            let name = rest.trim_end_matches(';').trim();
            (!name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'))
            .then(|| name.to_string())
        })
        .collect()
}

fn sibling_rust_modules(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read test module dir {}: {e}", dir.display()))
        .map(|entry| entry.unwrap_or_else(|e| panic!("read dir entry {}: {e}", dir.display())))
        .filter_map(|entry| {
            let path = entry.path();
            let is_rs = path.extension().is_some_and(|ext| ext == "rs");
            let is_mod = path.file_name().is_some_and(|name| name == "mod.rs");
            if !is_rs || is_mod {
                return None;
            }
            path.file_stem().map(|stem| stem.to_string_lossy().into_owned())
        })
        .collect()
}

fn manifest_for_dir(tests_root: &Path, dir: &Path) -> PathBuf {
    let rel = dir
        .strip_prefix(tests_root)
        .unwrap_or_else(|e| panic!("{} under {}: {e}", dir.display(), tests_root.display()));
    if rel.components().count() == 1 {
        let standalone = tests_root.join(format!("{}.rs", rel.display()));
        if standalone.exists() {
            return standalone;
        }
    }
    dir.join("mod.rs")
}

fn visit_module_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read test tree {}: {e}", dir.display()))
    {
        let entry = entry.unwrap_or_else(|e| panic!("read test tree entry {}: {e}", dir.display()));
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.join("mod.rs").exists() {
            out.push(path.clone());
        }
        visit_module_dirs(&path, out);
    }
}

#[test]
fn every_verifier_test_module_file_is_declared() {
    let tests_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut module_dirs = Vec::new();
    visit_module_dirs(&tests_root, &mut module_dirs);
    module_dirs.sort();

    let mut problems = Vec::new();
    for dir in module_dirs {
        let manifest = manifest_for_dir(&tests_root, &dir);
        let declared = declared_modules(&manifest);
        let files = sibling_rust_modules(&dir);
        let orphaned: Vec<&String> = files.difference(&declared).collect();
        if !orphaned.is_empty() {
            problems.push(format!(
                "{} declares {} module(s), but {} sibling file(s) are not declared: {:?}",
                manifest
                    .strip_prefix(&tests_root)
                    .unwrap_or(&manifest)
                    .display(),
                declared.len(),
                orphaned.len(),
                orphaned
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "orphaned verifier test files are invisible coverage loss:\n{}",
        problems.join("\n")
    );
}
