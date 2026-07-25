//! KH-GAP-140: CLI ships empty `property/` and `concurrent/` mods. STANDARD categories 3/5 missing.
//!
//! This is the watchdog for the orphaned-test-file class of rot: a directory under
//! `tests/` may accumulate `#[test]`-bearing `.rs` files while no compiled module
//! owns them. The guard accepts both category-manifest `mod` declarations and
//! source-module `#[path = "..."] mod` declarations, because private unit tests
//! need the latter to exercise their production owner's internals. For the
//! watchdog itself to run it must be declared in `gap/mod.rs`.

use std::path::{Path, PathBuf};

/// Count of `.rs` files (excluding `mod.rs`) in `dir` that contain at least one
/// `#[test]` attribute (covers plain unit tests and `proptest!`/`#[test]` bodies).
fn test_bearing_files(dir: &Path) -> Vec<String> {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read test dir {}: {e}", dir.display()));
    let mut files = entries
        .map(|entry| entry.unwrap_or_else(|e| panic!("read test dir entry {}: {e}", dir.display())))
        .filter_map(|e| {
            let path = e.path();
            let is_rs = path.extension().is_some_and(|x| x == "rs");
            let is_mod = e.file_name() == "mod.rs";
            if !is_rs || is_mod {
                return None;
            }
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read test module {}: {e}", path.display()));
            if src.contains("#[test]") {
                path.file_stem().map(|s| s.to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// Return the category's module manifest. Standalone test binaries like
/// `tests/adversarial.rs` intentionally keep heavy suites out of `all_tests`.
fn declaration_manifest(base: &Path, category: &str) -> PathBuf {
    let standalone = base.join(format!("{category}.rs"));
    if standalone.exists() {
        standalone
    } else {
        base.join(category).join("mod.rs")
    }
}

/// Module declarations in the category manifest, plus externally split unit
/// modules compiled by a production owner through Rust's `#[path]` attribute.
fn declared_mods(manifest: &Path, base: &Path, category: &str) -> Vec<String> {
    let src = std::fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("read test module manifest {}: {e}", manifest.display()));
    let mut mods: Vec<String> = src
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Skip doc/comment lines so a commented-out `// mod x;` does not count.
            if line.starts_with("//") {
                return None;
            }
            let rest = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))?;
            let name = rest.trim_end_matches(';').trim();
            // Reject inline modules (`mod x { ... }`) and anything non-leaf.
            if name.is_empty() || name.contains(['{', ' ', ':']) {
                return None;
            }
            Some(name.to_string())
        })
        .collect();
    mods.extend(externally_owned_mods(base, category));
    mods.sort();
    mods.dedup();
    mods
}

fn externally_owned_mods(base: &Path, category: &str) -> Vec<String> {
    fn visit(dir: &Path, category_dir: &Path, owned: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read source dir {}: {e}", dir.display()))
        {
            let path = entry.expect("source dir entry").path();
            if path.is_dir() {
                visit(&path, category_dir, owned);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read source module {}: {e}", path.display()));
            for line in source.lines() {
                let Some(relative) = line
                    .trim()
                    .strip_prefix("#[path = \"")
                    .and_then(|line| line.strip_suffix("\"]"))
                else {
                    continue;
                };
                let target = path
                    .parent()
                    .expect("source module has a parent")
                    .join(relative)
                    .canonicalize()
                    .unwrap_or_else(|e| {
                        panic!(
                            "resolve external test module {} from {}: {e}",
                            relative,
                            path.display()
                        )
                    });
                if target.parent() == Some(category_dir) {
                    owned.push(
                        target
                            .file_stem()
                            .expect("external test module has a stem")
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
    }

    let category_dir = base
        .join(category)
        .canonicalize()
        .unwrap_or_else(|e| panic!("resolve tests/{category}: {e}"));
    let mut owned = Vec::new();
    visit(
        &base.parent().expect("tests has a crate root").join("src"),
        &category_dir,
        &mut owned,
    );
    owned
}

/// STANDARD Test Contract categories 3 (property) and 5 (concurrent) must each ship
/// at least one test module, and every test-bearing file must have a compiled owner.
#[test]
fn property_and_concurrent_categories_have_tests() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    for category in ["property", "concurrent"] {
        let dir = base.join(category);
        let manifest = declaration_manifest(&base, category);
        let files = test_bearing_files(&dir);
        let declared = declared_mods(&manifest, &base, category);
        assert!(
            !files.is_empty() || !declared.is_empty(),
            "tests/{category}/ must ship at least one test module per STANDARD Test Contract"
        );
        let missing: Vec<&String> = files.iter().filter(|f| !declared.contains(f)).collect();
        assert!(
            missing.is_empty(),
            "{} declares {} module(s) but {} test-bearing file(s) exist; \
             orphaned (never-compiled) test files: {:?}",
            manifest.strip_prefix(&base).unwrap_or(&manifest).display(),
            declared.len(),
            files.len(),
            missing
        );
    }
}

/// Watchdog over ALL test categories: every test-bearing `tests/<dir>/*.rs` file
/// must have either a category-manifest owner or an external production unit-test
/// owner, so no test silently rots.
#[test]
fn no_test_category_has_orphaned_files() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut offenders: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(&base).expect("read tests/ dir");
    for entry in entries.map(|entry| {
        entry.unwrap_or_else(|e| panic!("read tests/ dir entry {}: {e}", base.display()))
    }) {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let category = dir.file_name().unwrap().to_string_lossy().into_owned();
        let manifest = declaration_manifest(&base, &category);
        // Only directories that act as a category (have a manifest) are guarded.
        if !manifest.exists() {
            continue;
        }
        let files = test_bearing_files(&dir);
        let declared = declared_mods(&manifest, &base, &category);
        // Regression: externally split private unit tests are already executed
        // by their production module; duplicating them in all_tests does not compile.
        let missing: Vec<&String> = files.iter().filter(|f| !declared.contains(f)).collect();
        if !missing.is_empty() {
            offenders.push(format!(
                "{}: {} declared vs {} test files; orphaned: {:?}",
                manifest.strip_prefix(&base).unwrap_or(&manifest).display(),
                declared.len(),
                files.len(),
                missing
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "orphaned test files detected (declared in no category manifest, so never compiled/run):\n{}",
        offenders.join("\n")
    );
}
