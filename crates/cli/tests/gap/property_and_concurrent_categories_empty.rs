//! KH-GAP-140: CLI ships empty `property/` and `concurrent/` mods. STANDARD categories 3/5 missing.
//!
//! This is the watchdog for the orphaned-test-file class of rot: a directory under
//! `tests/` may accumulate `#[test]`-bearing `.rs` files while its module manifest
//! declares fewer (or zero) `mod` items, so those tests never compile or run. The
//! guard walks every test category at test time and fails when the category's
//! `mod.rs` or standalone `tests/<category>.rs` manifest declares fewer modules
//! than there are test-bearing `.rs` files in that directory. For the watchdog
//! itself to run it must be declared in `gap/mod.rs` (KH-GAP-140 cross-file fix).

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

/// Count of module declarations in the category manifest (matches `pub mod x;`
/// and `mod x;`).
fn declared_mods(manifest: &Path) -> Vec<String> {
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
    mods.sort();
    mods
}

/// STANDARD Test Contract categories 3 (property) and 5 (concurrent) must each ship
/// at least one test module, and every test-bearing file must be declared in the
/// category manifest.
#[test]
fn property_and_concurrent_categories_have_tests() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    for category in ["property", "concurrent"] {
        let dir = base.join(category);
        let manifest = declaration_manifest(&base, category);
        let files = test_bearing_files(&dir);
        let declared = declared_mods(&manifest);
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

/// Watchdog over ALL test categories: every `tests/<dir>/` that contains test-bearing
/// `.rs` files must declare each of them in its category manifest, so no test
/// silently rots.
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
        let declared = declared_mods(&manifest);
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
