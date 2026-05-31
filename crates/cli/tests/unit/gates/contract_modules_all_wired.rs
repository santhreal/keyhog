//! Gate: every `tests/<dir>/*.rs` test file MUST be declared in its declaring
//! module file. A subdir test file only compiles/runs if a `mod`/`pub mod` line
//! includes it; a file dropped in without that line is silently DEAD coverage
//! (no error, no warning). This regressed badly across the whole cli test tree
//! (contract 3/97 wired, adversarial/property/concurrent mod.rs EMPTY, gap
//! 18/48), so this is a HARD gate over every directory that has had drift.
//!
//! Declaring files differ by layout:
//!   - in-`all_tests` dirs declare in `<dir>/mod.rs` (`pub mod NAME;`)
//!   - standalone test binaries declare in `tests/<dir>.rs` (`#[path] mod NAME;`)

use std::collections::BTreeSet;

/// Module names declared via `mod NAME;` / `pub mod NAME;` in `decl_file`.
/// `#[path = "..."]` attribute lines (no trailing `;` after an identifier) are
/// ignored — only the `mod NAME;` line itself is counted.
fn declared_modules(decl_file: &str) -> BTreeSet<String> {
    let src = std::fs::read_to_string(decl_file)
        .unwrap_or_else(|e| panic!("declaring file {decl_file} readable: {e}"));
    src.lines()
        .filter_map(|line| {
            let line = line.trim().strip_suffix(';')?;
            let rest = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))?;
            rest.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| rest.to_string())
        })
        .collect()
}

/// Test-module file stems on disk in `dir` (every `*.rs` except `mod.rs`).
fn files_on_disk(dir: &str) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("test dir {dir} readable: {e}"))
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".rs")?;
            (stem != "mod").then(|| stem.to_string())
        })
        .collect()
}

#[test]
fn contract_modules_all_wired() {
    let root = env!("CARGO_MANIFEST_DIR");
    // (subdir under tests/, file that declares its modules, relative to tests/).
    // `gap/` is intentionally excluded: it is a curated "wire-as-you-close-it"
    // known-gap tracker whose own watchdog (gap::…::no_test_category_has_orphaned_files)
    // governs it; gating it here would force every open gap test green-or-wired.
    let pairs = [
        ("contract", "contract/mod.rs"),
        ("concurrent", "concurrent/mod.rs"),
        ("adversarial", "adversarial.rs"), // standalone binary root
        ("property", "property.rs"),       // standalone binary root
    ];

    let mut problems = Vec::new();
    for (dir, decl) in pairs {
        let dir_abs = format!("{root}/tests/{dir}");
        let decl_abs = format!("{root}/tests/{decl}");
        let declared = declared_modules(&decl_abs);
        let on_disk = files_on_disk(&dir_abs);

        // Orphan direction only: a file on disk that is NOT declared is silently
        // dead coverage (the compiler never sees it — no error). The reverse
        // (a declared module with no file) is a hard compile error (E0583), so
        // it needs no gate; and standalone binary roots legitimately declare
        // out-of-dir prelude modules (e.g. adversarial.rs pulls in the e2e
        // support helper via `#[path]`), which a reverse check would misflag.
        let orphaned: Vec<&String> = on_disk.difference(&declared).collect();
        if !orphaned.is_empty() {
            problems.push(format!(
                "{dir}/: {} file(s) on disk but NOT declared in {decl} \
                 (they never compile or run): {orphaned:?}",
                orphaned.len()
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "test-directory wiring drift (orphaned tests are invisible coverage loss):\n{}",
        problems.join("\n")
    );
}
