//! LR2-A8 harness integration: sources `gap` module wiring is consistent.
//!
//! Supersedes a brittle `assert_eq!(pub-mod count, 24)` that broke every time a
//! gap test was wired or un-wired (the `gap/` dir is a curated "wire-as-you-
//! close-it" tracker, so its count legitimately moves). The robust invariant:
//! every `gap/NAME.rs` file has exactly one `pub mod NAME;` declaration and
//! every declaration has a matching file. A file on disk without a declaration
//! is never compiled or run.

use std::collections::BTreeSet;

fn declared_modules(mod_rs_src: &str) -> BTreeSet<String> {
    mod_rs_src
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") {
                return None;
            }
            let name = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))?;
            let name = name.strip_suffix(';')?.trim();
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| name.to_string())
        })
        .collect()
}

fn gap_file_modules(gap_dir: &std::path::Path) -> BTreeSet<String> {
    std::fs::read_dir(gap_dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", gap_dir.display()))
        .map(|entry| entry.expect("gap dir entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .filter_map(|path| {
            let stem = path.file_stem()?.to_str()?;
            (stem != "mod").then(|| stem.to_string())
        })
        .collect()
}

#[test]
fn gap_mod_wiring_is_consistent() {
    let gap_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap");
    let src = std::fs::read_to_string(gap_dir.join("mod.rs")).expect("gap/mod.rs readable");

    let declared = declared_modules(&src);
    let files = gap_file_modules(&gap_dir);

    assert!(
        !declared.is_empty(),
        "tests/gap/mod.rs must wire at least one gap module"
    );

    let orphan_files: Vec<&String> = files.difference(&declared).collect();
    assert!(
        orphan_files.is_empty(),
        "tests/gap contains .rs files that are not registered in mod.rs and therefore never run: {orphan_files:?}"
    );

    let dangling: Vec<&String> = declared.difference(&files).collect();
    assert!(
        dangling.is_empty(),
        "tests/gap/mod.rs declares modules with no matching gap/<name>.rs file: {dangling:?}"
    );
}
