//! Gate: every `tests/contract/*.rs` file MUST be declared in
//! `tests/contract/mod.rs`. A contract test only runs if its module is wired;
//! a file dropped in the directory without a `pub mod` line is silently dead
//! coverage. This regressed badly once (3 of 97 contract modules wired, 94
//! orphaned and never compiled), so this is a HARD gate, not advisory.

#[test]
fn contract_modules_all_wired() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/contract");
    let mod_rs =
        std::fs::read_to_string(format!("{dir}/mod.rs")).expect("contract/mod.rs readable");

    // Module names declared in mod.rs (`pub mod NAME;` / `mod NAME;`).
    let declared: std::collections::BTreeSet<String> = mod_rs
        .lines()
        .filter_map(|line| {
            let line = line.trim().strip_suffix(';')?;
            let rest = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))?;
            // Reject anything with extra tokens (e.g. `mod foo { ... }`).
            rest.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| rest.to_string())
        })
        .collect();

    // Module names present on disk (every `*.rs` except `mod.rs`).
    let on_disk: std::collections::BTreeSet<String> = std::fs::read_dir(dir)
        .expect("contract dir readable")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".rs")?;
            (stem != "mod").then(|| stem.to_string())
        })
        .collect();

    let orphaned: Vec<&String> = on_disk.difference(&declared).collect();
    let dangling: Vec<&String> = declared.difference(&on_disk).collect();

    assert!(
        orphaned.is_empty(),
        "contract test files on disk but NOT declared in tests/contract/mod.rs \
         (they never compile or run — add `pub mod NAME;`): {orphaned:?}"
    );
    assert!(
        dangling.is_empty(),
        "tests/contract/mod.rs declares modules with no matching file \
         (remove the stale `pub mod NAME;`): {dangling:?}"
    );
}
