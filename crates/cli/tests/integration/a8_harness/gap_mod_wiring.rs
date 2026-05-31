//! LR2-A8 harness integration: cli `gap` module wiring is consistent.
//!
//! Replaces a brittle `assert_eq!(pub-mod count, 17)` that broke every time a
//! gap test was wired or un-wired (the `gap/` dir is a curated "wire-as-you-
//! close-it" tracker, so its count legitimately moves). The robust invariant:
//! every `pub mod NAME;` declared in `tests/gap/mod.rs` has a matching
//! `gap/NAME.rs` file (no dangling declaration), and the manifest is non-empty.

#[test]
fn gap_mod_wiring_is_consistent() {
    let gap_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap");
    let src = std::fs::read_to_string(gap_dir.join("mod.rs")).expect("gap/mod.rs readable");

    let declared: Vec<String> = src
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let name = line.strip_prefix("pub mod ").or_else(|| line.strip_prefix("mod "))?;
            let name = name.strip_suffix(';')?;
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| name.to_string())
        })
        .collect();

    assert!(
        !declared.is_empty(),
        "tests/gap/mod.rs must wire at least one gap module"
    );

    let dangling: Vec<&String> = declared
        .iter()
        .filter(|name| !gap_dir.join(format!("{name}.rs")).exists())
        .collect();
    assert!(
        dangling.is_empty(),
        "tests/gap/mod.rs declares modules with no matching gap/<name>.rs file: {dangling:?}"
    );
}
