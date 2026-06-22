//! LR2-A8 harness integration: a3 adversarial decode files are wired.

use std::collections::BTreeSet;

#[test]
fn a3_adversarial_decode_files_are_declared() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/a3_decode");
    let files = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let entry = e.as_ref().unwrap();
            let path = entry.path();
            if path.extension().map(|x| x == "rs").unwrap_or(false)
                && path.file_name().unwrap() != "mod.rs"
            {
                path.file_stem().map(|stem| stem.to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    let mod_src = std::fs::read_to_string(dir.join("mod.rs")).expect("a3_decode/mod.rs");
    let declared = mod_src
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("mod ")?;
            let name = rest.strip_suffix(';')?;
            Some(name.to_string())
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        files, declared,
        "tests/adversarial/a3_decode files must be declared in mod.rs so they compile and run"
    );
}
