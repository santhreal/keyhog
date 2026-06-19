use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn declared_modules(mod_rs_src: &str) -> BTreeSet<String> {
    mod_rs_src
        .lines()
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

pub(super) fn rs_file_stems(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("read entry in {}: {e}", dir.display()))
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .filter_map(|path| {
            let stem = path.file_stem()?.to_str()?;
            (stem != "mod").then(|| stem.to_string())
        })
        .collect()
}

#[test]
fn every_unit_gate_file_is_declared() {
    let gate_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unit/gates");
    let mod_rs = gate_dir.join("mod.rs");
    let mod_src = std::fs::read_to_string(&mod_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", mod_rs.display()));

    let files = rs_file_stems(&gate_dir);
    let declared = declared_modules(&mod_src);

    assert!(
        !files.is_empty(),
        "no scanner unit gate files found under {}",
        gate_dir.display()
    );

    let orphaned: Vec<&String> = files.difference(&declared).collect();
    assert!(
        orphaned.is_empty(),
        "{}: gate files on disk are not declared in mod.rs, so they never compile or run: {orphaned:?}",
        gate_dir.display()
    );
}
