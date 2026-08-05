use std::path::Path;

use super::unit_gate_modules_all_wired::{declared_modules, rs_file_stems};

#[test]
fn every_unit_engine_case_file_is_declared() {
    let engine_cases_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unit/engine_cases");
    let mod_rs = engine_cases_dir.join("mod.rs");
    let mod_src = std::fs::read_to_string(&mod_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", mod_rs.display()));

    let files = rs_file_stems(&engine_cases_dir);
    let declared = declared_modules(&mod_src);

    assert!(
        !files.is_empty(),
        "no scanner unit engine-case files found under {}",
        engine_cases_dir.display()
    );

    let orphaned: Vec<&String> = files.difference(&declared).collect();
    assert!(
        orphaned.is_empty(),
        "{}: engine-case files on disk are not declared in mod.rs, so they never compile or run: {orphaned:?}",
        engine_cases_dir.display()
    );
}
