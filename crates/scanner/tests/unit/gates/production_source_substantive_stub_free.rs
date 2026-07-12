//! Gate: EVERY production source file under `src/` is substantive (not a
//! near-empty stub) and free of `todo!()` / `unimplemented!()` in real code.
//!
//! This one directory-walking gate replaces the ~60 per-module `*_non_empty`
//! template gates, which each hand-picked a single module and asserted the
//! identical pair of facts. Walking `src/` covers every one of them PLUS every
//! module they never listed (66 hand-picked -> all 205 source files), and it
//! cannot drift as new modules are added. The few `*_non_empty` gates that
//! carried EXTRA, module-specific assertions keep their own gate for those
//! checks; only the pure-template ones were folded in here.

use super::support::{collect_rs_files, read, scanner_src, uncommented_code};

/// Minimum trimmed byte length for a source file to count as substantive. The
/// smallest real scanner source is ~112 non-whitespace bytes, so 20 is a safe
/// floor that still catches an accidentally-emptied or stubbed-out file.
const MIN_SUBSTANTIVE_TRIMMED_BYTES: usize = 20;

#[test]
fn every_production_source_is_substantive_and_stub_free() {
    let src = scanner_src();
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "no production source files found under {}",
        src.display()
    );

    let mut thin = Vec::new();
    let mut stubbed = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&src)
            .unwrap_or(path)
            .display()
            .to_string();
        let source = read(path);
        if source.trim().len() < MIN_SUBSTANTIVE_TRIMMED_BYTES {
            thin.push(format!("{rel} ({} trimmed bytes)", source.trim().len()));
        }
        // Uncommented so a `todo!()` mentioned in a doc/// line is not flagged.
        let prod = uncommented_code(&source);
        if prod.contains("todo!()") || prod.contains("unimplemented!()") {
            stubbed.push(rel);
        }
    }

    assert!(
        thin.is_empty(),
        "production source files are not substantive (near-empty/stub): {thin:#?}"
    );
    assert!(
        stubbed.is_empty(),
        "todo!()/unimplemented!() forbidden in production source (Law 2): {stubbed:#?}"
    );
}
