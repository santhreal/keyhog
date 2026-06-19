//! KH-GAP-004: Inline `#[cfg(test)]` modules in `src/` violate the
//! Santh folder contract - all micro gates live under `tests/unit/`.
//!
//! ALLOWLIST: a SMALL, explicit set of crate-private modules whose tests are
//! white-box - they assert on private fields / call `pub(crate)` items whose
//! types are deliberately NOT part of the crate's public API. Migrating those
//! tests to an external `tests/` file would force exposing the internals as
//! `pub` purely to satisfy this lint, a worse trade (Law 1 / minimal public
//! surface) than keeping the white-box tests co-located with the code they pin.
//! Every entry is reviewed and must STAY a real offender: a stale entry (file
//! removed, or its tests since migrated) fails this gate loudly, so the
//! exception can never silently outlive the reason it was granted.

use std::path::{Path, PathBuf};

/// Crate-private modules permitted to keep co-located `#[cfg(test)]` white-box
/// tests. Paths are relative to `src/`. Keep this list SHORT and justified.
const INLINE_TEST_ALLOWLIST: &[&str] = &[
    // `MegakernelCatalog` is a `pub(crate)` GPU DFA-lowering internal. Its catalog
    // classification (lowerable-vs-host) tests assert on the `pub(crate)`
    // build/host_detectors API and the private rule set. No external test can
    // reach this without making GPU internals `pub`, so white-box co-location is
    // the correct place for the coverage (Law 1 / minimal public surface).
    "engine/megakernel.rs",
    // The catalog cache wire (de)serialization, split out of megakernel.rs
    // (Law 5). Its round-trip test asserts on the `pub(super)` private fields
    // (`rules`, `rule_to_detector`, `host_detectors`) and calls `pub(crate)`
    // build + the `MatchEngineCache` to_bytes/from_bytes — same white-box
    // rationale as megakernel.rs: external `tests/` would force exposing the
    // catalog internals as `pub`.
    "engine/megakernel_wire.rs",
    // `merge_validated_triggers` and `validation_window_range` are `pub(crate)`
    // dispatch helpers whose tests assert on private result fields
    // (`raw_pairs`, `gpu_overfire_dropped`, `gpu_underfire_recovered`,
    // `triggers`).  Moving them to `tests/` would require making those fields
    // `pub`, violating the minimal-surface law (Law 1).  The inline module is
    // gated `#[cfg(all(test, feature = "gpu"))]` — same white-box rationale as
    // megakernel.rs / megakernel_wire.rs above.
    "engine/megakernel_dispatch.rs",
];

/// True iff `path` ends with an allowlisted `src/`-relative path (component-wise,
/// so it is exact and cross-platform - never a loose substring match).
fn is_allowlisted(path: &Path) -> bool {
    INLINE_TEST_ALLOWLIST
        .iter()
        .any(|rel| path.ends_with(Path::new(rel)))
}

fn scan_rust_sources(dir: &Path, offenders: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_rust_sources(&path, offenders);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
        let has_inline_test = super::inline_gate::contains_inline_test_module_or_function(&content);
        if has_inline_test {
            offenders.push(path);
        }
    }
}

#[test]
fn no_inline_tests_in_src() {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan_rust_sources(&src_dir, &mut offenders);
    offenders.sort();

    let rel = |p: &Path| {
        p.strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(p)
            .display()
            .to_string()
    };

    // Disallowed offenders: every inline-test src file that is NOT allowlisted.
    let disallowed: Vec<String> = offenders
        .iter()
        .filter(|p| !is_allowlisted(p))
        .map(|p| rel(p))
        .collect();
    assert!(
        disallowed.is_empty(),
        "{} scanner/src files still contain #[cfg(test)] - migrate to tests/unit/:\n  - {}",
        disallowed.len(),
        disallowed.join("\n  - ")
    );

    // Stale-allowlist guard: each allowlist entry must still correspond to a real
    // inline-test offender. If a file was removed or its tests migrated, the entry
    // is dead and must be deleted - otherwise it would silently exempt a future
    // file at the same path (Law 9: no evasion; the exception must earn its place
    // every run).
    for entry in INLINE_TEST_ALLOWLIST {
        assert!(
            offenders.iter().any(|p| p.ends_with(Path::new(entry))),
            "stale INLINE_TEST_ALLOWLIST entry `{entry}`: it no longer contains an inline \
             #[cfg(test)] (file moved or tests migrated) - remove it from the allowlist",
        );
    }
}
