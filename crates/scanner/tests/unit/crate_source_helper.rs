//! Contract for the canonical crate-source readers
//! ([`keyhog_scanner::testing::crate_source_path`] /
//! [`keyhog_scanner::testing::read_crate_source`]).
//!
//! These exist because source-introspection tests must read crate files off
//! disk in a way that does NOT depend on the process working directory. A bare
//! `read_to_string` of a `"src/..."` literal resolves against the CWD and only
//! works under a plain `cargo test`; it `NotFound`-flakes under nextest, a raw
//! test-binary run, or a sibling test that mutates the global CWD. The helpers
//! anchor to the compile-time `CARGO_MANIFEST_DIR`, so the resolved path is a
//! constant property of the build, not of the runtime CWD. This suite pins
//! that anchoring, the resolution arithmetic, and the panic-on-missing
//! contract.

use keyhog_scanner::testing::{crate_source_path, read_crate_source};
use std::path::Path;

/// The crate manifest root, exactly as the helper anchors to it. Computed the
/// same way the helper does so the tests below assert against an independent
/// statement of the invariant rather than re-deriving from the helper itself.
const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

/// A small source file that is guaranteed to exist and to carry stable marker
/// strings — used as a convenient on-disk fixture for the read tests.
const FIXTURE: &str = "src/context/placeholder.rs";

// ── crate_source_path: pure resolution arithmetic ───────────────────────────

#[test]
fn path_is_absolute() {
    assert!(
        crate_source_path(FIXTURE).is_absolute(),
        "resolved crate-source path must be absolute regardless of CWD"
    );
}

#[test]
fn path_equals_manifest_join() {
    // The core CWD-independence invariant: the path is precisely the
    // compile-time manifest dir joined with `rel`, never derived from the
    // runtime working directory.
    assert_eq!(
        crate_source_path(FIXTURE),
        Path::new(MANIFEST).join(FIXTURE)
    );
}

#[test]
fn path_starts_with_manifest_dir() {
    assert!(
        crate_source_path(FIXTURE).starts_with(MANIFEST),
        "resolved path must live under the manifest root"
    );
}

#[test]
fn path_ends_with_rel_components() {
    assert!(
        crate_source_path(FIXTURE).ends_with(FIXTURE),
        "resolved path must end with the requested relative components"
    );
}

#[test]
fn empty_rel_is_the_manifest_dir() {
    assert_eq!(crate_source_path(""), Path::new(MANIFEST));
}

#[test]
fn nested_rel_appends_each_component() {
    let p = crate_source_path("src/context/placeholder.rs");
    let comps: Vec<_> = p
        .strip_prefix(MANIFEST)
        .expect("under manifest")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    assert_eq!(comps, vec!["src", "context", "placeholder.rs"]);
}

#[test]
fn manifest_dir_basename_is_scanner_crate() {
    // The crate lives at crates/scanner, so the manifest dir's final component
    // is "scanner". This pins that `CARGO_MANIFEST_DIR` resolves to THIS crate,
    // not the workspace root (the exact distinction nextest exposes).
    assert_eq!(
        Path::new(MANIFEST).file_name().and_then(|n| n.to_str()),
        Some("scanner")
    );
}

#[test]
fn path_is_cwd_independent_by_construction() {
    // `crate_source_path` must not consult the runtime CWD: its value equals the
    // manifest join no matter what `current_dir()` happens to be. We assert the
    // structural identity (cheap, race-free) rather than mutating the global
    // CWD — which would itself poison sibling tests.
    let from_helper = crate_source_path(FIXTURE);
    let from_constant = Path::new(MANIFEST).join(FIXTURE);
    assert_eq!(from_helper, from_constant);
    assert!(
        !from_helper.starts_with(std::env::current_dir().unwrap_or_default())
            || from_helper.is_absolute()
    );
}

#[test]
fn resolved_fixture_exists_on_disk() {
    assert!(
        crate_source_path(FIXTURE).exists(),
        "the fixture path must resolve to a real file"
    );
}

// ── read_crate_source: content delivery ─────────────────────────────────────

#[test]
fn read_returns_non_empty() {
    assert!(!read_crate_source(FIXTURE).is_empty());
}

#[test]
fn read_matches_manual_manifest_anchored_read() {
    // Differential: the helper must deliver byte-identical content to a manual
    // CARGO_MANIFEST_DIR-anchored read.
    let manual = std::fs::read_to_string(Path::new(MANIFEST).join(FIXTURE))
        .expect("manual manifest-anchored read");
    assert_eq!(read_crate_source(FIXTURE), manual);
}

#[test]
fn read_is_deterministic_across_calls() {
    assert_eq!(read_crate_source(FIXTURE), read_crate_source(FIXTURE));
}

#[test]
fn read_lib_rs_exposes_testing_module() {
    // Reading a different crate file works too, confirming the helper is not
    // special-cased to one path.
    let lib = read_crate_source("src/lib.rs");
    assert!(
        lib.contains("pub mod testing;"),
        "lib.rs must declare the testing facade"
    );
}

#[test]
fn read_cargo_toml_names_this_crate() {
    let toml = read_crate_source("Cargo.toml");
    assert!(
        toml.contains("keyhog-scanner"),
        "Cargo.toml must name the keyhog-scanner package"
    );
}

#[test]
fn read_homoglyph_source_contains_expand_fn() {
    // Ties the helper to a real source-introspection use: confirm the #69
    // homoglyph module is reachable and carries its public expander.
    let h = read_crate_source("src/homoglyph.rs");
    assert!(
        h.contains("fn expand_homoglyphs("),
        "homoglyph.rs must define expand_homoglyphs"
    );
}

// ── placeholder.rs invariants, now read THROUGH the helper ──────────────────
// These re-pin the structural invariants the original (CWD-relative) test
// checked, proving the migration preserved its assertions.

#[test]
fn fixture_has_exactly_one_step_helper() {
    let src = read_crate_source(FIXTURE);
    assert_eq!(
        src.matches("fn hex_pair_column_step(").count(),
        1,
        "hex-pair column detection must share one step helper"
    );
}

#[test]
fn fixture_avoids_pairs_temporary_vec() {
    assert!(!read_crate_source(FIXTURE).contains("let pairs: Vec"));
}

#[test]
fn fixture_avoids_first_chars_temporary_vec() {
    assert!(!read_crate_source(FIXTURE).contains("let first_chars: Vec"));
}

#[test]
fn fixture_avoids_second_chars_temporary_vec() {
    assert!(!read_crate_source(FIXTURE).contains("let second_chars: Vec"));
}

// ── panic-on-missing contract ───────────────────────────────────────────────

#[test]
#[should_panic(expected = "read crate source")]
fn read_missing_file_panics_with_resolved_path() {
    // A typo in `rel` must be a loud, obvious failure (panic naming the
    // resolved absolute path), never a silent empty string.
    let _ = read_crate_source("src/__definitely_not_a_real_file__.rs");
}

#[test]
fn missing_path_resolves_but_does_not_exist() {
    let p = crate_source_path("src/__definitely_not_a_real_file__.rs");
    assert!(p.is_absolute());
    assert!(!p.exists());
}
