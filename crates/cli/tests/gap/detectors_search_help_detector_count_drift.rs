//! KH-GAP-094: `keyhog detectors --help` must cite the SAME corpus size the
//! binary actually loads (drift-proof, with no hardcoded number).
//!
//! History: this originally pinned a literal "894-strong" in the help text.
//! The count is now rendered at runtime from `keyhog_core::embedded_detector_count()`
//! (see the crates/cli/src/main.rs command builder), so a hardcoded expectation
//! is itself the drift bug. This test derives the expected value from the
//! binary's own `detectors --format json` output and asserts the help text agrees, so
//! adding or removing a detector can never silently desync the advertised
//! corpus size from the corpus actually compiled in.

use crate::e2e::support::binary;
use std::process::Command;

/// Embedded detector count = number of objects in `keyhog detectors --format json`.
/// Counts the per-detector `"companions":` key (every detector object emits
/// exactly one) to avoid pulling a JSON dependency into the test.
fn embedded_count() -> usize {
    let out = Command::new(binary())
        .args(["detectors", "--format", "json"])
        .output()
        .expect("spawn detectors --format json");
    let json = String::from_utf8_lossy(&out.stdout);
    let trimmed = json.trim();
    assert!(
        trimmed.starts_with('['),
        "detectors --format json must emit a JSON array; got first 80 bytes: {:?}",
        &trimmed[..trimmed.len().min(80)]
    );
    json.matches("\"companions\":").count()
}

/// Parse the `<N>-strong corpus` count cited in `detectors --help`.
fn help_cited_count() -> usize {
    let out = Command::new(binary())
        .args(["detectors", "--help"])
        .output()
        .expect("spawn detectors --help");
    let help = String::from_utf8_lossy(&out.stdout);
    let idx = help
        .find("-strong")
        .unwrap_or_else(|| panic!("detectors --help must cite an <N>-strong corpus; help={help}"));
    let tail: String = help[..idx]
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    tail.chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("could not parse the <N>-strong count from help; help={help}"))
}

#[test]
fn detectors_search_help_does_not_undercount_embedded_corpus() {
    let embedded = embedded_count();
    let cited = help_cited_count();
    assert_eq!(
        cited, embedded,
        "detectors --help cites a {cited}-strong corpus but the binary loads {embedded} \
         detectors; the help count must track keyhog_core::embedded_detector_count() and \
         never drift (KH-GAP-094)"
    );
}
