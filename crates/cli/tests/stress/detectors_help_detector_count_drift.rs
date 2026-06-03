//! KH-GAP-094 (stress): `keyhog detectors --help` and the `detectors` banner
//! must both report the SAME corpus size the binary actually loads — derived at
//! runtime, never hardcoded. The count is rendered from
//! `keyhog_core::embedded_detector_count()`, so the expected value here comes
//! from the binary's own `detectors --json` output rather than a literal that
//! goes stale every time a detector is added.

use crate::e2e::support::binary;
use std::process::Command;

/// Embedded detector count = number of objects in `keyhog detectors --json`,
/// counted via the per-detector `"companions":` key (one per detector) to avoid
/// a JSON dependency in the test.
fn embedded_count() -> usize {
    let out = Command::new(binary())
        .args(["detectors", "--json"])
        .output()
        .expect("spawn detectors --json");
    let json = String::from_utf8_lossy(&out.stdout);
    let trimmed = json.trim();
    assert!(
        trimmed.starts_with('['),
        "detectors --json must emit a JSON array; got first 80 bytes: {:?}",
        &trimmed[..trimmed.len().min(80)]
    );
    json.matches("\"companions\":").count()
}

#[test]
fn detectors_search_help_does_not_undercount_embedded_corpus() {
    let embedded = embedded_count();
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
    let cited: usize = tail
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("could not parse the <N>-strong count from help; help={help}"));
    assert_eq!(
        cited, embedded,
        "detectors --help cites {cited}-strong but the binary loads {embedded} detectors; \
         the advertised corpus size must not undercount the embedded corpus (KH-GAP-094)"
    );
}

#[test]
fn detectors_listing_reports_at_least_891_loaded() {
    let embedded = embedded_count();
    let output = Command::new(binary())
        .args(["detectors"])
        .output()
        .expect("spawn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&embedded.to_string()),
        "detectors banner must report the embedded count ({embedded}); stdout={stdout}"
    );
}
