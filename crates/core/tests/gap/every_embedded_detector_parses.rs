//! Embedded-set integrity gate (DET-01 / MC-16 / T-04 / T-05 / DF-07).
//!
//! The dead `discord-bot-token` detector — a single-quoted TOML literal whose
//! char class embedded a `'`, breaking the parse — reached a *benched release
//! binary* as an invisible recall hole. It slipped through because:
//!   1. the runtime embedded-load path silently dropped unparseable detectors
//!      (`tracing::debug!` then continue — a Law-10 silent fallback, now fixed
//!      to fail closed in `cli::orchestrator_config::load_detectors_embedded_or_fail`),
//!      and
//!   2. the existing self-validation test parsed TOMLs from the **on-disk**
//!      `detectors/` tree, NOT the bytes actually **compiled into the binary**.
//!      An embed-time drop or an in-place edit could diverge from what shipped.
//!
//! This gate closes both holes at the source crate: it parses the EXACT
//! embedded slice (`keyhog_core::embedded_detector_tomls()` — the same bytes the
//! CLI loads) with the SAME `DetectorFile` deserializer the runtime uses, and
//! fails — naming every offender by file stem with the toml error — if a single
//! embedded detector does not parse. A detector that loads but is silently
//! dropped is decoration; this makes that impossible to ship.

use keyhog_core::{embedded_detector_count, embedded_detector_tomls, DetectorFile};

#[test]
fn every_embedded_detector_parses() {
    let embedded = embedded_detector_tomls();
    assert!(
        !embedded.is_empty(),
        "embedded detector catalog is empty — build.rs detector-embedding step \
         did not run; rebuild from a tree that contains `detectors/`"
    );

    let mut failed: Vec<String> = Vec::new();
    for (name, toml_content) in embedded {
        if let Err(error) = toml::from_str::<DetectorFile>(toml_content) {
            failed.push(format!("  - {name}: {error}"));
        }
    }

    assert!(
        failed.is_empty(),
        "{} of {} EMBEDDED detector(s) failed to parse — the binary would ship a \
         corrupt detector set with silently degraded recall (this is exactly how \
         the dead discord-bot-token detector reached a benched release). \
         Offenders:\n{}",
        failed.len(),
        embedded.len(),
        failed.join("\n"),
    );
}

/// T-05: the parseable embedded count must equal the embedded slice length, so
/// an embed-time drop (slice shorter than expected) or a parse failure (covered
/// above) cannot pass as a healthy load. Pinning the count to the slice length
/// — rather than a magic number — keeps the gate honest as the corpus grows.
#[test]
fn embedded_parseable_count_equals_slice_len() {
    let embedded = embedded_detector_tomls();
    let parseable = embedded
        .iter()
        .filter(|(_, toml_content)| toml::from_str::<DetectorFile>(toml_content).is_ok())
        .count();

    assert_eq!(
        parseable,
        embedded.len(),
        "only {parseable} of {} embedded detectors parse — every embedded TOML \
         must deserialize into a DetectorFile",
        embedded.len(),
    );
    assert_eq!(
        embedded.len(),
        embedded_detector_count(),
        "embedded slice length must match the authoritative embedded_detector_count()"
    );
}
