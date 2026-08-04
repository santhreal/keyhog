//! One detector's pattern must not change another detector's findings.
//!
//! Adding a leading character-class guard to `wix-api-credentials` pattern 0
//! made `datadog-application-key` stop reporting eight credentials on the mirror
//! corpus, on input containing no `wix` at all. The mechanism was the shared
//! prefilter: removing the leading literal left the pattern with nothing to
//! route on, and the prefilter degraded for the whole corpus rather than for
//! that one pattern. Declaring `required_literals = ["wix"]` restored them.
//!
//! Two things are pinned here. The concrete victim, because eight real
//! credentials went missing and a count is what proves they are back. And the
//! invariant, because the next pattern edited without a routing literal will
//! break some other detector, and a test naming only datadog would not say so.

use keyhog_core::{Chunk, DetectorSpec};
use keyhog_scanner::CompiledScanner;

mod support;
use support::paths::detector_dir;

/// A Datadog application key in the form the mirror corpus plants it.
const DATADOG_FIXTURE: &str =
    "[production]\ndatadog_app_key = e6cfaf62f60ad477feb548bfabea6eea5c18eadd\n";

fn corpus() -> Vec<DetectorSpec> {
    keyhog_core::load_detectors(&detector_dir()).expect("detector corpus loads from disk")
}

fn detectors_firing(detectors: Vec<DetectorSpec>, text: &str) -> Vec<String> {
    let scanner = CompiledScanner::compile(detectors).expect("detector corpus compiles");
    let mut ids: Vec<String> = scanner
        .scan(&Chunk::from(text.to_string()))
        .expect("scan succeeds")
        .into_iter()
        .map(|m| m.detector_id.to_string())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The victim reports again.
///
/// A plain count, on the exact input that lost it, so a future prefilter change
/// that quietly drops Datadog fails here rather than in a corpus diff nobody
/// runs.
#[test]
fn datadog_application_key_reports_from_the_full_corpus() {
    let firing = detectors_firing(corpus(), DATADOG_FIXTURE);
    assert!(
        firing.iter().any(|id| id == "datadog-application-key"),
        "the full corpus must report a Datadog application key; fired: {firing:?}"
    );
}

/// Dropping an unrelated detector must not change what the others report.
///
/// This is the invariant the bug violated, stated without naming the culprit:
/// removing `wix-api-credentials` entirely must leave the Datadog result
/// untouched. If a pattern of one detector can reach another's admission, the
/// two sides of this comparison come apart.
#[test]
fn removing_one_detector_does_not_change_another_detectors_findings() {
    let with_wix = detectors_firing(corpus(), DATADOG_FIXTURE);
    let without_wix = detectors_firing(
        corpus()
            .into_iter()
            .filter(|d| d.id.as_str() != "wix-api-credentials")
            .collect(),
        DATADOG_FIXTURE,
    );

    assert_eq!(
        with_wix, without_wix,
        "wix-api-credentials must not influence what other detectors report on input \
         containing no wix credential"
    );
}

/// Every prefixless pattern that declares a literal keeps that literal provable.
///
/// `validate_required_literals` proves a declaration is a necessary condition of
/// every match, so a declaration cannot silently narrow recall. Running it over
/// the shipped corpus turns that per-pattern proof into a corpus-wide one, which
/// is what makes the twenty-three declarations added for this fix safe.
#[test]
fn every_declared_routing_literal_is_a_proven_necessary_condition() {
    let mut invalid = Vec::new();
    for detector in corpus() {
        for (index, pattern) in detector.patterns.iter().enumerate() {
            if pattern.required_literals.is_empty() {
                continue;
            }
            if let Err(reason) = pattern.validate_required_literals() {
                invalid.push(format!("{}[{index}]: {reason}", detector.id));
            }
        }
    }
    assert!(
        invalid.is_empty(),
        "a declared routing literal that is not required by every match would silently \
         narrow recall: {invalid:?}"
    );
}
