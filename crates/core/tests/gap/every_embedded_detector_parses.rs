//! Embedded-set integrity gate (DET-01 / MC-16 / T-04 / T-05 / DF-07).
//!
//! The dead `discord-bot-token` detector, a single-quoted TOML literal whose
//! char class embedded a `'`, breaking the parse, reached a *benched release
//! binary* as an invisible recall hole. It slipped through because:
//!   1. the runtime embedded-load path silently dropped unparseable detectors
//!      (`tracing::debug!` then continue, a Law-10 silent fallback, now fixed
//!      to fail closed in the single shared loader
//!      `keyhog_core::load_embedded_detectors_or_fail`, which every scan
//!      entry point routes through), and
//!   2. the existing self-validation test parsed TOMLs from the **on-disk**
//!      `detectors/` tree, NOT the bytes actually **compiled into the binary**.
//!      An embed-time drop or an in-place edit could diverge from what shipped.
//!
//! This gate closes both holes at the source crate: it parses the EXACT
//! embedded slice (exposed to tests through `keyhog_core::testing`: the same
//! bytes the CLI loads) with the SAME `DetectorFile` deserializer the runtime uses, and
//! fails, naming every offender by file stem with the toml error, if a single
//! embedded detector does not parse. A detector that loads but is silently
//! dropped is decoration; this makes that impossible to ship.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{embedded_detector_count, DetectorFile};

fn embedded_detector_tomls() -> &'static [(&'static str, &'static str)] {
    CoreTestApi::embedded_detector_tomls(&TestApi)
}

#[test]
fn every_embedded_detector_parses() {
    let embedded = embedded_detector_tomls();
    assert!(
        !embedded.is_empty(),
        "embedded detector catalog is empty, build.rs detector-embedding step \
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
        "{} of {} EMBEDDED detector(s) failed to parse, the binary would ship a \
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
/// rather than a magic number (keeps the gate honest as the corpus grows).
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
        "only {parseable} of {} embedded detectors parse, every embedded TOML \
         must deserialize into a DetectorFile",
        embedded.len(),
    );
    assert_eq!(
        embedded.len(),
        embedded_detector_count(),
        "embedded slice length must match the authoritative embedded_detector_count()"
    );
}

/// The shared fail-closed loader is now the SINGLE path every scan entry point
/// uses to turn the compiled-in corpus into `DetectorSpec`s.
/// Drive it directly (not a re-implementation): on a healthy build it returns
/// exactly one detector per embedded TOML, no silent drops, with the count
/// pinned to the authoritative `embedded_detector_count()`.
#[test]
fn shared_loader_returns_every_embedded_detector() {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("a healthy embedded corpus must load via the shared fail-closed loader");

    assert_eq!(
        detectors.len(),
        embedded_detector_count(),
        "the shared loader returned {} detectors but the embedded corpus holds {}. \
         a shorter result means a detector was silently dropped, the exact bug this \
         fail-closed loader exists to prevent",
        detectors.len(),
        embedded_detector_count(),
    );
    assert!(
        detectors.iter().all(|d| !d.id.is_empty()),
        "every loaded detector must carry a non-empty id, an empty-shell spec \
         indicates a malformed parse that slipped through"
    );
    assert!(
        detectors
            .iter()
            .all(|d| !d.patterns.is_empty() || !d.keywords.is_empty()),
        "every loaded detector must be able to MATCH, via a regex pattern, OR \
         (for keyword/entropy phase-2 detectors like generic-api-key / \
         generic-secret / generic-keyword-secret, which carry NO regex by design) \
         via a keyword. A spec with NEITHER would never fire and signals a corrupt load"
    );
}

/// The fail-closed error path is user-facing: when the embedded corpus is
/// corrupt the loader must name every offender and tell the operator it is a
/// build bug (so a corrupt set is a hard stop, never a buried log line). We can't
/// corrupt the compiled-in corpus from a test, so assert the error TYPE renders
/// the contract (offender list + "build/source bug" framing + the fix).
#[test]
fn embedded_corpus_corrupt_error_names_offenders() {
    let err = keyhog_core::SpecError::EmbeddedCorpusCorrupt {
        failed_count: 2,
        total: 902,
        detail: "  - discord-bot-token: invalid char class\n  - foo: trailing comma".to_string(),
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("discord-bot-token: invalid char class"),
        "the corrupt-corpus error must name each offending detector; got: {rendered}"
    );
    assert!(
        rendered.contains("2 of 902"),
        "the error must report how many of how many detectors failed; got: {rendered}"
    );
    assert!(
        rendered.contains("build/source bug") && rendered.contains("rebuild keyhog"),
        "the error must frame this as a build bug and tell the operator to rebuild; \
         got: {rendered}"
    );
}
