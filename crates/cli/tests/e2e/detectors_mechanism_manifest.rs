//! KH-367: `keyhog detectors --mechanisms` must publish a declared recovery
//! contract per detector, derived from the corpus rather than from a table.
//!
//! The contracts worth defending are the ones an operator would otherwise have
//! to take on faith:
//!
//! * every detector in the loaded corpus appears and lists its mechanisms, so
//!   the manifest cannot quietly describe a subset;
//! * a mechanism KeyHog cannot express yet is reported as unavailable with the
//!   reason, never omitted, because a missing row and "no detector uses this"
//!   are different facts;
//! * each declared mechanism names the detector TOML field that proves it, so
//!   the claim is auditable against the data file;
//! * the manifest tracks the corpus: pointing `--detectors` at a smaller corpus
//!   changes the answer, which is what "derived, not tabulated" means;
//! * the flag is additive: `keyhog detectors` and `keyhog detectors --format
//!   json` are untouched.

use crate::e2e::support::binary;
use std::process::Command;

fn manifest(extra: &[&str]) -> serde_json::Value {
    let output = Command::new(binary())
        .args(["detectors", "--mechanisms", "--format", "json"])
        .args(extra)
        .output()
        .expect("spawn");
    assert!(
        output.status.success(),
        "detectors --mechanisms failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("manifest JSON")
}

#[test]
fn every_detector_appears_and_lists_at_least_one_mechanism() {
    let doc = manifest(&[]);
    let detectors = doc["detectors"].as_array().expect("detectors array");
    let count = doc["detector_count"].as_u64().expect("detector_count");

    assert_eq!(
        detectors.len() as u64,
        count,
        "row count must equal the count it reports"
    );
    assert!(
        count > 100,
        "the embedded corpus should be large, got {count}"
    );

    let silent: Vec<&str> = detectors
        .iter()
        .filter(|row| {
            row["mechanisms"]
                .as_array()
                .is_some_and(|list| list.is_empty())
        })
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(
        silent.is_empty(),
        "these detectors declare no mechanism at all, so the manifest cannot \
         describe what they recover: {silent:?}"
    );
}

#[test]
fn a_mechanism_keyhog_cannot_express_is_reported_not_omitted() {
    let doc = manifest(&[]);
    let summary = doc["summary"].as_array().expect("summary array");

    let unavailable: Vec<&serde_json::Value> = summary
        .iter()
        .filter(|row| row["available"] == serde_json::Value::Bool(false))
        .collect();
    assert!(
        !unavailable.is_empty(),
        "byte-pair likelihood is unbuilt, so at least one row must say so \
         rather than the manifest quietly listing eleven mechanisms"
    );
    for row in unavailable {
        let reason = row["unavailable_reason"]
            .as_str()
            .expect("an unavailable mechanism must carry its reason");
        assert!(!reason.trim().is_empty(), "empty reason on {}", row["id"]);
        assert_eq!(
            row["detectors"], 0,
            "a mechanism nothing can declare must count zero detectors"
        );
    }

    // The row must still be present in the vocabulary, not dropped.
    let ids: Vec<&str> = summary
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(ids.contains(&"byte_pair_likelihood"), "{ids:?}");
}

#[test]
fn each_declared_mechanism_names_the_field_that_proves_it() {
    let doc = manifest(&["--search", "aws-access-key"]);
    let row = doc["detectors"]
        .as_array()
        .expect("detectors")
        .iter()
        .find(|row| row["id"] == "aws-access-key")
        .expect("aws-access-key in the corpus")
        .clone();

    for mechanism in row["mechanisms"].as_array().expect("mechanisms") {
        let evidence = mechanism["evidence"].as_array().expect("evidence array");
        assert!(
            !evidence.is_empty(),
            "mechanism {} claims to be active with no field behind it",
            mechanism["id"]
        );
        for field in evidence {
            let name = field.as_str().expect("evidence entry is a field name");
            assert!(!name.is_empty());
        }
    }

    // A regex detector with a live verifier must say so, and name `verify`.
    let verification = row["mechanisms"]
        .as_array()
        .expect("mechanisms")
        .iter()
        .find(|mechanism| mechanism["id"] == "verification")
        .expect("aws-access-key verifies");
    assert_eq!(verification["evidence"][0], "verify");
}

#[test]
fn the_manifest_is_derived_from_the_corpus_not_from_a_table() {
    // The distinguishing property: scoping the manifest must change every
    // number in it. A hardcoded per-mechanism table would keep reporting
    // corpus-wide counts no matter what was in scope, so this is the assertion
    // that separates derivation from tabulation.
    let full = manifest(&[]);
    let scoped = manifest(&["--search", "aws"]);

    let full_count = full["detector_count"].as_u64().expect("count");
    let scoped_count = scoped["detector_count"].as_u64().expect("count");
    assert!(
        scoped_count > 0,
        "the search must match something to be a test"
    );
    assert!(
        scoped_count < full_count,
        "scoping must shrink the corpus: {scoped_count} vs {full_count}"
    );
    assert_eq!(
        scoped["detectors"].as_array().expect("rows").len() as u64,
        scoped_count
    );

    // Every summary count must also shrink to the rows actually in scope, and
    // must equal a recount of those rows. Equality with an independent recount
    // is what makes this non-vacuous: a stale table would pass a "less than"
    // check by accident only if it happened to be smaller, never this.
    for row in scoped["summary"].as_array().expect("summary") {
        let id = row["id"].as_str().expect("id");
        let claimed = row["detectors"].as_u64().expect("count");
        let recounted = scoped["detectors"]
            .as_array()
            .expect("rows")
            .iter()
            .filter(|detector| {
                detector["mechanisms"]
                    .as_array()
                    .is_some_and(|list| list.iter().any(|active| active["id"] == id))
            })
            .count() as u64;
        assert_eq!(
            claimed, recounted,
            "summary count for {id} disagrees with the rows it summarizes"
        );
        let full_claimed = full["summary"]
            .as_array()
            .expect("summary")
            .iter()
            .find(|full_row| full_row["id"] == id)
            .and_then(|full_row| full_row["detectors"].as_u64())
            .expect("same mechanism in both");
        assert!(
            claimed <= full_claimed,
            "scoped count for {id} exceeds the whole corpus: {claimed} > {full_claimed}"
        );
    }

    // At least one mechanism must genuinely differ between the two documents,
    // otherwise the check above would hold for a table that never moved.
    let moved = scoped["summary"]
        .as_array()
        .expect("summary")
        .iter()
        .any(|row| {
            let id = &row["id"];
            full["summary"]
                .as_array()
                .expect("summary")
                .iter()
                .any(|full_row| &full_row["id"] == id && full_row["detectors"] != row["detectors"])
        });
    assert!(
        moved,
        "no mechanism count changed under --search, so nothing was derived"
    );
}

#[test]
fn the_flag_is_additive_and_the_plain_listing_is_untouched() {
    let plain = Command::new(binary())
        .args(["detectors", "--format", "json"])
        .output()
        .expect("spawn");
    assert!(plain.status.success());
    let listing: serde_json::Value =
        serde_json::from_slice(&plain.stdout).expect("plain listing JSON");
    assert!(
        listing.is_array(),
        "the plain listing must stay a JSON array of detectors"
    );
    // The manifest is a distinct document, not a field bolted onto the listing.
    let first = &listing[0];
    assert!(
        first.get("mechanisms").is_none(),
        "the plain listing must not grow a mechanisms field: {first}"
    );
}
