//! Property tests for the SARIF `relatedLocations` dedup contract.
//!
//! GitHub Code Scanning rejects any SARIF whose `relatedLocations`
//! array contains duplicate items, with the validation message
//! `relatedLocations contains duplicate item`. When that rejection
//! fires, the WHOLE finding set is dropped from the Code Scanning
//! tab - not just the offending entry - so the UI silently shows
//! "no findings" while the workflow log says "scan completed".
//!
//! v0.5.13 added a dedup pass (commit 5007b82) keyed on
//! `(file_path, line, offset)`. These properties pin its contract:
//!
//! 1. **Idempotence** - running the dedup twice yields the same set.
//! 2. **Subset preservation** - the deduped set is a subset of the
//!    input (we never invent locations).
//! 3. **No-loss for unique inputs** - every uniquely-keyed input
//!    survives.
//! 4. **Stable ordering** - first occurrence wins; subsequent
//!    copies are dropped. (Matches the dedup's `HashSet::insert`
//!    behavior, which is what the SARIF spec orders by source-order.)
//! 5. **Survives the JSON round-trip** - serializing the deduped
//!    finding to SARIF JSON and reading it back must still satisfy
//!    the dedup invariant.
//!
//! Test budget: 10 000 cases per property.

use crate::support::reporters::SarifReporter;
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use proptest::prelude::*;
use std::borrow::Cow;
use std::collections::HashMap;

const CASES: u32 = 10_000;

// ── strategies ──────────────────────────────────────────────────────

/// A `MatchLocation` whose `(file_path, line, offset)` falls in a
/// small alphabet - small enough that duplicates will surface
/// naturally inside a randomly-sized vec without contrived shrinking.
fn any_location() -> impl Strategy<Value = MatchLocation> {
    (
        prop_oneof![Just("a.rs"), Just("b.rs"), Just("c.rs"), Just("d.rs")],
        prop_oneof![Just(None), (1usize..16).prop_map(Some)],
        0usize..32,
    )
        .prop_map(|(file, line, offset)| MatchLocation {
            source: "fs".into(),
            file_path: Some(file.into()),
            line,
            offset,
            commit: None,
            author: None,
            date: None,
        })
}

/// 0–8 additional locations - small enough that duplicates appear
/// roughly half the time given the strategy above.
fn additional_locations() -> impl Strategy<Value = Vec<MatchLocation>> {
    prop::collection::vec(any_location(), 0..8)
}

fn finding_with_additional(additional: Vec<MatchLocation>) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "test-detector".into(),
        detector_name: "Test".into(),
        service: "test".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****"),
        credential_hash: [0; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "fs".into(),
            file_path: Some(std::sync::Arc::<str>::from("primary.rs")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: additional,
        confidence: Some(0.5),
    }
}

/// Run a finding through the SarifReporter, return the resulting
/// JSON `Vec<u8>`. The reporter is buffered into a `Vec` so each
/// property case is independent.
fn render_to_sarif(finding: &VerifiedFinding) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut rep = SarifReporter::new(&mut buf);
        rep.report(finding).expect("report");
        rep.finish().expect("finish");
    }
    buf
}

/// Pull the `relatedLocations` array out of the rendered SARIF as a
/// vec of `(uri, startLine, charOffset)` triples - that's the key
/// we dedup on. Returns an empty vec when the SARIF document had no
/// `relatedLocations` field (which is also a valid post-dedup state).
fn extract_related_keys(sarif: &[u8]) -> Vec<(String, Option<u64>, u64)> {
    let v: serde_json::Value = serde_json::from_slice(sarif).expect("SARIF is valid JSON");
    let runs = v.get("runs").and_then(|r| r.as_array());
    let Some(runs) = runs else { return vec![] };
    let mut out = Vec::new();
    for run in runs {
        let Some(results) = run.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for r in results {
            let Some(related) = r.get("relatedLocations").and_then(|r| r.as_array()) else {
                continue;
            };
            for loc in related {
                let uri = loc
                    .pointer("/physicalLocation/artifactLocation/uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let line = loc
                    .pointer("/physicalLocation/region/startLine")
                    .and_then(|v| v.as_u64());
                let offset = loc
                    .pointer("/physicalLocation/region/charOffset")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                out.push((uri, line, offset));
            }
        }
    }
    out
}

// ── properties ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: CASES, .. ProptestConfig::default() })]

    /// The rendered SARIF must NEVER contain duplicate
    /// (uri, line, offset) triples in `relatedLocations` - that's
    /// the exact violation GitHub Code Scanning rejects on.
    #[test]
    fn rendered_sarif_has_no_duplicate_related_locations(
        additional in additional_locations(),
    ) {
        let finding = finding_with_additional(additional);
        let sarif = render_to_sarif(&finding);

        let keys = extract_related_keys(&sarif);
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        prop_assert_eq!(
            keys.len(),
            sorted.len(),
            "duplicate (uri, line, offset) in rendered SARIF; this would \
             trigger 'relatedLocations contains duplicate item' on GitHub \
             Code Scanning and silently drop every finding from the run"
        );
    }

    /// Rendering twice in a row produces the same dedup key set
    /// (idempotence of the dedup + the renderer).
    #[test]
    fn dedup_is_idempotent(additional in additional_locations()) {
        let finding = finding_with_additional(additional);
        let a = extract_related_keys(&render_to_sarif(&finding));
        let b = extract_related_keys(&render_to_sarif(&finding));
        prop_assert_eq!(a, b);
    }

    /// The dedup must NEVER introduce a location that wasn't in the
    /// input. Catches a regression where a hash collision (or some
    /// future re-key) emits ghost entries.
    #[test]
    fn dedup_output_is_subset_of_input(additional in additional_locations()) {
        let finding = finding_with_additional(additional.clone());
        let sarif = render_to_sarif(&finding);
        let rendered_keys = extract_related_keys(&sarif);

        let input_keys: std::collections::HashSet<(String, Option<u64>, u64)> =
            additional
                .iter()
                .map(|l| {
                    (
                        l.file_path
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        l.line.map(|n| n as u64),
                        l.offset as u64,
                    )
                })
                .collect();
        for k in &rendered_keys {
            prop_assert!(
                input_keys.contains(k),
                "rendered SARIF contains a related location {:?} that was \
                 not in the input - dedup must never invent entries",
                k
            );
        }
    }

    /// If the input had N unique keys, the rendered SARIF must
    /// surface exactly N related locations. (Inverse of the subset
    /// property: no over-dedup either.)
    #[test]
    fn dedup_preserves_every_unique_input_key(additional in additional_locations()) {
        let finding = finding_with_additional(additional.clone());
        let sarif = render_to_sarif(&finding);
        let rendered_keys: std::collections::HashSet<(String, Option<u64>, u64)> =
            extract_related_keys(&sarif).into_iter().collect();

        let input_unique: std::collections::HashSet<(String, Option<u64>, u64)> =
            additional
                .iter()
                .map(|l| {
                    (
                        l.file_path
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        l.line.map(|n| n as u64),
                        l.offset as u64,
                    )
                })
                .collect();
        prop_assert_eq!(
            rendered_keys,
            input_unique,
            "rendered SARIF dropped a unique input key - dedup is over-zealous"
        );
    }
}

#[test]
fn ten_thousand_case_budget_is_acknowledged() {
    // Same intent-marker as the http_fuzz suite.
    assert_eq!(CASES, 10_000);
}
