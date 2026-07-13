//! Regression coverage for the multi-location contract of a deduped finding:
//! `DedupedMatch::primary_location` + `DedupedMatch::additional_locations`,
//! owned by `keyhog_core` (`core::dedup`). Distinct from the sibling
//! `regression_finding_dedup.rs` / `regression_finding_dedup_merge.rs` /
//! `new_core_finding_dedup.rs` files, which pin group counts and cross-detector
//! companion folding: THIS file pins ONLY the `additional_locations` vector 
//! how the same credential seen at N places records exactly one primary plus
//! the deduped remainder, with each recorded location's exact
//! source/file/line/offset asserted.
//!
//! The dedup identity that decides "same finding, collapse" is
//! `(source, file_path, line, commit)`: offset is deliberately EXCLUDED (the
//! structured-preprocessor synthetic-line alias fires the same value twice on
//! one line at two offsets, one past EOF; both are one finding). Every test
//! below asserts a concrete value: exact `additional_locations.len()`, exact
//! primary offset/line, exact per-location file/source/commit, never
//! `is_empty()` / `len() > 0` alone.
//!
//! Host-independent: pure in-process `keyhog_core` API, no accelerator, no
//! scanner engine, no `env_no_gpu` branch.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, CredentialHash, DedupScope, MatchLocation, RawMatch,
    SensitiveString, Severity,
};
use std::collections::HashMap;
use std::sync::Arc;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

/// A filesystem location on `file` at 1-based `line` / byte `offset`.
fn loc(file: &str, line: usize, offset: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from(file)),
        line: Some(line),
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

/// A location with an explicit `source` backend and optional `commit`, used to
/// exercise the `(source, ..., commit)` axes of the dedup identity.
fn loc_src(
    source: &str,
    file: &str,
    line: usize,
    offset: usize,
    commit: Option<&str>,
) -> MatchLocation {
    MatchLocation {
        source: Arc::from(source),
        file_path: Some(Arc::from(file)),
        line: Some(line),
        offset,
        commit: commit.map(Arc::from),
        author: None,
        date: None,
    }
}

fn raw(
    detector_id: &str,
    credential: &str,
    confidence: Option<f64>,
    location: MatchLocation,
) -> RawMatch {
    raw_named(
        detector_id,
        detector_id,
        "svc",
        credential,
        confidence,
        location,
    )
}

fn raw_named(
    detector_id: &str,
    detector_name: &str,
    service: &str,
    credential: &str,
    confidence: Option<f64>,
    location: MatchLocation,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_name),
        service: Arc::from(service),
        severity: Severity::High,
        credential: SensitiveString::from(credential),
        credential_hash: sha256(credential),
        companions: HashMap::new(),
        location,
        entropy: None,
        confidence,
    }
}

/// Read the (line, offset) pair of a location for exact assertions.
fn li(location: &MatchLocation) -> (Option<usize>, usize) {
    (location.line, location.offset)
}

// ---------------------------------------------------------------------------
// 1. Positive: same detector+credential at three DISTINCT lines, Credential
//    scope -> ONE finding, primary = lowest offset, additional = the other two
//    in offset order, each with its exact line/offset.
// ---------------------------------------------------------------------------
#[test]
fn credential_scope_records_primary_plus_two_additional_locations() {
    let matches = vec![
        raw(
            "generic-password",
            "s3cr3tvalue",
            Some(0.7),
            loc("a.env", 1, 10),
        ),
        raw(
            "generic-password",
            "s3cr3tvalue",
            Some(0.7),
            loc("a.env", 2, 30),
        ),
        raw(
            "generic-password",
            "s3cr3tvalue",
            Some(0.7),
            loc("a.env", 3, 50),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1, "one credential -> one finding");
    let f = &out[0];
    assert_eq!(
        li(&f.primary_location),
        (Some(1), 10),
        "primary = lowest offset"
    );
    assert_eq!(
        f.additional_locations.len(),
        2,
        "two extra locations recorded"
    );
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 30));
    assert_eq!(li(&f.additional_locations[1]), (Some(3), 50));
}

// ---------------------------------------------------------------------------
// 2. Negative twin (#16 regression): same (file, line), DIFFERENT offset ->
//    the higher-offset synthetic alias collapses; NO additional location.
// ---------------------------------------------------------------------------
#[test]
fn same_file_line_different_offset_collapses_no_additional() {
    let matches = vec![
        raw(
            "generic-password",
            "aliasedval",
            Some(0.6),
            loc("one.env", 1, 27),
        ),
        // synthetic-preprocessor alias: same line 1, offset past the real chunk.
        raw(
            "generic-password",
            "aliasedval",
            Some(0.6),
            loc("one.env", 1, 80),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(
        li(&f.primary_location),
        (Some(1), 27),
        "lowest offset kept as primary"
    );
    assert_eq!(
        f.additional_locations.len(),
        0,
        "same (file,line) alias must not appear as a second location"
    );
}

// ---------------------------------------------------------------------------
// 3. File scope SPLITS a shared credential across two files -> two findings,
//    each with an EMPTY additional_locations vector.
// ---------------------------------------------------------------------------
#[test]
fn file_scope_splits_across_files_each_zero_additional() {
    let matches = vec![
        raw("generic-password", "shared", Some(0.5), loc("a.env", 1, 10)),
        raw("generic-password", "shared", Some(0.5), loc("b.env", 1, 10)),
    ];
    let out = dedup_matches(matches, &DedupScope::File);
    assert_eq!(out.len(), 2, "file scope -> one finding per file");
    assert_eq!(out[0].additional_locations.len(), 0);
    assert_eq!(out[1].additional_locations.len(), 0);
}

// ---------------------------------------------------------------------------
// 4. Credential scope UNIFIES the same credential across two files -> ONE
//    finding, primary = lexicographically-first file, other file as the single
//    additional location.
// ---------------------------------------------------------------------------
#[test]
fn credential_scope_unifies_across_files_second_file_is_additional() {
    let matches = vec![
        raw("generic-password", "shared", Some(0.5), loc("b.env", 1, 10)),
        raw("generic-password", "shared", Some(0.5), loc("a.env", 1, 10)),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(
        f.primary_location.file_path.as_deref(),
        Some("a.env"),
        "file_path sorts ascending -> a.env is primary"
    );
    assert_eq!(f.additional_locations.len(), 1);
    assert_eq!(
        f.additional_locations[0].file_path.as_deref(),
        Some("b.env")
    );
}

// ---------------------------------------------------------------------------
// 5. None scope NEVER populates additional_locations, even for byte-identical
//    matches -> three findings, each with zero additional locations.
// ---------------------------------------------------------------------------
#[test]
fn none_scope_never_records_additional_locations() {
    let matches = vec![
        raw("generic-password", "dupval", Some(0.4), loc("x.env", 1, 5)),
        raw("generic-password", "dupval", Some(0.4), loc("x.env", 1, 5)),
        raw("generic-password", "dupval", Some(0.4), loc("x.env", 1, 5)),
    ];
    let out = dedup_matches(matches, &DedupScope::None);
    assert_eq!(out.len(), 3, "None scope keeps every raw match");
    for f in &out {
        assert_eq!(f.additional_locations.len(), 0);
    }
}

// ---------------------------------------------------------------------------
// 6. Boundary: SAME offset, DIFFERENT line. line is part of the identity, so
//    the two are distinct locations -> one additional.
// ---------------------------------------------------------------------------
#[test]
fn same_offset_different_line_is_distinct_location() {
    let matches = vec![
        raw(
            "generic-password",
            "lineval",
            Some(0.5),
            loc("c.env", 1, 10),
        ),
        raw(
            "generic-password",
            "lineval",
            Some(0.5),
            loc("c.env", 2, 10),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(f.additional_locations.len(), 1);
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 10));
}

// ---------------------------------------------------------------------------
// 7. Exact-duplicate location (same file/line/offset) collapses to the primary
//    only -> zero additional locations.
// ---------------------------------------------------------------------------
#[test]
fn exact_duplicate_location_collapses_to_primary_only() {
    let matches = vec![
        raw(
            "generic-password",
            "exactdup",
            Some(0.5),
            loc("d.env", 3, 42),
        ),
        raw(
            "generic-password",
            "exactdup",
            Some(0.5),
            loc("d.env", 3, 42),
        ),
        raw(
            "generic-password",
            "exactdup",
            Some(0.5),
            loc("d.env", 3, 42),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(li(&f.primary_location), (Some(3), 42));
    assert_eq!(f.additional_locations.len(), 0);
}

// ---------------------------------------------------------------------------
// 8. commit is part of the identity: same file/line/offset but two commits ->
//    distinct locations, one additional with the second commit.
// ---------------------------------------------------------------------------
#[test]
fn different_commit_is_distinct_location() {
    let matches = vec![
        raw(
            "generic-password",
            "commitval",
            Some(0.5),
            loc_src("git", "hist.env", 1, 0, Some("bbb")),
        ),
        raw(
            "generic-password",
            "commitval",
            Some(0.5),
            loc_src("git", "hist.env", 1, 0, Some("aaa")),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(
        f.primary_location.commit.as_deref(),
        Some("aaa"),
        "commit sorts ascending -> aaa is primary"
    );
    assert_eq!(f.additional_locations.len(), 1);
    assert_eq!(f.additional_locations[0].commit.as_deref(), Some("bbb"));
}

// ---------------------------------------------------------------------------
// 9. source is part of the identity: same file/line/offset from two backends ->
//    distinct locations, one additional carrying the second source.
// ---------------------------------------------------------------------------
#[test]
fn different_source_backend_is_distinct_location() {
    let matches = vec![
        raw(
            "generic-password",
            "srcval",
            Some(0.5),
            loc_src("git", "s.env", 1, 0, None),
        ),
        raw(
            "generic-password",
            "srcval",
            Some(0.5),
            loc_src("filesystem", "s.env", 1, 0, None),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(
        &*f.primary_location.source, "filesystem",
        "source sorts ascending -> filesystem is primary"
    );
    assert_eq!(f.additional_locations.len(), 1);
    assert_eq!(&*f.additional_locations[0].source, "git");
}

// ---------------------------------------------------------------------------
// 10. Primary selection is offset-ascending regardless of input order:
//     descending-offset input still yields the lowest offset as primary.
// ---------------------------------------------------------------------------
#[test]
fn primary_is_lowest_offset_regardless_of_input_order() {
    let matches = vec![
        raw("generic-password", "ordval", Some(0.5), loc("o.env", 5, 50)),
        raw("generic-password", "ordval", Some(0.5), loc("o.env", 3, 30)),
        raw("generic-password", "ordval", Some(0.5), loc("o.env", 1, 10)),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(f.additional_locations.len(), 2);
    assert_eq!(li(&f.additional_locations[0]), (Some(3), 30));
    assert_eq!(li(&f.additional_locations[1]), (Some(5), 50));
}

// ---------------------------------------------------------------------------
// 11. Adversarial mix: a synthetic-alias collapse AND a real distinct line in
//     one group -> exactly one additional (the distinct line), the alias gone.
// ---------------------------------------------------------------------------
#[test]
fn mixed_alias_and_distinct_line_keeps_only_the_distinct_line() {
    let matches = vec![
        raw("generic-password", "mixval", Some(0.5), loc("m.env", 1, 10)),
        raw("generic-password", "mixval", Some(0.5), loc("m.env", 2, 40)),
        // alias of the primary line 1 at a higher offset -> must collapse.
        raw("generic-password", "mixval", Some(0.5), loc("m.env", 1, 90)),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(
        f.additional_locations.len(),
        1,
        "only the distinct line 2 survives"
    );
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 40));
}

// ---------------------------------------------------------------------------
// 12. Cross-detector fold: two detectors on one credential at DIFFERENT lines
//     -> ONE finding; the loser's location joins the winner's
//     additional_locations, plus the exact companion evidence string.
// ---------------------------------------------------------------------------
#[test]
fn cross_detector_fold_adds_loser_location_as_additional() {
    let deduped = dedup_matches(
        vec![
            raw_named(
                "aws-key",
                "AWS",
                "aws",
                "sameval",
                Some(0.9),
                loc("app.env", 1, 10),
            ),
            raw_named(
                "gcp-key",
                "GCP",
                "gcp",
                "sameval",
                Some(0.5),
                loc("app.env", 2, 20),
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        deduped.len(),
        2,
        "distinct detectors before cross-detector fold"
    );
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1, "same credential_hash -> one finding");
    let f = &out[0];
    assert_eq!(&*f.detector_id, "aws-key", "higher confidence wins");
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(f.additional_locations.len(), 1, "loser location folded in");
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 20));
    assert_eq!(
        f.companions.get("cross_detector.0").map(String::as_str),
        Some("gcp (GCP) [0.50]")
    );
}

// ---------------------------------------------------------------------------
// 13. Cross-detector fold at the SAME location: the loser shares the winner's
//     location identity -> NO additional location, but the companion is still
//     recorded.
// ---------------------------------------------------------------------------
#[test]
fn cross_detector_same_location_adds_no_additional() {
    let deduped = dedup_matches(
        vec![
            raw_named(
                "aws-key",
                "AWS",
                "aws",
                "coloc",
                Some(0.9),
                loc("app.env", 1, 10),
            ),
            raw_named(
                "gcp-key",
                "GCP",
                "gcp",
                "coloc",
                Some(0.5),
                loc("app.env", 1, 10),
            ),
        ],
        &DedupScope::Credential,
    );
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(&*f.detector_id, "aws-key");
    assert_eq!(
        f.additional_locations.len(),
        0,
        "same (file,line) loser must not add a location"
    );
    assert!(
        f.companions.contains_key("cross_detector.0"),
        "companion evidence still recorded"
    );
}

// ---------------------------------------------------------------------------
// 14. Pipeline: a winner that ALREADY owns an additional location keeps it and
//     appends the loser's distinct location -> two additionals total, primary
//     unchanged.
// ---------------------------------------------------------------------------
#[test]
fn cross_detector_preserves_winner_existing_additionals() {
    let deduped = dedup_matches(
        vec![
            // winning detector seen at two lines -> primary line1, additional line2.
            raw_named(
                "aws-key",
                "AWS",
                "aws",
                "pipeval",
                Some(0.9),
                loc("p.env", 1, 10),
            ),
            raw_named(
                "aws-key",
                "AWS",
                "aws",
                "pipeval",
                Some(0.9),
                loc("p.env", 2, 30),
            ),
            // losing detector at a third line.
            raw_named(
                "gcp-key",
                "GCP",
                "gcp",
                "pipeval",
                Some(0.5),
                loc("p.env", 3, 50),
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(deduped.len(), 2);
    let out = dedup_cross_detector(deduped);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(&*f.detector_id, "aws-key");
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(f.additional_locations.len(), 2, "own line2 + loser line3");
    let lines: Vec<Option<usize>> = f.additional_locations.iter().map(|l| l.line).collect();
    assert!(
        lines.contains(&Some(2)),
        "winner keeps its own additional line 2"
    );
    assert!(lines.contains(&Some(3)), "loser's line 3 appended");
}
