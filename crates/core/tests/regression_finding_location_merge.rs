//! Regression coverage for the LOCATION-MERGE half of `core::dedup`
//! (`keyhog_core`): how `dedup_matches` folds the same credential seen at many
//! places into ONE `DedupedMatch` with a `primary_location` plus a deduped
//! `additional_locations` vector, and how `dedup_cross_detector` folds a loser
//! detector's WHOLE location set (primary + its own additionals) into the
//! winner while collapsing duplicates.
//!
//! Deliberately DISTINCT from the sibling files:
//!   * `new_core_finding_dedup.rs` / `regression_finding_dedup.rs` pin GROUP
//!     COUNTS and the dedup KEY (detector / file-scope / credential-hash);
//!   * `regression_finding_multi_location.rs` pins the plain
//!     `additional_locations` axis under Credential scope.
//! THIS file exercises three paths those do not touch:
//!   1. the DECODER-ALIAS merge (`is_decoder_alias_pair`): a decoder-source
//!      location adjacent to its plaintext twin collapses (with a primary swap
//!      when the decoder arrives first), and the exact line/offset boundaries
//!      (`abs_diff(line) <= 1`, `abs_diff(offset) <= 16` when line is unknown)
//!      that decide alias-vs-distinct;
//!   2. File-scope multi-line merge and cross-detector per-file SPLIT;
//!   3. `dedup_cross_detector` folding a loser's OWN `additional_locations`,
//!      with in-fold duplicate collapse, plus the serialized JSON shape of
//!      `additional_locations`.
//!
//! Dedup identity that decides "same finding, collapse" is
//! `(source, file_path, line, commit)`: offset is EXCLUDED. Every assertion is
//! a concrete value (exact len / line / offset / source / f64-eps), never
//! `is_empty()` / `len() > 0` alone.
//!
//! Host-independent: pure in-process `keyhog_core` API, no accelerator.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, CredentialHash, DedupScope, DedupedMatch, MatchLocation,
    RawMatch, SensitiveString, Severity,
};
use std::collections::HashMap;
use std::sync::Arc;

const EPS: f64 = 1e-9;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

/// A location with explicit `source` backend, optional `line`, and byte `offset`.
fn loc_full(source: &str, file: &str, line: Option<usize>, offset: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from(source),
        file_path: Some(Arc::from(file)),
        line,
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

/// Filesystem location on `file` at 1-based `line` / byte `offset`.
fn loc(file: &str, line: usize, offset: usize) -> MatchLocation {
    loc_full("filesystem", file, Some(line), offset)
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

/// Build a `DedupedMatch` directly (public struct, public fields) to drive the
/// cross-detector fold with a hand-authored loser location set.
fn deduped(
    detector_id: &str,
    credential: &str,
    confidence: f64,
    primary: MatchLocation,
    additional: Vec<MatchLocation>,
) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("svc"),
        severity: Severity::High,
        credential: SensitiveString::from(credential),
        credential_hash: sha256(credential),
        companions: HashMap::new(),
        primary_location: primary,
        additional_locations: additional,
        entropy: None,
        confidence: Some(confidence),
    }
}

fn li(location: &MatchLocation) -> (Option<usize>, usize) {
    (location.line, location.offset)
}

/// Sorted set of the line numbers across every recorded additional location.
fn additional_lines(f: &DedupedMatch) -> Vec<Option<usize>> {
    let mut v: Vec<Option<usize>> = f.additional_locations.iter().map(|l| l.line).collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------
// 1. Decoder-alias SWAP: the decoder-source twin arrives FIRST (lower offset)
//    and becomes the provisional primary; its adjacent plaintext twin (same
//    line) then REPLACES it as primary. Net: ONE finding, primary is the
//    plaintext (`filesystem`) location, zero additional locations.
// ---------------------------------------------------------------------------
#[test]
fn decoder_alias_swaps_primary_to_plaintext_no_additional() {
    let matches = vec![
        // lower offset -> sorts first -> provisional primary (decoder source).
        raw(
            "generic-password",
            "sekret",
            Some(0.3),
            loc_full("filesystem/base64", "d.env", Some(1), 5),
        ),
        // adjacent plaintext twin on the same line, higher offset.
        raw(
            "generic-password",
            "sekret",
            Some(0.8),
            loc_full("filesystem", "d.env", Some(1), 10),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1, "decoder + plaintext twin = one finding");
    let f = &out[0];
    assert_eq!(
        &*f.primary_location.source, "filesystem",
        "plaintext twin wins primary"
    );
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(
        f.additional_locations.len(),
        0,
        "alias twin must not add a location"
    );
    // confidence is the max across the merged pair.
    assert!((f.confidence.unwrap() - 0.8).abs() < EPS);
}

// ---------------------------------------------------------------------------
// 2. Decoder-alias DROP: the plaintext twin arrives first (lower offset,
//    primary), then the decoder twin on the same line is DROPPED (no swap, no
//    additional). Primary stays plaintext.
// ---------------------------------------------------------------------------
#[test]
fn decoder_alias_drops_decoder_twin_when_plaintext_is_primary() {
    let matches = vec![
        raw(
            "generic-password",
            "sekret",
            Some(0.8),
            loc_full("filesystem", "d.env", Some(1), 5),
        ),
        raw(
            "generic-password",
            "sekret",
            Some(0.3),
            loc_full("filesystem/hex", "d.env", Some(1), 20),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(&*f.primary_location.source, "filesystem");
    assert_eq!(li(&f.primary_location), (Some(1), 5));
    assert_eq!(
        f.additional_locations.len(),
        0,
        "decoder alias twin dropped"
    );
}

// ---------------------------------------------------------------------------
// 3. Negative twin of the alias merge: decoder line 1 vs plaintext line 5 ->
//    abs_diff(line) = 4 > 1, so NOT an alias pair; the two are distinct
//    locations and the second is recorded as an additional. Proves the
//    `abs_diff(line) <= 1` boundary rejects far-apart lines.
// ---------------------------------------------------------------------------
#[test]
fn decoder_line_gap_over_one_is_distinct_location() {
    let matches = vec![
        raw(
            "generic-password",
            "sekret",
            Some(0.5),
            loc_full("filesystem/hex", "d.env", Some(1), 5),
        ),
        raw(
            "generic-password",
            "sekret",
            Some(0.5),
            loc_full("filesystem", "d.env", Some(5), 50),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    // decoder (offset 5) sorts first and stays primary; no swap (not an alias).
    assert_eq!(&*f.primary_location.source, "filesystem/hex");
    assert_eq!(li(&f.primary_location), (Some(1), 5));
    assert_eq!(
        f.additional_locations.len(),
        1,
        "far-line plaintext is a distinct location"
    );
    assert_eq!(li(&f.additional_locations[0]), (Some(5), 50));
    assert_eq!(&*f.additional_locations[0].source, "filesystem");
}

// ---------------------------------------------------------------------------
// 4. Alias offset boundary when line is UNKNOWN (None): abs_diff(offset) == 16
//    is INSIDE the window -> alias collapse (primary swaps to plaintext, zero
//    additional).
// ---------------------------------------------------------------------------
#[test]
fn decoder_alias_offset_diff_16_collapses_when_line_unknown() {
    let matches = vec![
        raw(
            "generic-password",
            "sekret",
            Some(0.5),
            loc_full("filesystem/hex", "d.env", None, 0),
        ),
        raw(
            "generic-password",
            "sekret",
            Some(0.5),
            loc_full("filesystem", "d.env", None, 16),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(
        &*f.primary_location.source, "filesystem",
        "swapped to plaintext at diff 16"
    );
    assert_eq!(li(&f.primary_location), (None, 16));
    assert_eq!(f.additional_locations.len(), 0);
}

// ---------------------------------------------------------------------------
// 5. Boundary twin: abs_diff(offset) == 17 (> 16) with unknown line -> NOT an
//    alias; distinct locations -> one additional recorded.
// ---------------------------------------------------------------------------
#[test]
fn decoder_alias_offset_diff_17_is_distinct_when_line_unknown() {
    let matches = vec![
        raw(
            "generic-password",
            "sekret",
            Some(0.5),
            loc_full("filesystem/hex", "d.env", None, 0),
        ),
        raw(
            "generic-password",
            "sekret",
            Some(0.5),
            loc_full("filesystem", "d.env", None, 17),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    // decoder (offset 0) primary; plaintext (offset 17) is a distinct location.
    assert_eq!(&*f.primary_location.source, "filesystem/hex");
    assert_eq!(li(&f.primary_location), (None, 0));
    assert_eq!(
        f.additional_locations.len(),
        1,
        "offset gap 17 exceeds the 16 window"
    );
    assert_eq!(li(&f.additional_locations[0]), (None, 17));
}

// ---------------------------------------------------------------------------
// 6. File-scope multi-line merge: the same credential on three lines of ONE
//    file collapses to ONE finding with the lowest offset as primary and the
//    other two as offset-ordered additionals (File scope, not Credential).
// ---------------------------------------------------------------------------
#[test]
fn file_scope_merges_three_lines_of_one_file() {
    let matches = vec![
        raw(
            "generic-password",
            "filecred",
            Some(0.5),
            loc("cfg.env", 3, 60),
        ),
        raw(
            "generic-password",
            "filecred",
            Some(0.5),
            loc("cfg.env", 1, 20),
        ),
        raw(
            "generic-password",
            "filecred",
            Some(0.5),
            loc("cfg.env", 2, 40),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::File);
    assert_eq!(out.len(), 1, "one file, one credential -> one finding");
    let f = &out[0];
    assert_eq!(
        li(&f.primary_location),
        (Some(1), 20),
        "lowest offset is primary"
    );
    assert_eq!(f.additional_locations.len(), 2);
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 40));
    assert_eq!(li(&f.additional_locations[1]), (Some(3), 60));
}

// ---------------------------------------------------------------------------
// 7. Cross-detector SPLIT by file: the same detector+credential in two files
//    under File scope is two findings sharing a credential_hash; the
//    cross-detector fold keys on (hash, file_path), so it must KEEP them as two
//    findings, each with an empty additional_locations vector.
// ---------------------------------------------------------------------------
#[test]
fn cross_detector_keeps_per_file_split() {
    let deduped_in = dedup_matches(
        vec![
            raw("generic-password", "shared", Some(0.6), loc("a.env", 1, 10)),
            raw("generic-password", "shared", Some(0.6), loc("b.env", 1, 10)),
        ],
        &DedupScope::File,
    );
    assert_eq!(deduped_in.len(), 2, "file scope splits across two files");
    let out = dedup_cross_detector(deduped_in);
    assert_eq!(
        out.len(),
        2,
        "cross-detector fold must not merge across files"
    );
    assert_eq!(out[0].additional_locations.len(), 0);
    assert_eq!(out[1].additional_locations.len(), 0);
    // both files preserved as distinct primaries.
    let mut files: Vec<&str> = out
        .iter()
        .map(|f| f.primary_location.file_path.as_deref().unwrap())
        .collect();
    files.sort();
    assert_eq!(files, vec!["a.env", "b.env"]);
}

// ---------------------------------------------------------------------------
// 8. Cross-detector fold of a loser's WHOLE location set: the loser carries its
//    own additional_locations, and BOTH its primary and its additional fold
//    into the winner (winner has none of its own). Two additionals result.
// ---------------------------------------------------------------------------
#[test]
fn cross_detector_folds_loser_primary_and_its_additionals() {
    let winner = deduped("aws-key", "sameval", 0.9, loc("app.env", 1, 10), vec![]);
    let loser = deduped(
        "gcp-key",
        "sameval",
        0.5,
        loc("app.env", 2, 20),
        vec![loc("app.env", 3, 30)],
    );
    let out = dedup_cross_detector(vec![winner, loser]);
    assert_eq!(out.len(), 1, "same credential_hash + file -> one finding");
    let f = &out[0];
    assert_eq!(&*f.detector_id, "aws-key", "higher confidence wins");
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(
        f.additional_locations.len(),
        2,
        "loser primary + loser additional folded"
    );
    assert_eq!(additional_lines(f), vec![Some(2), Some(3)]);
}

// ---------------------------------------------------------------------------
// 9. In-fold duplicate collapse: a loser additional whose identity equals the
//    WINNER's primary must NOT be re-added; only the genuinely-new loser
//    locations survive.
// ---------------------------------------------------------------------------
#[test]
fn cross_detector_fold_drops_loser_additional_equal_to_winner_primary() {
    let winner = deduped("aws-key", "sameval", 0.9, loc("app.env", 1, 10), vec![]);
    let loser = deduped(
        "gcp-key",
        "sameval",
        0.5,
        loc("app.env", 2, 20),
        // line 1 duplicates the winner primary identity; line 4 is new.
        vec![loc("app.env", 1, 99), loc("app.env", 4, 40)],
    );
    let out = dedup_cross_detector(vec![winner, loser]);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(&*f.detector_id, "aws-key");
    assert_eq!(
        f.additional_locations.len(),
        2,
        "loser line1 collapses into winner primary"
    );
    let lines = additional_lines(f);
    assert_eq!(lines, vec![Some(2), Some(4)]);
    assert!(
        !lines.contains(&Some(1)),
        "winner-primary duplicate not re-added"
    );
}

// ---------------------------------------------------------------------------
// 10. Serialized shape: `additional_locations` appears in the JSON with the
//     exact recorded line/offset so downstream reporters see the merge result.
// ---------------------------------------------------------------------------
#[test]
fn additional_locations_serialize_with_exact_lines() {
    let matches = vec![
        raw(
            "generic-password",
            "jsonval",
            Some(0.5),
            loc("s.env", 1, 10),
        ),
        raw(
            "generic-password",
            "jsonval",
            Some(0.5),
            loc("s.env", 2, 30),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let v = serde_json::to_value(&out[0]).expect("DedupedMatch serializes");
    let extra = v
        .get("additional_locations")
        .and_then(|x| x.as_array())
        .expect("additional_locations is a JSON array");
    assert_eq!(extra.len(), 1, "one additional location serialized");
    assert_eq!(extra[0]["line"].as_u64(), Some(2));
    assert_eq!(extra[0]["offset"].as_u64(), Some(30));
    assert_eq!(v["primary_location"]["line"].as_u64(), Some(1));
    assert_eq!(v["primary_location"]["offset"].as_u64(), Some(10));
}

// ---------------------------------------------------------------------------
// 11. Multi-file ordering under Credential scope: additionals are ordered by
//     (file_path asc, offset asc). Primary is the lexicographically-first file
//     at its lowest offset; a second line of that file precedes the other file.
// ---------------------------------------------------------------------------
#[test]
fn credential_scope_orders_additionals_by_file_then_offset() {
    let matches = vec![
        raw("generic-password", "ordcred", Some(0.5), loc("z.env", 1, 5)),
        raw("generic-password", "ordcred", Some(0.5), loc("a.env", 2, 9)),
        raw("generic-password", "ordcred", Some(0.5), loc("a.env", 1, 5)),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(f.primary_location.file_path.as_deref(), Some("a.env"));
    assert_eq!(li(&f.primary_location), (Some(1), 5));
    assert_eq!(f.additional_locations.len(), 2);
    assert_eq!(
        f.additional_locations[0].file_path.as_deref(),
        Some("a.env")
    );
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 9));
    assert_eq!(
        f.additional_locations[1].file_path.as_deref(),
        Some("z.env")
    );
    assert_eq!(li(&f.additional_locations[1]), (Some(1), 5));
}

// ---------------------------------------------------------------------------
// 12. Repeated-additional collapse: five matches on two distinct lines (line 1
//     x3, line 7 x2) -> ONE finding, primary line 1, exactly ONE additional
//     (line 7). The seen-set must not record line 7 twice.
// ---------------------------------------------------------------------------
#[test]
fn repeated_additional_location_recorded_once() {
    let matches = vec![
        raw(
            "generic-password",
            "repcred",
            Some(0.5),
            loc("r.env", 1, 10),
        ),
        raw(
            "generic-password",
            "repcred",
            Some(0.5),
            loc("r.env", 7, 70),
        ),
        raw(
            "generic-password",
            "repcred",
            Some(0.5),
            loc("r.env", 1, 10),
        ),
        raw(
            "generic-password",
            "repcred",
            Some(0.5),
            loc("r.env", 7, 70),
        ),
        raw(
            "generic-password",
            "repcred",
            Some(0.5),
            loc("r.env", 1, 10),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(li(&f.primary_location), (Some(1), 10));
    assert_eq!(
        f.additional_locations.len(),
        1,
        "line 7 recorded once despite two hits"
    );
    assert_eq!(li(&f.additional_locations[0]), (Some(7), 70));
}

// ---------------------------------------------------------------------------
// 13. Confidence is the MAX across a location merge: two locations with 0.3 and
//     0.85 merge to one finding whose confidence is 0.85, with one additional.
// ---------------------------------------------------------------------------
#[test]
fn location_merge_keeps_max_confidence() {
    let matches = vec![
        raw(
            "generic-password",
            "confcred",
            Some(0.30),
            loc("c.env", 1, 10),
        ),
        raw(
            "generic-password",
            "confcred",
            Some(0.85),
            loc("c.env", 2, 20),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert!(
        (f.confidence.unwrap() - 0.85).abs() < EPS,
        "max confidence retained"
    );
    assert_eq!(f.additional_locations.len(), 1);
    assert_eq!(li(&f.additional_locations[0]), (Some(2), 20));
}

// ---------------------------------------------------------------------------
// 14. Two decoder twins of ONE plaintext primary both collapse: base64 twin and
//     hex twin, each on the primary's line, add ZERO additional locations.
// ---------------------------------------------------------------------------
#[test]
fn multiple_decoder_twins_all_collapse_into_one_primary() {
    let matches = vec![
        raw(
            "generic-password",
            "multitwin",
            Some(0.9),
            loc_full("filesystem", "m.env", Some(1), 5),
        ),
        raw(
            "generic-password",
            "multitwin",
            Some(0.4),
            loc_full("filesystem/base64", "m.env", Some(1), 12),
        ),
        raw(
            "generic-password",
            "multitwin",
            Some(0.4),
            loc_full("filesystem/hex", "m.env", Some(1), 18),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(
        &*f.primary_location.source, "filesystem",
        "plaintext stays primary"
    );
    assert_eq!(li(&f.primary_location), (Some(1), 5));
    assert_eq!(
        f.additional_locations.len(),
        0,
        "both decoder twins collapse"
    );
}
