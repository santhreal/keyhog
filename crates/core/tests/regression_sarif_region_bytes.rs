//! Regression: SARIF `physicalLocation.region` **byte/line math**.
//!
//! Distinct from `regression_sarif_schema.rs` (which pins the OUTER envelope
//! shape) this file pins the exact arithmetic that maps a keyhog
//! [`MatchLocation`] `(line, offset)` pair onto a SARIF `region`:
//!
//!   * `region.startLine`  == `location.line`  (1-based, verbatim)
//!   * `region.charOffset` == `location.offset` (byte offset from chunk start),
//!     emitted under the SARIF key `charOffset`: NEVER `byteOffset`.
//!   * The region object exists iff `line.is_some() || offset != 0`.
//!     - line present, offset 0  -> region has startLine, NO charOffset
//!     - line absent,  offset !=0 -> region has charOffset, NO startLine
//!     - line absent,  offset 0  -> NO region object at all (the boundary)
//!   * A multi-line finding (primary + `additional_locations`) maps EACH
//!     location's `(line, offset)` onto its own region under `relatedLocations`.
//!   * The auto-fix `deletedRegion` carries the same `startLine`.
//!
//! Every assertion pins a concrete integer / null. The reporter uses `usize`
//! offsets, so large offsets must survive as exact `u64` in JSON with no
//! truncation.

use keyhog_core::{
    sha256_hash, write_report, MatchLocation, ReportFormat, Severity, VerificationResult,
    VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

const AWS_VALUE: &str = "AKIAIOSFODNN7EXAMPLE";

/// Build a finding at a caller-chosen `(file, line, offset)` with optional
/// additional locations. `line`/`file` are `Option` so we can exercise the
/// region-presence boundary.
fn finding_with(
    file: Option<&str>,
    line: Option<usize>,
    offset: usize,
    additional: Vec<MatchLocation>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA****"),
        credential_hash: sha256_hash(AWS_VALUE),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: file.map(|f| f.into()),
            line,
            offset,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: additional,
        entropy: None,
        confidence: None,
    }
}

fn loc(file: &str, line: Option<usize>, offset: usize) -> MatchLocation {
    MatchLocation {
        source: "filesystem".into(),
        file_path: Some(file.into()),
        line,
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

fn render_sarif(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        findings,
    )
    .expect("finish SARIF document");
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

/// Convenience: the primary result's `physicalLocation.region` node.
fn primary_region(json: &serde_json::Value) -> serde_json::Value {
    json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].clone()
}

// ---------------------------------------------------------------------------
// startLine math
// ---------------------------------------------------------------------------

/// `region.startLine` equals the finding's 1-based line verbatim.
#[test]
fn start_line_equals_exact_line() {
    let json = render_sarif(&[finding_with(Some("a.env"), Some(42), 0, vec![])]);
    let region = primary_region(&json);
    assert_eq!(
        region["startLine"].as_u64(),
        Some(42),
        "region.startLine must be the finding's exact 1-based line"
    );
}

/// The minimum legal 1-based line (1) with a zero offset still produces a
/// region carrying `startLine == 1` and NO `charOffset`.
#[test]
fn line_one_offset_zero_boundary_emits_start_line_only() {
    let json = render_sarif(&[finding_with(Some("a.env"), Some(1), 0, vec![])]);
    let region = primary_region(&json);
    assert!(!region.is_null(), "line present must produce a region");
    assert_eq!(
        region["startLine"].as_u64(),
        Some(1),
        "startLine must be exactly 1"
    );
    assert!(
        region["charOffset"].is_null(),
        "a zero offset must not emit charOffset"
    );
}

// ---------------------------------------------------------------------------
// charOffset (byte) math
// ---------------------------------------------------------------------------

/// A zero offset alongside a present line emits `startLine` but the reporter
/// must NOT leak a `charOffset: 0`: offset 0 means "no offset".
#[test]
fn offset_zero_does_not_leak_charoffset_zero() {
    let json = render_sarif(&[finding_with(Some("a.env"), Some(9), 0, vec![])]);
    let region = primary_region(&json);
    assert_eq!(region["startLine"].as_u64(), Some(9));
    assert!(
        region["charOffset"].is_null(),
        "charOffset must be absent (never 0) for a zero offset"
    );
}

/// The smallest non-zero offset (1) crosses the `offset != 0` boundary and is
/// preserved verbatim as `charOffset == 1`.
#[test]
fn smallest_nonzero_offset_one_is_preserved() {
    let json = render_sarif(&[finding_with(Some("blob.bin"), None, 1, vec![])]);
    let region = primary_region(&json);
    assert!(
        !region.is_null(),
        "offset 1 is non-zero and must produce a region"
    );
    assert_eq!(
        region["charOffset"].as_u64(),
        Some(1),
        "charOffset must be exactly 1"
    );
    assert!(region["startLine"].is_null(), "no line means no startLine");
}

/// Line AND a non-zero offset present: the region carries BOTH the exact
/// startLine and the exact charOffset.
#[test]
fn line_and_nonzero_offset_emit_both_values() {
    let json = render_sarif(&[finding_with(Some("src/config.rs"), Some(7), 1024, vec![])]);
    let region = primary_region(&json);
    assert_eq!(region["startLine"].as_u64(), Some(7), "startLine must be 7");
    assert_eq!(
        region["charOffset"].as_u64(),
        Some(1024),
        "charOffset must be the exact byte offset 1024"
    );
}

/// The offset is emitted under the SARIF `charOffset` key, the region must NOT
/// carry a `byteOffset` key (keyhog's chosen schema field for offsets).
#[test]
fn offset_uses_charoffset_key_not_byteoffset() {
    let json = render_sarif(&[finding_with(Some("blob.bin"), None, 512, vec![])]);
    let region = primary_region(&json);
    assert_eq!(
        region["charOffset"].as_u64(),
        Some(512),
        "offset must serialize under the charOffset key"
    );
    assert!(
        region["byteOffset"].is_null(),
        "the reporter must not emit a byteOffset key"
    );
}

/// A large offset (> u32::MAX) survives as an exact u64 in JSON, no
/// truncation of the `usize` offset when serialized.
#[test]
fn large_offset_preserved_without_truncation() {
    let big: usize = 4_294_967_296; // u32::MAX + 1
    let json = render_sarif(&[finding_with(Some("huge.bin"), None, big, vec![])]);
    let region = primary_region(&json);
    assert_eq!(
        region["charOffset"].as_u64(),
        Some(4_294_967_296),
        "large offset must round-trip exactly with no truncation"
    );
}

// ---------------------------------------------------------------------------
// Region-presence boundary
// ---------------------------------------------------------------------------

/// The exact boundary: line absent AND offset 0 -> NO region object at all
/// (the `line.is_some() || offset != 0` predicate is false).
#[test]
fn no_line_and_zero_offset_omits_region_entirely() {
    let json = render_sarif(&[finding_with(Some("blob.bin"), None, 0, vec![])]);
    let phys = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert!(
        phys["region"].is_null(),
        "no line and zero offset must emit no region object"
    );
    // The artifactLocation still names the file so the finding stays anchored.
    assert_eq!(
        phys["artifactLocation"]["uri"].as_str(),
        Some("blob.bin"),
        "artifactLocation.uri survives even with no region"
    );
}

/// Offset present but line absent: region carries `charOffset` and NO
/// `startLine` (offset-only anchoring for binary/blob scans).
#[test]
fn offset_without_line_emits_charoffset_only() {
    let json = render_sarif(&[finding_with(Some("blob.bin"), None, 8192, vec![])]);
    let region = primary_region(&json);
    assert!(!region.is_null(), "a non-zero offset must produce a region");
    assert_eq!(
        region["charOffset"].as_u64(),
        Some(8192),
        "charOffset must be the exact byte offset"
    );
    assert!(region["startLine"].is_null(), "no line means no startLine");
}

/// The emitted region carries ONLY startLine/charOffset, never the
/// end-line/column keys the reporter always sets to `None`.
#[test]
fn region_omits_end_line_and_columns() {
    let json = render_sarif(&[finding_with(Some("a.env"), Some(3), 64, vec![])]);
    let region = primary_region(&json);
    assert!(
        region["startColumn"].is_null(),
        "startColumn is not populated"
    );
    assert!(region["endLine"].is_null(), "endLine is not populated");
    assert!(region["endColumn"].is_null(), "endColumn is not populated");
    // ...but the two values we DO populate are present and exact.
    assert_eq!(region["startLine"].as_u64(), Some(3));
    assert_eq!(region["charOffset"].as_u64(), Some(64));
}

// ---------------------------------------------------------------------------
// Multi-line finding (primary + relatedLocations)
// ---------------------------------------------------------------------------

/// A finding spanning multiple lines maps its primary and additional locations
/// onto independent regions: primary under `locations`, extras under
/// `relatedLocations`, each with its own exact `(startLine, charOffset)`.
#[test]
fn multi_line_finding_maps_each_location_region() {
    let json = render_sarif(&[finding_with(
        Some("multi.env"),
        Some(10),
        100,
        vec![loc("multi.env", Some(250), 5000)],
    )]);
    let result = &json["runs"][0]["results"][0];

    let primary = &result["locations"][0]["physicalLocation"]["region"];
    assert_eq!(
        primary["startLine"].as_u64(),
        Some(10),
        "primary region startLine"
    );
    assert_eq!(
        primary["charOffset"].as_u64(),
        Some(100),
        "primary region charOffset"
    );

    let related = &result["relatedLocations"][0]["physicalLocation"]["region"];
    assert_eq!(
        related["startLine"].as_u64(),
        Some(250),
        "related region startLine must be the extra location's line"
    );
    assert_eq!(
        related["charOffset"].as_u64(),
        Some(5000),
        "related region charOffset must be the extra location's offset"
    );
}

/// Two additional locations that differ ONLY by line are both kept (distinct
/// `(file, line, offset)` tuples) with their exact, distinct startLines.
#[test]
fn distinct_lines_same_offset_are_not_deduped() {
    let json = render_sarif(&[finding_with(
        Some("dup.env"),
        Some(1),
        0,
        vec![loc("dup.env", Some(20), 0), loc("dup.env", Some(40), 0)],
    )]);
    let related = json["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .expect("relatedLocations must be an array");
    assert_eq!(
        related.len(),
        2,
        "two locations differing by line are distinct tuples"
    );
    assert_eq!(
        related[0]["physicalLocation"]["region"]["startLine"].as_u64(),
        Some(20),
    );
    assert_eq!(
        related[1]["physicalLocation"]["region"]["startLine"].as_u64(),
        Some(40),
    );
}

/// Byte-identical additional locations collapse to a single relatedLocation
/// (dedup by the `(file, line, offset)` tuple) (its region startLine is exact).
#[test]
fn identical_related_locations_dedup_to_one_region() {
    let json = render_sarif(&[finding_with(
        Some("same.env"),
        Some(1),
        0,
        vec![
            loc("same.env", Some(77), 900),
            loc("same.env", Some(77), 900),
        ],
    )]);
    let related = json["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .expect("relatedLocations must be an array");
    assert_eq!(
        related.len(),
        1,
        "two identical (file,line,offset) tuples dedup to one relatedLocation"
    );
    let region = &related[0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"].as_u64(), Some(77));
    assert_eq!(region["charOffset"].as_u64(), Some(900));
}

// ---------------------------------------------------------------------------
// Auto-fix deletedRegion
// ---------------------------------------------------------------------------

/// The auto-fix `deletedRegion` (emitted when file_path AND line are present)
/// carries the SAME `startLine` as the finding, with NO charOffset.
#[test]
fn fix_deleted_region_carries_start_line() {
    let json = render_sarif(&[finding_with(Some("leak.env"), Some(55), 0, vec![])]);
    let deleted = &json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["replacements"]
        [0]["deletedRegion"];
    assert!(
        !deleted.is_null(),
        "a finding with file+line must carry an auto-fix deletedRegion"
    );
    assert_eq!(
        deleted["startLine"].as_u64(),
        Some(55),
        "deletedRegion.startLine must match the finding's line"
    );
    assert!(
        deleted["charOffset"].is_null(),
        "deletedRegion pins the line only, no charOffset"
    );
}
