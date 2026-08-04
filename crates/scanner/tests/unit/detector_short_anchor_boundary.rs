//! A detector whose leading anchor accepts a short bare token must require a
//! word boundary before it.
//!
//! `africastalking-api-key` matched `(?:africas?talking|...|at|AT)[_.-]?API...`
//! with nothing in front of the alternation. `SNAPCHAT_API_KEY=<64 hex>`
//! contains a literal `AT_API_KEY=`, so every Snapchat token in the corpus was
//! also reported as an Africa's Talking key. Cross-detector deduplication hid
//! it from the report, because both matches carry the same credential, so the
//! only place it surfaced was autoroute calibration, where the GPU
//! region-presence route found the extra raw matches and the scalar route did
//! not. That divergence blocked GPU calibration for the whole workload class.
//!
//! `\b` fixes it precisely: `AT_API_KEY=` at a token start still matches, and
//! `SNAPCHAT_API_KEY=`, `FORMAT_API_KEY=` and `CHAT_API_KEY=` no longer do.
//!
//! This is a ratchet, not a clean bill of health. Thirty-three patterns still
//! carry the same shape and are listed below with the token that makes them
//! reachable. A NEW one fails immediately; fixing a listed one also fails,
//! which is deliberate, because deleting its line is how the debt shrinks
//! visibly instead of silently.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Patterns known to admit a short bare token with no leading boundary, as
/// `(detector file stem, index of the pattern within that file)`.
///
/// Each is a live false-positive source: the token can appear at the tail of an
/// unrelated identifier. `mexico-datosgobmx-api-key` pattern 2 is the widest,
/// since a bare `api` means any `<anything>api_key=<uuid>` is reported as a
/// Mexican government key.
const KNOWN_UNANCHORED: &[(&str, usize)] = &[
    ("azure-client-secret", 0),          // AAD, ARM
    ("bluejeans-api", 0),                // BJN
    ("carbon-black-api-key", 0),         // CB
    ("carbon-black-api-key", 1),         // CB
    ("carbon-black-api-key", 2),         // CB
    ("cmcom-api-key", 0),                // CM, cm
    ("cmcom-api-key", 2),                // CM, cm
    ("countly-api-key", 0),              // APP
    ("eu-open-data-api-key", 0),         // EU
    ("eu-open-data-api-key", 1),         // EU
    ("eu-open-data-api-key", 2),         // EDP
    ("github-webhook-secret", 0),        // gh
    ("leptonai-api-token", 0),           // run
    ("mexico-datosgobmx-api-key", 2),    // api
    ("neon-serverless-driver-token", 0), // URL
    ("newrelic-license-key", 0),         // NR, nr
    ("openweathermap-api-key", 0),       // OWM
    ("oracle-cloud-api-key", 0),         // OCI
    ("powerbi-credentials", 0),          // PBI
    ("powerbi-credentials", 1),          // PBI
    ("powerbi-credentials", 2),          // PBI
    ("powerbi-credentials", 3),          // PBI
    ("sap-api-key", 0),                  // sap
    ("sap-api-key", 1),                  // sap
    ("sap-api-key", 2),                  // sap
    ("servicenow-api-key", 0),           // SN
    ("singapore-govtech-api-key", 0),    // SG
    ("wix-api-credentials", 0),          // WIX, wix
    ("wix-api-credentials", 1),          // WIX, wix
    ("wix-api-credentials", 2),          // WIX, wix
    ("workday-api-key", 0),              // WD
    ("worldweatheronline-api-key", 0),   // WWO
    ("zscaler-api-key", 0),              // ZPA, zpa
    ("zscaler-api-key", 1),              // ZPA, zpa
];

fn detector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

/// The pattern bodies of one detector file, in declaration order.
///
/// Read as text rather than through the loader: the loader normalises and this
/// gate is about the authored source, which is what a reviewer edits.
fn pattern_bodies(source: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("regex = '''") {
        let after = &rest[start + "regex = '''".len()..];
        let Some(end) = after.find("'''") else {
            break;
        };
        bodies.push(&after[..end]);
        rest = &after[end + 3..];
    }
    bodies
}

/// Whether the pattern already refuses to start inside a larger identifier.
fn starts_at_a_boundary(pattern: &str) -> bool {
    pattern.starts_with("\\b")
        || pattern.starts_with('^')
        || pattern.starts_with("(?:^|[^")
        || pattern.starts_with("(?i)\\b")
}

/// The short bare alternatives in a leading `(?:a|b|c)` group.
///
/// Only the leading group matters: a short token later in the pattern is
/// already fenced by whatever had to match before it.
fn leading_short_tokens(pattern: &str) -> BTreeSet<&str> {
    let Some(rest) = pattern.strip_prefix("(?:") else {
        return BTreeSet::new();
    };
    let Some(end) = rest.find(')') else {
        return BTreeSet::new();
    };
    rest[..end]
        .split('|')
        .filter(|token| {
            !token.is_empty()
                && token.len() <= 3
                && token.chars().all(|ch| ch.is_ascii_alphabetic())
        })
        .collect()
}

fn unanchored_short_anchors() -> BTreeSet<(String, usize)> {
    let mut found = BTreeSet::new();
    let entries = std::fs::read_dir(detector_dir()).expect("detector corpus readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let source = std::fs::read_to_string(&path).expect("detector readable");
        for (index, pattern) in pattern_bodies(&source).into_iter().enumerate() {
            if starts_at_a_boundary(pattern) {
                continue;
            }
            if !leading_short_tokens(pattern).is_empty() {
                found.insert((stem.to_string(), index));
            }
        }
    }
    found
}

/// The set of unanchored short-token anchors matches the recorded debt exactly.
///
/// A new one is a new family of false positives and a new cross-backend parity
/// hazard. A fixed one must leave the list, so the count in this file always
/// states how much of this debt is actually left.
#[test]
fn detector_short_anchors_match_the_recorded_debt() {
    let found = unanchored_short_anchors();
    let known: BTreeSet<(String, usize)> = KNOWN_UNANCHORED
        .iter()
        .map(|(stem, index)| ((*stem).to_string(), *index))
        .collect();

    let added: Vec<_> = found.difference(&known).collect();
    assert!(
        added.is_empty(),
        "new detector patterns start with a short bare token and no `\\b`, so the token \
         matches at the tail of an unrelated identifier: {added:?}"
    );

    let fixed: Vec<_> = known.difference(&found).collect();
    assert!(
        fixed.is_empty(),
        "these patterns are anchored now; delete their lines from KNOWN_UNANCHORED so the \
         remaining debt stays honest: {fixed:?}"
    );
}

/// The detector that caused the parity divergence is anchored.
///
/// Pinned by name rather than only by absence from the list above, so the fix
/// cannot be undone by re-adding a line.
#[test]
fn africastalking_requires_a_token_boundary_before_its_anchor() {
    let source = std::fs::read_to_string(detector_dir().join("africastalking-api-key.toml"))
        .expect("africastalking detector readable");
    let patterns = pattern_bodies(&source);

    assert_eq!(patterns.len(), 2, "africastalking declares two patterns");
    for pattern in patterns {
        assert!(
            pattern.starts_with("\\b"),
            "africastalking must not match inside a larger identifier: {pattern}"
        );
    }
}

/// The gate would actually catch the bug it was written for.
///
/// A ratchet that cannot detect its own founding case is decoration, so the
/// pre-fix pattern is checked directly.
#[test]
fn the_detection_recognises_the_pattern_that_caused_the_divergence() {
    let before = "(?:africas?talking|AFRICAS?TALKING|at|AT)[_.-]?(?:api|API)[_.-]?(?:key|KEY)?";
    let after = "\\b(?:africas?talking|AFRICAS?TALKING|at|AT)[_.-]?(?:api|API)[_.-]?(?:key|KEY)?";

    assert!(!starts_at_a_boundary(before));
    assert_eq!(
        leading_short_tokens(before),
        ["at", "AT"].into_iter().collect::<BTreeSet<_>>(),
        "the bare two-letter alternatives are what made the pattern reachable"
    );
    assert!(starts_at_a_boundary(after));
}

/// A long leading anchor is not debt.
///
/// Without this the gate could pass by flagging everything, and every detector
/// that spells out its vendor name would be dragged into the list.
#[test]
fn a_long_leading_anchor_is_not_reported() {
    assert!(leading_short_tokens("(?:stripe|STRIPE)[_-]?key").is_empty());
    assert!(leading_short_tokens("(?:github|GITHUB)[_-]?token").is_empty());
}
