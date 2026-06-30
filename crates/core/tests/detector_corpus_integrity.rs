//! Integrity guard for the embedded detector corpus.
//!
//! `assemble_detector_load` collects every parsed spec into a `Vec` and sorts by
//! id — it never checks that ids are UNIQUE or well-formed. With 905 detectors
//! authored across many sessions, a copy-pasted `id` would silently double-fire
//! (or shadow the original in any id-keyed downstream map), and a malformed id
//! breaks doc/registry cross-references — both invisible at scan time. These
//! tests lock the sound, engine-independent corpus invariants so a future
//! malformed or duplicate spec fails CI instead of silently degrading recall.
//!
//! The corpus under test is the EMBEDDED one (`load_embedded_detectors_or_fail`)
//! — exactly the set the shipped binary scans with, not a loose on-disk copy.

use std::collections::HashSet;

fn corpus() -> Vec<keyhog_core::DetectorSpec> {
    keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
}

/// `true` iff `id` is a clean kebab-case slug: lowercase ASCII alphanumerics and
/// single internal hyphens, no leading/trailing/double hyphen.
fn is_kebab_case(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// ── load + size sanity ──────────────────────────────────────────────────────

#[test]
fn embedded_corpus_loads() {
    assert!(!corpus().is_empty(), "the embedded detector corpus must not be empty");
}

#[test]
fn corpus_has_at_least_900_detectors() {
    let n = corpus().len();
    assert!(n >= 900, "expected the full corpus (>=900 detectors), got {n}");
}

// ── id uniqueness (the unguarded silent-shadow hazard) ──────────────────────

#[test]
fn all_detector_ids_are_unique() {
    let detectors = corpus();
    let mut seen = HashSet::new();
    let dups: Vec<&str> = detectors
        .iter()
        .filter(|d| !seen.insert(d.id.as_str()))
        .map(|d| d.id.as_str())
        .collect();
    assert!(dups.is_empty(), "duplicate detector ids would shadow/double-fire: {dups:?}");
}

#[test]
fn all_detector_ids_are_unique_case_insensitively() {
    let detectors = corpus();
    let mut seen = HashSet::new();
    let collisions: Vec<String> = detectors
        .iter()
        .map(|d| d.id.to_ascii_lowercase())
        .filter(|id| !seen.insert(id.clone()))
        .collect();
    assert!(
        collisions.is_empty(),
        "ids must not collide even ignoring case (registry/doc lookups are case-folded): {collisions:?}"
    );
}

// ── id well-formedness (doc/registry cross-reference contract) ──────────────

#[test]
fn all_detector_ids_are_nonempty() {
    for d in corpus() {
        assert!(!d.id.is_empty(), "detector '{}' has an empty id", d.name);
    }
}

#[test]
fn all_detector_ids_are_kebab_case() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| !is_kebab_case(&d.id))
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "ids must be clean kebab-case slugs; offenders: {bad:?}");
}

#[test]
fn no_detector_id_contains_whitespace() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.id.chars().any(|c| c.is_whitespace()))
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "detector ids must not contain whitespace: {bad:?}");
}

// ── required string fields ──────────────────────────────────────────────────

#[test]
fn all_detector_names_are_nonempty() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.name.trim().is_empty())
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "detectors missing a human-readable name: {bad:?}");
}

#[test]
fn all_detector_services_are_nonempty() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.service.trim().is_empty())
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "detectors missing a service: {bad:?}");
}

#[test]
fn no_service_contains_whitespace() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.service.chars().any(|c| c.is_whitespace()))
        .map(|d| format!("{}={}", d.id, d.service))
        .collect();
    assert!(bad.is_empty(), "service tags must be single tokens: {bad:?}");
}

// ── patterns ────────────────────────────────────────────────────────────────

#[test]
fn every_detector_has_at_least_one_pattern() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.patterns.is_empty())
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "a detector with no pattern can never fire: {bad:?}");
}

#[test]
fn every_pattern_regex_is_nonempty() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.patterns.iter().any(|p| p.regex.trim().is_empty()))
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "empty pattern regex never matches: {bad:?}");
}

#[test]
fn pattern_capture_group_indices_are_sane() {
    // The corpus only ever references groups 0-2; a value far above that is a
    // typo that would silently capture nothing. Bound it well above real usage
    // (engine-independent: a true bound needs the compiled regex, but no honest
    // detector declares a double-digit capture group).
    let bad: Vec<String> = corpus()
        .iter()
        .flat_map(|d| d.patterns.iter().filter_map(move |p| p.group.map(|g| (d.id.clone(), g))))
        .filter(|(_, g)| *g > 8)
        .map(|(id, g)| format!("{id} group={g}"))
        .collect();
    assert!(bad.is_empty(), "implausible capture-group index (likely a typo): {bad:?}");
}

// ── keywords ────────────────────────────────────────────────────────────────

#[test]
fn no_keyword_is_empty() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter(|d| d.keywords.iter().any(|k| k.is_empty()))
        .map(|d| d.id.clone())
        .collect();
    assert!(bad.is_empty(), "an empty-string keyword matches everything: {bad:?}");
}

#[test]
fn no_keyword_has_edge_whitespace() {
    // A keyword with leading/trailing whitespace is an authoring typo: the
    // prefilter matches the literal bytes, so " token" never co-occurs with the
    // intended `token`.
    let bad: Vec<String> = corpus()
        .iter()
        .flat_map(|d| {
            d.keywords
                .iter()
                .filter(|k| k.trim() != k.as_str())
                .map(move |k| format!("{}:'{k}'", d.id))
        })
        .collect();
    assert!(bad.is_empty(), "keywords must not carry edge whitespace: {bad:?}");
}

// ── self-declared confidence floor ──────────────────────────────────────────

#[test]
fn min_confidence_is_within_unit_range() {
    let bad: Vec<String> = corpus()
        .iter()
        .filter_map(|d| d.min_confidence.map(|mc| (d.id.clone(), mc)))
        .filter(|(_, mc)| !(0.0..=1.0).contains(mc))
        .map(|(id, mc)| format!("{id}={mc}"))
        .collect();
    assert!(bad.is_empty(), "min_confidence must be within [0.0, 1.0]: {bad:?}");
}
