//! Fail-closed contract for the core detector-spec loader.
//!
//! keyhog's recall is only as complete as the detector corpus it actually
//! loads. The load path therefore has ONE binding rule (Law 10, NO SILENT
//! FALLBACKS): a detector that cannot be parsed or validated must produce a
//! LOUD, offender-naming hard error — never a silent `continue` that drops it
//! and reports "all detectors loaded". This is exactly how the dead
//! `discord-bot-token` detector (a single-quoted TOML literal that broke the
//! parse) reached a benched release as an invisible recall hole.
//!
//! This file drives the three real fail-closed entry points end to end:
//!   * `load_embedded_detectors_or_fail` — the compiled-in corpus,
//!   * `load_detectors` (public, directory-based) — an on-disk corpus,
//!   * `load_detectors_from_str` / `load_detectors_with_gate` (testing facade)
//!     — single-string and gated loads,
//! plus the two operator-facing error variants' rendered contracts. Every
//! assertion pins a concrete value: an exact count, an exact `SpecError`
//! variant + its fields, an exact detector field, or an exact substring of the
//! rendered error the operator sees.

use std::collections::HashSet;
use std::path::PathBuf;

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{
    embedded_detector_count, load_detectors, load_embedded_detectors_or_fail, DetectorSpec,
    Severity, SpecError,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn from_str(toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError> {
    CoreTestApi::load_detectors_from_str(&TestApi, toml_str)
}

fn with_gate(dir: &std::path::Path, enforce: bool) -> Result<Vec<DetectorSpec>, SpecError> {
    CoreTestApi::load_detectors_with_gate(&TestApi, dir, enforce)
}

fn write_toml(dir: &std::path::Path, file: &str, body: &str) {
    std::fs::write(dir.join(file), body).expect("write detector toml fixture");
}

const VALID_DETECTOR_TOML: &str = r#"
[detector]
id = "demo"
name = "Demo Detector"
service = "demo"
severity = "high"
keywords = ["demo_"]

[[detector.patterns]]
regex = "demo_[A-Z0-9]{8}"
"#;

// ─── embedded corpus: loads EXACTLY the authoritative count ──────────────────

/// The compiled-in corpus loads exactly one `DetectorSpec` per embedded TOML,
/// pinned to the authoritative `embedded_detector_count()` (which equals the
/// embedded slice length). A shorter result = a silently dropped detector, the
/// precise defect this loader exists to make impossible.
#[test]
fn embedded_corpus_loads_exactly_the_authoritative_count() {
    let detectors = load_embedded_detectors_or_fail()
        .expect("a healthy embedded corpus must load via the shared fail-closed loader");

    let authoritative = embedded_detector_count();
    let slice_len = CoreTestApi::embedded_detector_tomls(&TestApi).len();

    assert_eq!(
        detectors.len(),
        authoritative,
        "loader returned {} detectors but the authoritative count is {authoritative}",
        detectors.len(),
    );
    assert_eq!(
        authoritative, slice_len,
        "authoritative count {authoritative} must equal the embedded slice length {slice_len}",
    );
    // Lower bound so a catastrophically truncated embed (e.g. one detector)
    // cannot pass by coincidentally matching a shrunken count. The shipped
    // corpus is 900+; a floor of 800 catches a collapse without being brittle
    // to routine corpus churn.
    assert!(
        detectors.len() >= 800,
        "embedded corpus collapsed to {} detectors; the shipped tree carries 900+",
        detectors.len(),
    );
}

/// A specific, stable detector must survive the embedded load with its exact
/// declared fields — proof the loader materialises real spec content, not
/// empty-shell structs that a lossy parse could leave behind.
#[test]
fn embedded_corpus_contains_aws_access_key_with_exact_fields() {
    let detectors = load_embedded_detectors_or_fail().expect("embedded corpus loads");

    let aws = detectors
        .iter()
        .find(|d| d.id == "aws-access-key")
        .expect("aws-access-key detector must be present in the embedded corpus");

    assert_eq!(aws.service, "aws");
    assert_eq!(aws.severity, Severity::Critical);
    assert!(
        aws.keywords.iter().any(|k| k == "AKIA"),
        "aws-access-key must keep its AKIA keyword; got {:?}",
        aws.keywords,
    );
    assert!(
        !aws.patterns.is_empty(),
        "aws-access-key must carry at least one pattern"
    );
    assert!(
        aws.patterns[0].regex.contains("AKIA"),
        "aws-access-key primary regex must reference the AKIA prefix; got {}",
        aws.patterns[0].regex,
    );
}

/// Every embedded detector carries a non-empty id AND at least one pattern.
/// A zero-count for each failure class is a stronger claim than
/// "the vector is non-empty".
#[test]
fn every_embedded_detector_has_nonempty_id_and_patterns() {
    let detectors = load_embedded_detectors_or_fail().expect("embedded corpus loads");

    let empty_id = detectors.iter().filter(|d| d.id.is_empty()).count();
    let no_patterns = detectors.iter().filter(|d| d.patterns.is_empty()).count();

    assert_eq!(
        empty_id, 0,
        "{empty_id} embedded detectors have an empty id"
    );
    assert_eq!(
        no_patterns, 0,
        "{no_patterns} embedded detectors have zero patterns and could never match",
    );
}

/// Detector ids across the embedded corpus are globally unique. A duplicate id
/// would shadow/double-fire at scan time; the loader materialises the whole set
/// so this invariant is verifiable here on the exact bytes that ship.
#[test]
fn embedded_corpus_ids_are_globally_unique() {
    let detectors = load_embedded_detectors_or_fail().expect("embedded corpus loads");

    let mut seen: HashSet<&str> = HashSet::with_capacity(detectors.len());
    let dups: Vec<&str> = detectors
        .iter()
        .filter(|d| !seen.insert(d.id.as_str()))
        .map(|d| d.id.as_str())
        .collect();

    assert!(dups.is_empty(), "duplicate detector ids present: {dups:?}");
    assert_eq!(
        seen.len(),
        detectors.len(),
        "unique-id count {} must equal detector count {}",
        seen.len(),
        detectors.len(),
    );
}

// ─── single-string load: exact fields + fail-closed on garbage ───────────────

/// A valid single-detector TOML parses to exactly one spec with every field at
/// its declared (or documented default) value.
#[test]
fn valid_single_detector_parses_to_exact_fields() {
    let specs = from_str(VALID_DETECTOR_TOML).expect("valid detector must parse");

    assert_eq!(specs.len(), 1, "one TOML detector must yield one spec");
    let d = &specs[0];
    assert_eq!(d.id, "demo");
    assert_eq!(d.name, "Demo Detector");
    assert_eq!(d.service, "demo");
    assert_eq!(d.severity, Severity::High);
    assert_eq!(d.keywords, vec!["demo_".to_string()]);
    assert_eq!(d.patterns.len(), 1);
    // No separator classes in this regex, so canonicalisation is a no-op and
    // the string round-trips byte-for-byte.
    assert_eq!(d.patterns[0].regex, "demo_[A-Z0-9]{8}");
    assert!(!d.patterns[0].client_safe, "client_safe defaults to false");
    // Documented defaults for the omitted optional fields.
    assert!(d.companions.is_empty(), "companions default to empty");
    assert!(d.verify.is_none(), "verify defaults to None");
    assert!(d.tests.is_empty(), "inline tests default to empty");
    assert_eq!(d.min_confidence, None, "min_confidence defaults to None");
}

/// Boundary parse: `severity = "client-safe"`, `min_confidence = 0.0` (the low
/// edge of `[0.0, 1.0]`), and a `client_safe = true` pattern must each land
/// exactly, not collapse to a default.
#[test]
fn client_safe_severity_and_zero_min_confidence_parse_at_boundary() {
    let toml = r#"
[detector]
id = "pub"
name = "Public Token"
service = "sentry"
severity = "client-safe"
min_confidence = 0.0
keywords = ["sentry"]

[[detector.patterns]]
regex = "https://[a-f0-9]{32}@sentry"
client_safe = true
"#;
    let specs = from_str(toml).expect("client-safe detector must parse");
    assert_eq!(specs.len(), 1);
    let d = &specs[0];
    assert_eq!(d.severity, Severity::ClientSafe);
    assert_eq!(d.min_confidence, Some(0.0));
    assert!(
        d.patterns[0].client_safe,
        "client_safe = true must survive the parse"
    );
}

/// Malformed TOML is a HARD error, not a silent skip: `load_detectors_from_str`
/// returns `SpecError::InvalidToml` whose `path` is the `<string>` sentinel and
/// whose rendered message points the operator at the syntax.
#[test]
fn malformed_toml_string_yields_invalid_toml_not_silent_skip() {
    // Unterminated string / stray bracket — invalid TOML syntax.
    let broken = "[detector]\nid = \"oops\nseverity = \"high\"\n";
    let err = from_str(broken).expect_err("malformed TOML must fail closed, not return empty");

    match &err {
        SpecError::InvalidToml { path, .. } => {
            assert_eq!(
                path,
                &PathBuf::from("<string>"),
                "in-memory load must tag the source as <string>; got {path:?}",
            );
        }
        other => panic!("expected SpecError::InvalidToml, got {other:?}"),
    }
    assert!(
        err.to_string().contains("invalid TOML"),
        "error must announce invalid TOML; got: {err}"
    );
}

/// The schema's `deny_unknown_fields` typo-guard is load-bearing: a detector
/// with a misspelled field (`sevrity`) is REJECTED rather than loaded with the
/// intended field silently defaulted — otherwise a typo'd severity would ship
/// an Info-tier detector no one asked for.
#[test]
fn unknown_field_is_rejected_fail_closed() {
    let toml = r#"
[detector]
id = "typo"
name = "Typo"
service = "x"
sevrity = "high"

[[detector.patterns]]
regex = "x_[A-Z0-9]{8}"
"#;
    let err = from_str(toml).expect_err("unknown field must be rejected by deny_unknown_fields");
    assert!(
        matches!(err, SpecError::InvalidToml { .. }),
        "unknown-field rejection must surface as InvalidToml; got {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("sevrity") || rendered.contains("unknown field"),
        "error should name the offending unknown field; got: {rendered}"
    );
}

// ─── directory load: fail-closed corpus rejection ────────────────────────────

/// A directory with one valid detector loads exactly that detector with its
/// declared fields intact.
#[test]
fn dir_with_single_valid_detector_loads_one_with_exact_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_toml(dir.path(), "demo.toml", VALID_DETECTOR_TOML);

    let specs = load_detectors(dir.path()).expect("single valid detector dir must load");
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].id, "demo");
    assert_eq!(specs[0].severity, Severity::High);
}

/// A directory whose only detector file is malformed rejects the WHOLE corpus
/// with `DetectorCorpusRejected`, naming the offending file — not a silent skip
/// that returns an empty (recall-zero) set.
#[test]
fn dir_with_malformed_toml_rejects_corpus_naming_offender() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_toml(dir.path(), "broken.toml", "id = \"x\ngarbage = [[[");

    let err = load_detectors(dir.path()).expect_err("malformed corpus must fail closed");
    match &err {
        SpecError::DetectorCorpusRejected {
            failed_count,
            total,
            detail,
            ..
        } => {
            assert_eq!(*failed_count, 1, "exactly one file failed");
            assert_eq!(*total, 1, "the malformed file still counts toward total");
            assert!(
                detail.contains("broken.toml"),
                "the offender must be named by file; got detail: {detail}"
            );
        }
        other => panic!("expected DetectorCorpusRejected, got {other:?}"),
    }
}

/// Mixing one valid and one malformed detector must NOT return the valid one:
/// a partial corpus silently drops recall, so the loader fails closed on the
/// whole set (`failed_count = 1`, `total = 2`).
#[test]
fn dir_mixing_valid_and_malformed_fails_closed_not_partial() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_toml(dir.path(), "good.toml", VALID_DETECTOR_TOML);
    write_toml(dir.path(), "bad.toml", "not = valid = toml = at = all");

    let err = load_detectors(dir.path())
        .expect_err("a partial corpus must be rejected wholesale, never returned partial");
    match &err {
        SpecError::DetectorCorpusRejected {
            failed_count,
            total,
            ..
        } => {
            assert_eq!(*failed_count, 1, "one of two files failed");
            assert_eq!(*total, 2, "both .toml files count toward total");
        }
        other => panic!("expected DetectorCorpusRejected, got {other:?}"),
    }
}

/// An empty directory (no `*.toml`) is rejected, not treated as a valid
/// zero-detector corpus. `failed_count` and `total` are both 0 and the message
/// tells the operator to add a detector.
#[test]
fn empty_dir_is_rejected_with_zero_counts() {
    let dir = tempfile::tempdir().expect("tempdir");

    let err = load_detectors(dir.path()).expect_err("empty dir is not a valid empty corpus");
    match &err {
        SpecError::DetectorCorpusRejected {
            failed_count,
            total,
            detail,
            ..
        } => {
            assert_eq!(*failed_count, 0);
            assert_eq!(*total, 0);
            assert!(
                detail.contains("no detector TOML files found"),
                "empty-dir detail must explain the cause; got: {detail}"
            );
        }
        other => panic!("expected DetectorCorpusRejected, got {other:?}"),
    }
    assert!(
        err.to_string().contains("refusing to scan"),
        "empty-corpus error must state it refuses to scan; got: {err}"
    );
}

/// The quality gate is fail-closed when enforced: a detector with zero patterns
/// (`patterns = []`) is rejected under `enforce_gate = true` naming the cause,
/// but the same directory loads it under `enforce_gate = false` (the explicit
/// gate-off path) — proving the gate is what does the rejecting, not the parse.
#[test]
fn patternless_detector_is_gate_rejected_but_loads_gate_off() {
    let patternless = r#"
[detector]
id = "empty"
name = "Empty"
service = "x"
severity = "low"
keywords = ["x"]
patterns = []
"#;
    let dir = tempfile::tempdir().expect("tempdir");
    write_toml(dir.path(), "empty.toml", patternless);

    // enforce_gate = true → rejected, cause named.
    let err = with_gate(dir.path(), true).expect_err("patternless detector must be gate-rejected");
    match &err {
        SpecError::DetectorCorpusRejected {
            failed_count,
            detail,
            ..
        } => {
            assert_eq!(*failed_count, 1);
            assert!(
                detail.contains("no patterns defined"),
                "gate rejection must name the quality error; got: {detail}"
            );
        }
        other => panic!("expected DetectorCorpusRejected, got {other:?}"),
    }

    // enforce_gate = false → the same spec loads (gate is the only difference).
    let specs = with_gate(dir.path(), false).expect("gate-off load must succeed");
    assert_eq!(specs.len(), 1, "gate-off keeps the patternless detector");
    assert_eq!(specs[0].id, "empty");
    assert!(specs[0].patterns.is_empty());
}

// ─── operator-facing error rendering contracts ───────────────────────────────

/// `EmbeddedCorpusCorrupt` cannot be produced from a healthy build, so its
/// Display contract is asserted on a constructed value: it must name every
/// offender, report "X of Y", frame the failure as a compile-time build bug
/// with silently-degraded recall, and tell the operator to rebuild.
#[test]
fn embedded_corpus_corrupt_error_renders_full_contract() {
    let err = SpecError::EmbeddedCorpusCorrupt {
        failed_count: 3,
        total: 916,
        detail: "  - discord-bot-token: invalid char class\n  - foo: trailing comma\n  - bar: eof"
            .to_string(),
    };
    let r = err.to_string();

    assert!(
        r.contains("discord-bot-token: invalid char class"),
        "must name each offender; got: {r}"
    );
    assert!(r.contains("3 of 916"), "must report X of Y; got: {r}");
    assert!(
        r.contains("silently degraded"),
        "must call out the silent recall loss (Law 10); got: {r}"
    );
    assert!(
        r.contains("build/source bug") && r.contains("rebuild keyhog"),
        "must frame this as a build bug fixed by rebuilding; got: {r}"
    );
}

/// `DetectorCorpusRejected` Display must name the directory, explain it is a
/// partial-corpus refusal (silent recall drop), and give the fix.
#[test]
fn detector_corpus_rejected_error_renders_dir_and_fix() {
    let err = SpecError::DetectorCorpusRejected {
        dir: "/etc/keyhog/detectors".to_string(),
        failed_count: 2,
        total: 5,
        detail: "  - a.toml: bad\n  - b.toml: bad".to_string(),
    };
    let r = err.to_string();

    assert!(
        r.contains("/etc/keyhog/detectors"),
        "must name the rejected directory; got: {r}"
    );
    assert!(r.contains("2 of 5"), "must report X of Y; got: {r}");
    assert!(
        r.contains("refusing to scan") && r.contains("partial"),
        "must explain the partial-corpus refusal; got: {r}"
    );
    assert!(
        r.contains("Fix:"),
        "must include an actionable fix; got: {r}"
    );
}
