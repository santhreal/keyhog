//! Regression: embedded detector-registry integrity + phantom-const audit.
//!
//! These tests pin the compiled-in detector corpus to CONCRETE expected values
//! through the public `keyhog_core` loaders (`load_embedded_detectors_or_fail`,
//! `embedded_detector_count`, `detector_digest`). They also prove that the two
//! detector-id constants an over-eager dead-code lint flags — `GENERIC_PASSWORD`
//! and `GENERIC_DATABASE_URL` in `crates/scanner/src/detector_ids.rs` — are NOT
//! phantom: `generic-password` backs a real embedded detector AND a real
//! entropy-floor family, and `generic-database-url` backs a real entropy-floor
//! family (and is reserved as the canonical literal owner). Removing either
//! const would orphan `rules/entropy-floors.toml` families and break the
//! `detector_id_owner` gate, so the consts are deliberately retained.

use std::collections::HashMap;
use std::path::PathBuf;

use keyhog_core::{
    detector_digest, embedded_detector_count, load_embedded_detectors_or_fail, DetectorSpec,
    Severity,
};

/// EXACT number of detector TOMLs embedded at build time. This equals the count
/// of `detectors/*.toml` files (build.rs embeds every `.toml`, one detector per
/// file). Assert the concrete value — a silent drift means the shipped binary
/// scans with a different rule set than the tree claims.
const EXPECTED_EMBEDDED_DETECTOR_COUNT: usize = 916;

fn load_specs() -> Vec<DetectorSpec> {
    load_embedded_detectors_or_fail().expect("embedded detector corpus must load fail-closed")
}

fn spec_by_id<'a>(specs: &'a [DetectorSpec], id: &str) -> &'a DetectorSpec {
    specs
        .iter()
        .find(|d| d.id == id)
        .unwrap_or_else(|| panic!("embedded corpus must contain detector id `{id}`"))
}

/// Repo-root path for `rules/entropy-floors.toml` (CARGO_MANIFEST_DIR is
/// `crates/scanner`, so go up two levels).
fn entropy_floors_toml_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("rules")
        .join("entropy-floors.toml")
}

#[test]
fn embedded_detector_count_is_exactly_916() {
    assert_eq!(
        embedded_detector_count(),
        EXPECTED_EMBEDDED_DETECTOR_COUNT,
        "embedded_detector_count() must equal the pinned corpus size"
    );
}

#[test]
fn loaded_spec_len_equals_reported_count_and_pinned_value() {
    let specs = load_specs();
    assert_eq!(
        specs.len(),
        EXPECTED_EMBEDDED_DETECTOR_COUNT,
        "parsed embedded spec count must equal the pinned corpus size"
    );
    assert_eq!(
        specs.len(),
        embedded_detector_count(),
        "parsed spec count must equal the count-helper (each embedded TOML is one detector)"
    );
}

#[test]
fn every_embedded_detector_id_is_unique() {
    let specs = load_specs();
    let mut seen: HashMap<&str, usize> = HashMap::with_capacity(specs.len());
    for spec in &specs {
        *seen.entry(spec.id.as_str()).or_insert(0) += 1;
    }
    let dups: Vec<(&str, usize)> = seen
        .iter()
        .filter(|(_, &n)| n > 1)
        .map(|(&id, &n)| (id, n))
        .collect();
    assert!(
        dups.is_empty(),
        "embedded detector ids must be unique; duplicates found: {dups:?}"
    );
    assert_eq!(
        seen.len(),
        EXPECTED_EMBEDDED_DETECTOR_COUNT,
        "distinct id count must equal the corpus size (no id collisions)"
    );
}

#[test]
fn no_embedded_detector_id_is_empty() {
    let specs = load_specs();
    let empty_count = specs.iter().filter(|d| d.id.is_empty()).count();
    assert_eq!(
        empty_count, 0,
        "no embedded detector may have an empty-string id"
    );
}

#[test]
fn every_embedded_id_is_lowercase_kebab_ascii_no_whitespace() {
    let specs = load_specs();
    let offenders: Vec<&str> = specs
        .iter()
        .map(|d| d.id.as_str())
        .filter(|id| {
            *id != id.trim()
                || !id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        .collect();
    assert_eq!(
        offenders,
        Vec::<&str>::new(),
        "every detector id must be trimmed, lowercase ascii kebab (`[a-z0-9-]`)"
    );
}

#[test]
fn aws_access_key_detector_present_with_exact_fields() {
    let specs = load_specs();
    let aws = spec_by_id(&specs, "aws-access-key");

    assert_eq!(aws.name, "AWS Access Key");
    assert_eq!(aws.service, "aws");
    assert_eq!(aws.severity, Severity::Critical);
    assert_eq!(aws.keywords, vec!["AKIA".to_string(), "ASIA".to_string()]);
    assert_eq!(
        aws.patterns.len(),
        1,
        "aws-access-key has exactly one pattern"
    );
    assert_eq!(
        aws.patterns[0].description.as_deref(),
        Some("AWS access key ID")
    );
    assert_eq!(
        aws.companions.len(),
        2,
        "aws-access-key declares secret_key + session_token companions"
    );
    assert_eq!(aws.companions[0].name, "secret_key");
    assert_eq!(aws.companions[0].within_lines, 5);
    assert_eq!(aws.companions[1].name, "session_token");
    assert_eq!(aws.companions[1].within_lines, 5);
    assert!(
        aws.verify.is_some(),
        "aws-access-key ships an STS GetCallerIdentity verify block"
    );
    assert_eq!(
        aws.min_confidence, None,
        "aws-access-key uses the global confidence floor"
    );
}

#[test]
fn near_miss_aws_id_is_absent_but_canonical_id_present() {
    let specs = load_specs();
    // The canonical id is `aws-access-key`, NOT the plausible-looking
    // `aws-access-key-id` typo. Assert the exact boundary.
    assert!(
        specs.iter().any(|d| d.id == "aws-access-key"),
        "canonical id `aws-access-key` must exist"
    );
    assert!(
        !specs.iter().any(|d| d.id == "aws-access-key-id"),
        "the near-miss id `aws-access-key-id` must NOT exist"
    );
}

#[test]
fn generic_password_is_a_real_embedded_detector_not_phantom() {
    // Proves GENERIC_PASSWORD ("generic-password") in detector_ids.rs backs a
    // real embedded detector — it is NOT dead code.
    let specs = load_specs();
    let gp = spec_by_id(&specs, "generic-password");
    assert_eq!(gp.name, "Generic Password");
    assert_eq!(gp.service, "generic");
    assert_eq!(gp.severity, Severity::Medium);
    assert_eq!(
        gp.patterns.len(),
        5,
        "generic-password ships five assignment/connection/JSON patterns"
    );
    assert_eq!(
        gp.keywords.first().map(String::as_str),
        Some("password"),
        "generic-password's first prefilter keyword is `password`"
    );
    assert!(
        gp.verify.is_none(),
        "generic-password has no verify endpoint (service unknown)"
    );
}

#[test]
fn generic_database_url_has_no_embedded_detector_but_owns_an_entropy_family() {
    // GENERIC_DATABASE_URL ("generic-database-url") has no detector TOML, yet it
    // owns a real entropy-floor family and is the canonical literal owner — so
    // the const is NOT dead. Pin both facts.
    let specs = load_specs();
    assert!(
        !specs.iter().any(|d| d.id == "generic-database-url"),
        "generic-database-url is a data/entropy-floor id, not an embedded detector"
    );

    let floors = std::fs::read_to_string(entropy_floors_toml_path())
        .expect("rules/entropy-floors.toml must be readable");
    assert!(
        floors.contains("detector = \"generic-database-url\""),
        "entropy-floors.toml must own a generic-database-url family (const is live data)"
    );
    assert!(
        floors.contains("detector = \"generic-password\""),
        "entropy-floors.toml must own a generic-password family"
    );
    // Exactly five per-family entropy floors ship today.
    let family_rows = floors.matches("detector = ").count();
    assert_eq!(
        family_rows, 5,
        "entropy-floors.toml declares exactly five per-family floors"
    );
}

#[test]
fn github_classic_pat_present_with_exact_fields() {
    let specs = load_specs();
    let gh = spec_by_id(&specs, "github-classic-pat");
    assert_eq!(gh.name, "GitHub Classic PAT");
    assert_eq!(gh.service, "github");
    assert_eq!(gh.severity, Severity::Critical);
}

#[test]
fn stripe_secret_key_present_with_exact_fields() {
    let specs = load_specs();
    let stripe = spec_by_id(&specs, "stripe-secret-key");
    assert_eq!(stripe.name, "Stripe Secret Key");
    assert_eq!(stripe.service, "stripe");
    assert_eq!(stripe.severity, Severity::Critical);
}

#[test]
fn private_key_detector_present_with_exact_fields() {
    let specs = load_specs();
    let pk = spec_by_id(&specs, "private-key");
    assert_eq!(pk.name, "Private Key (PEM)");
    assert_eq!(pk.service, "crypto");
    assert_eq!(pk.severity, Severity::Critical);
}

#[test]
fn detector_digest_count_prefix_matches_embedded_count() {
    // detector_digest() is `"{count}-{fnv1a:016x}"`. The numeric prefix must
    // equal the live embedded count, and the suffix must be 16 lowercase hex.
    let digest = detector_digest();
    let (prefix, suffix) = digest
        .split_once('-')
        .unwrap_or_else(|| panic!("detector_digest `{digest}` must be `<count>-<hex>`"));
    let parsed: usize = prefix
        .parse()
        .unwrap_or_else(|e| panic!("digest count prefix `{prefix}` must be a usize: {e}"));
    assert_eq!(
        parsed,
        embedded_detector_count(),
        "digest count prefix must equal embedded_detector_count()"
    );
    assert_eq!(parsed, EXPECTED_EMBEDDED_DETECTOR_COUNT);
    assert_eq!(suffix.len(), 16, "digest hash suffix is 16 hex chars");
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "digest hash suffix `{suffix}` must be lowercase hex"
    );
}

#[test]
fn every_embedded_severity_is_a_known_enum_variant() {
    let specs = load_specs();
    const KNOWN: [Severity; 6] = [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let unknown = specs
        .iter()
        .filter(|d| !KNOWN.contains(&d.severity))
        .count();
    assert_eq!(unknown, 0, "every detector severity must be a known tier");
    // Concrete anchor: at least the aws critical detector contributes to the
    // Critical bucket, so the corpus is non-degenerate.
    let critical = specs
        .iter()
        .filter(|d| d.severity == Severity::Critical)
        .count();
    assert!(
        critical >= 1,
        "corpus must contain at least one Critical detector (e.g. aws-access-key)"
    );
    assert_eq!(
        spec_by_id(&specs, "aws-access-key").severity,
        Severity::Critical
    );
}

#[test]
fn every_embedded_detector_has_a_nonempty_service_and_name() {
    let specs = load_specs();
    let bad: Vec<&str> = specs
        .iter()
        .filter(|d| d.service.trim().is_empty() || d.name.trim().is_empty())
        .map(|d| d.id.as_str())
        .collect();
    assert_eq!(
        bad,
        Vec::<&str>::new(),
        "every embedded detector must declare a non-empty service and name"
    );
}
