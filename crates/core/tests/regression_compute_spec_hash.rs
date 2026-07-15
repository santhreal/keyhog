//! Regression: pin the field-coverage and structural semantics of
//! `compute_spec_hash`, the single BLAKE3 digest the incremental merkle cache
//! stores to prove the detector corpus is unchanged before it trusts a
//! "skip this file" decision.
//!
//! This file is DELIBERATELY distinct from `regression_merkle_spec_hash.rs`.
//! That file pins the digest's role in the cold-start load contract (schema /
//! parse / spec-change cold starts). This file pins, field by field, WHICH
//! detector attributes participate in the digest, and, crucially, exercises
//! adversarial shapes (delimiter injection, cross-detector field swaps,
//! duplicate entries) that a single-detector single-field test cannot reach.
//!
//! TEST-TRUTH: every assertion is an EXACT 32-byte digest equality/inequality
//! (or an exact byte reconstruction against a hand-fed `blake3::Hasher`), never
//! a shape check.
//!
//! Two tests below (`bug_*`) encode CONFIRMED digest-collision defects: a field
//! that changes real scan OUTPUT (per-detector severity, and a pattern's
//! `client_safe` downgrade flag) does NOT enter the digest, so the merkle cache
//! would silently keep a stale skip (Law 10). They assert the CORRECT behaviour
//! (the digest MUST change) and therefore fail until the source binds those
//! fields into the hash. That is the intended encoding of a dogfood finding.

use keyhog_core::compute_spec_hash;
use keyhog_core::{
    CanonicalHexKeyMaterialSpec, CompanionSpec, CredentialShape, DetectorKind, DetectorSpec,
    EntropyFallbackMetadata, EntropyFloorBucket, EntropyShapeSpec, PatternSpec, Severity,
    VerifySpec,
};

/// Fully-populated single-pattern detector. `name`/`service` are set equal to
/// `id` so a test that changes only `name` keeps `id` (and thus every hashed
/// key) fixed.
fn det(id: &str, severity: Severity, regex: &str, keywords: &[&str]) -> DetectorSpec {
    DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: id.to_string(),
        name: id.to_string(),
        service: id.to_string(),
        severity,
        keywords: keywords.iter().map(|k| k.to_string()).collect(),
        min_confidence: None,
        patterns: vec![PatternSpec {
            regex: regex.to_string(),
            ..Default::default()
        }],
        companions: vec![],
        verify: None,
        // Default any newer optional spec fields so this exhaustive literal does
        // not break each time DetectorSpec grows a field (explicit fields win).
        ..Default::default()
    }
}

fn companion(name: &str, regex: &str, within_lines: usize, required: bool) -> CompanionSpec {
    CompanionSpec {
        name: name.to_string(),
        regex: regex.to_string(),
        within_lines,
        required,
    }
}

// ── exact byte reconstruction ───────────────────────────────────────────────

#[test]
fn spec_hash_of_bare_detector_matches_hand_fed_blake3() {
    // A detector with NO patterns, keywords, or companions contributes exactly
    // three keys: `id:x`, `service:x:x`, and `sev:x:High` (the severity and
    // service keys are bound to the detector id so swaps between detectors are
    // not hash collisions). They are sorted and each is terminated with a
    // newline. Reconstruct the exact pre-image so an accidental salt byte,
    // separator change, or reordering is caught.
    let bare = DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "x".to_string(),
        name: "x".to_string(),
        service: "x".to_string(),
        severity: Severity::High,
        keywords: Vec::new(),
        min_confidence: None,
        patterns: Vec::new(),
        companions: Vec::new(),
        verify: None,
        ..Default::default()
    };
    let got = compute_spec_hash(std::slice::from_ref(&bare));
    let expect = *blake3::hash(b"id:x\nservice:x:x\nsev:x:High\n").as_bytes();
    assert_eq!(
        got, expect,
        "bare detector must hash BLAKE3(\"id:x\\nservice:x:x\\nsev:x:High\\n\") exactly"
    );
}

#[test]
fn spec_hash_is_stable_across_many_independent_rebuilds() {
    let first = compute_spec_hash(std::slice::from_ref(&det(
        "svc",
        Severity::Medium,
        "sk_[0-9a-f]{32}",
        &["sk", "secret"],
    )));
    for _ in 0..5 {
        let again = compute_spec_hash(std::slice::from_ref(&det(
            "svc",
            Severity::Medium,
            "sk_[0-9a-f]{32}",
            &["sk", "secret"],
        )));
        assert_eq!(
            first, again,
            "an independently rebuilt but identical detector must hash identically"
        );
    }
}

// ── keyword-set identity ────────────────────────────────────────────────────

#[test]
fn spec_hash_differs_for_distinct_keyword_sets() {
    let a = det("d", Severity::High, "[A-Z]{16}", &["alpha"]);
    let b = det("d", Severity::High, "[A-Z]{16}", &["bravo"]);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&a)),
        compute_spec_hash(std::slice::from_ref(&b)),
        "detectors with distinct keyword sets must hash differently"
    );
}

#[test]
fn spec_hash_binds_each_keyword_to_its_detector_id() {
    // The SAME keyword string assigned to a different detector must change the
    // digest, because keyword keys are prefixed `kw:<id>:<kw>`. This is the
    // positive twin of `bug_spec_hash_must_change_when_severity_swapped` (which
    // proves severity is NOT so bound).
    let left = compute_spec_hash(&[
        det("a", Severity::High, "RA", &["shared"]),
        det("b", Severity::High, "RB", &[]),
    ]);
    let right = compute_spec_hash(&[
        det("a", Severity::High, "RA", &[]),
        det("b", Severity::High, "RB", &["shared"]),
    ]);
    assert_ne!(
        left, right,
        "moving a keyword to a different detector id must change the digest (kw is id-bound)"
    );
}

// ── ordering / duplication structure ────────────────────────────────────────

#[test]
fn spec_hash_is_invariant_under_detector_permutation() {
    let a = det("alpha", Severity::High, "A[0-9]{10}", &["a"]);
    let b = det("beta", Severity::Low, "B[0-9]{10}", &["b"]);
    let c = det("gamma", Severity::Medium, "C[0-9]{10}", &["c"]);
    let order1 = compute_spec_hash(&[a.clone(), b.clone(), c.clone()]);
    let order2 = compute_spec_hash(&[c, a, b]);
    assert_eq!(
        order1, order2,
        "the global key sort makes detector slice order irrelevant"
    );
}

#[test]
fn spec_hash_duplicate_detector_entry_changes_digest() {
    // Keys are sorted but NOT de-duplicated, so a corpus that lists the same
    // detector twice feeds every key twice and must differ from the singleton.
    let d = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    let single = compute_spec_hash(std::slice::from_ref(&d));
    let doubled = compute_spec_hash(&[d.clone(), d.clone()]);
    assert_ne!(
        single, doubled,
        "a duplicated detector entry doubles the key material and must change the digest"
    );
}

// ── pattern capture-group coverage ──────────────────────────────────────────

#[test]
fn spec_hash_pattern_group_none_versus_some_zero_differ() {
    let none_group = det("d", Severity::High, "(x)(y)", &["k"]);
    let mut some_group = none_group.clone();
    some_group.patterns[0].group = Some(0);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&none_group)),
        compute_spec_hash(std::slice::from_ref(&some_group)),
        "an explicit capture group index must change the digest vs. no group"
    );
}

#[test]
fn spec_hash_pattern_group_indices_differ() {
    let mut g1 = det("d", Severity::High, "(x)(y)", &["k"]);
    g1.patterns[0].group = Some(1);
    let mut g2 = g1.clone();
    g2.patterns[0].group = Some(2);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&g1)),
        compute_spec_hash(std::slice::from_ref(&g2)),
        "distinct capture-group indices must produce distinct digests"
    );
}

// ── companion field coverage ────────────────────────────────────────────────

#[test]
fn spec_hash_companion_within_lines_change_differs() {
    let mut near = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    near.companions
        .push(companion("secret", "s=([A-Z]+)", 2, true));
    let mut far = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    far.companions
        .push(companion("secret", "s=([A-Z]+)", 9, true));
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&near)),
        compute_spec_hash(std::slice::from_ref(&far)),
        "a companion's within_lines window is hashed; changing it must change the digest"
    );
}

#[test]
fn spec_hash_companion_required_flag_differs() {
    let mut req = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    req.companions
        .push(companion("secret", "s=([A-Z]+)", 3, true));
    let mut opt = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    opt.companions
        .push(companion("secret", "s=([A-Z]+)", 3, false));
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&req)),
        compute_spec_hash(std::slice::from_ref(&opt)),
        "flipping a companion's required flag must change the digest"
    );
}

#[test]
fn spec_hash_companion_name_and_regex_changes_differ() {
    let mut base = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    base.companions
        .push(companion("secret", "s=([A-Z]+)", 3, true));

    let mut renamed = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    renamed
        .companions
        .push(companion("token", "s=([A-Z]+)", 3, true));

    let mut reregexed = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    reregexed
        .companions
        .push(companion("secret", "t=([a-z]+)", 3, true));

    let base_h = compute_spec_hash(std::slice::from_ref(&base));
    assert_ne!(
        base_h,
        compute_spec_hash(std::slice::from_ref(&renamed)),
        "renaming a companion must change the digest"
    );
    assert_ne!(
        base_h,
        compute_spec_hash(std::slice::from_ref(&reregexed)),
        "changing a companion regex must change the digest"
    );
}

// ── adversarial: delimiter injection must not forge a collision ──────────────

#[test]
fn spec_hash_delimiter_injection_does_not_collide() {
    // The keyword key is `kw:<id>:<kw>`. Detector id "a" with keyword "b:c" and
    // detector id "a:b" with keyword "c" both emit the byte-identical keyword
    // key `kw:a:b:c`. If the digest depended on keyword keys alone this would be
    // a forged collision. It must NOT collide: the `id:` and `p:` keys still
    // carry the true id boundary (`id:a` vs `id:a:b`, `p:a:...` vs `p:a:b:...`).
    let x = compute_spec_hash(std::slice::from_ref(&det(
        "a",
        Severity::High,
        "R",
        &["b:c"],
    )));
    let y = compute_spec_hash(std::slice::from_ref(&det(
        "a:b",
        Severity::High,
        "R",
        &["c"],
    )));
    assert_ne!(
        x, y,
        "a colliding kw key must not forge a full-digest collision (id/pattern keys disambiguate)"
    );
}

// ── negative: cosmetic fields must not thrash the cache ──────────────────────

#[test]
fn spec_hash_ignores_cosmetic_name_field() {
    // `name` does not affect what is detected, so it is intentionally NOT hashed:
    // renaming a detector must NOT invalidate the merkle cache (no spurious full
    // re-scan). `id` (which IS hashed) is held fixed.
    let mut a = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    a.name = "friendly-name-one".to_string();
    let mut b = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    b.name = "friendly-name-two".to_string();
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&a)),
        compute_spec_hash(std::slice::from_ref(&b)),
        "the display-only name field must not enter the digest (no cache thrash on rename)"
    );
}

// ── positive contrast: a single detector's severity IS load-bearing ──────────

#[test]
fn spec_hash_single_detector_severity_change_differs() {
    // With one detector the severity-key MULTISET changes ({sev:High} -> {sev:Critical}),
    // so the digest changes. This is the case the swap test below defeats.
    let high = det("d", Severity::High, "[A-Z]{16}", &["k"]);
    let critical = det("d", Severity::Critical, "[A-Z]{16}", &["k"]);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&high)),
        compute_spec_hash(std::slice::from_ref(&critical)),
        "changing a lone detector's severity must change the digest"
    );
}

// ── CONFIRMED BUGS (encoded as failing regressions) ─────────────────────────

#[test]
fn bug_spec_hash_must_change_when_two_detectors_swap_severity() {
    // CONFIRMED DEFECT: `compute_spec_hash` emits the severity key as
    // `format!("sev:{:?}", d.severity)`: WITHOUT the detector id. So for two
    // detectors A(High) and B(Low), the key multiset contains {sev:High, sev:Low}
    // regardless of WHICH detector owns which severity. Swapping the two
    // severities (A->Low, B->High) yields the identical sorted key stream and
    // therefore the identical digest. The merkle cache would keep a stale skip
    // even though every finding's severity, and severity-threshold suppression
    // just changed (Law 10 silent staleness). Correct behaviour: the digest MUST
    // change. Fix: bind severity to id, e.g. `format!("sev:{}:{:?}", d.id, ..)`.
    let original = compute_spec_hash(&[
        det("a", Severity::High, "RA", &["ka"]),
        det("b", Severity::Low, "RB", &["kb"]),
    ]);
    let swapped = compute_spec_hash(&[
        det("a", Severity::Low, "RA", &["ka"]),
        det("b", Severity::High, "RB", &["kb"]),
    ]);
    assert_ne!(
        original, swapped,
        "swapping severities between two detectors changes scan output and MUST change the digest"
    );
}

#[test]
fn bug_spec_hash_must_change_when_pattern_client_safe_toggled() {
    // CONFIRMED DEFECT: the pattern key is `format!("p:{}:{}|g:{}", id, regex, group)`
    // and omits `PatternSpec.client_safe`. Toggling `client_safe` downgrades every
    // match of that pattern to `Severity::ClientSafe` (and it is gated behind
    // `--hide-client-safe`), which materially changes reported output, yet the
    // digest is unchanged, so the merkle cache keeps a stale skip (Law 10).
    // Correct behaviour: the digest MUST change. Fix: fold `client_safe` (and the
    // other output-affecting pattern fields) into the pattern key.
    let base = det("d", Severity::High, "pk_live_[0-9A-Za-z]{24}", &["pk_live"]);
    let mut toggled = base.clone();
    toggled.patterns[0].client_safe = true;
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&toggled)),
        "toggling a pattern's client_safe downgrade flag changes output and MUST change the digest"
    );
}

#[test]
fn spec_hash_binds_pattern_order_within_a_detector() {
    let mut original = knob_base();
    original.patterns.push(PatternSpec {
        regex: "second-[A-Z0-9]{8}".to_string(),
        group: Some(0),
        ..Default::default()
    });
    let mut reordered = original.clone();
    reordered.patterns.swap(0, 1);

    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&original)),
        compute_spec_hash(std::slice::from_ref(&reordered)),
        "pattern order controls compiled pattern indices and must invalidate cached scan state"
    );
}

#[test]
fn spec_hash_binds_companion_order_within_a_detector() {
    let mut original = knob_base();
    original.companions = vec![
        CompanionSpec {
            name: "first".to_string(),
            regex: "first=([A-Z0-9]{8})".to_string(),
            within_lines: 1,
            required: true,
        },
        CompanionSpec {
            name: "second".to_string(),
            regex: "second=([A-Z0-9]{8})".to_string(),
            within_lines: 2,
            required: false,
        },
    ];
    let mut reordered = original.clone();
    reordered.companions.swap(0, 1);

    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&original)),
        compute_spec_hash(std::slice::from_ref(&reordered)),
        "companion order controls compiled companion indices and must invalidate cached scan state"
    );
}

// ── migration-knob field coverage (2026-07-07 per-detector recall/precision) ──
// Every per-detector knob added in the 2026-07-07 migration (`kind`,
// `min_confidence`, `entropy_floor`, the four entropy thresholds,
// BPE and decoded-hex policy, `keyword_free_min_len`, `min_len`, `max_len`, the
// allowlists/stopwords, the three classification flags, `credential_shape`)
// OVERRIDES a scan-match/suppress
// decision, so changing it changes WHICH findings a scan emits. Each MUST enter
// the digest (Law 10: else the merkle cache keeps a stale skip). Each test flips
// exactly ONE knob from its default and asserts an EXACT digest inequality; the
// companion tests pin the non-collision, order, and cache-thrash boundaries.

/// A generic-shaped base detector whose every migration knob is at its default,
/// so flipping one knob is the sole difference under test.
fn knob_base() -> DetectorSpec {
    det("gd", Severity::High, "[A-Za-z0-9]{20}", &["k"])
}

macro_rules! knob_changes_digest {
    ($name:ident, $mutate:expr) => {
        #[test]
        fn $name() {
            let base = knob_base();
            let mut changed = base.clone();
            let mutate: fn(&mut DetectorSpec) = $mutate;
            mutate(&mut changed);
            assert_ne!(
                compute_spec_hash(std::slice::from_ref(&base)),
                compute_spec_hash(std::slice::from_ref(&changed)),
                concat!(
                    stringify!($name),
                    ": a non-default knob changes scan output and MUST change the digest"
                )
            );
        }
    };
}

knob_changes_digest!(spec_hash_binds_kind, |d| d.kind =
    DetectorKind::Phase2Generic);
knob_changes_digest!(spec_hash_binds_min_confidence, |d| d.min_confidence =
    Some(0.42));
knob_changes_digest!(spec_hash_binds_entropy_floor, |d| d.entropy_floor =
    vec![EntropyFloorBucket {
        max_len: Some(24),
        floor: 3.0,
    }]);
knob_changes_digest!(spec_hash_binds_entropy_high, |d| d.entropy_high = Some(4.5));
knob_changes_digest!(spec_hash_binds_entropy_low, |d| d.entropy_low = Some(3.1));
knob_changes_digest!(spec_hash_binds_entropy_very_high, |d| d.entropy_very_high =
    Some(5.2));
knob_changes_digest!(spec_hash_binds_sensitive_path_entropy_very_high, |d| d
    .sensitive_path_entropy_very_high =
    Some(5.2));
knob_changes_digest!(spec_hash_binds_entropy_fallback_metadata, |d| d
    .entropy_fallback =
    Some(EntropyFallbackMetadata {
        id: "entropy-custom".into(),
        name: "Custom entropy".into(),
        service: "generic".into(),
    }));
knob_changes_digest!(spec_hash_binds_entropy_shapes, |d| d.entropy_shapes =
    vec![EntropyShapeSpec::LowerDashAppPassword {
        entropy_floor: 3.9,
        group_count: 4,
        group_length: 4,
        special_min_length: 16,
    }]);
knob_changes_digest!(spec_hash_binds_mixed_alnum_floor, |d| d.mixed_alnum_floor =
    Some(3.7));
knob_changes_digest!(spec_hash_binds_entropy_policy_priority, |d| d
    .entropy_policy_priority =
    Some(80));
knob_changes_digest!(spec_hash_binds_bpe_max_bytes_per_token, |d| d
    .bpe_max_bytes_per_token =
    Some(2.4));
knob_changes_digest!(spec_hash_binds_bpe_enabled, |d| d.bpe_enabled = Some(false));
knob_changes_digest!(spec_hash_binds_decoded_hex_key_material_lengths, |d| d
    .decoded_hex_key_material_lengths =
    vec![32, 48]);
knob_changes_digest!(spec_hash_binds_canonical_hex_key_material, |d| d
    .canonical_hex_key_material =
    vec![CanonicalHexKeyMaterialSpec {
        lengths: vec![64],
        keywords: vec!["k".into()],
    }]);
knob_changes_digest!(spec_hash_binds_keyword_free_min_len, |d| d
    .keyword_free_min_len =
    Some(32));
knob_changes_digest!(spec_hash_binds_min_len, |d| d.min_len = Some(16));
#[test]
fn spec_hash_binds_max_len() {
    let mut base = knob_base();
    base.kind = DetectorKind::Phase2Generic;
    let mut changed = base.clone();
    changed.max_len = Some(256);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&changed)),
        "phase-2 max_len changes scan output and must change the digest"
    );
}
knob_changes_digest!(spec_hash_binds_allowlist_paths, |d| d.allowlist_paths =
    vec!["(?i)/test/".to_string()]);
knob_changes_digest!(spec_hash_binds_allowlist_values, |d| d.allowlist_values =
    vec!["EXAMPLE".to_string()]);
knob_changes_digest!(spec_hash_binds_stopwords, |d| d.stopwords =
    vec!["password".to_string()]);
knob_changes_digest!(spec_hash_binds_structural_password_slot, |d| d
    .structural_password_slot =
    true);
knob_changes_digest!(spec_hash_binds_weak_anchor, |d| d.weak_anchor = true);
knob_changes_digest!(spec_hash_binds_private_key_block, |d| d.private_key_block =
    true);
knob_changes_digest!(spec_hash_binds_credential_shape, |d| d.credential_shape =
    Some(CredentialShape {
        exact_length: Some(20),
        ..Default::default()
    }));

#[test]
fn spec_hash_distinguishes_entropy_thresholds_from_one_another() {
    // The SAME f64 assigned to DIFFERENT threshold fields must NOT collide: each
    // field carries a distinct key prefix (`eh:`/`el:`/`evh:`/`maf:`), so the
    // digest reflects which gate the operator actually moved.
    let mut high = knob_base();
    high.entropy_high = Some(4.0);
    let mut low = knob_base();
    low.entropy_low = Some(4.0);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&high)),
        compute_spec_hash(std::slice::from_ref(&low)),
        "the same value on entropy_high vs entropy_low must not collide"
    );
}

#[test]
fn spec_hash_entropy_floor_bucket_order_is_load_bearing() {
    // Buckets are consulted in listed order (first `max_len >= L` wins), so a
    // reordered floor table is a DIFFERENT gate and must change the digest.
    let mut a = knob_base();
    a.entropy_floor = vec![
        EntropyFloorBucket {
            max_len: Some(24),
            floor: 3.0,
        },
        EntropyFloorBucket {
            max_len: None,
            floor: 3.5,
        },
    ];
    let mut b = knob_base();
    b.entropy_floor = vec![
        EntropyFloorBucket {
            max_len: None,
            floor: 3.5,
        },
        EntropyFloorBucket {
            max_len: Some(24),
            floor: 3.0,
        },
    ];
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&a)),
        compute_spec_hash(std::slice::from_ref(&b)),
        "entropy_floor bucket order is semantic and must change the digest"
    );
}

#[test]
fn spec_hash_allowlist_order_is_not_load_bearing() {
    // Allowlist entries are OR-any membership: a mere reorder is the SAME gate and
    // must NOT thrash the cache (they are sorted before hashing).
    let mut a = knob_base();
    a.allowlist_values = vec!["AAA".to_string(), "BBB".to_string()];
    let mut b = knob_base();
    b.allowlist_values = vec!["BBB".to_string(), "AAA".to_string()];
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&a)),
        compute_spec_hash(std::slice::from_ref(&b)),
        "reordering an OR-any allowlist must not change the digest"
    );
}

#[test]
fn spec_hash_binds_each_knob_to_its_detector_id() {
    // A knob set on detector A vs the same knob set on detector B must differ:
    // every knob key is id-bound, mirroring `spec_hash_binds_each_keyword_to_its_
    // detector_id`. Uses `weak_anchor` as the representative id-bound flag.
    let left = compute_spec_hash(&[
        {
            let mut d = det("a", Severity::High, "RA", &[]);
            d.weak_anchor = true;
            d
        },
        det("b", Severity::High, "RB", &[]),
    ]);
    let right = compute_spec_hash(&[det("a", Severity::High, "RA", &[]), {
        let mut d = det("b", Severity::High, "RB", &[]);
        d.weak_anchor = true;
        d
    }]);
    assert_ne!(
        left, right,
        "moving a knob to a different detector id must change the digest (knobs are id-bound)"
    );
}

#[test]
fn spec_hash_binds_service_to_its_detector_id() {
    let base = knob_base();
    let mut changed = base.clone();
    changed.service = "generic".into();
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&changed)),
        "service changes generic keyword ownership and must invalidate the digest"
    );
}

#[test]
fn spec_hash_ignores_live_verify_and_cosmetic_description() {
    // `verify` (live-verification config) changes a finding's post-scan verdict,
    // not the scanned finding SET the merkle cache reuses; a pattern's
    // `description` is display-only. Like `name`, neither may thrash the cache.
    let base = knob_base();
    let mut with_verify = knob_base();
    with_verify.verify = Some(VerifySpec {
        service: "example".to_string(),
        ..Default::default()
    });
    let mut with_desc = knob_base();
    with_desc.patterns[0].description = Some("a friendly description".to_string());
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&with_verify)),
        "live-verify config must not thrash the scan cache"
    );
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&with_desc)),
        "a pattern's cosmetic description must not thrash the scan cache"
    );
}

#[test]
fn spec_hash_bare_detector_preimage_survives_knob_migration() {
    // The all-default detector still emits no optional migration knobs. Its
    // non-empty service is material and therefore appears in the pre-image;
    // an empty service remains the compatibility case with no service key.
    let bare = DetectorSpec {
        id: "x".to_string(),
        name: "x".to_string(),
        service: "x".to_string(),
        severity: Severity::High,
        ..Default::default()
    };
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&bare)),
        *blake3::hash(b"id:x\nservice:x:x\nsev:x:High\n").as_bytes(),
        "a detector with service x must hash BLAKE3(\"id:x\\nservice:x:x\\nsev:x:High\\n\")"
    );
}
