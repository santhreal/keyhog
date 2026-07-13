//! Regression lock for the report-scope match dedup KEY `(detector_id,
//! credential)`.
//!
//! The scanner emits raw matches; the pipeline then collapses them to
//! operator-visible findings through `keyhog_core::dedup_matches`. Under
//! `DedupScope::Credential` the grouping key is exactly
//! `(detector_id, credential, None)` (see `core/src/dedup.rs`, `DedupKey`), so
//! this file pins the KEY axis specifically:
//!   * two matches sharing `(detector_id, credential)` collapse to ONE finding;
//!   * differing only in `credential` stays TWO (credential is in the key);
//!   * differing only in `detector_id` stays TWO (detector_id is in the key);
//!   * the survivor carries the max confidence and the lowest-offset primary;
//!   * `LocationIdentity` excludes offset, so same `(file,line)` collapses with
//!     zero additional locations while a distinct line becomes an additional;
//!   * output is deterministically sorted by `(detector_id, credential)`;
//!   * the key is BYTE-EXACT (credential and detector_id are case-sensitive).
//!
//! This is deliberately distinct from `regression_into_matches_dedup_order_
//! invariant.rs`, which locks the scanner-internal `ScanState::into_matches`
//! identity `(detector, credential, OFFSET)`. Here the key has NO offset.
//!
//! Scanner-crate test; imports only the `keyhog_core` dedup API (core is a
//! direct dependency of the scanner crate).

use keyhog_core::{
    dedup_matches, DedupScope, DedupedMatch, MatchLocation, RawMatch, SensitiveString, Severity,
};

/// Build a `RawMatch`. `credential_hash` is left zeroed on purpose: the
/// `DedupScope::Credential` key is `(detector_id, credential, None)`: the hash
/// plays NO role in the collapse decision, and `dedup_matches` recomputes the
/// effective hash from the credential bytes when it is zero.
fn rm(
    detector: &str,
    cred: &str,
    file: &str,
    line: usize,
    offset: usize,
    conf: f64,
    sev: Severity,
) -> RawMatch {
    RawMatch {
        detector_id: detector.into(),
        detector_name: detector.into(),
        service: "svc".into(),
        severity: sev,
        credential: SensitiveString::from(cred),
        credential_hash: [0u8; 32].into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some(file.into()),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(conf),
    }
}

/// High-severity convenience.
fn hi(detector: &str, cred: &str, file: &str, line: usize, offset: usize, conf: f64) -> RawMatch {
    rm(detector, cred, file, line, offset, conf, Severity::High)
}

/// The ordered `(detector_id, credential)` key list of a dedup result.
fn keys(v: &[DedupedMatch]) -> Vec<(String, String)> {
    v.iter()
        .map(|d| (d.detector_id.to_string(), d.credential.as_ref().to_string()))
        .collect()
}

// ── The three headline key contracts ─────────────────────────────────────────

#[test]
fn identical_detector_credential_collapse_to_one() {
    let a = hi("aws-access-key", "AKIAcredential01", "a.env", 1, 10, 0.80);
    let b = hi("aws-access-key", "AKIAcredential01", "a.env", 1, 10, 0.80);
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);

    assert_eq!(
        out.len(),
        1,
        "same (detector_id, credential) collapse to one"
    );
    assert_eq!(&*out[0].detector_id, "aws-access-key");
    assert_eq!(out[0].credential.as_ref(), "AKIAcredential01");
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "same (file,line) leaves zero additional locations"
    );
    assert_eq!(out[0].primary_location.offset, 10);
    assert_eq!(out[0].confidence, Some(0.80));
}

#[test]
fn different_credentials_same_detector_stay_two() {
    let a = hi("aws-access-key", "AKIAcredentialAA", "a.env", 1, 10, 0.80);
    let b = hi("aws-access-key", "AKIAcredentialBB", "a.env", 2, 40, 0.80);
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);

    assert_eq!(out.len(), 2, "credential is part of the key: no collapse");
    // Sorted by (detector_id, credential): AA before BB.
    assert_eq!(
        keys(&out),
        vec![
            ("aws-access-key".to_string(), "AKIAcredentialAA".to_string()),
            ("aws-access-key".to_string(), "AKIAcredentialBB".to_string()),
        ]
    );
}

#[test]
fn same_credential_different_detector_stay_two() {
    // Detector id IS part of the key, so one shared credential under two
    // detectors must remain two distinct findings from `dedup_matches` (the
    // separate `dedup_cross_detector` pass is what folds these (not this one)).
    let a = hi(
        "google-api-key",
        "AIzaSyShared0000000000000000000000000000",
        "a.env",
        1,
        10,
        0.80,
    );
    let b = hi(
        "google-maps-key",
        "AIzaSyShared0000000000000000000000000000",
        "a.env",
        1,
        10,
        0.80,
    );
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);

    assert_eq!(out.len(), 2, "detector_id is part of the key: no collapse");
    let ids: Vec<&str> = out.iter().map(|d| &*d.detector_id).collect();
    assert_eq!(
        ids,
        vec!["google-api-key", "google-maps-key"],
        "output sorted by detector_id ascending"
    );
}

// ── Survivor fields under collapse ───────────────────────────────────────────

#[test]
fn collapse_keeps_max_confidence() {
    let out = dedup_matches(
        vec![
            hi(
                "stripe-secret-key",
                "sk_live_dedupkey000",
                "a.env",
                1,
                10,
                0.30,
            ),
            hi(
                "stripe-secret-key",
                "sk_live_dedupkey000",
                "a.env",
                1,
                10,
                0.90,
            ),
            hi(
                "stripe-secret-key",
                "sk_live_dedupkey000",
                "a.env",
                1,
                10,
                0.55,
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].confidence,
        Some(0.90),
        "the collapsed finding carries the maximum confidence of the group"
    );
}

#[test]
fn collapse_lowest_offset_is_primary_distinct_line_is_additional() {
    // Same (detector, credential) at two distinct lines in one file: they
    // collapse to one finding whose primary is the LOWEST offset; the other line
    // (a distinct LocationIdentity) lands in additional_locations.
    let out = dedup_matches(
        vec![
            hi("gh-pat", "ghp_dedupkeytoken00", "a.env", 5, 400, 0.60),
            hi("gh-pat", "ghp_dedupkeytoken00", "a.env", 1, 10, 0.60),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1, "same key across two lines is one finding");
    assert_eq!(
        out[0].primary_location.offset, 10,
        "lowest offset becomes the primary location"
    );
    assert_eq!(out[0].primary_location.line, Some(1));
    assert_eq!(
        out[0].additional_locations.len(),
        1,
        "the distinct-line occurrence is one additional location"
    );
    assert_eq!(out[0].additional_locations[0].offset, 400);
    assert_eq!(out[0].additional_locations[0].line, Some(5));
}

#[test]
fn same_line_different_offset_collapses_with_zero_additional() {
    // LocationIdentity is (source, file_path, line, commit) (offset EXCLUDED).
    // So two hits on the same (file,line) at different offsets are one finding
    // with NO additional location (the synthetic-preprocessor alias case).
    let out = dedup_matches(
        vec![
            hi("gh-pat", "ghp_sameline0000000", "a.env", 1, 10, 0.60),
            hi("gh-pat", "ghp_sameline0000000", "a.env", 1, 27, 0.60),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].primary_location.offset, 10,
        "primary is lowest offset"
    );
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "offset is not part of LocationIdentity: no additional location"
    );
}

// ── Byte-exact key (adversarial twins) ───────────────────────────────────────

#[test]
fn credential_key_is_case_sensitive_not_folded() {
    // "secret" vs "SECRET" are DIFFERENT credentials (the key is byte-exact).
    let out = dedup_matches(
        vec![
            hi("generic-password", "SecretValue00", "a.env", 1, 10, 0.50),
            hi("generic-password", "secretvalue00", "a.env", 2, 40, 0.50),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        out.len(),
        2,
        "credential comparison is case-sensitive; these do not collapse"
    );
}

#[test]
fn detector_id_key_is_case_sensitive_not_folded() {
    let out = dedup_matches(
        vec![
            hi(
                "aws-access-key",
                "AKIAcasekeytest0000",
                "a.env",
                1,
                10,
                0.50,
            ),
            hi(
                "AWS-ACCESS-KEY",
                "AKIAcasekeytest0000",
                "a.env",
                1,
                10,
                0.50,
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        out.len(),
        2,
        "detector_id comparison is case-sensitive; these do not collapse"
    );
    // Uppercase sorts before lowercase in byte order.
    assert_eq!(&*out[0].detector_id, "AWS-ACCESS-KEY");
    assert_eq!(&*out[1].detector_id, "aws-access-key");
}

#[test]
fn empty_credential_is_a_valid_key_and_collapses() {
    // Boundary: an empty credential is still a well-formed key component.
    let out = dedup_matches(
        vec![
            hi("generic-secret", "", "a.env", 1, 10, 0.20),
            hi("generic-secret", "", "a.env", 1, 10, 0.40),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        out.len(),
        1,
        "two empty-credential hits under one detector collapse"
    );
    assert_eq!(out[0].credential.as_ref(), "");
    assert_eq!(out[0].confidence, Some(0.40));
}

// ── Scale / order / scope boundaries ─────────────────────────────────────────

#[test]
fn k_repeat_same_key_same_location_collapses_to_one() {
    let mut input = Vec::new();
    let confs = [0.10, 0.55, 0.33, 0.99, 0.42];
    for &c in &confs {
        input.push(hi("gitlab-pat", "glpat-krepeat000000", "a.env", 1, 10, c));
    }
    let out = dedup_matches(input, &DedupScope::Credential);
    assert_eq!(
        out.len(),
        1,
        "five identical-key/-location hits collapse to one"
    );
    assert_eq!(
        out[0].confidence,
        Some(0.99),
        "survivor carries the group's max confidence"
    );
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "identical location adds no additional locations"
    );
}

#[test]
fn output_sorted_by_detector_then_credential_regardless_of_input_order() {
    // Feed keys in a scrambled order; output must be sorted (detector asc,
    // credential asc) (the deterministic report ordering SARIF/baselines need).
    let out = dedup_matches(
        vec![
            hi("zeta-detector", "zzz_credential00000", "a.env", 1, 10, 0.5),
            hi("alpha-detector", "mmm_credential00000", "a.env", 2, 40, 0.5),
            hi("alpha-detector", "aaa_credential00000", "a.env", 3, 70, 0.5),
            hi("mike-detector", "kkk_credential00000", "a.env", 4, 100, 0.5),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        keys(&out),
        vec![
            (
                "alpha-detector".to_string(),
                "aaa_credential00000".to_string()
            ),
            (
                "alpha-detector".to_string(),
                "mmm_credential00000".to_string()
            ),
            (
                "mike-detector".to_string(),
                "kkk_credential00000".to_string()
            ),
            (
                "zeta-detector".to_string(),
                "zzz_credential00000".to_string()
            ),
        ],
        "sorted by detector_id ascending, then credential ascending"
    );
}

#[test]
fn dedup_output_is_order_independent() {
    let base = vec![
        hi("det-a", "cred_alpha00000000", "a.env", 1, 10, 0.7),
        hi("det-a", "cred_alpha00000000", "a.env", 1, 10, 0.9), // dup of first (key+loc)
        hi("det-b", "cred_bravo00000000", "b.env", 1, 10, 0.6),
        hi("det-a", "cred_charlie000000", "a.env", 2, 40, 0.4),
    ];
    let mut reversed = base.clone();
    reversed.reverse();

    let forward = dedup_matches(base, &DedupScope::Credential);
    let backward = dedup_matches(reversed, &DedupScope::Credential);

    assert_eq!(forward.len(), 3, "three distinct keys survive");
    assert_eq!(
        keys(&forward),
        keys(&backward),
        "the sorted key list is identical regardless of input order"
    );
    // And the collapsed det-a/cred_alpha finding kept its max confidence in both.
    let conf_fwd = forward
        .iter()
        .find(|d| &*d.detector_id == "det-a" && d.credential.as_ref() == "cred_alpha00000000")
        .and_then(|d| d.confidence);
    assert_eq!(
        conf_fwd,
        Some(0.9),
        "collapsed survivor keeps max confidence"
    );
}

#[test]
fn none_scope_never_collapses_identical_matches() {
    // DedupScope::None is the pass-through contract: every raw match becomes its
    // own finding, even byte-identical ones (the key is not consulted at all).
    let a = hi(
        "aws-access-key",
        "AKIAnoscope00000000",
        "a.env",
        1,
        10,
        0.80,
    );
    let b = hi(
        "aws-access-key",
        "AKIAnoscope00000000",
        "a.env",
        1,
        10,
        0.80,
    );
    let out = dedup_matches(vec![a, b], &DedupScope::None);
    assert_eq!(
        out.len(),
        2,
        "DedupScope::None keeps every match as its own finding"
    );
    assert!(
        out.iter().all(|d| d.additional_locations.is_empty()),
        "None-scope findings never accumulate additional_locations"
    );
}

#[test]
fn file_scope_splits_same_key_across_files_but_credential_scope_merges() {
    // Same (detector, credential) in two files:
    //   * DedupScope::File  -> key includes file -> TWO findings;
    //   * DedupScope::Credential -> file NOT in key -> ONE finding, the second
    //     file recorded as an additional location.
    let inputs = || {
        vec![
            hi("gh-pat", "ghp_twofilekey00000", "a.env", 1, 10, 0.6),
            hi("gh-pat", "ghp_twofilekey00000", "b.env", 1, 10, 0.6),
        ]
    };

    let file_scoped = dedup_matches(inputs(), &DedupScope::File);
    assert_eq!(
        file_scoped.len(),
        2,
        "file scope keeps one finding per file"
    );

    let cred_scoped = dedup_matches(inputs(), &DedupScope::Credential);
    assert_eq!(cred_scoped.len(), 1, "credential scope merges across files");
    assert_eq!(
        cred_scoped[0].additional_locations.len(),
        1,
        "the second file becomes an additional location under credential scope"
    );
    // Primary is the alphabetically-first file (sort by file_path ascending).
    assert_eq!(
        cred_scoped[0].primary_location.file_path.as_deref(),
        Some("a.env")
    );
    assert_eq!(
        cred_scoped[0].additional_locations[0].file_path.as_deref(),
        Some("b.env")
    );
}

#[test]
fn none_confidence_and_some_confidence_collapse_to_the_scored_max() {
    // max_confidence(None, Some(0.5)) == Some(0.5); order must not matter.
    let mut none_first = hi("det", "cred_confmix000000", "a.env", 1, 10, 0.0);
    none_first.confidence = None;
    let some = hi("det", "cred_confmix000000", "a.env", 1, 10, 0.5);

    let out = dedup_matches(vec![none_first, some], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].confidence,
        Some(0.5),
        "a scored duplicate wins the confidence over a None one"
    );
}

#[test]
fn mixed_batch_has_exact_final_key_multiset() {
    // A realistic mix: dup pairs, distinct-credential siblings, distinct-detector
    // siblings, and a singleton (pinned to the EXACT surviving key multiset).
    let out = dedup_matches(
        vec![
            hi("aws-access-key", "AKIAmix000000000001", "a.env", 1, 10, 0.5),
            hi("aws-access-key", "AKIAmix000000000001", "a.env", 1, 10, 0.8), // dup -> merge
            hi("aws-access-key", "AKIAmix000000000002", "a.env", 2, 40, 0.5), // diff cred
            hi("gh-pat", "AKIAmix000000000001", "a.env", 3, 70, 0.5), // diff detector, same cred
            hi(
                "stripe-secret-key",
                "sk_live_mix00000000",
                "a.env",
                4,
                100,
                0.5,
            ), // singleton
        ],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 4, "5 raw matches collapse to 4 distinct keys");
    assert_eq!(
        keys(&out),
        vec![
            (
                "aws-access-key".to_string(),
                "AKIAmix000000000001".to_string()
            ),
            (
                "aws-access-key".to_string(),
                "AKIAmix000000000002".to_string()
            ),
            ("gh-pat".to_string(), "AKIAmix000000000001".to_string()),
            (
                "stripe-secret-key".to_string(),
                "sk_live_mix00000000".to_string()
            ),
        ]
    );
    // The merged aws/…0001 pair kept the higher 0.8 confidence.
    let merged = out
        .iter()
        .find(|d| {
            &*d.detector_id == "aws-access-key" && d.credential.as_ref() == "AKIAmix000000000001"
        })
        .unwrap();
    assert_eq!(merged.confidence, Some(0.8));
}
