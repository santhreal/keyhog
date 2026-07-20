use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn partial_alternation_detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "partial-alt".into(),
        name: "Partial Alternation".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "(AKIA|[A-Z0-9]{4})TESTSECRET".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

#[test]
fn partial_alternation_unprefixed_branch_still_scans() {
    let scanner = CompiledScanner::compile(vec![partial_alternation_detector()])
        .expect("compile detector with partial alternation");
    let chunk = Chunk {
        data: "prefix 1234TESTSECRET suffix".into(),
        metadata: ChunkMetadata {
            path: Some("partial-alt.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == "1234TESTSECRET"),
        "unprefixed alternation branch must not be silently dead; matches={matches:?}"
    );
}

#[cfg(feature = "simdsieve")]
#[test]
fn loaded_hot_detector_without_matching_ac_prefix_degrades_gracefully_and_still_detects() {
    // The hot-pattern table is an internal SIMD optimization keyed to the
    // embedded corpus. A caller who reuses a hot-table id (`github-classic-pat`)
    // with a regex that exposes a DIFFERENT prefix (`not_ghp_`) must NOT fail
    // construction: the `ghp_` hot slot it cannot back goes inactive, and the
    // credential is still found by the confirmed AC scan (the hot path is a pure
    // accelerator over it). Drift in the SHIPPED table is caught separately by
    // `hot_pattern_table_fully_backed_by_embedded_corpus` (internal unit test).
    let detector = DetectorSpec {
        id: "github-classic-pat".into(),
        name: "GitHub Classic PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"not_ghp_[A-Za-z0-9_]{36}".into(),
            ..Default::default()
        }],
        keywords: vec!["ghp".into()],
        min_confidence: Some(0.1),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };

    let scanner = CompiledScanner::compile(vec![detector])
        .expect("a detector that cannot back a hot slot must still compile (slot goes inactive)");

    // not_ghp_ + exactly 36 high-entropy body chars from [A-Za-z0-9_].
    let credential = "not_ghp_Kp7Rm2Qx9Bn4Lv6Tw8Ys1Hj3Dg5Fc0Zb2aQp";
    let chunk = Chunk {
        data: format!("token = \"{credential}\"\n").into(),
        metadata: ChunkMetadata {
            path: Some("degraded-hot-slot.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == credential),
        "credential must still be detected via the confirmed AC scan even though its hot \
         slot is inactive; matches={matches:?}"
    );
}
