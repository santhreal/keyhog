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
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        min_confidence: None,
        ..Default::default()
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
fn loaded_hot_detector_without_matching_ac_prefix_fails_construction() {
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
        ..Default::default()
    };

    let err = match CompiledScanner::compile(vec![detector]) {
        Ok(_) => {
            panic!("loaded hot detector with stale HOT_PATTERNS prefix must fail construction")
        }
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("simdsieve hot-pattern slot")
            && msg.contains("github-classic-pat")
            && msg.contains("ghp_")
            && msg.contains("no compiled AC entry"),
        "error must name stale hot-pattern prefix mapping and fix context; got {msg}"
    );
}
