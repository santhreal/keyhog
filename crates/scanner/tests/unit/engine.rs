use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::engine::{
    build_rule_pipeline, floor_char_boundary, line_number_for_offset, next_window_offset,
    window_chunk, window_end_offset, CompiledScanner,
};
use keyhog_scanner::hw_probe::ScanBackend;

fn demo_detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..Default::default()
    }
}

fn chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

// ── engine/windowed.rs ──────────────────────────────────────────────

#[test]
fn window_end_offset_stays_on_char_boundary() {
    let text = "αβγ";
    let end = window_end_offset(text, 0, 1);
    assert!(text.is_char_boundary(end));
    assert!(end <= text.len());
}

#[test]
fn window_end_offset_rejects_invalid_start() {
    let text = "hello";
    assert_eq!(window_end_offset(text, text.len(), 10), text.len());
}

#[test]
fn next_window_offset_applies_overlap_without_splitting_chars() {
    let text = "αβγδεζηθικλ";
    let end = window_end_offset(text, 0, 6);
    let next = next_window_offset(text, end, 2);
    assert!(text.is_char_boundary(next));
    assert!(next <= end);
}

#[test]
fn window_chunk_slices_data_and_preserves_metadata() {
    let mut meta = ChunkMetadata::default();
    meta.path = Some("src/main.rs".into());
    let parent = Chunk {
        data: "0123456789".into(),
        metadata: meta.clone(),
    };
    let slice = window_chunk(&parent, 2, 6);
    assert_eq!(slice.data.as_ref(), "2345");
    assert_eq!(slice.metadata.path.as_deref(), Some("src/main.rs"));
}

#[test]
fn floor_char_boundary_never_splits_multibyte_char() {
    let text = "aαb";
    let idx = floor_char_boundary(text, 2);
    assert!(text.is_char_boundary(idx));
    assert_eq!(idx, 1);
}

#[test]
fn line_number_for_offset_counts_newlines() {
    let text = "line1\nline2\nline3";
    assert_eq!(line_number_for_offset(text, 0), 1);
    assert_eq!(line_number_for_offset(text, 6), 2);
    assert_eq!(line_number_for_offset(text, text.len()), 3);
}

// ── engine/mod.rs - compile + rule pipeline ─────────────────────────

#[test]
fn compiled_scanner_compile_happy_path() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let matches = scanner.scan(&chunk("prefix abc suffix"));
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].credential.as_ref(), "abc");
}

#[test]
fn compiled_scanner_compile_rejects_invalid_regex() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = "(unclosed".into();
    assert!(CompiledScanner::compile(vec![detector]).is_err());
}

#[test]
fn build_rule_pipeline_compiles_simple_pattern() {
    let _pipeline = build_rule_pipeline(&["abc"], 1024).unwrap();
}

#[test]
fn build_rule_pipeline_rejects_unsupported_regex_features() {
    // Lookahead is outside the byte-NFA frontend.
    let err = build_rule_pipeline(&["(?=abc)"], 1024).unwrap_err();
    let _ = err.to_string();
}

// ── engine/scan.rs + fallback paths (via scan) ──────────────────────

#[test]
fn scan_empty_chunk_returns_no_matches() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner.scan(&chunk("")).is_empty());
}

#[test]
fn scan_rejects_cross_chunk_pattern_via_chunks_api() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let chunks = vec![chunk("ab"), chunk("c")];
    let per_chunk = scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    assert!(per_chunk.iter().all(Vec::is_empty));
}

// ── engine/backend.rs ───────────────────────────────────────────────

#[test]
fn backend_scan_with_backend_cpu_fallback_finds_match() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let matches = scanner.scan_with_backend(&chunk("abc token"), ScanBackend::CpuFallback);
    assert_eq!(matches.len(), 1);
}

#[test]
fn backend_scan_with_backend_empty_chunk_returns_empty() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner
        .scan_with_backend(&chunk(""), ScanBackend::CpuFallback)
        .is_empty());
}

// ── engine/fallback.rs + fallback_entropy.rs + fallback_generic.rs ─

#[test]
fn fallback_pattern_fires_on_keyword_chunk() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let matches = scanner.scan(&chunk(&format!("export TOKEN={token}")));
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}

#[test]
fn fallback_pattern_skips_plaintext_without_keyword() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    assert!(scanner.scan(&chunk("the quick brown fox")).is_empty());
}

// ── engine/scan_gpu.rs + hot_patterns.rs (via warm_backend) ─────────

#[test]
fn scan_gpu_warm_backend_cpu_paths_always_succeed() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner.warm_backend(ScanBackend::CpuFallback));
    assert!(scanner.warm_backend(ScanBackend::SimdCpu));
}

#[test]
fn scan_gpu_megascan_warm_degrades_gracefully_without_gpu() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    // Returns false when no GPU adapter, but must not panic.
    let _ = scanner.warm_backend(ScanBackend::MegaScan);
}

// ── engine/scan_filters.rs (keyword gating via generic assignment) ──

#[test]
fn scan_filters_generic_assignment_requires_secret_keyword() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let matches = scanner.scan(&chunk("username = randomuser1234567890"));
    assert!(matches.is_empty());
}

#[test]
fn scan_filters_generic_assignment_fires_with_secret_keyword() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let matches = scanner.scan(&chunk(&format!("api_key = \"{token}\"")));
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}

#[test]
fn scan_filters_generic_assignment_accepts_dotted_and_dashed_keys() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");

    for key in ["api.key", "auth-token", "client.secret"] {
        let matches = scanner.scan(&chunk(&format!("{key} = \"{token}\"")));
        assert!(
            matches.iter().any(|m| m.credential.as_ref() == token),
            "{key} should admit generic assignment scanning"
        );
    }
}

// CredData's dominant credential-env shape is `*_PASS=` (GRAPHITE_PASS,
// JENKINS_PASS, DB_PASS, …). The bridge keyword list historically had
// `password`/`passwd`/`pwd` but not the bare `pass` abbreviation, so these were
// never surfaced as candidates — a real recall hole on the home-turf corpus.
// `pass` is now in the list, made safe by the whole-word left boundary in
// GENERIC_RE. The value below has entropy above the generic-secret floor (2.8)
// but below the standalone entropy-fallback bar, so it is reachable ONLY through
// the keyword bridge — which isolates the keyword change from the entropy path.
#[test]
fn generic_assignment_bridges_bare_pass_abbreviation() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let value = "k7m2p9q4t6w1x8z3v5";
    for key in ["GRAPHITE_PASS", "DB_PASS", "jenkins_pass", "ses.pass"] {
        let matches = scanner.scan(&chunk(&format!("{key} = \"{value}\"")));
        assert!(
            matches.iter().any(|m| m.credential.as_ref() == value),
            "{key} (bare `pass` key) should bridge to the generic-secret fallback"
        );
    }
}

// Boundary twin: `pass` must match as a whole word, never as the tail of
// `bypass`/`compass`/`encompass`. Same value as the positive test, which the
// standalone entropy path will not promote on its own — so a match here would
// mean the boundary leaked and `bypass`/`compass` are firing as `pass`.
#[test]
fn generic_assignment_bare_pass_respects_word_boundary() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let value = "k7m2p9q4t6w1x8z3v5";
    for key in ["BYPASS", "COMPASS", "encompass"] {
        let matches = scanner.scan(&chunk(&format!("{key} = \"{value}\"")));
        assert!(
            !matches.iter().any(|m| m.credential.as_ref() == value),
            "{key} ends in `pass` but is not a credential key; must stay silent"
        );
    }
}

// The `generic_keyword_low_entropy` knob must be load-bearing: a
// keyword-anchored value whose entropy sits BELOW the high `generic-secret`
// floor (2.8) but ABOVE the relaxed `generic-keyword-secret` floor (1.5) is the
// real-world low-entropy credential class (config passwords). With the knob on
// (default) it must surface; with `--no-keyword-low-entropy` it must be gated
// out. ML is disabled and the confidence floor dropped so the test isolates the
// entropy-floor decision from the MoE scoring stage.
#[test]
fn generic_keyword_low_entropy_knob_gates_low_entropy_values() {
    // `q7q4m7k4p2`: 6 distinct symbols (q,7,4 twice; m,k,p once) => ~2.4 bits/byte,
    // inside the (1.5, 2.8) window that distinguishes the relaxed keyword floor
    // from the high generic-secret floor. 10 chars (length gate), 6 distinct
    // (clears the low-diversity placeholder filter that an `aabbccdd`-style value
    // trips), no other shape-filter triggers, longest run 1. Verified to toggle
    // end-to-end via `--no-keyword-low-entropy` on the real binary.
    let value = "q7q4m7k4p2";
    let line = format!("PASSWORD = \"{value}\"");

    let relaxed = CompiledScanner::compile(vec![demo_detector()])
        .unwrap()
        .with_config(keyhog_scanner::ScannerConfig {
            scan: keyhog_core::config::ScanConfig {
                generic_keyword_low_entropy: true,
                ml_enabled: false,
                min_confidence: 0.0,
                ..Default::default()
            },
            ..Default::default()
        });
    assert!(
        relaxed
            .scan(&chunk(&line))
            .iter()
            .any(|m| m.credential.as_ref() == value),
        "with generic_keyword_low_entropy on, a low-entropy keyword-anchored \
         value must surface"
    );

    let strict = CompiledScanner::compile(vec![demo_detector()])
        .unwrap()
        .with_config(keyhog_scanner::ScannerConfig {
            scan: keyhog_core::config::ScanConfig {
                generic_keyword_low_entropy: false,
                ml_enabled: false,
                min_confidence: 0.0,
                ..Default::default()
            },
            ..Default::default()
        });
    assert!(
        !strict
            .scan(&chunk(&line))
            .iter()
            .any(|m| m.credential.as_ref() == value),
        "with --no-keyword-low-entropy the high generic-secret floor must gate \
         the same low-entropy value out"
    );
}

// ── engine/segment_attribution.rs ───────────────────────────────────
// Covered in segment_attribution.rs unit module.

// ── engine/boundary.rs ──────────────────────────────────────────────
// Covered by inline #[cfg(test)] in boundary.rs (lib tests).
