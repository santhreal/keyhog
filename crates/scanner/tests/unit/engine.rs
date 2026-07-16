use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::engine::CompiledScanner;
use keyhog_scanner::hw_probe::testing::ScanBackend;
use keyhog_scanner::testing::{
    floor_char_boundary, line_number_for_offset, next_window_offset, phase2_gate_prefix_literals,
    phase2_required_prefix_literals, window_chunk, window_end_offset,
};
use keyhog_scanner::ScannerConfig;
use std::sync::Arc;

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
        min_confidence: Some(0.0),
        ..Default::default()
    }
}

fn mx_api_detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "mx-api-credentials".into(),
        name: "MX API Credentials".into(),
        service: "mx".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r#"(?:MX|mx)[._-]?(?:API|api)?[._-]?(?:KEY|key)[=:\s"'']+([a-f0-9]{32})"#.into(),
            description: Some("MX API Key".into()),
            group: Some(1),
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["MX_API_KEY".into(), "api_key".into()],
        min_confidence: None,
        ..Default::default()
    }
}

fn service_context_detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "unit-service-token".into(),
        name: "Unit Service Token".into(),
        service: "unit".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r#"(HARDTOK[A-Za-z0-9]{20})"#.into(),
            description: Some("Unit service token".into()),
            group: Some(1),
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["HARDTOK".into()],
        min_confidence: None,
        ..Default::default()
    }
}

fn embedded_detector(id: &str) -> DetectorSpec {
    keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must load")
        .into_iter()
        .find(|detector| detector.id == id)
        .unwrap_or_else(|| panic!("embedded detector {id} must exist"))
}

fn chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

fn file_chunk(data: String, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "unit-boundary".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

fn repeated_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"Ab3Cd4Ef5Gh6Jk7Lm8Np9Qr0StUvWxYz";
    (0..len)
        .map(|idx| ALPHABET[idx % ALPHABET.len()] as char)
        .collect()
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

// ── engine/mod.rs - compile ─────────────────────────────────────────

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

// ── engine/scan.rs paths (via scan) ─────────────────────────────────

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

// ── engine/phase2.rs + phase2_entropy.rs + phase2_generic.rs ─

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

#[test]
fn phase2_required_prefix_literals_share_gate_prefix_owner() {
    let src = r#"(?:MX|mx)[._-]?(?:API|api)?[._-]?(?:KEY|key)[=:\s"'']+([a-f0-9]{32})"#;
    let anchor_lits = phase2_required_prefix_literals(src).expect("MX anchors");
    let mut gate_lits: Vec<String> = phase2_gate_prefix_literals(src)
        .expect("MX gate literals")
        .into_iter()
        .map(|bytes| {
            String::from_utf8(bytes)
                .expect("gate literals are ASCII")
                .to_ascii_lowercase()
        })
        .collect();
    gate_lits.sort_unstable();
    gate_lits.dedup();

    assert_eq!(anchor_lits, gate_lits);
    assert_eq!(anchor_lits.len(), 29);
    assert!(anchor_lits.iter().any(|lit| lit == "mx_api_key"));
}

#[test]
fn phase2_required_prefix_literals_rejects_non_ascii_and_oversized_sets() {
    assert!(phase2_required_prefix_literals("ÉSECRET[0-9]+").is_none());

    let oversized = format!(
        "(?:{})[=:\\s]+([a-f0-9]{{32}})",
        (0..33)
            .map(|idx| format!("ALT{idx:02}"))
            .collect::<Vec<_>>()
            .join("|")
    );
    assert!(phase2_required_prefix_literals(&oversized).is_none());
}

#[test]
fn mx_api_key_phase2_pattern_is_shared_anchor_localized() {
    let scanner = crate::engine::CompiledScanner::compile(vec![mx_api_detector()])
        .expect("MX detector compiles");
    let phase2_index = scanner
        .phase2_patterns
        .iter()
        .position(|(pattern, _)| pattern.regex.as_str().contains("(?:API|api)?"))
        .expect("MX API key pattern is in phase2");
    let anchor_index = scanner
        .phase2_anchor_index
        .as_ref()
        .expect("phase2 anchor index built");
    assert!(anchor_index.is_eligible(phase2_index));

    let value = "abcdef0123456789abcdef0123456789";
    let matches = scanner.scan(&chunk(&format!("export MX_API_KEY={value}")));
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == value),
        "localized MX phase2 pattern must still report the API key: {matches:?}"
    );
}

#[test]
fn named_detector_honors_min_confidence_and_traces_reject() {
    let _guard = super::telemetry_serial::lock();
    let value = "abcdef0123456789abcdef0123456789";
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.99;
    config.ml_enabled = false;
    config.test_keywords.clear();
    config.placeholder_keywords.clear();

    let scanner = CompiledScanner::compile(vec![mx_api_detector()])
        .unwrap()
        .with_config(config);
    keyhog_scanner::telemetry::testing::reset();
    let trace = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    trace.enable_dogfood();
    let chunk = file_chunk(
        format!("export MX_API_KEY={value}"),
        "named_min_floor.env",
        0,
    );
    let matches = keyhog_scanner::telemetry::with_scan_telemetry(&trace, || scanner.scan(&chunk));

    assert!(
        !matches.iter().any(|m| m.credential.as_ref() == value),
        "named detector candidate below min_confidence must not emit; got {matches:?}"
    );
    let reasons: Vec<_> = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            keyhog_scanner::telemetry::DogfoodEvent::ShapeSuppressed {
                path: Some(path),
                reason,
                ..
            } if path == "named_min_floor.env" => Some(reason.into_owned()),
            _ => None,
        })
        .collect();
    assert!(
        reasons.iter().any(|reason| reason == "below_min_confidence"),
        "named detector min-confidence reject must be operator-visible through adjudication; got {reasons:?}"
    );
}

#[test]
fn named_detector_comment_anchor_floor_keeps_anchored_secret_visible() {
    let _guard = super::telemetry_serial::lock();
    let value = "HARDTOKabcdefghijklmno12345";
    let mut config = ScannerConfig::default();
    config.ml_enabled = false;
    config.min_confidence = 0.0;
    config.test_keywords.clear();
    config.placeholder_keywords.clear();

    let scanner = CompiledScanner::compile(vec![service_context_detector()])
        .unwrap()
        .with_config(config);
    let chunk = file_chunk(format!("<!--{value}-->"), "named_comment_floor.html", 0);
    let matches = scanner.scan(&chunk);

    // The `<!--…-->` line IS classified as Comment context, and with the default
    // `scan_comments = false` the comment confidence penalty (×0.4) applies. But
    // the keyword-anchored named-detector floor (NAMED_DETECTOR_ANCHOR_FLOOR, the
    // recall feature added in 9f5dfc097: "lift keyword-anchored named-detector
    // matches to a confidence floor") lifts a `HARDTOK`-anchored named match back
    // to 0.55, above the 0.5 comment hard-suppression threshold, so a real
    // anchored secret pasted into a comment still SURFACES instead of being
    // silently hard-suppressed (keyhog is recall-bound; a key in a comment is a
    // real leak). Precise hard_suppressed_context tracing for the matches that DO
    // hard-suppress (weak/unanchored) is covered by tests/unit/adjudicate.rs and
    // gates/suppression_named_detector_ctx_owner.rs.
    let hit = matches
        .iter()
        .find(|m| m.credential.as_ref() == value)
        .unwrap_or_else(|| {
            panic!(
                "keyword-anchored named detector in a comment must still surface \
                 via the anchor floor; got {matches:?}"
            )
        });
    assert!(
        hit.confidence.unwrap_or(0.0) >= keyhog_scanner::testing::NAMED_DETECTOR_ANCHOR_FLOOR,
        "anchor floor must lift the comment-penalized confidence to at least \
         NAMED_DETECTOR_ANCHOR_FLOOR ({}); got {:?}",
        keyhog_scanner::testing::NAMED_DETECTOR_ANCHOR_FLOOR,
        hit.confidence
    );
}

#[test]
fn entropy_fallback_honors_min_secret_len_config() {
    let value = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ";
    assert_eq!(value.len(), 32);
    let mut config = ScannerConfig::default();
    config.entropy_in_source_files = true;
    config.entropy_threshold = 3.0;
    config.min_confidence = 0.0;
    config.ml_enabled = false;
    config.entropy_ml_authoritative = false;
    config.secret_keywords = vec!["MARKER".into()];
    config.test_keywords.clear();
    config.placeholder_keywords.clear();

    let scanner = CompiledScanner::compile(Vec::new())
        .unwrap()
        .with_config(config.clone());
    let matches = scanner.scan(&chunk(&format!("MARKER = \"{value}\"")));
    assert!(
        matches.iter().any(|m| {
            m.credential.as_ref() == value && m.detector_id.as_ref().starts_with("entropy-")
        }),
        "min_secret_len=32 should admit the entropy candidate; got {matches:?}"
    );

    config.min_secret_len = 33;
    let scanner = CompiledScanner::compile(Vec::new())
        .unwrap()
        .with_config(config);
    let matches = scanner.scan(&chunk(&format!("MARKER = \"{value}\"")));
    assert!(
        !matches.iter().any(|m| {
            m.credential.as_ref() == value && m.detector_id.as_ref().starts_with("entropy-")
        }),
        "min_secret_len=33 should reject the 32-byte entropy candidate; got {matches:?}"
    );
}

#[test]
fn entropy_fallback_precheck_admits_symbolic_password_runs() {
    let value = "1E1B3b4Ho$U4kYBi";
    assert_eq!(value.len(), 16);
    let mut config = ScannerConfig::default();
    config.entropy_in_source_files = true;
    config.entropy_threshold = 3.0;
    config.min_confidence = 0.0;
    config.ml_enabled = false;
    config.entropy_ml_authoritative = false;
    config.secret_keywords = vec!["SECRET".into()];
    config.test_keywords.clear();
    config.placeholder_keywords.clear();

    let scanner = CompiledScanner::compile(Vec::new())
        .unwrap()
        .with_config(config);
    let matches = scanner.scan(&chunk(&format!("SECRET = \"{value}\"")));
    assert!(
        matches.iter().any(|m| {
            m.credential.as_ref() == value && m.detector_id.as_ref().starts_with("entropy-")
        }),
        "credential-context symbolic password should reach entropy fallback; got {matches:?}"
    );
}

#[test]
fn entropy_fallback_rejection_is_operator_visible() {
    let _guard = super::telemetry_serial::lock();
    let value = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ";
    let mut config = ScannerConfig::default();
    config.entropy_in_source_files = true;
    config.entropy_threshold = 3.0;
    config.min_confidence = 0.99;
    config.ml_enabled = false;
    config.entropy_ml_authoritative = false;
    config.secret_keywords = vec!["MARKER".into()];
    config.test_keywords.clear();
    config.placeholder_keywords.clear();

    let scanner = CompiledScanner::compile(Vec::new())
        .unwrap()
        .with_config(config);
    keyhog_scanner::telemetry::testing::reset();
    let trace = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    trace.enable_dogfood();
    let chunk = file_chunk(format!("MARKER = \"{value}\""), "entropy_min_floor.env", 0);
    let matches = keyhog_scanner::telemetry::with_scan_telemetry(&trace, || scanner.scan(&chunk));

    assert!(
        !matches.iter().any(|m| m.credential.as_ref() == value),
        "entropy candidate the scanner rejects must not emit; got {matches:?}"
    );
    // A scanner-path entropy rejection MUST stay operator-visible through the
    // --dogfood trace (Law 10: no silent drop). The entropy fallback drops this
    // generic candidate at the entropy floor (it does not clear the fallback's
    // high-entropy bar, which is above the configured candidate threshold) and
    // records it with `path: None`: only early gates carry the source file; a
    // later/fallback stage records None by design (see the dedup note in
    // telemetry.rs), so filter by reason, not path. Min-confidence reject
    // tracing (below_min_confidence) for a candidate that DOES clear the entropy
    // floor is covered by `named_detector_min_floor`.
    let reasons: Vec<_> = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            keyhog_scanner::telemetry::DogfoodEvent::ShapeSuppressed { reason, .. } => {
                Some(reason.into_owned())
            }
            _ => None,
        })
        .collect();
    assert!(
        reasons.iter().any(|reason| reason == "entropy_below_floor"),
        "scanner entropy-fallback rejection must be operator-visible; got {reasons:?}"
    );
}

#[test]
fn phase2_first_bigram_set_casefolds_and_saturates_short_literals() {
    let gate =
        keyhog_scanner::engine::phase2::FirstBigramSet::from_literals([b"mx_api".as_slice()], true);
    assert!(gate.may_have_match("const MX_API_KEY = value"));
    assert!(!gate.may_have_match("const sk_live_key = value"));

    let saturated =
        keyhog_scanner::engine::phase2::FirstBigramSet::from_literals([b"x".as_slice()], true);
    assert!(
        saturated.may_have_match("zz"),
        "short literals cannot prove absence, so the prescreen must fail open"
    );
    assert!(
        saturated.may_have_match("z"),
        "short-literal fail-open must also hold for one-byte texts"
    );
}

#[test]
fn azure_subscription_key_named_detector_fires_on_normal_and_zero_width_anchor() {
    let value = "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d";
    assert_eq!(value.len(), 32);
    let mut config = ScannerConfig::default();
    config.ml_enabled = false;
    config.min_confidence = 0.0;
    config.test_keywords.clear();
    config.placeholder_keywords.clear();

    let scanner = CompiledScanner::compile(vec![embedded_detector("azure-subscription-key")])
        .expect("azure subscription key detector compiles")
        .with_config(config);

    for text in [
        format!("azure_subscription_key = \"{value}\""),
        format!("azure_subscription\u{200b}_key = \"{value}\""),
    ] {
        let matches = scanner.scan(&chunk(&text));
        assert!(
            matches.iter().any(|m| {
                m.detector_id.as_ref() == "azure-subscription-key"
                    && m.credential.as_ref() == value
            }),
            "Azure subscription key must fire through its named detector, not a generic substitute; text={text:?} matches={matches:?}"
        );
    }
}

#[test]
fn strong_secret_assignment_surfaces_printable_base64_transport_value() {
    let value = "Y2FsaWNvLW9uLWt1YmUtYXV0aC1rZXk=";
    let mut config = ScannerConfig::default();
    config.ml_enabled = false;
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = CompiledScanner::compile(vec![
        embedded_detector("generic-secret"),
        embedded_detector("generic-keyword-secret"),
    ])
    .expect("generic detectors compile")
    .with_config(config);
    let matches = scanner.scan(&chunk(&format!("K8S_FULL_SECRET=\"{value}\"")));
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == value),
        "strong *_SECRET assignment must retain its printable base64 transport value; matches={matches:?}"
    );
}

#[test]
fn boundary_scan_uses_bounded_detector_match_width_past_1024_bytes() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"LONG_[A-Za-z0-9]{1500}_END".into();
    detector.keywords = vec!["LONG_".into()];
    let mut config = ScannerConfig::default();
    config.entropy_enabled = false;
    config.ml_enabled = false;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![detector])
        .unwrap()
        .with_config(config);

    let secret = format!("LONG_{}_END", repeated_alnum(1500));
    let split_at = 1200;
    let mut left = "prefix\n".to_string();
    left.push_str(&secret[..split_at]);
    let left_len = left.len();
    let mut right = secret[split_at..].to_string();
    right.push_str("\n");

    let chunks = vec![
        file_chunk(left, "long-boundary.txt", 0),
        file_chunk(right, "long-boundary.txt", left_len),
    ];
    let matches = scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    assert!(
        matches
            .iter()
            .flatten()
            .any(|m| m.credential.as_ref() == secret),
        "bounded detector match starting more than 1024 bytes before the seam must surface"
    );
}

#[test]
fn boundary_scan_uses_full_pair_for_unbounded_detector_regex() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"LONG_[A-Za-z0-9]+_END".into();
    detector.keywords = vec!["LONG_".into()];
    let mut config = ScannerConfig::default();
    config.entropy_enabled = false;
    config.ml_enabled = false;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![detector])
        .unwrap()
        .with_config(config);

    let secret = format!("LONG_{}_END", repeated_alnum(1500));
    let split_at = 1200;
    let mut left = "prefix\n".to_string();
    left.push_str(&secret[..split_at]);
    let left_len = left.len();
    let mut right = secret[split_at..].to_string();
    right.push_str("\n");

    let chunks = vec![
        file_chunk(left, "unbounded-boundary.txt", 0),
        file_chunk(right, "unbounded-boundary.txt", left_len),
    ];
    let matches = scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    assert!(
        matches
            .iter()
            .flatten()
            .any(|m| m.credential.as_ref() == secret),
        "unbounded detector regex must scan the full adjacent seam pair"
    );
}

// ── engine/scan_gpu.rs + hot_patterns.rs (via warm_backend) ─────────

#[test]
fn scan_gpu_warm_backend_cpu_paths_always_succeed() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner.warm_backend(ScanBackend::CpuFallback));
    let simd_ready = scanner.warm_backend(ScanBackend::SimdCpu);
    assert_eq!(
        simd_ready,
        scanner.warm_backend(ScanBackend::SimdCpu),
        "SIMD warmup must report stable live-backend readiness instead of pretending every scanner has a SIMD prefilter"
    );
}

#[test]
fn scan_gpu_warm_reports_stable_backend_readiness() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let gpu_ready = scanner.warm_backend(ScanBackend::GpuWgpu);
    assert_eq!(gpu_ready, scanner.warm_backend(ScanBackend::GpuWgpu));
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

#[test]
fn generic_assignment_compact_prefilter_keeps_webhook_url_recall() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(), embedded_detector("generic-secret")])
            .unwrap();
    let value = "Zx9KmPq2LvWnB7tRsYz3BcDe";
    let matches = scanner.scan(&chunk(&format!("webhook_url = \"{value}\"")));
    assert!(
        matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "generic-secret" && m.credential.as_ref() == value),
        "webhook_url must still reach the generic bridge after compact prefilter stemming"
    );
}

#[test]
fn generic_assignment_prefilter_collects_casefolded_keyword_lines_once() {
    let text = concat!(
        "plain first line\n",
        "API_KEY = 'one'\n",
        "token and SECRET both on one line\n",
        "COMPASS = broad-prefilter-boundary-rejected-later\n",
        "webhook_url = 'two'"
    );
    let mut lines = Vec::new();
    keyhog_scanner::engine::phase2_generic::keywords::collect_generic_keyword_lines(
        text, &mut lines,
    );
    assert_eq!(lines, vec![1, 2, 3, 4]);
}

#[test]
fn generic_assignment_prefilter_collects_gpu_position_lines_once() {
    let text = concat!(
        "plain first line\n",
        "API_KEY = 'one'\n",
        "token and SECRET both on one line\n",
        "webhook_url = 'two'"
    );
    let offsets = keyhog_scanner::testing::compute_line_offsets(text);
    let positions = [
        text.find("API_KEY").unwrap() as u32,
        text.find("token").unwrap() as u32,
        text.find("SECRET").unwrap() as u32,
        text.find("webhook").unwrap() as u32,
    ];
    let mut lines = Vec::new();
    keyhog_scanner::engine::phase2_generic::keywords::collect_generic_keyword_lines_from_positions(
        &offsets, &positions, &mut lines,
    );
    assert_eq!(lines, vec![1, 2, 3]);
}

// CredData's dominant credential-env shape is `*_PASS=` (GRAPHITE_PASS,
// JENKINS_PASS, DB_PASS, …). The bridge keyword list historically had
// `password`/`passwd`/`pwd` but not the bare `pass` abbreviation, so these were
// never surfaced as candidates (a real recall hole on the home-turf corpus).
// `pass` is now in the list, made safe by the whole-word left boundary in
// GENERIC_RE. The value below has entropy above the generic-secret floor (2.8)
// but below the standalone entropy-fallback bar, so it is reachable ONLY through
// the keyword bridge (which isolates the keyword change from the entropy path).
#[test]
fn generic_assignment_bridges_bare_pass_abbreviation() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(), embedded_detector("generic-secret")])
            .unwrap();
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
// standalone entropy path will not promote on its own, so a match here would
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
    // `q7q4q7k4p2`: 6 distinct symbols with counts 3,2,2,1,1,1 =>
    // ~2.45 bits/byte,
    // inside the (1.5, 2.8) window that distinguishes the relaxed keyword floor
    // from the high generic-secret floor. 10 chars (length gate), 6 distinct
    // (clears the low-diversity placeholder filter that an `aabbccdd`-style value
    // trips), no other shape-filter triggers, longest run 1. Verified to toggle
    // end-to-end via `--no-keyword-low-entropy` on the real binary.
    let value = "q7q4q7k4p2";
    let line = format!("PASSWORD = \"{value}\"");

    let active_detectors = || {
        vec![
            demo_detector(),
            keyhog_core::detector_spec_by_id(crate::detector_ids::GENERIC_SECRET)
                .expect("generic-secret policy exists")
                .clone(),
            keyhog_core::detector_spec_by_id(crate::detector_ids::GENERIC_KEYWORD_SECRET)
                .expect("generic-keyword-secret policy exists")
                .clone(),
        ]
    };

    let relaxed = CompiledScanner::compile(active_detectors())
        .unwrap()
        .with_config(keyhog_scanner::ScannerConfig {
            scan: keyhog_core::ScanConfig {
                generic_keyword_low_entropy: true,
                entropy_enabled: false,
                #[cfg(feature = "ml")]
                ml_mode: None,
                #[cfg(not(feature = "ml"))]
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

    let strict = CompiledScanner::compile(active_detectors())
        .unwrap()
        .with_config(keyhog_scanner::ScannerConfig {
            scan: keyhog_core::ScanConfig {
                generic_keyword_low_entropy: false,
                entropy_enabled: false,
                #[cfg(feature = "ml")]
                ml_mode: None,
                #[cfg(not(feature = "ml"))]
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
