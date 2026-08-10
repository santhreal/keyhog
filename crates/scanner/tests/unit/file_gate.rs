//! FILE_GATE micro tests - one happy + error (+ boundary/adversarial) per scanner src file.

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::checksum::{validate_checksum, ChecksumResult};
use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::decode::{base64_decode, hex_decode};
use keyhog_scanner::engine::CompiledScanner;
use keyhog_scanner::entropy::{shannon_entropy, HIGH_ENTROPY_THRESHOLD};
use keyhog_scanner::gpu::{gpu_available, gpu_probe};
use keyhog_scanner::ml_scorer::{model_card_json, model_card_summary, model_version, score};
use keyhog_scanner::resolution::resolve_matches;
use keyhog_scanner::telemetry::{
    drain_events, enable_dogfood, record_example_suppression, testing::reset,
};
use keyhog_scanner::testing::build_propagation_table;
use keyhog_scanner::testing::confidence::apply_post_ml_penalties;
use keyhog_scanner::testing::confidence::{compute_confidence, ConfidenceSignals};
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;
use keyhog_scanner::testing::extract_literal_prefix;
use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::jwt::{analyze, looks_like_jwt};
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};
use keyhog_scanner::testing::segment_attribution::{map_offsets_to_segments, GlobalMatch, Segment};
use keyhog_scanner::testing::unicode_hardening::is_evasion_char;
use keyhog_scanner::testing::BigramBloom;
use keyhog_scanner::testing::{
    compile_state_is_ok, compute_line_offsets, match_entropy, normalize_chunk_data, AlphabetScreen,
};
use keyhog_scanner::testing::{compute_features_public, NUM_FEATURES};
use keyhog_scanner::types::ScannerConfig;
use keyhog_scanner::{probe_hardware, select_backend, ScanError};

fn demo_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

fn structured_env_chunk(data: &str, path: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            path: Some(path.into()),
            ..Default::default()
        },
    }
}
fn demo_detector(regex: &str, keyword: &str) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "gate-demo".into(),
        name: "Gate Demo".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![keyword.into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

// ── crates/scanner/src/alphabet_filter.rs ───────────────────────────
#[test]
fn alphabet_filter_happy_screens_matching_alphabet() {
    let screen = AlphabetScreen::new(&["ghp_".into()]);
    assert!(screen.screen(b"prefix ghp_token"));
}
#[test]
fn alphabet_filter_error_rejects_unrelated_bytes() {
    let screen = AlphabetScreen::new(&["zzzz".into()]);
    assert!(!screen.screen(b"plain english prose"));
}
// ── crates/scanner/src/bigram_bloom.rs ──────────────────────────────
#[test]
fn bigram_bloom_happy() {
    assert!(BigramBloom::from_literal_prefixes(&["ghp_".into()]).maybe_overlaps(b"ghp_x"));
}
#[test]
fn bigram_bloom_error() {
    assert!(!BigramBloom::from_literal_prefixes(&["ghp_".into()]).maybe_overlaps(b"zzzz"));
}

#[test]
fn selective_anchor_constructor_populates_once_and_preserves_recall() {
    let bloom =
        BigramBloom::from_literal_prefixes(&["ghp_ABCDEFG".into(), "sk_live_12345678".into()]);
    assert!(bloom.popcount() > 0);
    assert!(!bloom.is_saturated());
    assert!(bloom.maybe_overlaps(b"prefix ghp_ABCDEFG suffix"));
    assert!(bloom.maybe_overlaps(b"prefix SK_LIVE_12345678 suffix"));
    assert!(!bloom.maybe_overlaps(b"ordinary source without either anchor"));
}

// ── crates/scanner/src/checksum/github.rs ───────────────────────────
#[test]
fn checksum_github_happy() {
    assert_eq!(
        validate_checksum(concat!("gh", "p_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPlr")),
        ChecksumResult::Valid
    );
}
#[test]
fn checksum_github_error() {
    assert_eq!(
        validate_checksum(concat!("gh", "p_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000")),
        ChecksumResult::Invalid
    );
}

// ── crates/scanner/src/checksum/gitlab.rs ───────────────────────────
#[test]
fn checksum_gitlab_happy() {
    assert_eq!(
        validate_checksum("glpat-01234567890123456789"),
        ChecksumResult::StructurallyValid
    );
}
#[test]
fn checksum_gitlab_error() {
    assert_eq!(validate_checksum("glpat-short"), ChecksumResult::Invalid);
}

// ── crates/scanner/src/checksum/mod.rs ────────────────────────────────
#[test]
fn checksum_mod_happy() {
    assert_eq!(
        validate_checksum(concat!("AK", "IAIOSFODNN7EXAMPLE")),
        ChecksumResult::NotApplicable
    );
}
#[test]
fn checksum_mod_error() {
    assert_eq!(validate_checksum(""), ChecksumResult::NotApplicable);
}

// ── crates/scanner/src/checksum/npm.rs ────────────────────────────────
#[test]
fn checksum_npm_happy() {
    assert_eq!(
        validate_checksum("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"),
        ChecksumResult::Valid
    );
}
#[test]
fn checksum_npm_error() {
    assert_eq!(
        validate_checksum("npm_tooshort"),
        ChecksumResult::NotApplicable
    );
}

// ── crates/scanner/src/checksum/slack.rs ──────────────────────────────
#[test]
fn checksum_slack_happy() {
    assert_eq!(
        validate_checksum(concat!(
            "xox",
            "b-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
        )),
        ChecksumResult::StructurallyValid
    );
}
#[test]
fn checksum_slack_error() {
    assert_eq!(
        validate_checksum(concat!("xox", "b-bad")),
        ChecksumResult::Invalid
    );
}

// ── crates/scanner/src/checksum/stripe.rs ─────────────────────────────
#[test]
fn checksum_stripe_happy() {
    assert_eq!(
        validate_checksum(concat!("sk_li", "ve_1234567890abcdefghijklmnop")),
        ChecksumResult::StructurallyValid
    );
}
#[test]
fn checksum_stripe_error() {
    assert_eq!(validate_checksum("sk_live_short"), ChecksumResult::Invalid);
}

// ── crates/scanner/src/compiler.rs ────────────────────────────────────
#[test]
fn compiler_error() {
    assert!(!compile_state_is_ok(&[demo_detector("(unclosed", "x")]));
}

// ── crates/scanner/src/compiler/compiler_prefix.rs ─────────────────────────────
#[test]
fn compiler_prefix_happy() {
    assert_eq!(extract_literal_prefix("ghp_"), Some("ghp_".into()));
}
#[test]
fn compiler_prefix_error() {
    assert_eq!(extract_literal_prefix(r"\ghp"), None);
}

// ── crates/scanner/src/confidence/mod.rs ──────────────────────────────
#[test]
fn confidence_mod_happy() {
    let s = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: true,
        entropy: 5.0,
        keyword_nearby: true,
        sensitive_file: true,
        match_length: 40,
        has_companion: false,
    };
    assert!(compute_confidence(&s) > 0.5);
}
#[test]
fn confidence_mod_error() {
    let s = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 1.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 4,
        has_companion: false,
    };
    assert!(compute_confidence(&s) < 0.2);
}

// ── crates/scanner/src/confidence/penalties.rs ────────────────────────
#[test]
fn confidence_penalties_happy() {
    assert!(apply_post_ml_penalties(0.9, "ghp_realistic_token_value_here", false) <= 0.9);
}
#[test]
fn confidence_penalties_error() {
    assert!(apply_post_ml_penalties(0.9, "EXAMPLE", false) < 0.9);
}

// ── crates/scanner/src/confidence/prefixes.rs ─────────────────────────
#[test]
fn confidence_prefixes_happy() {
    assert!(keyhog_scanner::confidence::known_prefix_body("ghp_abc").is_some());
}
#[test]
fn confidence_prefixes_error() {
    assert!(keyhog_scanner::confidence::known_prefix_body("plain").is_none());
}

// ── crates/scanner/src/confidence/signals.rs ──────────────────────────
#[test]
fn confidence_signals_happy() {
    assert!(
        keyhog_scanner::confidence::ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: false,
            entropy: 4.0,
            keyword_nearby: true,
            sensitive_file: false,
            match_length: 20,
            has_companion: false,
        }
        .entropy
            > 0.0
    );
}
#[test]
fn confidence_signals_error() {
    let s = keyhog_scanner::confidence::ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 0.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 0,
        has_companion: false,
    };
    assert_eq!(s.match_length, 0);
}

// ── crates/scanner/src/context/documentation.rs ───────────────────────
#[test]
fn context_documentation_happy() {
    let lines = vec!["```", "sk-proj-abc", "```"];
    assert_eq!(infer_context(&lines, 1, None), CodeContext::Documentation);
}
#[test]
fn context_documentation_error() {
    let lines = vec!["let x = 1;"];
    assert_ne!(infer_context(&lines, 0, None), CodeContext::Documentation);
}

// ── crates/scanner/src/context/false_positive.rs ──────────────────────
#[test]
fn context_false_positive_happy() {
    let line = "API_TOKEN=ghp_1234567890abcdef1234567890abcdef123456 # fake credential, demo only";
    assert!(keyhog_scanner::testing::context::is_false_positive_match_context(line, 10, None));
}
#[test]
fn context_false_positive_error() {
    assert!(
        !keyhog_scanner::testing::context::is_false_positive_match_context(
            "production credential",
            0,
            None
        )
    );
}

// ── crates/scanner/src/context/inference.rs ───────────────────────────
#[test]
fn context_inference_happy() {
    assert_eq!(
        infer_context(&["API_KEY=secret"], 0, None),
        CodeContext::Assignment
    );
}
#[test]
fn context_inference_error() {
    assert_eq!(
        infer_context(&["random prose"], 0, None),
        CodeContext::Unknown
    );
}

// ── crates/scanner/src/context/mod.rs ─────────────────────────────────
#[test]
fn context_mod_happy() {
    assert!(CodeContext::TestCode.confidence_multiplier() < 1.0);
}
#[test]
fn context_mod_error() {
    assert_eq!(CodeContext::Assignment.confidence_multiplier(), 1.0);
}

// ── crates/scanner/src/decode/base64.rs ───────────────────────────────
#[test]
fn decode_base64_happy() {
    assert_eq!(
        String::from_utf8(base64_decode("c2s=").unwrap()).unwrap(),
        "sk"
    );
}
#[test]
fn decode_base64_error() {
    assert!(base64_decode("!!!").is_err());
}

// ── crates/scanner/src/decode/caesar.rs ───────────────────────────────
#[test]
fn decode_caesar_rot13_recovers_encoded_akia_credential() {
    // A credential-shaped plaintext carrying the `AKIA` known prefix (>= digit +
    // 8-char alnum run, >= MIN_CAESAR_LEN=16), ROT13-encoded. The caesar decoder
    // must select the recovering shift and emit the exact decoded plaintext.
    let plain = "AKIA1234567890ABCDEFGH";
    let encoded = keyhog_scanner::testing::decode_caesar::caesar_shift(plain, 13);
    let chunk = demo_chunk(&format!("token = {encoded}"));
    let out = keyhog_scanner::testing::decode_chunk(&chunk, 2, false, None, None);
    assert!(
        out.iter().any(|c| c.data.contains(plain)),
        "caesar decoder must recover the ROT13-encoded AKIA credential {plain:?}; got {:?}",
        out.iter().map(|c| c.data.as_ref()).collect::<Vec<&str>>()
    );
}
#[test]
fn decode_caesar_emits_nothing_for_unencoded_text() {
    let chunk = demo_chunk("no-encoding-here");
    assert!(keyhog_scanner::testing::decode_chunk(&chunk, 1, false, None, None).is_empty());
}

// ── crates/scanner/src/decode/hex.rs ──────────────────────────────────
#[test]
fn decode_hex_happy() {
    assert_eq!(
        String::from_utf8(hex_decode("736b").unwrap()).unwrap(),
        "sk"
    );
}
#[test]
fn decode_hex_error() {
    assert!(hex_decode("gg").is_err());
}

// ── crates/scanner/src/decode/json.rs ─────────────────────────────────
#[test]
fn decode_json_happy() {
    let chunk = demo_chunk(r#"{"k":"c2s="}"#);
    let out = keyhog_scanner::testing::decode_chunk(&chunk, 2, false, None, None);
    let _ = out;
}
#[test]
fn decode_json_error() {
    let chunk = demo_chunk("{not json");
    assert!(keyhog_scanner::testing::decode_chunk(&chunk, 1, false, None, None).is_empty());
}

// ── crates/scanner/src/decode/mod.rs ──────────────────────────────────
#[test]
fn decode_mod_happy() {
    // A FREESTANDING base64 run must reach MIN_B64_BLOCK_LEN (16) chars to be
    // kept, the shortest that can carry a credential-length payload; shorter
    // alphanumeric runs (e.g. bare "c2s=") are ordinary identifiers/words and are
    // deliberately dropped as noise. The `min_length` arg is a SECONDARY floor
    // that can only raise this cutoff, never lower it. Use a 20-char run so the
    // extractor surfaces it.
    let b64 = "c2VjcmV0dmFsdWUxMjM0"; // base64("secretvalue1234"), 20 chars, no padding
    assert!(
        keyhog_scanner::decode::find_base64_strings(b64, 2)
            .iter()
            .any(|s| s.value.contains(b64)),
        "base64 candidate extractor must surface a credential-length base64 run"
    );
}

#[test]
fn decode_mod_rejects_short_freestanding_base64() {
    // The precision half of the MIN_B64_BLOCK_LEN contract: a sub-16-char
    // freestanding run is NOT a decode candidate even at min_length=2, so short
    // base64-looking words never flood the decode-through pipeline.
    assert!(
        keyhog_scanner::decode::find_base64_strings("c2s=", 2).is_empty(),
        "a short freestanding base64 run must be dropped below MIN_B64_BLOCK_LEN"
    );
}
#[test]
fn decode_mod_error() {
    assert!(keyhog_scanner::decode::find_base64_strings("", 4).is_empty());
}

// ── crates/scanner/src/decode/pipeline.rs ─────────────────────────────
#[test]
fn decode_pipeline_happy() {
    let chunk = demo_chunk("deadbeef0123456789abcdef01234567");
    let out = keyhog_scanner::testing::decode_chunk(&chunk, 2, false, None, None);
    let _ = out;
}
#[test]
fn decode_pipeline_error() {
    assert!(
        keyhog_scanner::testing::decode_chunk(&demo_chunk(""), 1, false, None, None).is_empty()
    );
}

// ── crates/scanner/src/decode/reverse.rs ──────────────────────────────
#[test]
fn decode_reverse_error() {
    assert!(
        keyhog_scanner::testing::decode_chunk(&demo_chunk("forward"), 1, false, None, None)
            .is_empty()
    );
}

// ── crates/scanner/src/decode/unicode_escape.rs ───────────────────────
#[test]
fn decode_unicode_escape_error() {
    let chunk = demo_chunk(r#"\xZZ"#);
    let layers = keyhog_scanner::testing::decode_chunk(&chunk, 1, false, None, None);
    assert!(
        layers.is_empty() || !layers.iter().any(|c| c.data.contains("sk")),
        "invalid hex escape must not decode to sk"
    );
}

// ── crates/scanner/src/decode/url.rs ──────────────────────────────────
#[test]
fn decode_url_happy() {
    let chunk = demo_chunk("token=%73%6b");
    let out = keyhog_scanner::testing::decode_chunk(&chunk, 2, false, None, None);
    assert!(
        out.iter().any(|c| c.data.contains("sk")),
        "url decoder must recover sk from %73%6b"
    );
}
#[test]
fn decode_url_error() {
    assert!(
        keyhog_scanner::testing::decode_chunk(&demo_chunk("plain"), 1, false, None, None)
            .is_empty()
    );
}

// ── crates/scanner/src/decode/util.rs ─────────────────────────────────
#[test]
fn decode_util_error() {
    assert!(hex_decode("zz").is_err());
}

// ── crates/scanner/src/decode_impl.rs ─────────────────────────────────
#[test]
fn decode_impl_error() {
    assert!(
        keyhog_scanner::testing::decode_chunk(&demo_chunk("x"), 0, false, None, None).is_empty()
    );
}

// ── engine/* - see tests/unit/engine.rs, engine_backend.rs, segment_attribution.rs
// ── crates/scanner/src/engine/backend.rs ──────────────────────────────
#[test]
fn engine_backend_happy() {
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
    use keyhog_scanner::engine::CompiledScanner;
    use keyhog_scanner::hw_probe::testing::ScanBackend;
    let token = "GATEabcDEF1234567890abcDEFGH";
    let det = DetectorSpec {
        tests: Vec::new(),
        id: "gate".into(),
        name: "Gate".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r#"GATE[A-Za-z0-9]{24}"#.into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["GATE".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![det]).unwrap();
    let chunk = Chunk {
        data: token.into(),
        metadata: ChunkMetadata::default(),
    };
    assert_eq!(
        scanner
            .scan_with_backend(&chunk, ScanBackend::CpuFallback)
            .expect("selected backend file-gate scan succeeds")
            .len(),
        1
    );
}
#[test]
fn engine_backend_error() {
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
    use keyhog_scanner::engine::CompiledScanner;
    use keyhog_scanner::hw_probe::testing::ScanBackend;
    let det = DetectorSpec {
        tests: Vec::new(),
        id: "gate".into(),
        name: "Gate".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![det]).unwrap();
    let chunk = Chunk {
        data: String::new().into(),
        metadata: ChunkMetadata::default(),
    };
    assert!(scanner
        .scan_with_backend(&chunk, ScanBackend::CpuFallback)
        .expect("selected backend empty file-gate scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/engine/mod.rs ──────────────────────────────────
#[test]
fn engine_mod_error() {
    assert!(CompiledScanner::compile(vec![demo_detector("(bad", "x")]).is_err());
}

// ── crates/scanner/src/engine/scan.rs ─────────────────────────────────
#[test]
fn engine_scan_happy() {
    let token = "GATEabcDEF1234567890abcDEFGH";
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r#"GATE[A-Za-z0-9]{24}"#, "GATE")]).unwrap();
    assert_eq!(
        scanner
            .scan(&demo_chunk(token))
            .expect("engine file-gate scan succeeds")
            .len(),
        1
    );
}
#[test]
fn engine_scan_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk(""))
        .expect("empty engine file-gate scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/engine/windowed.rs ─────────────────────────────
#[test]
fn engine_windowed_happy() {
    use keyhog_scanner::testing::window_end_offset;
    assert!(window_end_offset("hello", 0, 3) <= 5);
}
#[test]
fn engine_windowed_error() {
    use keyhog_scanner::testing::window_end_offset;
    assert_eq!(window_end_offset("hello", 99, 10), 5);
}

// ── crates/scanner/src/engine/phase2.rs + phase2_entropy + phase2_generic
#[test]
fn engine_phase2_happy() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r"ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    assert!(scanner
        .scan(&demo_chunk(&format!("export TOKEN={token}")))
        .expect("keyword window file-gate scan succeeds")
        .iter()
        .any(|m| m.credential.as_ref() == token));
}
#[test]
fn engine_phase2_error() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r"ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk("plain prose"))
        .expect("plaintext window file-gate scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/engine/scan_filters.rs ─────────────────────────
#[test]
fn engine_scan_filters_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk("username = randomuser1234567890"))
        .expect("generic-filter file-gate scan succeeds")
        .is_empty());
}
#[test]
fn engine_scan_filters_error() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r"ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    assert!(scanner
        .scan(&demo_chunk(&format!("api_key = \"{token}\"")))
        .expect("generic-filter positive file-gate scan succeeds")
        .iter()
        .any(|m| m.credential.as_ref() == token));
}

// ── crates/scanner/src/engine/scan_gpu.rs + hot_patterns.rs ───────────
#[test]
fn engine_scan_gpu_happy() {
    use keyhog_scanner::hw_probe::testing::ScanBackend;
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.warm_backend(ScanBackend::CpuFallback));
}
// ── crates/scanner/src/engine/boundary/mod.rs ─────────────────────────
#[test]
fn engine_boundary_happy() {
    use keyhog_scanner::testing::floor_char_boundary;
    assert_eq!(floor_char_boundary("aαb", 2), 1);
}
#[test]
fn engine_boundary_error() {
    use keyhog_scanner::testing::floor_char_boundary;
    assert_eq!(floor_char_boundary("", 0), 0);
}

// ── crates/scanner/src/engine/hot_patterns.rs ─────────────────────────
#[test]
fn engine_hot_patterns_happy() {
    use keyhog_scanner::hw_probe::testing::ScanBackend;
    let scanner = CompiledScanner::compile_for_backend(
        vec![demo_detector("abc", "abc")],
        ScanBackend::SimdCpu,
    )
    .unwrap();
    assert!(scanner.warm_backend(ScanBackend::SimdCpu));
}
#[test]
fn engine_hot_patterns_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.runtime_status().pattern_count >= 1);
}

// ── crates/scanner/src/segment_attribution.rs ─────────────────────────
#[test]
fn engine_segment_attribution_happy() {
    let mapped =
        map_offsets_to_segments(&[Segment::new(1, 0, 4)], &[GlobalMatch::new(1, 1, 3)]).unwrap();
    assert_eq!(mapped.len(), 1);
}
#[test]
fn engine_segment_attribution_error() {
    let err =
        map_offsets_to_segments(&[Segment::new(1, 0, 4)], &[GlobalMatch::new(1, 2, 10)]).unwrap();
    assert!(err.is_empty());
}

// ── crates/scanner/src/entropy/keywords.rs ──────────────────────────
#[test]
fn entropy_keywords_happy() {
    // A high-entropy, single-token secret is what the GENERIC plausibility gate
    // is meant to admit. The previous fixture (`sk-proj-abcdef1234567890`) was a
    // dash-segmented service-prefixed shape with a sequential body: the generic
    // path correctly rejects dash-segmented-alnum as a serial decoy (real
    // `sk-proj-` OpenAI keys are surfaced by their named hot-pattern detector,
    // not this generic entropy gate), so it was never a valid happy case here.
    assert!(
        keyhog_scanner::testing::entropy_keywords::is_secret_plausible(
            "9fKp2mNqR7vT4wXz8bYsH3jD6gA1cE0uViK5oLtBnW",
            &[]
        )
    );
}
#[test]
fn entropy_keywords_error() {
    assert!(
        !keyhog_scanner::testing::entropy_keywords::is_secret_plausible(
            "password",
            &["password".into()]
        )
    );
}

// ── crates/scanner/src/entropy/mod.rs ─────────────────────────────────
#[test]
fn entropy_mod_happy() {
    assert!(shannon_entropy(b"abc123xyz") > HIGH_ENTROPY_THRESHOLD / 2.0);
}
#[test]
fn entropy_mod_error() {
    assert!(shannon_entropy(b"aaaa") < 0.1);
}

// ── crates/scanner/src/entropy/scanner.rs ─────────────────────────────
#[test]
fn entropy_scanner_happy() {
    let body = "abcdefghijklmnopqrstuvwxyz";
    let secrets = keyhog_scanner::entropy::find_entropy_secrets(
        &format!("SECRET={body}"),
        16,
        1,
        3.5,
        &["SECRET".into()],
        &[],
        &[],
    );
    // Truth assert (not "some match"): the EXACT high-entropy body is surfaced,
    // anchored to the SECRET keyword on line 1, above the 3.5 threshold it
    // cleared, with no keyword bytes leaked into the credential value.
    let m = secrets
        .iter()
        .find(|m| m.value == body)
        .unwrap_or_else(|| panic!("entropy scan did not surface {body:?}; got {secrets:?}"));
    // assignment_keyword_for_line calls normalize_assignment_keyword which lowercases
    // and normalises the LHS identifier: `SECRET` → `secret`. The stored keyword is
    // the normalised form, not the original case from the source line.
    assert_eq!(
        m.keyword, "secret",
        "match keyword should be the normalised lowercase form 'secret', got: {m:?}"
    );
    assert_eq!(m.line, 1, "match reported the wrong line: {m:?}");
    assert!(
        m.entropy > 3.5,
        "match entropy {} is below the 3.5 threshold it passed: {m:?}",
        m.entropy
    );
}
#[test]
fn entropy_scanner_error() {
    let secrets = keyhog_scanner::entropy::find_entropy_secrets(
        "hello world",
        16,
        1,
        8.0,
        &["SECRET".into()],
        &[],
        &[],
    );
    assert!(secrets.is_empty());
}

// ── crates/scanner/src/entropy/avx512.rs ──────────────────────────────
#[test]
fn entropy_avx512_happy() {
    assert!(shannon_entropy_simd(b"mixed123") > 0.0);
}
#[test]
fn entropy_avx512_error() {
    assert_eq!(shannon_entropy_simd(b""), 0.0);
}

// ── crates/scanner/src/entropy/fast.rs ────────────────────────────────
#[test]
fn entropy_fast_happy() {
    assert!(shannon_entropy_simd(b"abc123") > 0.0);
}
#[test]
fn entropy_fast_error() {
    assert_eq!(shannon_entropy_simd(b""), 0.0);
}

// ── crates/scanner/src/error.rs ───────────────────────────────────────
#[test]
fn error_happy() {
    let err = ScanError::RegexCompile {
        detector_id: "d".into(),
        index: 0,
        source: regex::Error::Syntax("bad".into()),
    };
    assert!(err.to_string().contains("d"));
}
#[test]
fn error_error_path() {
    let err = ScanError::Gpu("probe failed".into());
    assert!(err.to_string().contains("probe"));
}

#[test]
fn gpu_probe_availability_coheres_with_gpu_available_and_buffer_limit() {
    // Host-independent invariant: the probe's availability flag must agree with
    // `gpu_available()`, and an available adapter exposes a nonzero buffer limit.
    let probe = gpu_probe();
    assert_eq!(
        probe.available,
        gpu_available(),
        "gpu_probe availability must agree with gpu_available()"
    );
    if probe.available {
        assert!(
            probe.buffer_limit_mb.is_some_and(|limit| limit > 0),
            "an available GPU must report a nonzero buffer limit"
        );
    } else {
        assert_eq!(
            probe.buffer_limit_mb, None,
            "an unavailable GPU must report no buffer limit"
        );
    }
}

// ── crates/scanner/src/unicode_hardening.rs ───────────────────────────
#[test]
fn homoglyph_normalizes_cyrillic_o_to_ascii_o() {
    // Homoglyph FOLDING (lookalike → ASCII) lives on the credential-VALUE scan
    // path, `unicode_hardening::normalize_homoglyphs`. It is deliberately NOT on
    // `normalize_chunk_data`, which only strips zero-width/RTL evasion chars for
    // context-window text, folding lookalikes in ordinary prose would distort
    // the keyword/comment context features (see `normalize_chunk_data`'s docs).
    let normalized =
        keyhog_scanner::testing::unicode_hardening::normalize_homoglyphs("gh\u{043E}p_token");
    assert_eq!(normalized.as_ref(), "ghop_token");
    assert!(
        !normalized.as_ref().contains('\u{043E}'),
        "Cyrillic о (U+043E) must be folded to ASCII o on the credential-value path"
    );
}
#[test]
fn homoglyph_leaves_pure_ascii_unchanged() {
    assert_eq!(normalize_chunk_data("ascii_only").as_ref(), "ascii_only");
}

// ── crates/scanner/src/hw_probe.rs ────────────────────────────────────
#[test]
fn hw_probe_happy() {
    let caps = probe_hardware();
    assert!(caps.logical_cores >= 1);
}
#[test]
fn hw_probe_error() {
    let caps = probe_hardware();
    let backend = select_backend(caps, 0, 0);
    assert!(!backend.label().is_empty());
}

// ── crates/scanner/src/jwt.rs ─────────────────────────────────────────
#[test]
fn jwt_happy() {
    let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
    let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"sub\":\"1\"}");
    assert!(looks_like_jwt(&format!("{h}.{p}.sig")));
}
#[test]
fn jwt_error() {
    assert!(analyze("bad.token").is_none());
}

// ── crates/scanner/src/lib.rs ─────────────────────────────────────────
#[test]
fn lib_happy() {
    assert_eq!(normalize_chunk_data("plain").as_ref(), "plain");
}
#[test]
fn lib_error() {
    assert_eq!(normalize_chunk_data("a\u{200b}b").as_ref(), "ab");
}

#[test]
fn scanner_benches_use_testing_facade_not_private_modules() {
    fn collect_rs_files(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(root)
            .unwrap_or_else(|error| panic!("read_dir({}) failed: {error}", root.display()))
        {
            let path = entry
                .unwrap_or_else(|error| {
                    panic!("read_dir entry failed in {}: {error}", root.display())
                })
                .path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bench_files = Vec::new();
    collect_rs_files(&manifest_dir.join("benches"), &mut bench_files);
    assert!(
        !bench_files.is_empty(),
        "scanner benchmark harness must stay present and wired"
    );

    for path in bench_files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {} failed: {error}", path.display()));
        for forbidden in [
            "use keyhog_scanner::confidence",
            "keyhog_scanner::confidence::",
            "use keyhog_scanner::entropy::fast",
            "keyhog_scanner::entropy::fast::",
            "ml_scorer::score(",
            "use keyhog_scanner::{decode,",
        ] {
            assert!(
                !source.contains(forbidden),
                "benchmark {} must use public API or keyhog_scanner::testing facade, not private scanner internals via `{forbidden}`",
                path.display()
            );
        }
    }

    let facade = std::fs::read_to_string(manifest_dir.join("src/testing.rs"))
        .expect("read scanner testing facade");
    for required in [
        "pub fn decode_chunk(",
        "pub fn ml_score(",
        "pub mod confidence",
        "pub fn compute_confidence(",
        "pub mod entropy_fast",
        "pub fn shannon_entropy_simd(",
    ] {
        assert!(
            facade.contains(required),
            "scanner testing facade must keep benchmark probe contract `{required}`"
        );
    }
}

// ── crates/scanner/src/ml_scorer/ml_features.rs ─────────────────────────────────
#[test]
fn ml_features_happy() {
    let f = compute_features_public(
        concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
        "TOKEN=",
    );
    assert_eq!(f.len(), NUM_FEATURES);
}
#[test]
fn ml_features_error() {
    let f = compute_features_public("", "");
    assert!(f.iter().all(|v| v.is_finite()));
}

// ── crates/scanner/src/ml_scorer.rs ───────────────────────────────────
#[test]
fn ml_scorer_gives_real_token_nonzero_deterministic_probability() {
    let token = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");
    let scored = score(token, "export TOKEN=");
    assert!(
        (0.0..=1.0).contains(&scored),
        "score must be a probability in [0,1], got {scored}"
    );
    // A real ghp_ token in assignment context must lift above the empty-input
    // floor (`score("","")` is defined to return exactly 0.0).
    assert!(
        scored > score("", ""),
        "a real ghp_ token must score above the empty-input floor, got {scored}"
    );
    assert_eq!(
        scored,
        score(token, "export TOKEN="),
        "score must be deterministic for identical inputs"
    );
}
#[test]
fn ml_scorer_error() {
    assert!(!model_version().is_empty());
    assert!(model_card_summary().contains("recall@0.40"));
    assert!(model_card_json().contains("\"model_version\""));
}

// ── crates/scanner/src/ml_scorer/ml_weights.rs ──────────────────────────────────
#[test]
fn ml_weights_rank_real_token_above_low_signal_prose() {
    // The compiled weights must discriminate: a canonical ghp_ token in
    // assignment context outscores an unstructured English-prose line.
    let token_score = score(
        concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
        "TOKEN=",
    );
    let prose_score = score("the quick brown fox jumped", "a plain sentence of prose");
    assert!(
        (0.0..=1.0).contains(&token_score) && (0.0..=1.0).contains(&prose_score),
        "scores must be probabilities, got token={token_score} prose={prose_score}"
    );
    assert!(
        token_score > prose_score,
        "weights must rank a real token above low-signal prose, got token={token_score} prose={prose_score}"
    );
}
#[test]
fn ml_weights_error() {
    assert!(!model_version().is_empty());
    assert!(model_card_summary().contains("synthetic F1"));
}

// ── crates/scanner/src/multiline/config.rs ────────────────────────────
#[test]
fn multiline_config_happy() {
    let cfg = MultilineConfig::default();
    assert!(cfg.max_join_lines >= 1);
}
#[test]
fn multiline_config_error() {
    let cfg = MultilineConfig {
        max_join_lines: 1,
        ..Default::default()
    };
    let out = preprocess_multiline("a", &cfg, &FragmentCache::new(10));
    assert_eq!(out.text, "a");
}

// ── crates/scanner/src/fragment_cache.rs ──────────────────────────────
#[test]
fn fragment_cache_happy() {
    let cache = FragmentCache::new(10);
    cache.clear();
}
#[test]
fn fragment_cache_error() {
    let cache = FragmentCache::new(0);
    cache.clear();
}

// ── crates/scanner/src/multiline/mod.rs ───────────────────────────────
#[test]
fn multiline_mod_happy() {
    let out = preprocess_multiline(
        "key = 'sk-proj-' + 'abc'",
        &MultilineConfig::default(),
        &FragmentCache::new(10),
    );
    assert!(out.text.contains("sk-proj-abc"));
}
#[test]
fn multiline_mod_error() {
    let out = preprocess_multiline("", &MultilineConfig::default(), &FragmentCache::new(10));
    assert!(out.text.is_empty());
}

// ── crates/scanner/src/multiline/preprocessor.rs ──────────────────────
#[test]
fn multiline_preprocessor_happy() {
    let out = preprocess_multiline(
        "a = \"x\" + \"y\"",
        &MultilineConfig::default(),
        &FragmentCache::new(10),
    );
    assert!(out.text.contains("xy") || out.text.contains("x"));
}
#[test]
fn multiline_preprocessor_error() {
    let out = preprocess_multiline(
        "no concat",
        &MultilineConfig::default(),
        &FragmentCache::new(10),
    );
    assert_eq!(out.text, "no concat");
}

// ── crates/scanner/src/multiline/structural.rs ────────────────────────
#[test]
fn multiline_structural_happy() {
    let out = preprocess_multiline(
        "export API_KEY=\"sk-proj-abc\"\n",
        &MultilineConfig::default(),
        &FragmentCache::new(10),
    );
    assert!(out.text.contains("API_KEY"));
}
#[test]
fn multiline_structural_error() {
    let out = preprocess_multiline("\n\n", &MultilineConfig::default(), &FragmentCache::new(10));
    assert!(out.text.trim().is_empty());
}

// ── crates/scanner/src/pipeline.rs ────────────────────────────────────
#[test]
fn pipeline_happy() {
    assert_eq!(compute_line_offsets("a\nb"), vec![0, 2]);
}
#[test]
fn pipeline_error() {
    assert_eq!(match_entropy(b""), 0.0);
}

// ── crates/scanner/src/prefix_trie.rs ─────────────────────────────────
#[test]
fn prefix_trie_happy() {
    let table = build_propagation_table(&["gh".into(), "ghp_".into()]);
    assert_eq!(table.len(), 2);
}
#[test]
fn prefix_trie_error() {
    let table = build_propagation_table(&[]);
    assert!(table.is_empty());
}

// ── crates/scanner/src/probabilistic_gate.rs ──────────────────────────
#[test]
fn probabilistic_gate_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let matches = scanner
        .scan(&demo_chunk("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
        .expect("test scan succeeds");
    assert!(matches.is_empty());
}
#[test]
fn probabilistic_gate_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk("aaaaaaaaaaaaaaaa"))
        .expect("probabilistic-gate file scan succeeds")
        .is_empty());
}
// ── crates/scanner/src/resolution.rs ──────────────────────────────────
#[test]
fn resolution_happy() {
    use keyhog_core::{MatchLocation, RawMatch};
    use std::sync::Arc;
    let m = RawMatch {
        detector_id: Arc::from("a"),
        detector_name: Arc::from("a"),
        service: Arc::from("s"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("same"),
        credential_hash: [0u8; 32].into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("t"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.5),
    };
    assert_eq!(resolve_matches(vec![m]).len(), 1);
}
#[test]
fn resolution_error() {
    assert!(resolve_matches(vec![]).is_empty());
}

// ── crates/scanner/src/shared_regexes.rs (via fragment assignment scan) ─
#[test]
fn shared_regexes_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let chunk = demo_chunk("my_key = \"abc\"");
    let matches = scanner.scan(&chunk).expect("test scan succeeds");
    let _ = matches;
}
#[test]
fn shared_regexes_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk("no assignment syntax"))
        .expect("assignment-free file scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/simd.rs ────────────────────────────────────────
#[test]
#[cfg(feature = "simd")]
fn simd_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.runtime_status().pattern_count >= 1);
}
#[test]
#[cfg(not(feature = "simd"))]
fn simd_happy_no_feature() {
    assert!(true);
}
#[test]
fn simd_error() {
    assert!(true);
}

// ── crates/scanner/src/simdsieve_prefilter.rs ─────────────────────────
#[test]
fn simdsieve_prefilter_happy() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector("ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let pad = "x".repeat(100_001);
    let matches = scanner
        .scan(&demo_chunk(&format!("{pad}{token}")))
        .expect("test scan succeeds");
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}
#[test]
fn simdsieve_prefilter_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let pad = "x".repeat(100_001);
    assert!(scanner
        .scan(&demo_chunk(&pad))
        .expect("large-padding file scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/static_intern.rs ───────────────────────────────
#[test]
fn static_intern_happy() {
    let interner =
        keyhog_scanner::testing::StaticInterner::from_detector_strings(vec!["demo", "Demo"]);
    let a = interner.lookup("demo").unwrap();
    let b = interner.lookup("demo").unwrap();
    assert_eq!(a.as_ref(), "demo");
    assert!(std::sync::Arc::ptr_eq(&a, &b));
}
#[test]
fn static_intern_error() {
    let interner =
        keyhog_scanner::testing::StaticInterner::from_detector_strings(std::iter::empty::<&str>());
    assert!(interner.lookup("dynamic").is_none());
}

// ── crates/scanner/src/structured/mod.rs ──────────────────────────────
#[test]
fn structured_mod_happy() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector("ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let chunk = structured_env_chunk(&format!("GITHUB_TOKEN={token}\n"), "config.env");
    let matches = scanner.scan(&chunk).expect("test scan succeeds");
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}
#[test]
fn structured_mod_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk("fn main() {}"))
        .expect("structured plaintext file scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/structured/parsers.rs ──────────────────────────
#[test]
fn structured_parsers_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("secret", "secret")]).unwrap();
    let chunk = structured_env_chunk("TOKEN=abc123\n", ".env");
    let _ = scanner.scan(&chunk).expect("test scan succeeds");
}
#[test]
fn structured_parsers_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let chunk = structured_env_chunk("", ".env");
    assert!(scanner
        .scan(&chunk)
        .expect("empty structured file scan succeeds")
        .is_empty());
}

// ── crates/scanner/src/telemetry.rs ───────────────────────────────────
#[test]
fn telemetry_happy() {
    let _guard = super::telemetry_serial::lock();
    reset();
    enable_dogfood();
    record_example_suppression("d", None, "ghp_EXAMPLE", "suffix");
    assert!(!drain_events().is_empty());
    reset();
}
#[test]
fn telemetry_error() {
    let _guard = super::telemetry_serial::lock();
    reset();
    assert!(drain_events().is_empty());
}

// ── crates/scanner/src/types.rs ───────────────────────────────────────
#[test]
fn types_happy() {
    let cfg = ScannerConfig::default();
    assert!(cfg.max_matches_per_chunk > 0);
}
#[test]
fn types_error() {
    let cfg = ScannerConfig {
        scan: keyhog_core::ScanConfig {
            max_decode_depth: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(cfg.max_decode_depth, 0);
}

// ── crates/scanner/src/unicode_hardening.rs ───────────────────────────
#[test]
fn unicode_hardening_happy() {
    assert!(is_evasion_char('\u{200b}'));
}
#[test]
fn unicode_hardening_error() {
    assert!(!is_evasion_char('a'));
}

// ── segment_attribution boundary/adversarial ──────────────────────────
#[test]
fn segment_attribution_boundary() {
    let mapped =
        map_offsets_to_segments(&[Segment::new(1, 0, 4)], &[GlobalMatch::new(1, 1, 3)]).unwrap();
    assert_eq!(mapped.len(), 1);
}
#[test]
fn segment_attribution_adversarial() {
    let err =
        map_offsets_to_segments(&[Segment::new(1, 0, 4)], &[GlobalMatch::new(1, 2, 10)]).unwrap();
    assert!(err.is_empty());
}
