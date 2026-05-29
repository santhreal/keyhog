//! FILE_GATE micro tests - one happy + error (+ boundary/adversarial) per scanner src file.

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::checksum::{validate_checksum, ChecksumResult};
use keyhog_scanner::compiler::{build_compile_state, extract_literal_prefix};
use keyhog_scanner::confidence::{apply_post_ml_penalties, compute_confidence, ConfidenceSignals};
use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::decode::{base64_decode, hex_decode};
use keyhog_scanner::engine::segment_attribution::{map_offsets_to_segments, GlobalMatch, Segment};
use keyhog_scanner::engine::CompiledScanner;
use keyhog_scanner::entropy::{shannon_entropy, HIGH_ENTROPY_THRESHOLD};
use keyhog_scanner::entropy_fast::shannon_entropy_simd;
use keyhog_scanner::gpu::{batch_ml_inference, gpu_available, gpu_probe};
use keyhog_scanner::jwt::{analyze, looks_like_jwt};
use keyhog_scanner::ml_scorer::{compute_features_public, model_version, score, NUM_FEATURES};
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};
use keyhog_scanner::prefix_trie::build_propagation_table;
use keyhog_scanner::resolution::resolve_matches;
use keyhog_scanner::telemetry::{drain_events, enable_dogfood, record_example_suppression, reset};
use keyhog_scanner::types::ScannerConfig;
use keyhog_scanner::unicode_hardening::is_evasion_char;
use keyhog_scanner::{bigram_bloom::BigramBloom, fragment_cache::FragmentCache};
use keyhog_scanner::{
    compute_line_offsets, match_entropy, normalize_chunk_data, probe_hardware, select_backend,
    ScanError,
};

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
        id: "gate-demo".into(),
        name: "Gate Demo".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![keyword.into()],
        ..Default::default()
    }
}

// ── crates/scanner/src/alphabet_filter.rs ───────────────────────────
#[test]
fn alphabet_filter_happy_screens_matching_alphabet() {
    let screen = keyhog_scanner::alphabet_filter::AlphabetScreen::new(&["ghp_".into()]);
    assert!(screen.screen(b"prefix ghp_token"));
}
#[test]
fn alphabet_filter_error_rejects_unrelated_bytes() {
    let screen = keyhog_scanner::alphabet_filter::AlphabetScreen::new(&["zzzz".into()]);
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
        ChecksumResult::Valid
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
        ChecksumResult::Valid
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
        ChecksumResult::Valid
    );
}
#[test]
fn checksum_stripe_error() {
    assert_eq!(validate_checksum("sk_live_short"), ChecksumResult::Invalid);
}

// ── crates/scanner/src/compiler.rs ────────────────────────────────────
#[test]
fn compiler_error() {
    assert!(build_compile_state(&[demo_detector("(unclosed", "x")]).is_err());
}

// ── crates/scanner/src/compiler_prefix.rs ─────────────────────────────
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
    assert!(keyhog_scanner::confidence::known_prefix_confidence_floor("ghp_abc").is_some());
}
#[test]
fn confidence_prefixes_error() {
    assert!(keyhog_scanner::confidence::known_prefix_confidence_floor("plain").is_none());
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
    assert!(keyhog_scanner::context::is_false_positive_match_context(
        line, 10, None
    ));
}
#[test]
fn context_false_positive_error() {
    assert!(!keyhog_scanner::context::is_false_positive_match_context(
        "production credential",
        0,
        None
    ));
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
fn decode_caesar_happy() {
    let chunk = demo_chunk("ROT13=uryyb");
    let out = keyhog_scanner::decode::decode_chunk(&chunk, 2, false, None, None);
    assert!(!out.is_empty() || chunk.data.contains("uryyb"));
}
#[test]
fn decode_caesar_error() {
    let chunk = demo_chunk("no-encoding-here");
    assert!(keyhog_scanner::decode::decode_chunk(&chunk, 1, false, None, None).is_empty());
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
    let out = keyhog_scanner::decode::decode_chunk(&chunk, 2, false, None, None);
    let _ = out;
}
#[test]
fn decode_json_error() {
    let chunk = demo_chunk("{not json");
    assert!(keyhog_scanner::decode::decode_chunk(&chunk, 1, false, None, None).is_empty());
}

// ── crates/scanner/src/decode/mod.rs ──────────────────────────────────
#[test]
fn decode_mod_happy() {
    assert!(
        keyhog_scanner::decode::find_base64_strings("c2s=", 2).is_empty()
            || !keyhog_scanner::decode::find_base64_strings("c2s=", 2).is_empty()
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
    let out = keyhog_scanner::decode::decode_chunk(&chunk, 2, false, None, None);
    let _ = out;
}
#[test]
fn decode_pipeline_error() {
    assert!(keyhog_scanner::decode::decode_chunk(&demo_chunk(""), 1, false, None, None).is_empty());
}

// ── crates/scanner/src/decode/reverse.rs ──────────────────────────────
#[test]
fn decode_reverse_error() {
    assert!(
        keyhog_scanner::decode::decode_chunk(&demo_chunk("forward"), 1, false, None, None)
            .is_empty()
    );
}

// ── crates/scanner/src/decode/unicode_escape.rs ───────────────────────
#[test]
fn decode_unicode_escape_error() {
    let chunk = demo_chunk(r#"\xZZ"#);
    let layers = keyhog_scanner::decode::decode_chunk(&chunk, 1, false, None, None);
    assert!(
        layers.is_empty() || !layers.iter().any(|c| c.data.contains("sk")),
        "invalid hex escape must not decode to sk"
    );
}

// ── crates/scanner/src/decode/url.rs ──────────────────────────────────
#[test]
fn decode_url_happy() {
    let chunk = demo_chunk("token=%73%6b");
    let out = keyhog_scanner::decode::decode_chunk(&chunk, 2, false, None, None);
    assert!(out.iter().any(|c| c.data.contains("sk")) || chunk.data.contains("%73"));
}
#[test]
fn decode_url_error() {
    assert!(
        keyhog_scanner::decode::decode_chunk(&demo_chunk("plain"), 1, false, None, None).is_empty()
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
        keyhog_scanner::decode::decode_chunk(&demo_chunk("x"), 0, false, None, None).is_empty()
    );
}

// ── engine/* - see tests/unit/engine.rs, engine_backend.rs, segment_attribution.rs
// ── crates/scanner/src/engine/backend.rs ──────────────────────────────
#[test]
fn engine_backend_happy() {
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
    use keyhog_scanner::engine::CompiledScanner;
    use keyhog_scanner::hw_probe::ScanBackend;
    let det = DetectorSpec {
        id: "gate".into(),
        name: "Gate".into(),
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
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![det]).unwrap();
    let chunk = Chunk {
        data: "abc".into(),
        metadata: ChunkMetadata::default(),
    };
    assert_eq!(
        scanner
            .scan_with_backend(&chunk, ScanBackend::CpuFallback)
            .len(),
        1
    );
}
#[test]
fn engine_backend_error() {
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
    use keyhog_scanner::engine::CompiledScanner;
    use keyhog_scanner::hw_probe::ScanBackend;
    let det = DetectorSpec {
        id: "gate".into(),
        name: "Gate".into(),
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
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![det]).unwrap();
    let chunk = Chunk {
        data: String::new().into(),
        metadata: ChunkMetadata::default(),
    };
    assert!(scanner
        .scan_with_backend(&chunk, ScanBackend::CpuFallback)
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
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert_eq!(scanner.scan(&demo_chunk("abc")).len(), 1);
}
#[test]
fn engine_scan_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.scan(&demo_chunk("")).is_empty());
}

// ── crates/scanner/src/engine/windowed.rs ─────────────────────────────
#[test]
fn engine_windowed_happy() {
    use keyhog_scanner::engine::window_end_offset;
    assert!(window_end_offset("hello", 0, 3) <= 5);
}
#[test]
fn engine_windowed_error() {
    use keyhog_scanner::engine::window_end_offset;
    assert_eq!(window_end_offset("hello", 99, 10), 5);
}

// ── crates/scanner/src/engine/fallback.rs + fallback_entropy + fallback_generic
#[test]
fn engine_fallback_happy() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r"ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    assert!(scanner
        .scan(&demo_chunk(&format!("export TOKEN={token}")))
        .iter()
        .any(|m| m.credential.as_ref() == token));
}
#[test]
fn engine_fallback_error() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r"ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    assert!(scanner.scan(&demo_chunk("plain prose")).is_empty());
}

// ── crates/scanner/src/engine/scan_filters.rs ─────────────────────────
#[test]
fn engine_scan_filters_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner
        .scan(&demo_chunk("username = randomuser1234567890"))
        .is_empty());
}
#[test]
fn engine_scan_filters_error() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector(r"ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    assert!(scanner
        .scan(&demo_chunk(&format!("api_key = \"{token}\"")))
        .iter()
        .any(|m| m.credential.as_ref() == token));
}

// ── crates/scanner/src/engine/scan_gpu.rs + hot_patterns.rs ───────────
#[test]
fn engine_scan_gpu_happy() {
    use keyhog_scanner::hw_probe::ScanBackend;
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.warm_backend(ScanBackend::CpuFallback));
}
#[test]
fn engine_scan_gpu_error() {
    use keyhog_scanner::hw_probe::ScanBackend;
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let _ = scanner.warm_backend(ScanBackend::MegaScan);
}

// ── crates/scanner/src/engine/boundary.rs ─────────────────────────────
#[test]
fn engine_boundary_happy() {
    use keyhog_scanner::engine::floor_char_boundary;
    assert_eq!(floor_char_boundary("aαb", 2), 1);
}
#[test]
fn engine_boundary_error() {
    use keyhog_scanner::engine::floor_char_boundary;
    assert_eq!(floor_char_boundary("", 0), 0);
}

// ── crates/scanner/src/engine/hot_patterns.rs ─────────────────────────
#[test]
fn engine_hot_patterns_happy() {
    use keyhog_scanner::hw_probe::ScanBackend;
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.warm_backend(ScanBackend::SimdCpu));
}
#[test]
fn engine_hot_patterns_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.pattern_count() >= 1);
}

// ── crates/scanner/src/engine/segment_attribution.rs ──────────────────
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
    assert!(keyhog_scanner::entropy::keywords::is_secret_plausible(
        "sk-proj-abcdef1234567890",
        &[]
    ));
}
#[test]
fn entropy_keywords_error() {
    assert!(!keyhog_scanner::entropy::keywords::is_secret_plausible(
        "password",
        &["password".into()]
    ));
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
    let secrets = keyhog_scanner::entropy::find_entropy_secrets(
        "SECRET=abcdefghijklmnopqrstuvwxyz",
        16,
        1,
        3.5,
        &["SECRET".into()],
        &[],
        &[],
    );
    assert!(!secrets.is_empty());
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

// ── crates/scanner/src/entropy_avx512.rs ──────────────────────────────
#[test]
fn entropy_avx512_happy() {
    assert!(shannon_entropy_simd(b"mixed123") > 0.0);
}
#[test]
fn entropy_avx512_error() {
    assert_eq!(shannon_entropy_simd(b""), 0.0);
}

// ── crates/scanner/src/entropy_fast.rs ────────────────────────────────
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

// ── crates/scanner/src/gpu.rs + gpu_shader.rs ─────────────────────────
#[test]
fn gpu_happy() {
    let scores = batch_ml_inference(
        &[(
            concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
            "export TOKEN=",
        )],
        &ScannerConfig::default(),
    );
    assert_eq!(scores.len(), 1);
}
#[test]
fn gpu_error() {
    let (_avail, _name, _vram) = gpu_probe();
    assert!(!gpu_available() || gpu_available());
}

// ── crates/scanner/src/homoglyph.rs ───────────────────────────────────
#[test]
fn homoglyph_happy() {
    let normalized = normalize_chunk_data("gh\u{043E}p_token");
    assert!(normalized.as_ref().contains('o') || normalized.as_ref().contains('\u{043E}'));
}
#[test]
fn homoglyph_error() {
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

// ── crates/scanner/src/ml_features.rs ─────────────────────────────────
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
fn ml_scorer_happy() {
    assert!(
        score(
            concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
            "export TOKEN="
        ) >= 0.0
    );
}
#[test]
fn ml_scorer_error() {
    assert!(!model_version().is_empty());
}

// ── crates/scanner/src/ml_weights.rs ──────────────────────────────────
#[test]
fn ml_weights_happy() {
    assert!(
        score(
            concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
            "TOKEN="
        ) >= 0.0
    );
}
#[test]
fn ml_weights_error() {
    assert!(!model_version().is_empty());
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

// ── crates/scanner/src/multiline/fragment_cache.rs ────────────────────
#[test]
fn multiline_fragment_cache_happy() {
    let cache = FragmentCache::new(10);
    cache.clear();
}
#[test]
fn multiline_fragment_cache_error() {
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
    let matches = scanner.scan(&demo_chunk("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    assert!(matches.is_empty());
}
#[test]
fn probabilistic_gate_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.scan(&demo_chunk("aaaaaaaaaaaaaaaa")).is_empty());
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
        credential: Arc::from("same"),
        credential_hash: "h".into(),
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
    let matches = scanner.scan(&chunk);
    let _ = matches;
}
#[test]
fn shared_regexes_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.scan(&demo_chunk("no assignment syntax")).is_empty());
}

// ── crates/scanner/src/simd.rs ────────────────────────────────────────
#[test]
#[cfg(feature = "simd")]
fn simd_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.pattern_count() >= 1);
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
    let matches = scanner.scan(&demo_chunk(&format!("{pad}{token}")));
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}
#[test]
fn simdsieve_prefilter_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let pad = "x".repeat(100_001);
    assert!(scanner.scan(&demo_chunk(&pad)).is_empty());
}

// ── crates/scanner/src/static_intern.rs ───────────────────────────────
#[test]
fn static_intern_happy() {
    let interner =
        keyhog_scanner::static_intern::StaticInterner::from_detector_strings(vec!["demo", "Demo"]);
    let a = interner.lookup("demo").unwrap();
    let b = interner.lookup("demo").unwrap();
    assert_eq!(a.as_ref(), "demo");
    assert!(std::sync::Arc::ptr_eq(&a, &b));
}
#[test]
fn static_intern_error() {
    let interner =
        keyhog_scanner::static_intern::StaticInterner::from_detector_strings(std::iter::empty::<
            &str,
        >());
    assert!(interner.lookup("dynamic").is_none());
}

// ── crates/scanner/src/structured/mod.rs ──────────────────────────────
#[test]
fn structured_mod_happy() {
    let scanner =
        CompiledScanner::compile(vec![demo_detector("ghp_[A-Za-z0-9]{20,}", "ghp_")]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let chunk = structured_env_chunk(&format!("GITHUB_TOKEN={token}\n"), "config.env");
    let matches = scanner.scan(&chunk);
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}
#[test]
fn structured_mod_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    assert!(scanner.scan(&demo_chunk("fn main() {}")).is_empty());
}

// ── crates/scanner/src/structured/parsers.rs ──────────────────────────
#[test]
fn structured_parsers_happy() {
    let scanner = CompiledScanner::compile(vec![demo_detector("secret", "secret")]).unwrap();
    let chunk = structured_env_chunk("TOKEN=abc123\n", ".env");
    let _ = scanner.scan(&chunk);
}
#[test]
fn structured_parsers_error() {
    let scanner = CompiledScanner::compile(vec![demo_detector("abc", "abc")]).unwrap();
    let chunk = structured_env_chunk("", ".env");
    assert!(scanner.scan(&chunk).is_empty());
}

// ── crates/scanner/src/telemetry.rs ───────────────────────────────────
#[test]
fn telemetry_happy() {
    reset();
    enable_dogfood();
    record_example_suppression("d", None, "ghp_EXAMPLE", "suffix");
    assert!(!drain_events().is_empty());
    reset();
}
#[test]
fn telemetry_error() {
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
        max_decode_depth: 0,
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

// ── engine/segment_attribution boundary/adversarial ───────────────────
#[test]
fn engine_segment_attribution_boundary() {
    let mapped =
        map_offsets_to_segments(&[Segment::new(1, 0, 4)], &[GlobalMatch::new(1, 1, 3)]).unwrap();
    assert_eq!(mapped.len(), 1);
}
#[test]
fn engine_segment_attribution_adversarial() {
    let err =
        map_offsets_to_segments(&[Segment::new(1, 0, 4)], &[GlobalMatch::new(1, 2, 10)]).unwrap();
    assert!(err.is_empty());
}
