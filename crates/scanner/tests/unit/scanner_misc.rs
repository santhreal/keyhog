use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::compiler::{
    build_ac_pattern_set, build_compile_state, extract_literal_prefix, is_escaped_literal,
};
use keyhog_scanner::decode::decode_chunk;
use keyhog_scanner::engine::CompiledScanner;
use keyhog_scanner::jwt::{analyze, looks_like_jwt};
use keyhog_scanner::telemetry::{drain_events, enable_dogfood, record_example_suppression, reset};
use keyhog_scanner::types::ScannerConfig;
use keyhog_scanner::{bigram_bloom::BigramBloom, ScanError};

// ── bigram_bloom.rs ─────────────────────────────────────────────────

#[test]
fn bigram_bloom_detects_literal_prefix_overlap() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    assert!(bloom.maybe_overlaps(b"prefix ghp_token"));
}

#[test]
fn bigram_bloom_rejects_unrelated_text() {
    let bloom = BigramBloom::from_literal_prefixes(&["ghp_".into()]);
    assert!(!bloom.maybe_overlaps(b"the quick brown fox"));
}

// ── compiler.rs + compiler_prefix.rs ────────────────────────────────

#[test]
fn build_compile_state_collects_literals_for_detector() {
    let detectors = vec![DetectorSpec {
        id: "demo".into(),
        name: "Demo".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "ghp_[A-Za-z0-9]{20,}".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["ghp_".into()],
        ..Default::default()
    }];
    let state = build_compile_state(&detectors).unwrap();
    assert!(!state.ac_literals.is_empty());
    assert_eq!(build_ac_pattern_set(&state.ac_literals).unwrap().is_some(), true);
}

#[test]
fn extract_literal_prefix_skips_escaped_markers() {
    assert_eq!(extract_literal_prefix(r"\ghp_token"), None);
    assert!(is_escaped_literal('\\'));
}

#[test]
fn build_compile_state_errors_on_invalid_regex() {
    let detectors = vec![DetectorSpec {
        id: "bad".into(),
        name: "Bad".into(),
        service: "bad".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "(unclosed".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        ..Default::default()
    }];
    assert!(build_compile_state(&detectors).is_err());
}

// ── decode/* (caesar, json, reverse, url, pipeline, mod) ────────────

#[test]
fn decode_chunk_reverses_long_reversed_aws_key() {
    let secret = concat!("AK", "IAIOSFODNN7EXAMPLE");
    let reversed: String = secret.chars().rev().collect();
    let chunk = Chunk {
        data: format!("token = \"{reversed}\"").into(),
        metadata: ChunkMetadata {
            path: Some("payload.bin".into()),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 3, false, None, None);
    assert!(
        decoded.iter().any(|c| c.data.contains(secret)),
        "reverse decoder must surface AWS key"
    );
}

#[test]
fn decode_chunk_unescapes_json_string_value() {
    let chunk = Chunk {
        data: r#"{"api_key": "c2stcHJvai1hYmMxMjM="}"#.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 3, false, None, None);
    assert!(
        decoded.iter().any(|c| c.data.contains("sk-proj-abc123")),
        "json + base64 decode path must surface secret"
    );
}

#[test]
fn decode_chunk_url_percent_encoding() {
    let chunk = Chunk {
        data: "token=%73%6b%2d%70%72%6f%6a%2d%78".into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(decoded.iter().any(|c| c.data.contains("sk-proj-x")));
}

#[test]
fn decode_chunk_empty_input_is_noop() {
    let chunk = Chunk {
        data: "".into(),
        metadata: Default::default(),
    };
    assert!(decode_chunk(&chunk, 2, false, None, None).is_empty());
}

// ── decode/unicode_escape.rs ────────────────────────────────────────

#[test]
fn decode_chunk_unescapes_unicode_hex_sequence() {
    let chunk = Chunk {
        data: r#""\x73\x6b\x2d\x70\x72\x6f\x6a""#.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(decoded.iter().any(|c| c.data.contains("sk-proj")));
}

#[test]
fn decode_chunk_ignores_invalid_unicode_escape_runs() {
    let chunk = Chunk {
        data: r#"token = "\xZZ""#.into(),
        metadata: Default::default(),
    };
    let _ = decode_chunk(&chunk, 2, false, None, None);
}

// ── error.rs + lib.rs helpers ───────────────────────────────────────

#[test]
fn scan_error_display_includes_detector_id_for_regex_failure() {
    let err = ScanError::RegexCompile {
        detector_id: "demo".into(),
        index: 0,
        source: regex::Error::Syntax("bad".into()),
    };
    assert!(err.to_string().contains("demo"));
}

#[test]
fn scanner_config_default_is_constructible() {
    let config = ScannerConfig::default();
    assert!(config.max_decode_depth > 0);
}

// ── jwt.rs ──────────────────────────────────────────────────────────

#[test]
fn looks_like_jwt_accepts_well_formed_token() {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"sub\":\"123\"}");
    let token = format!("{header}.{payload}.signature");
    assert!(looks_like_jwt(&token));
}

#[test]
fn analyze_rejects_random_three_part_string() {
    assert!(analyze("not.a.jwt").is_none());
}

// ── structured/* via scan ───────────────────────────────────────────

#[test]
fn structured_env_preprocessing_surfaces_key_value_via_scan() {
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        id: "github-pat".into(),
        name: "GitHub PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "ghp_[A-Za-z0-9]{36}".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["ghp_".into()],
        ..Default::default()
    }])
    .unwrap();
    let chunk = Chunk {
        data: format!("GITHUB_TOKEN={token}\n").into(),
        metadata: ChunkMetadata {
            path: Some("config.env".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == token),
        "structured .env preprocessing must keep recall"
    );
}

// ── telemetry.rs ────────────────────────────────────────────────────

#[test]
fn telemetry_records_example_suppression_when_dogfood_enabled() {
    reset();
    enable_dogfood();
    record_example_suppression("demo", None, "ghp_EXAMPLE", "ends_with_EXAMPLE");
    let events = drain_events();
    assert!(!events.is_empty());
    reset();
}

#[test]
fn telemetry_reset_clears_dogfood_state() {
    reset();
    enable_dogfood();
    reset();
    assert!(drain_events().is_empty());
}
