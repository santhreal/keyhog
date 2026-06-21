use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::{
    compute_line_offsets, is_within_hex_context, known_example_suppressed, local_context_window,
    match_entropy, match_line_number, normalize_scannable_chunk,
};
use keyhog_scanner::testing::{find_companion, normalize_chunk_data};
use keyhog_scanner::types::ScannerPreprocessedText;

// ── Happy path ──────────────────────────────────────────────────────

#[test]
fn compute_line_offsets_marks_each_line_start() {
    let offsets = compute_line_offsets("a\nbc\n");
    assert_eq!(offsets, vec![0, 2, 5]);
}

#[test]
fn match_line_number_resolves_offset_to_line() {
    let text = "line1\nline2\nline3";
    let offsets = compute_line_offsets(text);
    let preprocessed = ScannerPreprocessedText::passthrough(text);
    assert_eq!(match_line_number(&preprocessed, &offsets, 6), 2);
}

#[test]
fn local_context_window_returns_surrounding_lines() {
    let text = "one\ntwo\nthree\nfour";
    let window = local_context_window(text, 3, 1);
    assert!(window.contains("two"));
    assert!(window.contains("three"));
    assert!(window.contains("four"));
}

#[test]
fn match_entropy_is_zero_for_uniform_bytes() {
    assert_eq!(match_entropy(b"aaaa"), 0.0);
}

#[test]
fn match_entropy_is_positive_for_mixed_bytes() {
    assert!(match_entropy(b"abc123") > 0.0);
}

#[test]
fn normalize_chunk_data_strips_zero_width_chars() {
    let input = "sk\u{200b}proj";
    let normalized = normalize_chunk_data(input);
    assert_eq!(normalized.as_ref(), "skproj");
}

#[test]
fn normalize_scannable_chunk_allocates_when_evasion_chars_present() {
    let chunk = Chunk {
        data: "key=\u{200b}val".into(),
        metadata: ChunkMetadata::default(),
    };
    let mut owned = None;
    let normalized = normalize_scannable_chunk(&chunk, &mut owned);
    assert!(!normalized.data.contains('\u{200b}'));
    assert_ne!(normalized.data.as_ref(), chunk.data.as_ref());
}

#[test]
fn known_example_suppressed_blocks_example_suffix() {
    assert!(known_example_suppressed(
        concat!("AK", "IAIOSFODNN7EXAMPLE"),
        None,
        CodeContext::Assignment
    ));
}

#[test]
fn is_within_hex_context_detects_hex_runs_near_match() {
    let data = "deadbeef0123456789abcdef01234567";
    assert!(is_within_hex_context(data, 8, 24));
}

#[test]
fn find_companion_locates_nearby_keyword() {
    let text = "aws_access_key_id = AKIA123\naws_secret_access_key = wJalrXUtnFEMI";
    let preprocessed = ScannerPreprocessedText::passthrough(text);
    let companion = keyhog_scanner::types::CompiledCompanion {
        name: "secret".into(),
        regex: regex::Regex::new("aws_secret_access_key\\s*=\\s*(\\S+)").unwrap(),
        capture_group: Some(1),
        within_lines: 3,
        required: false,
    };
    let value = find_companion(&preprocessed, 1, &companion);
    assert!(value.is_some());
}

// ── Error / negative paths ──────────────────────────────────────────

#[test]
fn match_line_number_empty_offsets_falls_back_safely() {
    let preprocessed = ScannerPreprocessedText::passthrough("solo line");
    assert_eq!(match_line_number(&preprocessed, &[], 0), 1);
}

#[test]
fn known_example_suppressed_allows_realistic_token() {
    assert!(!known_example_suppressed(
        concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17"),
        None,
        CodeContext::Assignment
    ));
}

#[test]
fn is_within_hex_context_rejects_short_non_hex_match() {
    let data = "not-a-hex-secret";
    assert!(!is_within_hex_context(data, 4, 10));
}

#[test]
fn find_companion_returns_none_when_pattern_missing() {
    let preprocessed = ScannerPreprocessedText::passthrough("TOKEN=abc");
    let companion = keyhog_scanner::types::CompiledCompanion {
        name: "missing".into(),
        regex: regex::Regex::new("does_not_exist=(\\S+)").unwrap(),
        capture_group: Some(1),
        within_lines: 3,
        required: false,
    };
    assert!(find_companion(&preprocessed, 1, &companion).is_none());
}
