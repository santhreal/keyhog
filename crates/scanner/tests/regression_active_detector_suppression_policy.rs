use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec};
use keyhog_scanner::CompiledScanner;

const ALLOWLISTED: &str = "m7_Q2vN9xK4cP8rT6wY3zH5s";
const RETAINED: &str = "n8_R3wP7yL5dQ9sV2xZ4cJ6t";

const MATCH_CONFIDENCE_POLICY: &str = r#"match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.1, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.8, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }"#;

const GENERIC_MATCH_CONFIDENCE_POLICY: &str = r#"match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, low_promise_confidence = 0.10, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.3, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.5, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, data_envelope_multiplier = 0.02, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }
entropy_fallback_confidence = { low_entropy_max = 0.55, high_entropy = 0.65, very_high_entropy = 0.75, keyword_lift = 0.1, max_confidence = 0.9 }"#;
const GENERIC_ASSIGNMENT_CONFIDENCE_POLICY: &str = r#"
[detector.generic_assignment_confidence]
ordinary_base = 0.60
test_base = 0.25
documentation_base = 0.30
comment_base = 0.30
scanned_comment_base = 0.60
entropy_reference = 3.5
entropy_gain_per_bit = 0.10
entropy_lift_max = 0.25
length_reference = 16
length_gain_per_byte = 0.005
length_lift_max = 0.15
max_confidence = 0.95
"#;

fn load_detector(name: &str, toml: &str) -> DetectorSpec {
    let dir = tempfile::tempdir().expect("tempdir");
    let is_generic = toml.contains(r#"kind = "phase2-generic""#);
    let match_policy = if is_generic {
        GENERIC_MATCH_CONFIDENCE_POLICY
    } else {
        MATCH_CONFIDENCE_POLICY
    };
    let mut toml = toml
        .replacen(
            "[detector]\n",
            &format!("[detector]\n{match_policy}\n"),
            1,
        )
        .replace(
            "isolated_symbolic_requires_non_underscore = true,",
            "isolated_symbolic_requires_non_underscore = true, isolated_alpha_only_min_symbols = 3, isolated_alpha_only_min_alpha_ratio = 0.5, min_alnum_ratio = 0.5, source_type_name_max_len = 40, source_type_name_min_uppercase = 2, url_path_high_entropy_min_len = 41,",
        );
    if is_generic {
        toml.push_str(GENERIC_ASSIGNMENT_CONFIDENCE_POLICY);
    }
    std::fs::write(dir.path().join(name), toml).expect("write custom detector");
    let mut detectors = keyhog_core::load_detectors(dir.path()).expect("load custom detector");
    assert_eq!(detectors.len(), 1, "fixture must load exactly one detector");
    detectors.pop().expect("one detector")
}

fn scan_credentials(scanner: &CompiledScanner, text: &str, detector_id: &str) -> Vec<String> {
    let chunk = Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "suppression-contract".into(),
            path: Some("production/credentials.env".into()),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .into_iter()
        .filter(|finding| finding.detector_id.as_ref() == detector_id)
        .map(|finding| finding.credential.as_str().to_string())
        .collect()
}

#[test]
fn custom_regex_detector_uses_its_loaded_toml_allowlist() {
    const ID: &str = "custom-regex-allowlist-contract";
    let detector = load_detector(
        "regex.toml",
        r#"
[detector]
id = "custom-regex-allowlist-contract"
name = "Custom Regex Allowlist Contract"
service = "kh674"
severity = "high"
ml = { match_mode = "blend", entropy_mode = "disabled", weight = 0.5, context_radius_lines = 5 }
keywords = ["kh674rx_"]
min_confidence = 0.0
allowlist_values = ['^m7_Q2vN9xK4cP8rT6wY3zH5s$']

[[detector.patterns]]
regex = 'kh674rx_([A-Za-z0-9_]{24})'
group = 1
"#,
    );
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile custom detector");

    assert_eq!(
        scan_credentials(
            &scanner,
            &format!("kh674rx_{ALLOWLISTED}\nkh674rx_{RETAINED}"),
            ID,
        ),
        [RETAINED]
    );
}

#[test]
fn custom_phase2_detector_uses_its_loaded_toml_allowlist() {
    const ID: &str = "custom-phase2-allowlist-contract";
    let detector = load_detector(
        "phase2.toml",
        r#"
[detector]
id = "custom-phase2-allowlist-contract"
name = "Custom Phase Two Allowlist Contract"
service = "generic"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "authoritative", weight = 1.0, context_radius_lines = 5 }
kind = "phase2-generic"
keywords = ["kh674_secret"]
min_confidence = 0.0
min_len = 8
max_len = 64
keyword_free_min_len = 20
entropy_low = 3.0
entropy_high = 4.5
entropy_very_high = 5.8
sensitive_path_entropy_very_high = 5.8
plausibility = { mixed_alnum_floor = 4.0, symbolic_entropy_floor = 3.5, second_half_entropy_floor = 2.5, second_half_min_len = 17, unique_chars_min_len = 17, min_unique_chars = 8, unanchored_hex_max_len = 10, identical_char_max_len = 4, structured_dotted_min_len = 40, mixed_alnum_min_len = 20, isolated_mixed_entropy_floor = 3.65, isolated_symbolic_min_len = 18, isolated_symbolic_min_symbols = 2, isolated_symbolic_requires_non_underscore = true, isolated_colon_left_min_len = 20, isolated_colon_right_min_len = 16, leading_slash_base64_entropy_floor = 4.8, leading_slash_base64_min_len = 40, reject_repeated_blocks = true, allow_alphabetic_credential = true, reject_program_identifiers = true, reject_source_symbol_identifiers = true, reject_dash_segmented_alnum = true }
entropy_policy_priority = 0
bpe_enabled = false
entropy_floor = [{ floor = 0.0 }]
allowlist_values = ['^m7_Q2vN9xK4cP8rT6wY3zH5s$']

[[detector.entropy_shapes]]
charset = "lower-alnum"
entropy_floor = 3.9
special_min_length = 16
grouping = { group_count = 4, group_length = 4, separator = "-" }
require_non_hex_alpha = true
require_group_alpha_digit = true

[detector.entropy_fallback]
class = "generic"
id = "entropy-custom-phase2-allowlist-contract"
name = "Custom Phase Two Allowlist Entropy"
service = "generic"
"#,
    );
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile custom detector");

    assert_eq!(
        scan_credentials(
            &scanner,
            &format!("kh674_secret={ALLOWLISTED}\nkh674_secret={RETAINED}"),
            ID,
        ),
        [RETAINED]
    );
}

#[test]
fn scanners_with_the_same_detector_id_keep_independent_policies() {
    const ID: &str = "custom-shared-id-policy-contract";
    let detector_with_allowlist = load_detector(
        "with-allowlist.toml",
        r#"
[detector]
id = "custom-shared-id-policy-contract"
name = "Custom Shared ID Policy Contract"
service = "kh674"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["kh674iso_"]
min_confidence = 0.0
allowlist_values = ['^m7_Q2vN9xK4cP8rT6wY3zH5s$']

[[detector.patterns]]
regex = 'kh674iso_([A-Za-z0-9_]{24})'
group = 1
"#,
    );
    let detector_without_allowlist = DetectorSpec {
        allowlist_values: Vec::new(),
        ..detector_with_allowlist.clone()
    };
    let scanner_with_allowlist =
        CompiledScanner::compile(vec![detector_with_allowlist]).expect("compile policy scanner");
    let scanner_without_allowlist = CompiledScanner::compile(vec![detector_without_allowlist])
        .expect("compile no-policy scanner");
    let text = format!("kh674iso_{ALLOWLISTED}");

    assert!(scan_credentials(&scanner_with_allowlist, &text, ID).is_empty());
    assert_eq!(
        scan_credentials(&scanner_without_allowlist, &text, ID),
        [ALLOWLISTED]
    );
}
