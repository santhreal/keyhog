use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec};
use keyhog_scanner::CompiledScanner;

const ALLOWLISTED: &str = "m7_Q2vN9xK4cP8rT6wY3zH5s";
const RETAINED: &str = "n8_R3wP7yL5dQ9sV2xZ4cJ6t";

fn load_detector(name: &str, toml: &str) -> DetectorSpec {
    let dir = tempfile::tempdir().expect("tempdir");
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
        .map(|finding| finding.credential.to_string())
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
plausibility = { mixed_alnum_floor = 4.0, symbolic_entropy_floor = 3.5, second_half_entropy_floor = 2.5, mixed_alnum_min_len = 20, isolated_mixed_entropy_floor = 3.65, isolated_symbolic_min_len = 18, isolated_symbolic_min_symbols = 2, isolated_symbolic_requires_non_underscore = true, isolated_colon_left_min_len = 20, isolated_colon_right_min_len = 16, leading_slash_base64_entropy_floor = 4.8, reject_repeated_blocks = true, allow_alphabetic_credential = true, reject_program_identifiers = true, reject_dash_segmented_alnum = true }
entropy_policy_priority = 0
bpe_enabled = false
entropy_floor = [{ floor = 0.0 }]
allowlist_values = ['^m7_Q2vN9xK4cP8rT6wY3zH5s$']

[[detector.entropy_shapes]]
kind = "lower-dash-app-password"
entropy_floor = 3.9
group_count = 4
group_length = 4
special_min_length = 16

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
