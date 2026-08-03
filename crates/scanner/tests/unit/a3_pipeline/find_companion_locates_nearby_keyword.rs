use keyhog_core::{EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation};
use keyhog_scanner::testing::{find_companion, CompiledCompanion, ScannerPreprocessedText};

#[test]
fn companion_within_window_returns_value() {
    let text = "aws_access_key_id = AKIA123\naws_secret_access_key = wJalrXUtnFEMI";
    let preprocessed = ScannerPreprocessedText::passthrough(text);
    let companion = CompiledCompanion {
        name: "secret".into(),
        regex: regex::Regex::new("aws_secret_access_key\\s*=\\s*(\\S+)").unwrap(),
        capture_group: Some(1),
        within_lines: 3,
        within_bytes: None,
        direction: EvidenceDirection::Either,
        scope: EvidenceScope::Window,
        requirement: EvidenceRequirement::Reinforcing,
        value_relation: EvidenceValueRelation::Present,
    };
    let primary_start = text.find("AKIA123").unwrap();
    let value = find_companion(
        &preprocessed,
        1,
        primary_start,
        primary_start + "AKIA123".len(),
        "AKIA123",
        &companion,
    );
    assert_eq!(value.as_deref(), Some("wJalrXUtnFEMI"));
}
