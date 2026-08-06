use keyhog_core::{EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation};
use keyhog_scanner::testing::{find_companion, CompiledCompanion, ScannerPreprocessedText};

#[test]
fn companion_beyond_within_lines_returns_none() {
    let text = (0..20)
        .map(|i| format!("line{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let pre = ScannerPreprocessedText::passthrough(&text);
    let companion = CompiledCompanion {
        name: "far".into(),
        regex: crate::types::LazyRegex::companion("TARGET=(\\S+)"),
        capture_group: Some(1),
        within_lines: 2,
        within_bytes: None,
        direction: EvidenceDirection::Either,
        scope: EvidenceScope::Window,
        requirement: EvidenceRequirement::Reinforcing,
        value_relation: EvidenceValueRelation::Present,
    };
    assert!(find_companion(&pre, 1, 0, 5, "line0", &companion).is_none());
}
