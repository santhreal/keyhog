use keyhog_scanner::testing::find_companion;
use keyhog_scanner::types::{CompiledCompanion, ScannerPreprocessedText};

#[test]
fn companion_beyond_within_lines_returns_none() {
    let text = (0..20)
        .map(|i| format!("line{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    let pre = ScannerPreprocessedText::passthrough(&text);
    let companion = CompiledCompanion {
        name: "far".into(),
        regex: regex::Regex::new("TARGET=(\\S+)").unwrap(),
        capture_group: Some(1),
        within_lines: 2,
        required: false,
    };
    assert!(find_companion(&pre, 1, &companion).is_none());
}
