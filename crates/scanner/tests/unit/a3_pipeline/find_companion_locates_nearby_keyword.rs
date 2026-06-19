use keyhog_scanner::testing::find_companion;
use keyhog_scanner::types::CompiledCompanion;
use keyhog_scanner::types::ScannerPreprocessedText;

#[test]
fn companion_within_window_returns_value() {
    let text = "aws_access_key_id = AKIA123\naws_secret_access_key = wJalrXUtnFEMI";
    let preprocessed = ScannerPreprocessedText::passthrough(text);
    let companion = CompiledCompanion {
        name: "secret".into(),
        regex: regex::Regex::new("aws_secret_access_key\\s*=\\s*(\\S+)").unwrap(),
        capture_group: Some(1),
        within_lines: 3,
        required: false,
    };
    let value = find_companion(&preprocessed, 1, &companion);
    assert_eq!(value.as_deref(), Some("wJalrXUtnFEMI"));
}
