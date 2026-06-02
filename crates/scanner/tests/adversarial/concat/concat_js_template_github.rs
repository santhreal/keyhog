//! R5-T-SCAN concat reassembly: js template github.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn concat_js_template_github() {
    let body = r#"const t = `ghp_${"abcdefghijklmnopqrstuvwxyz12343Tcn6I"}`;
"#;
    let matches = scan_text(body, "concat.txt");

    assert!(
        matches.iter().any(|m| m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == "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"),
        "github-classic-pat concat must surface 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; matches={:?}",
        matches.iter().map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>()
    );
}
