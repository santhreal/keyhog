//! R5-T-SCAN concat reassembly: js template github.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn concat_js_template_github() {
    let body = r#"const t = `ghp_${"abcdefghijklmnopqrstuvwxyz1234567890"}`;
"#;
    let matches = scan_text(body, "concat.txt");

    assert!(
        matches.iter().any(|m| m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == "ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
        "github-classic-pat concat must surface ghp_abcdefghijklmnopqrstuvwxyz1234567890; matches={:?}",
        matches.iter().map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>()
    );
}
