//! R5-REV-SCAN concat reassembly: TypeScript template slack token.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn concat_typescript_template_slack() {
    let body = r#"const a = "xoxb-";
const b = "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx";
export const token = `${a}${b}`;
"#;
    let matches = scan_text(body, "concat-ts-slack.txt");
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "slack-bot-token"
                && m.credential.as_ref().starts_with("xoxb-")
        }),
        "slack-bot-token concat must surface; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
