//! R5-T-SCAN concat reassembly: go string plus slack.

use crate::adversarial::oracle_support::scan_text;

#[test]
fn concat_go_string_plus_slack() {
    let body = r#"token := "xoxb-" + "1234567890-1234567890123-" + "abcdefghijklmnopqrstuvwx"
"#;
    let matches = scan_text(body, "concat.txt");

    assert!(
        matches.iter().any(|m| m.detector_id.as_ref() == "slack-bot-token" && m.credential.as_ref() == "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"),
        "slack-bot-token concat must surface xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx; matches={:?}",
        matches.iter().map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>()
    );
}
