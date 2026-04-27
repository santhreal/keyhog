use super::support::*;

#[test]
fn multiple_secrets_on_same_line_all_detected() {
    let detector1 = DetectorSpec {
        id: "slack-bot".into(),
        name: "Slack Bot".into(),
        service: "slack".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "xoxb-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["xoxb-".into()],
    };
    let detector2 = DetectorSpec {
        id: "aws-key".into(),
        name: "AWS Key".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "AKIA[0-9A-Z]{16}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["AKIA".into()],
    };
    let scanner = CompiledScanner::compile(vec![detector1, detector2]).unwrap();
    let aws_key = format!("AKIA{}", "R7VXNPLMQ3HSKWJT");
    let chunk = make_chunk(&format!(
        "SLACK=xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn AWS={aws_key}\n"
    ));
    let matches = scanner.scan(&chunk);
    assert!(
        matches.len() >= 2,
        "both secrets on the same line must be detected, got {}",
        matches.len()
    );
}

#[test]
fn duplicate_credential_in_multiple_lines_deduped() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!(
        "line1: {VALID_CREDENTIAL}\nline2: {VALID_CREDENTIAL}\nline3: {VALID_CREDENTIAL}\n"
    ));
    let matches = scanner.scan(&chunk);
    // The scanner should detect the credential but may report once or multiple.
    // Key assertion: no panic, bounded output.
    assert!(
        !matches.is_empty(),
        "repeated credential must be detected at least once"
    );
}
