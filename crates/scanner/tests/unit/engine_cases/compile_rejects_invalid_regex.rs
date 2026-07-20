use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

#[test]
fn compile_rejects_invalid_regex() {
    assert!(CompiledScanner::compile(vec![detector_with_regex("(unclosed")]).is_err());
}

#[test]
fn compile_rejects_regex_that_exceeds_corpus_limit() {
    let oversized_but_syntax_valid = (0..90_000)
        .map(|idx| format!("KEYHOGSIZE{idx:05}"))
        .collect::<Vec<_>>()
        .join("|");
    let regex = format!("(?:{oversized_but_syntax_valid})");

    let error = match CompiledScanner::compile(vec![detector_with_regex(&regex)]) {
        Ok(_) => panic!("scanner compile must reject regexes the runtime builder cannot build"),
        Err(error) => error,
    };

    let message = error.to_string().to_ascii_lowercase();
    assert!(
        message.contains("regex is too large") && message.contains("4096 byte limit"),
        "expected regex size-limit compile failure, got {error}"
    );
}

fn detector_with_regex(regex: &str) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}
