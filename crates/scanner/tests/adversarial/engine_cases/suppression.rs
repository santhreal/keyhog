use super::support::*;
use keyhog_scanner::telemetry::DogfoodEvent;

#[test]
fn pure_placeholder_not_flagged() {
    // A placeholder that matches the pattern but is obviously fake.
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "aws-key".into(),
        name: "AWS Key".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "AKIA[0-9A-Z]{16}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["AKIA".into()],
        min_confidence: None,
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = make_chunk("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n");
    let matches = scanner.scan(&chunk);
    // The known example credential should be suppressed.
    assert!(
        matches.is_empty(),
        "AKIAIOSFODNN7EXAMPLE is a known example credential and must be suppressed"
    );
}

/// Regression for TODO 2026-05-17 #2: scanning demo-secret.env's
/// `AKIAIOSFODNN7EXAMPLE` used to silently drop the match and print
/// "No secrets found", indistinguishable from a clean repo. The
/// scanner must now record the suppression so the reporter can
/// distinguish "clean" from "saw a known example".
#[test]
fn example_suppression_is_recorded_in_telemetry() {
    let _guard = keyhog_scanner::testing::telemetry_serial_lock();
    keyhog_scanner::telemetry::testing::reset();
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "aws-key".into(),
        name: "AWS Key".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "AKIA[0-9A-Z]{16}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["AKIA".into()],
        min_confidence: None,
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = make_chunk("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let matches = scanner.scan(&chunk);
    assert!(
        matches.is_empty(),
        "still suppressed (this is the bug we're closing the messaging gap on)"
    );
    assert!(
        keyhog_scanner::telemetry::example_suppression_count() >= 1,
        "telemetry must count the EXAMPLE suppression so the reporter can surface it"
    );
}

#[test]
fn dogfood_captures_redacted_event() {
    let _guard = keyhog_scanner::testing::telemetry_serial_lock();
    keyhog_scanner::telemetry::testing::reset();
    keyhog_scanner::telemetry::enable_dogfood();
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "aws-key".into(),
        name: "AWS Key".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "AKIA[0-9A-Z]{16}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["AKIA".into()],
        min_confidence: None,
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = make_chunk("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let _ = scanner.scan(&chunk);
    let events = keyhog_scanner::telemetry::drain_events();
    // Other tests may run concurrently and fire their own suppressions
    // while dogfood is enabled, so don't assume index 0 is ours.
    let redacted = events
        .iter()
        .find_map(|event| match event {
            // `drain_events()` empties a process-global telemetry buffer, so
            // under parallel test execution another test's EXAMPLE suppression
            // (e.g. `my_example_key`) can interleave ahead of ours. Pin to the
            // AKIA credential this test actually planted so we never assert
            // against a sibling's event.
            DogfoodEvent::ExampleSuppressed {
                credential_redacted,
                reason,
                ..
            } if reason.contains("EXAMPLE") && credential_redacted.starts_with("AKIA") => {
                Some(credential_redacted.as_str())
            }
            _ => None,
        })
        .expect("--dogfood must capture this AKIA suppression event");

    assert!(
        !redacted.contains(concat!("AK", "IAIOSFODNN7EXAMPLE")),
        "redacted output must NOT contain the full credential: {redacted}"
    );
    assert!(
        redacted.starts_with("AKIA"),
        "redacted output should include the provider prefix: {redacted}"
    );
    assert!(
        redacted.contains("..."),
        "redacted output should keep an ellipsis separator: {redacted}"
    );
    assert!(
        redacted.ends_with("MPLE"),
        "redacted output should retain trailing bytes for verification: {redacted}"
    );
    keyhog_scanner::telemetry::testing::reset();
}

#[test]
fn github_pat_example_suppressed() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "github-pat".into(),
        name: "GitHub PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"ghp_[A-Za-z0-9]{36}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["ghp_".into()],
        min_confidence: None,
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = make_chunk("token = ghp_example_0001_xxxxxxxxxxxxxxxxxxxx\n");
    let matches = scanner.scan(&chunk);
    assert!(
        matches.is_empty(),
        "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx must be suppressed as an example credential"
    );
}

#[test]
fn placeholder_keywords_suppressed() {
    use keyhog_scanner::context::CodeContext;
    use keyhog_scanner::testing::known_example_suppressed;

    let placeholders = vec![
        "my_example_key",
        "sample_token_123",
        "dummy_secret",
        "placeholder_value",
        "fake_password",
        "mock_api_key",
    ];
    for p in &placeholders {
        assert!(
            known_example_suppressed(p, None, CodeContext::Unknown),
            "{p} should be suppressed as a placeholder keyword"
        );
    }
}

#[test]
fn instructional_fragments_suppressed() {
    use keyhog_scanner::context::CodeContext;
    use keyhog_scanner::testing::known_example_suppressed;

    let examples = vec![
        "your_api_key_here",
        "your-token-goes-here",
        "insert_secret_here",
        "change_me_later",
        "replace_with_real_key",
    ];
    for e in &examples {
        assert!(
            known_example_suppressed(e, None, CodeContext::Unknown),
            "{e} should be suppressed as an instructional placeholder"
        );
    }
}

#[test]
fn repetitive_masking_suppressed() {
    use keyhog_scanner::context::CodeContext;
    use keyhog_scanner::testing::known_example_suppressed;

    let examples = vec![
        "ghp_xxx123456789012345678901234567890",
        "aaaabbbbccccddddeeeeffffgggg",
        "0000000000000000000000000000",
        "TESTKEY_11111111111111111111",
    ];
    for e in &examples {
        assert!(
            known_example_suppressed(e, None, CodeContext::Unknown),
            "{e} should be suppressed due to repetitive masking"
        );
    }
}

#[test]
fn fake_sequences_suppressed() {
    use keyhog_scanner::context::CodeContext;
    use keyhog_scanner::testing::known_example_suppressed;

    let examples = vec![
        "prefix_1234567890_suffix",
        "token_0123456789",
        "key_abcdefgh1234",
    ];
    for e in &examples {
        assert!(
            known_example_suppressed(e, None, CodeContext::Unknown),
            "{e} should be suppressed as a fake sequence"
        );
    }
}

#[test]
fn todo_fixme_suppressed() {
    use keyhog_scanner::context::CodeContext;
    use keyhog_scanner::testing::known_example_suppressed;

    assert!(
        known_example_suppressed("TODO_add_real_key_here", None, CodeContext::Unknown),
        "TODO marker should suppress credential"
    );
    assert!(
        known_example_suppressed("FIXME_replace_me", None, CodeContext::Unknown),
        "FIXME marker should suppress credential"
    );
}

#[test]
fn real_credentials_not_suppressed() {
    use keyhog_scanner::context::CodeContext;
    use keyhog_scanner::testing::known_example_suppressed;

    assert!(
        !known_example_suppressed("AKIAQWERTYUIOPASDFGHJKLZX", None, CodeContext::Unknown),
        "realistic AWS key without placeholder markers should not be suppressed"
    );
    assert!(
        !known_example_suppressed(
            concat!("sk_li", "ve_abcdefghijklmnopqrstuvwxyz"),
            None,
            CodeContext::Unknown
        ),
        "realistic Stripe key without placeholder markers should not be suppressed"
    );
}

#[test]
fn empty_input_returns_no_matches() {
    let scanner = test_scanner();
    let chunk = make_chunk("");
    let matches = scanner.scan(&chunk);
    assert!(matches.is_empty(), "empty input must produce zero matches");
}

#[test]
fn binary_garbage_returns_no_matches() {
    let scanner = test_scanner();
    // Random bytes that happen to include ASCII chars but form no pattern.
    let garbage: String = (0..10_000)
        .map(|i| char::from((i % 94 + 33) as u8))
        .collect();
    let chunk = make_chunk(&garbage);
    let matches = scanner.scan(&chunk);
    // We don't assert empty - we assert it doesn't panic or hang.
    let _ = matches;
}

#[test]
fn null_padded_binaryish_chunk_is_safe() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("\0BIN\0{VALID_CREDENTIAL}\0TAIL\0"));
    let _matches = scanner.scan(&chunk);
    // Success means it didn"t panic or hang.
}

/// KH-L-0409: the `process_match` engine pre-cascade gates (probabilistic,
/// entropy floor, camel, checksum, hex-fragment, FP-context, …) used to drop
/// candidates SILENTLY — invisible to `--dogfood`, which conflated them with
/// "never reached the engine" and blocked the recall decomposition. A
/// generic-* detector matching a low-diversity value is rejected by the
/// generic-only probabilistic gate (process.rs, BEFORE the suppression
/// cascade); that drop must now emit a `ShapeSuppressed` event naming the gate.
#[test]
fn dogfood_records_engine_probabilistic_gate_drop() {
    let _guard = keyhog_scanner::testing::telemetry_serial_lock();
    keyhog_scanner::telemetry::testing::reset();
    keyhog_scanner::telemetry::enable_dogfood();
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "generic-secret".into(),
        name: "Generic Secret".into(),
        service: "generic".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: "[a-z]{16}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    // 16 identical chars: matches the regex, has a "secret" keyword anchor, but
    // is the lowest-diversity value possible -> the probabilistic gate rejects it.
    let chunk = make_chunk("secret = aaaaaaaaaaaaaaaa\n");
    let _ = scanner.scan(&chunk);
    // Pin to OUR planted credential's redaction ("aaaa...aaaa") so a concurrent
    // test's suppression event can't satisfy the assertion.
    let reasons: Vec<String> = keyhog_scanner::telemetry::drain_events()
        .into_iter()
        .filter_map(|e| match e {
            DogfoodEvent::ShapeSuppressed {
                reason,
                credential_redacted,
                ..
            } if credential_redacted.starts_with("aaaa") => Some(reason.into_owned()),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r == "probabilistic_gate_not_promising"),
        "the generic-detector probabilistic engine-gate drop must be traced \
         (KH-L-0409); got reasons {reasons:?}"
    );
}
