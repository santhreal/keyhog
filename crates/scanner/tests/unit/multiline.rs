use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn test_python_backslash_continuation() {
    let text = "key = 'sk-proj-' + \\\n    'abcdef1234567890'";
    let preprocessed =
        preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(preprocessed.text.contains("sk-proj-abcdef1234567890"));
}

#[test]
fn test_python_implicit_concatenation() {
    let text = r#"api_key = "sk-" "live_" "abcdef123456""#;
    let preprocessed =
        preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(preprocessed.text.contains("sk-live_abcdef123456"));
}

#[test]
fn test_javascript_plus_concatenation() {
    let text = "const key = \"sk-\" +\n    \"test_\" +\n    \"secret123\";";
    let preprocessed =
        preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(preprocessed.text.contains("sk-test_secret123"));
}

#[test]
fn test_template_literal_and_go_concat() {
    let template = r#"const key = `sk-proj-${id}abcdef123456`;"#;
    let template_processed = preprocess_multiline(
        template,
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    );
    assert!(template_processed.text.contains("sk-proj-"));
    assert!(template_processed.text.contains("abcdef123456"));

    let go = "apiKey := \"sk-\" +\n    \"live_\" +\n    \"abcdef123456\"";
    let go_processed =
        preprocess_multiline(go, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(go_processed.text.contains("sk-live_abcdef123456"));
}

#[test]
fn test_passthrough_and_line_mapping() {
    let text = "line1\nline2\nline3";
    let preprocessed =
        preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_eq!(preprocessed.line_for_offset(0), Some(1));

    let empty = preprocess_multiline("", &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(empty.text.is_empty());
    assert!(empty.mappings.is_empty());
}

#[test]
fn test_aws_github_and_slack_multiline() {
    let aws = "AWS_ACCESS_KEY_ID = \"AKIA\" \\\n    \"IOSFODNN7EXAMPLE\"";
    assert!(
        preprocess_multiline(aws, &MultilineConfig::default(), &FragmentCache::new(100))
            .text
            .contains("AKIAIOSFODNN7EXAMPLE")
    );

    let github =
        "const token = \"ghp_\" +\n    \"xxxxxxxxxxxxxxxxxxxx\" +\n    \"xxxxxxxxxxxxxxxxxxxx\";";
    assert!(preprocess_multiline(
        github,
        &MultilineConfig::default(),
        &FragmentCache::new(100)
    )
    .text
    .contains("ghp_"));

    let slack =
        r#"slack_token = "xoxb-" "1234567890" "-" "1234567890" "-" "abcdefghijABCDEFGHIJklmn""#;
    assert!(
        preprocess_multiline(slack, &MultilineConfig::default(), &FragmentCache::new(100))
            .text
            .contains("xoxb-")
    );
}

#[test]
fn test_feature_flags_and_single_line_concat() {
    let text = r#"key = "part1" + "part2""#;
    let preprocessed = preprocess_multiline(
        text,
        &MultilineConfig {
            plus_concatenation: false,
            ..Default::default()
        },
        &FragmentCache::new(100),
    );
    assert!(preprocessed.text.contains("part1"));
    assert!(preprocessed.text.contains("part2"));

    let inline = r#"token = "xoxb-1234567890-" + "1234567890-" + "abcdefghijABCDEFGHIJklmn""#;
    let inline_processed = preprocess_multiline(
        inline,
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    );
    assert!(inline_processed
        .text
        .contains("xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn"));
}

#[test]
fn test_fstring_support() {
    let multiline = "key = f\"sk-proj-\" + \\\n    f\"{org_id}abcdef123456\"";
    let preprocessed = preprocess_multiline(
        multiline,
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    );
    assert!(preprocessed.text.contains("sk-proj-"));
    assert!(preprocessed.text.contains("abcdef123456"));
}
