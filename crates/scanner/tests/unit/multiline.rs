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
            .contains(concat!("AK", "IAIOSFODNN7EXAMPLE"))
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

    let inline =
        r#"token = concat!("xox", "b-1234567890-") + "1234567890-" + "abcdefghijABCDEFGHIJklmn""#;
    let inline_processed = preprocess_multiline(
        inline,
        &MultilineConfig::default(),
        &FragmentCache::new(100),
    );
    assert!(inline_processed.text.contains(concat!(
        "xox",
        "b-1234567890-1234567890-abcdefghijABCDEFGHIJklmn"
    )));
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

#[test]
fn split_string_testkey_concat_reassembly() {
    let text = "head = \"TESTKEY_\"\n\
                tail = \"aK7xP9mQ2wE5rT8yU1iO\"\n\
                token = head + tail\n";
    let preprocessed =
        preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(
        preprocessed.text.contains("TESTKEY_aK7xP9mQ2wE5rT8yU1iO"),
        "structural concat must reassemble split TESTKEY credential; got:\n{}",
        preprocessed.text
    );
}

#[test]
fn two_fragments_same_dir_join() {
    use keyhog_scanner::fragment_cache::SecretFragment;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    let cache = FragmentCache::new(1024);
    // First fragment recorded - no candidates yet, cluster size 1.
    let frag1 = SecretFragment {
        prefix: "aws_key".to_string(),
        var_name: "AWS_PREFIX".to_string(),
        value: Zeroizing::new("AKIAIOSFODNN7".to_string()),
        line: 10,
        path: Some(Arc::from("/repo/config/a.py")),
    };
    let candidates = cache.record_and_reassemble(frag1);
    assert!(
        candidates.is_empty(),
        "single fragment can't form a join candidate"
    );
    // Second fragment in the SAME directory with the SAME prefix -
    // cluster size hits 2, joiner produces both orderings.
    let frag2 = SecretFragment {
        prefix: "aws_key".to_string(),
        var_name: "AWS_SUFFIX".to_string(),
        value: Zeroizing::new("EXAMPLE".to_string()),
        line: 12,
        path: Some(Arc::from("/repo/config/b.py")),
    };
    let candidates = cache.record_and_reassemble(frag2);
    let joined: Vec<String> = candidates.iter().map(|c| c.as_str().to_string()).collect();
    assert!(
        joined.contains(&concat!("AK", "IAIOSFODNN7EXAMPLE").to_string()),
        "expected prefix+suffix join AKIAIOSFODNN7EXAMPLE, got {:?}",
        joined
    );
}

#[test]
fn fragments_in_different_directories_do_not_join() {
    use keyhog_scanner::fragment_cache::SecretFragment;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    let cache = FragmentCache::new(1024);
    let frag1 = SecretFragment {
        prefix: "key".to_string(),
        var_name: "PREFIX".to_string(),
        value: Zeroizing::new("AKIAIOSFODNN7".to_string()),
        line: 10,
        path: Some(Arc::from("/repo/config/a.py")),
    };
    cache.record_and_reassemble(frag1);
    let frag2 = SecretFragment {
        prefix: "key".to_string(),
        var_name: "SUFFIX".to_string(),
        value: Zeroizing::new("EXAMPLE".to_string()),
        line: 12,
        path: Some(Arc::from("/repo/vendor/some_lib/b.py")),
    };
    let candidates = cache.record_and_reassemble(frag2);
    assert!(
        candidates.is_empty(),
        "cross-directory fragments must not join: got {:?}",
        candidates
            .iter()
            .map(|c| c.as_str().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn three_fragments_emit_all_pairwise_joins() {
    use keyhog_scanner::fragment_cache::SecretFragment;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    let cache = FragmentCache::new(1024);
    let frag = |prefix: &str, var: &str, value: &str, path: &str, line: usize| SecretFragment {
        prefix: prefix.to_string(),
        var_name: var.to_string(),
        value: Zeroizing::new(value.to_string()),
        line,
        path: Some(Arc::from(path)),
    };

    cache.record_and_reassemble(frag("p", "A", "111", "/d/a.py", 1));
    cache.record_and_reassemble(frag("p", "B", "222", "/d/b.py", 2));
    let candidates = cache.record_and_reassemble(frag("p", "C", "333", "/d/c.py", 3));
    assert_eq!(
        candidates.len(),
        6,
        "expected 6 pairwise joins for cluster size 3, got {}",
        candidates.len()
    );
    let joined: std::collections::BTreeSet<String> =
        candidates.iter().map(|c| c.as_str().to_string()).collect();
    for expected in ["111222", "222111", "111333", "333111", "222333", "333222"] {
        assert!(
            joined.contains(expected),
            "missing join `{expected}` from {:?}",
            joined
        );
    }
}
