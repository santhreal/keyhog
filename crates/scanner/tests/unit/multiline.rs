use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{
    preprocess_multiline, source_offset_for_match_for_test, LineMapping, MultilineConfig,
};

/// Regression (dogfood): a `keyhog scan .` over a tree containing a compiled
/// binary (decoded to lossy UTF-8 with U+FFFD replacement scalars) aborted the
/// whole worker with
/// `panicked at multiline/config.rs: byte index N is not a char boundary; it is
/// inside '\u{FFFD}'`. The match-offset remap sliced `source` at a mapping's
/// `original_start_offset`, a raw byte offset that landed INSIDE a multi-byte
/// scalar. A secret scanner must never panic/abort on hostile bytes (LAW10):
/// the slice now snaps DOWN to the enclosing char boundary. Every offset the
/// remap returns must be a valid, in-bounds char boundary so downstream slicing
/// is panic-free.
#[test]
fn source_offset_remap_does_not_panic_on_mid_scalar_offset() {
    // Each case: source with a multi-byte scalar, plus a mapping whose
    // `original_start_offset` deliberately lands mid-scalar (and differs from
    // `start_offset`, so the remap reaches the slicing `source_line_at` path).
    // U+03A9 'Ω' and U+00E9 'é' are 2-byte; U+FFFD '\u{FFFD}' is 3-byte (the
    // exact replacement scalar from the original crash).
    let cases: &[(&str, usize, &str, usize)] = &[
        // (source, mid-scalar original_start_offset, credential, byte_len_of_scalar_at_offset)
        ("\u{03A9}=SECRET_TOKEN", 1, "SECRET_TOKEN", 2),
        ("caf\u{00E9}_KEY=ghp_TOKENVALUE", 4, "ghp_TOKENVALUE", 2),
        ("x\u{FFFD}y_TOKEN=AKIA_VALUE", 2, "AKIA_VALUE", 3),
        ("x\u{FFFD}y_TOKEN=AKIA_VALUE", 3, "AKIA_VALUE", 3),
    ];

    for (source, mid_offset, credential, scalar_len) in cases {
        // Sanity: the chosen offset really is mid-scalar (not a char boundary),
        // so the test exercises the snap rather than a trivially-aligned offset.
        assert!(
            !source.is_char_boundary(*mid_offset),
            "test setup: offset {mid_offset} must be mid-scalar in {source:?}"
        );
        let mapping = LineMapping {
            start_offset: 0,
            end_offset: source.len(),
            line_number: 1,
            original_start_offset: *mid_offset,
            transport_decoded: false,
        };
        // offset is a position inside the mapped span (>= start_offset, <
        // end_offset) so the remap selects this mapping and reaches the slice.
        let offset = mid_offset + scalar_len;
        let result = source_offset_for_match_for_test(source, offset, credential, mapping);

        // The contract: no panic, and the returned offset is a valid char
        // boundary within bounds (downstream code slices `source` at it).
        assert!(
            result <= source.len(),
            "remapped offset {result} out of bounds for {source:?} (len {})",
            source.len()
        );
        assert!(
            source.is_char_boundary(result),
            "remapped offset {result} is not a char boundary in {source:?}"
        );
    }
}

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
fn test_python_parenthesized_implicit_three_line_concatenation() {
    let text = "token = (\n    \"sk-proj-\"\n    \"abcdef123456\"\n    \"7890abcdef\"\n)\n";
    let preprocessed =
        preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(
        preprocessed.text.contains("sk-proj-abcdef1234567890abcdef"),
        "parenthesized implicit string block must append the joined credential; got:\n{}",
        preprocessed.text
    );
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
    use keyhog_scanner::testing::fragment_cache::SecretFragment;
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
    // Second fragment in the SAME file with the SAME prefix, within the
    // 100-line window - cluster size hits 2, joiner produces both orderings.
    // Reassembly is same-file-only (cross-file joins were removed to stop the
    // sibling-file cannibalization bug; see fragment_cache_inline), so the
    // pair must share a path to join.
    let frag2 = SecretFragment {
        prefix: "aws_key".to_string(),
        var_name: "AWS_SUFFIX".to_string(),
        value: Zeroizing::new("EXAMPLE".to_string()),
        line: 12,
        path: Some(Arc::from("/repo/config/a.py")),
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
    use keyhog_scanner::testing::fragment_cache::SecretFragment;
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
    use keyhog_scanner::testing::fragment_cache::SecretFragment;
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

    // Same-file cluster (reassembly is same-file-only): three fragments in
    // one file within the window emit all ordered pairwise joins.
    cache.record_and_reassemble(frag("p", "A", "111", "/d/a.py", 1));
    cache.record_and_reassemble(frag("p", "B", "222", "/d/a.py", 2));
    let candidates = cache.record_and_reassemble(frag("p", "C", "333", "/d/a.py", 3));
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
