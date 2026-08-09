//! Companion-gate unit coverage (migrated out of src inline tests).

#[test]
fn formbuilder_requires_form_or_fused_token() {
    let src = r#"(?:123[_\-\s]*form[_\-\s]*builder|123FORMBUILDER)[_.\s]*(?:api[_\-\s]*key)"#;
    let arms = keyhog_scanner::testing::companion_arms_for_test(src);
    assert!(
        !arms.is_empty(),
        "expected companion arms for 123formbuilder"
    );
    let padding = "const ordinary_value = 1234567890;\n";
    assert!(!keyhog_scanner::testing::companions_allow_for_test(
        src, padding
    ));
    assert!(keyhog_scanner::testing::companions_allow_for_test(
        src,
        "123_form_builder_api_key=abcdef"
    ));
    assert!(keyhog_scanner::testing::companions_allow_for_test(
        src,
        "123FORMBUILDER_api_key=abcdef"
    ));
}

#[test]
fn ip_api_requires_api_companion() {
    let src = r#"(?:IP[_\-\s]*API|ip[_\-\s]*api)(?:_KEY)?[=:\s"']+([a-zA-Z0-9_-]{10,})"#;
    let lorem = "lorem ipsum dolor sit amet, consectetur adipiscing elit.\n";
    assert!(!keyhog_scanner::testing::companions_allow_for_test(
        src, lorem
    ));
    assert!(keyhog_scanner::testing::companions_allow_for_test(
        src,
        "IPAPI_KEY=WnGcEBigw6"
    ));
}

#[test]
fn presence_scratch_clears_stale_flags_after_literal_set_grows() {
    // WHY: reusable presence scratch used to grow via resize(_, false) without
    // clearing 0..old_len, so leftover true bits from a shorter prior set
    // over-admitted the first chunk after growth.
    let small = [(0usize, r"formbuilder")];
    assert_eq!(
        keyhog_scanner::testing::companion_arms_for_test(small[0].1).is_empty(),
        false,
        "seed pattern must arm the companion gate"
    );
    let mut denied = Vec::new();
    keyhog_scanner::testing::companions_deny_absent_for_test(
        0xC0_u64,
        &small,
        "prefix formbuilder suffix",
        |idx| denied.push(idx),
    );
    assert!(
        denied.is_empty(),
        "seed chunk must admit when companions are present: {denied:?}"
    );

    // Grow the active literal set on the same thread. Haystack has none of
    // the companions: every armed pattern must be denied. Under the old
    // grow-skips-clear bug, stale true bits from the seed chunk over-admit.
    let large = [
        (0usize, r"formbuilder"),
        (1usize, r"webhooksecret"),
        (2usize, r"apikeytoken"),
        (3usize, r"passwordhashvalue"),
    ];
    for (_, src) in &large {
        assert_eq!(
            keyhog_scanner::testing::companion_arms_for_test(src).is_empty(),
            false,
            "large-set pattern must arm the companion gate: {src}"
        );
    }
    denied.clear();
    keyhog_scanner::testing::companions_deny_absent_for_test(
        0xC0_u64,
        &large,
        "lorem ipsum dolor ordinary_value = 1234567890 adipiscing",
        |idx| denied.push(idx),
    );
    denied.sort_unstable();
    assert_eq!(
        denied,
        vec![0, 1, 2, 3],
        "stale presence flags must not over-admit after scratch growth"
    );
}
