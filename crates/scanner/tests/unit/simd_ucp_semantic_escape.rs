/// UCP shorthand semantics can differ from Rust regex's Unicode tables, and
/// Hyperscan rejects word boundaries outright. Doubled backslashes remain
/// literals and must stay eligible for Hyperscan.
#[test]
fn classifier_respects_escape_parity_and_unicode_semantics() {
    for pattern in [
        r"\bsecret",
        r"secret\B",
        r"account:\d+",
        r"\p{Nd}+",
        r"\s+\w+",
        r"\\\D",
    ] {
        assert!(
            crate::simd::backend::contains_ucp_semantic_escape(pattern),
            "Unicode-semantic escape must use exact CPU recovery: {pattern:?}"
        );
    }
    for pattern in [r"\\bsecret", r"secret\\B", r"\\d+", r"[0-9]+"] {
        assert!(
            !crate::simd::backend::contains_ucp_semantic_escape(pattern),
            "literal or ASCII-only expression must stay eligible for Hyperscan: {pattern:?}"
        );
    }
}

/// A detector set made entirely of UCP-sensitive patterns must remain a valid
/// SIMD selection. Its empty Hyperscan shard set delegates every pattern to the
/// exact CPU recovery route instead of failing backend initialization.
#[test]
fn all_unsupported_patterns_compile_as_exact_cpu_recovery() {
    let caseless = [false];
    let patterns = [(0, 0, r"github_pat_[A-Za-z0-9_]{82}\b", false)];
    let opts = crate::simd::backend::HsCompileOpts {
        singlematch: true,
        caseless: Some(&caseless),
        utf8: true,
        ucp: true,
        ..Default::default()
    };

    let (scanner, unsupported) =
        crate::simd::backend::HsScanner::compile_with_opts(&patterns, opts)
            .expect("an all-recovery pattern set must initialize");
    assert_eq!(unsupported, vec![0]);
    assert_eq!(scanner.pattern_count(), 0);
    scanner
        .scan_matches_result(b"github_pat_example", |_, _, _| {
            panic!("an empty Hyperscan shard set cannot emit a match")
        })
        .expect("an empty Hyperscan shard set must scan successfully");
    scanner
        .warm()
        .expect("an empty Hyperscan shard set must warm successfully");
}
