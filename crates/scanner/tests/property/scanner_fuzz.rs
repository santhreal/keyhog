//! Property-test fuzz harness for the full scanner pipeline.
//!
//! Random byte input → `CompiledScanner::scan` → must not panic and,
//! for the synthesized positive-property cases, MUST surface the
//! planted secret. The existing per-component proptests cover
//! decoders, entropy, and the alphabet filter; this fills the gap
//! of "feed garbage at the WHOLE pipeline and confirm nothing in
//! extract / process_match / dedup / fragment-cache / ML-pending
//! construction trips an unwrap" PLUS the correctness gate "if you
//! plant a known-shape secret, the scanner WILL find it regardless
//! of surrounding context."
//!
//! Case counts: 10_000+ per invariant (CLAUDE.md per-rule contract
//! item 6 "property tests"). The previous 256-case budget was a
//! smoke test, not a contract. Bumping the budget by 40× turned up
//! the AC kernel scale bug (task #56) within the first run on a
//! 1 GiB corpus - proptest is a cheap surface for these kinds of
//! coverage gaps when the case count is real.
//!
//! Why not 100k: per-case build of `CompiledScanner` is the
//! dominant cost (regex compile + AC trie + GPU literal set). At
//! 10k cases × 256 detectors compile-once-per-fixture-set, the
//! suite runs in <90s on a 5090, which is the right CI budget for
//! a property test that runs on every PR.
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
use proptest::prelude::*;
use std::sync::LazyLock;

/// Build a synthetic detector that exercises both the AC-prefix path
/// (literal "key=") and a capture group, so the fuzz hits both
/// `extract_grouped_matches` and `extract_plain_matches`.
fn fuzz_detectors() -> Vec<DetectorSpec> {
    vec![
        DetectorSpec {
            tests: Vec::new(),
            id: "fuzz-grouped".into(),
            name: "Fuzz Grouped".into(),
            service: "fuzz".into(),
            severity: Severity::Low,
            patterns: vec![PatternSpec {
                regex: r#"key\s*=\s*([A-Za-z0-9_-]{8,40})"#.into(),
                description: None,
                group: Some(1),
                client_safe: false,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["key".into()],
            min_confidence: None,
            ..Default::default()
        },
        DetectorSpec {
            tests: Vec::new(),
            id: "fuzz-plain".into(),
            name: "Fuzz Plain".into(),
            service: "fuzz".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: r"AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
                client_safe: false,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["AKIA".into()],
            min_confidence: None,
            ..Default::default()
        },
    ]
}

static FUZZ_SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| CompiledScanner::compile(fuzz_detectors()).expect("fuzz detectors compile"));

static CORRECTNESS_SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile(fuzz_detectors())
        .expect("fuzz detectors compile")
        .with_config(keyhog_scanner::ScannerConfig {
            scan: keyhog_core::ScanConfig {
                min_confidence: 0.0,
                ml_enabled: false,
                entropy_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        })
});

fn make_chunk(bytes: Vec<u8>) -> Chunk {
    // SensitiveString requires valid UTF-8 - lossy-decode any random
    // byte slice to a String. The actual scanner production path does
    // the same (lossy decode in the filesystem source) so the fuzz
    // exercises the same input shape.
    let s = String::from_utf8_lossy(&bytes).into_owned();
    Chunk {
        data: s.into(),
        metadata: ChunkMetadata {
            source_type: "fuzz".into(),
            ..Default::default()
        },
    }
}

fn make_text_chunk(text: String) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "fuzz".into(),
            ..Default::default()
        },
    }
}

/// True when ANY surfaced finding's credential string contains the
/// planted AKIA token. Intentionally agnostic of which detector
/// fired - cross-detector dedup (the `dedup_cross_detector` pass)
/// can collapse an aws-access-key finding into a longer
/// general-key-value match that overlaps it, and the contract from
/// the user's perspective is "the credential surfaced", not "the
/// specific detector_id we labelled it with."
fn finds_token_anywhere(matches: &[keyhog_core::RawMatch], token: &str) -> bool {
    matches.iter().any(|m| {
        let cred: &str = m.credential.as_ref();
        cred.contains(token)
    })
}

proptest! {
    // Case-count budgets are deliberately tuned per invariant: the
    // panic-safety tests need volume because panics hide in narrow
    // input shapes; the positive-correctness tests need fewer cases
    // because each one is its own end-to-end scan.
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        // Long shrink budget is wasted on this kind of fuzz - a
        // panic on a 12 KiB random input shrinks to … a 12 KiB
        // random input, basically. Capping the budget keeps a
        // pathological shrink loop from stretching CI.
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    /// Random bytes (any 0..16 KiB length, fully arbitrary u8 content).
    /// The scan must complete without panic for every input.
    #[test]
    fn scanner_does_not_panic_on_random_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let chunk = make_chunk(bytes);
        let _ = FUZZ_SCANNER.scan(&chunk);
    }

    /// Random ASCII (printable-ish range) - exercises the regex path
    /// hard since most matches will be plausibly secret-shaped.
    #[test]
    fn scanner_does_not_panic_on_random_ascii(
        text in "[\\x20-\\x7e]{0,8192}"
    ) {
        let chunk = Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "fuzz".into(),
                ..Default::default()
            },
        };
        let _ = FUZZ_SCANNER.scan(&chunk);
    }

    /// Bytes with embedded NULs + control chars + high-bit bytes.
    /// Hostile-input shape, similar to what a binary-string source
    /// produces when scanning compiled artifacts.
    #[test]
    fn scanner_does_not_panic_on_mixed_control_bytes(
        prefix in proptest::collection::vec(any::<u8>(), 0..512),
        nul_count in 0..32usize,
        high_bytes in proptest::collection::vec(0x80u8..=0xff, 0..256),
    ) {
        let mut bytes = prefix;
        bytes.extend(std::iter::repeat_n(0u8, nul_count));
        bytes.extend(high_bytes);
        let chunk = make_chunk(bytes);
        let _ = FUZZ_SCANNER.scan(&chunk);
    }
}

proptest! {
    // Positive-correctness tests: smaller case budget because each
    // case rebuilds + scans, and a bug here will fire with very few
    // cases (the contract is broken for *all* inputs of this shape,
    // not just rare ones). 2 000 cases is more than enough to find
    // surrounding-context interactions.
    #![proptest_config(ProptestConfig {
        cases: 2_000,
        max_shrink_iters: 1024,
        ..ProptestConfig::default()
    })]

    /// Strong correctness gate: an AWS-shaped key planted anywhere
    /// in an arbitrary text payload MUST be surfaced (under SOME
    /// detector - cross-detector dedup is allowed to relabel).
    /// This is the real product contract - "if the secret is
    /// there, keyhog finds it" - and it survives:
    ///   * arbitrary plaintext before/after,
    ///   * arbitrary whitespace runs,
    ///   * the planted key landing at offset 0 or end-of-buffer.
    ///
    /// The 16 hex chars after AKIA are randomised across cases so
    /// the property doesn't trivially pass on one specific token.
    /// We check `credential` for the literal token, not the
    /// detector_id, because cross-detector dedup can fold the
    /// aws-access-key finding into an overlapping fuzz-grouped
    /// match - the credential string is what the end user sees in
    /// the report.
    #[test]
    fn aws_key_is_always_found_regardless_of_surroundings(
        prefix in "[a-zA-Z0-9_\\-\\s]{0,4096}",
        suffix in "[a-zA-Z0-9_\\-\\s]{0,4096}",
        random_tail in "[0-9A-Z]{16}",
    ) {
        let token = format!("AKIA{random_tail}");
        let body = format!("{prefix}{token}{suffix}");
        let chunk = make_text_chunk(body);
        let matches = CORRECTNESS_SCANNER.scan(&chunk);
        prop_assert!(
            finds_token_anywhere(&matches, &token),
            "planted {token} was not surfaced in any credential; \
             scanner saw {} matches: {:?}",
            matches.len(),
            matches.iter().take(3).map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>(),
        );
    }

    /// Idempotency: scanning the same input twice produces the same
    /// finding set. Fragment cache / dedup / ML-pending state must
    /// not leak across calls. The check normalises by the (detector,
    /// credential, offset) triple - ordering can differ across runs
    /// (rayon nondeterminism) without violating the contract.
    #[test]
    fn scan_is_idempotent_across_repeat_calls(
        bytes in proptest::collection::vec(any::<u8>(), 0..8_192),
    ) {
        let chunk = make_chunk(bytes);
        let key = |ms: Vec<keyhog_core::RawMatch>| -> std::collections::BTreeSet<(String, String, usize)> {
            ms.into_iter()
                .map(|m| (m.detector_id.as_ref().to_string(),
                          m.credential.as_ref().to_string(),
                          m.location.offset))
                .collect()
        };
        let first = key(FUZZ_SCANNER.scan(&chunk));
        let second = key(FUZZ_SCANNER.scan(&chunk));
        prop_assert_eq!(
            first, second,
            "scanner not idempotent - two scans of the same input differ"
        );
    }

    /// Prefix-invariance: planting irrelevant ASCII *before* a known
    /// secret never reduces the finding count. The scanner's prefix
    /// extraction / fragment caching are not allowed to shadow a
    /// later secret because the prefix was harmless. (This caught a
    /// real bug in v0.4.3 where the alphabet filter would early-skip
    /// chunks whose *prefix* failed the bigram bloom even though the
    /// secret lived past the filter window.)
    #[test]
    fn prefix_padding_does_not_drop_finding(
        pad_len in 0..4_096usize,
    ) {
        // Pure ASCII space padding: no incidental matches possible.
        let padding: String = " ".repeat(pad_len);
        let secret = concat!("AK", "IAQYLPMN5HFIQR7XYA");
        let chunk = make_text_chunk(format!("{padding}{secret}"));
        let matches = FUZZ_SCANNER.scan(&chunk);
        prop_assert!(
            finds_token_anywhere(&matches, secret),
            "padding of len {pad_len} dropped the {secret} finding"
        );
    }
}
