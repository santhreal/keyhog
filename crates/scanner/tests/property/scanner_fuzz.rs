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
//! Case counts: 10_000 per invariant (CLAUDE.md per-rule contract item 6
//! "property tests"). Randomized bodies stay small because input-shape diversity,
//! not repeatedly rescanning the maximum length, is the property-testing value.
//! Dedicated deterministic cases below pin every former maximum-length boundary.
//! Combining 10_000 cases with 8-16 KiB bodies made the debug CI suite retain
//! more than 4.9 GiB and run for more than fourteen minutes before completing
//! the first property. The bounded distribution preserves case diversity while
//! making the full library gate reliable.
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
            kind: Default::default(),
            entropy_floor: Vec::new(),
            tests: Vec::new(),
            id: "fuzz-grouped".into(),
            name: "Fuzz Grouped".into(),
            service: "fuzz".into(),
            severity: Severity::Low,
            patterns: vec![PatternSpec {
                regex: r#"key\s*=\s*([A-Za-z0-9_-]{8,40})"#.into(),
                description: None,
                group: Some(1),
                required_literals: Vec::new(),
                client_safe: false,
                weak_anchor: false,
                structural_password_slot: false,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["key".into()],
            min_confidence: None,
            ..keyhog_scanner::testing::named_detector_fixture_defaults()
        },
        DetectorSpec {
            kind: Default::default(),
            entropy_floor: Vec::new(),
            tests: Vec::new(),
            id: "fuzz-plain".into(),
            name: "Fuzz Plain".into(),
            service: "fuzz".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: r"(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b".into(),
                description: None,
                group: None,
                required_literals: Vec::new(),
                client_safe: false,
                weak_anchor: false,
                structural_password_slot: false,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["AKIA".into(), "ASIA".into()],
            min_confidence: None,
            ..keyhog_scanner::testing::named_detector_fixture_defaults()
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
                #[cfg(not(feature = "ml"))]
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

    /// Random bytes (any 0..256 length, fully arbitrary u8 content).
    /// The scan must complete without panic for every input. A dedicated test
    /// below pins the 16 KiB boundary without multiplying it by 10,000 cases.
    #[test]
    fn scanner_does_not_panic_on_random_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..256)
    ) {
        let chunk = make_chunk(bytes);
        let _ = FUZZ_SCANNER.scan(&chunk);
    }

    /// Random ASCII (printable-ish range) exercises the regex path hard because
    /// most matches are plausibly secret-shaped. A dedicated test below pins
    /// the former 8 KiB maximum.
    #[test]
    fn scanner_does_not_panic_on_random_ascii(
        text in "[\\x20-\\x7e]{0,256}"
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
    // Positive-correctness tests use the same 10,000-case contract as the
    // panic-safety properties. Random surroundings stay bounded; dedicated
    // maximum-length cases below pin the size boundaries separately.
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        max_shrink_iters: 1024,
        ..ProptestConfig::default()
    })]

    /// Strong correctness gate: a self-delimited AWS-shaped key planted in
    /// arbitrary text MUST be surfaced under some detector. AWS access-key IDs
    /// are exactly 20 bytes, so the generated context is separated by newlines;
    /// an adjacent uppercase alphanumeric byte would extend the token and make
    /// it invalid by the production detector contract. Dedicated cases below
    /// pin start-of-buffer and end-of-buffer placement.
    ///
    /// The 16 characters after AKIA are randomized across cases so the property
    /// does not trivially pass on one token. We check `credential` for the
    /// literal token rather than detector ID because cross-detector resolution
    /// may relabel an overlapping finding; the credential is what users see.
    #[test]
    fn aws_key_is_always_found_regardless_of_surroundings(
        prefix in "[a-zA-Z0-9_\\-\\s]{0,256}",
        suffix in "[a-zA-Z0-9_\\-\\s]{0,256}",
        random_tail in "[0-9A-Z]{16}",
    ) {
        let token = format!("AKIA{random_tail}");
        let body = format!("{prefix}\n{token}\n{suffix}");
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
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
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
        pad_len in 0..256usize,
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

/// Locks out size-distribution shrinkage by proving the full scanner accepts
/// the original 16 KiB arbitrary-byte ceiling without panic.
#[test]
fn scanner_does_not_panic_at_random_byte_size_boundary() {
    let mut state = 0x9e37_79b9_u32;
    let bytes = (0..16_384)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    let _ = FUZZ_SCANNER.scan(&make_chunk(bytes));
}

/// Locks out a fast-test loophole by exercising the regex-heavy printable
/// ASCII path at the original 8 KiB ceiling.
#[test]
fn scanner_does_not_panic_at_ascii_size_boundary() {
    let text: String = (0..8_192)
        .map(|index| char::from(b' ' + (index % 95) as u8))
        .collect();
    let _ = FUZZ_SCANNER.scan(&make_text_chunk(text));
}

/// Locks out context truncation by proving a planted key survives the original
/// maximum 4 KiB prefix and suffix in one production scan.
#[test]
fn aws_key_survives_maximum_surrounding_context() {
    let token = "AKIAQYLPMN5HFIQR7XYA";
    let body = format!("{} {token} {}", "a".repeat(4_095), "z".repeat(4_095));
    let matches = CORRECTNESS_SCANNER.scan(&make_text_chunk(body));
    assert!(
        finds_token_anywhere(&matches, token),
        "planted key at the maximum context boundary was not surfaced"
    );
}

/// Locks out chunk-edge blind spots while preserving the exact 20-byte AWS
/// token contract at both the start and end of the scanned buffer.
#[test]
fn aws_key_is_found_at_both_chunk_edges() {
    let token = "AKIAQYLPMN5HFIQR7XYA";
    for body in [format!("{token}\ncontext"), format!("context\n{token}")] {
        let matches = CORRECTNESS_SCANNER.scan(&make_text_chunk(body));
        assert!(
            finds_token_anywhere(&matches, token),
            "chunk-edge AWS access-key ID was not surfaced: {matches:?}"
        );
    }
}

/// Locks out case-insensitive prefix shadowing: an adjacent mixed-case `Aki`
/// must not consume the start of a canonical uppercase AWS access-key ID.
#[test]
fn mixed_case_prefix_does_not_shadow_canonical_aws_key() {
    let token = "AKIA00A000A0AA0A0A00";
    let matches = CORRECTNESS_SCANNER.scan(&make_text_chunk(format!("Aki{token}")));
    assert!(
        finds_token_anywhere(&matches, token),
        "mixed-case prefix shadowed the canonical AWS access-key ID: {matches:?}"
    );
}

/// Locks out state leaks that only appear on larger chunks by comparing exact
/// finding identities across repeated scans at the original 8 KiB ceiling.
#[test]
fn scan_is_idempotent_at_size_boundary() {
    let bytes = (0..8_192).map(|index| (index % 251) as u8).collect();
    let chunk = make_chunk(bytes);
    let key = |matches: Vec<keyhog_core::RawMatch>| {
        matches
            .into_iter()
            .map(|finding| {
                (
                    finding.detector_id.as_ref().to_string(),
                    finding.credential.as_ref().to_string(),
                    finding.location.offset,
                )
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        key(FUZZ_SCANNER.scan(&chunk)),
        key(FUZZ_SCANNER.scan(&chunk))
    );
}

/// Locks out prefix-window regressions at the property distribution boundary:
/// the largest formerly generated padding must not hide a following secret.
#[test]
fn maximum_prefix_padding_does_not_drop_finding() {
    let secret = concat!("AK", "IAQYLPMN5HFIQR7XYA");
    let chunk = make_text_chunk(format!("{}{secret}", " ".repeat(4_095)));
    let matches = FUZZ_SCANNER.scan(&chunk);
    assert!(
        finds_token_anywhere(&matches, secret),
        "4,095 bytes of prefix padding dropped the planted secret"
    );
}
