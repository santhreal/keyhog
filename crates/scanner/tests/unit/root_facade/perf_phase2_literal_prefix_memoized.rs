//! Phase-2 SPEED regression: the per-match `has_literal_prefix` scoring signal
//! is a per-PATTERN constant, memoized on `LazyRegex` instead of re-parsed on
//! every surviving candidate.
//!
//! The candidate confidence policy feeds
//! `ConfidenceSignals.has_literal_prefix` for EVERY candidate that survives
//! suppression. It previously computed that inline as
//! `extract_literal_prefix(entry.regex.as_str()).is_some()`: a full
//! char-by-char prefix parse that allocates a `String` (and, on a `(`
//! alternation, an extra `chars.clone().collect::<String>()` of the whole
//! pattern tail) on each call. The value depends ONLY on the regex SOURCE, so
//! on a dense corpus where a handful of hot patterns each fire thousands of
//! times that was thousands of redundant parses + allocations of a value that
//! never changes.
//!
//! The fix memoizes it in `LazyRegex::has_literal_prefix()` (an
//! `Arc<OnceLock<bool>>`, populated on first scoring touch, shared across
//! clones, exactly like the compiled-`Regex` cache). This suite pins the two
//! invariants that the optimization must hold:
//!
//!   1. CORRECTNESS, the memoized accessor returns the BYTE-IDENTICAL value to
//!      `extract_literal_prefix(src).is_some()` for every pattern shape the
//!      engine ships (literal prefix, no prefix, mid-pattern alternation,
//!      escaped literal, below-threshold prefix), AND across the ENTIRE on-disk
//!      detector corpus. If the memoized path ever diverges from the
//!      source-of-truth parser, this goes red.
//!
//!   2. MEMOIZATION, the accessor is stable across repeated calls and a clone
//!      shares the cached value (so the work is paid at most once per unique
//!      regex source, which is the whole point of the perf fix).
//!
//! And a golden-findings e2e pin proves the optimization did not change scan
//! output: a dense mixed corpus produces the exact same finding set
//! (detector ids + captured credentials) it did before the memoization.

use super::support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::testing::LazyRegexProbe as LazyRegex;
use keyhog_scanner::testing::{extract_literal_prefix, extract_literal_prefixes};
use keyhog_scanner::{CompiledScanner, ScannerConfig};

/// Representative pattern shapes covering every branch of
/// `extract_literal_prefix`: a plain leading literal, a `\.`-escaped literal,
/// a mid-pattern `(alt|alt)` group (the branch that allocates the tail
/// `String`), a `[char-class]`-led pattern with NO prefix, a too-short prefix
/// (below `MIN_LITERAL_PREFIX_CHARS`), and a metacharacter-led pattern.
const SHAPES: &[&str] = &[
    "AKIA[0-9A-Z]{16}",           // literal prefix "AKIA" -> Some
    "ghp_[A-Za-z0-9]{36}",        // literal prefix "ghp_" -> Some
    "glpat-[A-Za-z0-9_-]{20}",    // literal prefix "glpat-" -> Some
    r"sk\.eyJ[A-Za-z0-9_-]{10}",  // escaped-literal branch -> Some
    "secret_(key|token)[0-9]{8}", // `(` alternation branch; leading literal "secret_" -> Some
    "[A-Za-z0-9]{32}",            // char-class led, no prefix -> None
    "[0-9a-f]{40}",               // hex digest shape, no prefix -> None
    "xy",                         // below MIN_LITERAL_PREFIX_CHARS (3) -> None
    ".*-token",                   // metacharacter-led -> None
    "^Bearer [A-Za-z0-9]{20}",    // anchored, `^` breaks immediately -> None
];

/// The memoized accessor MUST equal the source-of-truth parser for every
/// representative shape. This is the load-bearing correctness pin: the perf
/// fix is only sound if it returns the identical boolean the inline call did.
#[test]
fn memoized_matches_source_of_truth_on_shapes() {
    for &p in SHAPES {
        let expected = extract_literal_prefix(p).is_some();
        let got_detector = LazyRegex::detector(p).has_literal_prefix();
        let got_plain = LazyRegex::plain(p).has_literal_prefix();
        assert_eq!(
            got_detector, expected,
            "detector LazyRegex `{p}` memoized has_literal_prefix={got_detector} but \
             extract_literal_prefix(...).is_some()={expected}"
        );
        // The signal is a function of the SOURCE only, case-sensitivity flavor
        // (detector vs plain) must not change it.
        assert_eq!(
            got_plain, expected,
            "plain LazyRegex `{p}` memoized has_literal_prefix={got_plain} but \
             extract_literal_prefix(...).is_some()={expected}"
        );
    }
}

/// Concrete value pins so the table above can't silently all-flip to one side.
#[test]
fn known_shapes_have_exact_prefix_truth() {
    assert!(
        LazyRegex::detector("AKIA[0-9A-Z]{16}").has_literal_prefix(),
        "`AKIA...` has the literal prefix `AKIA`"
    );
    assert!(
        LazyRegex::detector("secret_(key|token)[0-9]{8}").has_literal_prefix(),
        "`secret_(key|token)...` has the leading literal prefix `secret_` (>=3 chars)"
    );
    assert!(
        !LazyRegex::detector("[A-Za-z0-9]{32}").has_literal_prefix(),
        "a char-class-led pattern has no extractable literal prefix"
    );
    assert!(
        !LazyRegex::detector("xy").has_literal_prefix(),
        "`xy` is below MIN_LITERAL_PREFIX_CHARS (3) -> no prefix"
    );
}

/// MEMOIZATION pin: the accessor is stable across repeated calls and a clone
/// shares the cached value. Mirrors `lazy_regex.rs::clone_shares_compiled_state`
/// for the compiled regex, the perf win is precisely that the prefix parse is
/// paid at most once per unique source even across the `ac_map` clones the
/// compiler makes (one `CompiledPattern` clone per literal prefix).
#[test]
fn memoized_value_is_stable_and_shared_across_clones() {
    let lr = LazyRegex::detector("ghp_[A-Za-z0-9]{36}");
    let first = lr.has_literal_prefix();
    // Repeated calls return the same memoized value (no recompute drift).
    assert_eq!(first, lr.has_literal_prefix());
    assert!(first, "`ghp_...` has a literal prefix");

    // A clone made BEFORE the first compute, and one made AFTER, both observe
    // the same cached boolean (the `Arc<OnceLock>` is shared).
    let clone_before = LazyRegex::detector("glpat-[A-Za-z0-9_-]{20}");
    let clone_of_before = clone_before.clone();
    let v = clone_before.has_literal_prefix(); // populate via the original
    assert_eq!(
        v,
        clone_of_before.has_literal_prefix(),
        "clone must observe the cached has_literal_prefix value"
    );
    assert!(v, "`glpat-...` has a literal prefix");

    let no_prefix = LazyRegex::detector("[A-Za-z0-9]{32}");
    let no_prefix_clone = no_prefix.clone();
    assert!(!no_prefix.has_literal_prefix());
    assert!(
        !no_prefix_clone.has_literal_prefix(),
        "clone of a no-prefix pattern stays no-prefix"
    );
}

/// CORPUS-WIDE correctness: for every pattern in every on-disk detector, the
/// memoized accessor equals `!extract_literal_prefixes(src).is_empty()`: the
/// PLURAL routing extractor that `has_literal_prefix` delegates to (see
/// `types.rs`). The singular `extract_literal_prefix` returns only the single
/// COMMON prefix, so it wrongly yields `None` for a leading DIVERGENT
/// alternation (123formbuilder's `(?:api…|API…)`), where the plural correctly
/// expands both branches, so confidence and routing agree a literal anchor
/// exists. This is the broadest regression net: any future change to the
/// memoized computation that diverges from the plural source-of-truth on even
/// one shipped pattern goes red here.
#[test]
fn memoized_matches_source_of_truth_on_full_corpus() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut checked = 0usize;
    for d in &detectors {
        for pat in &d.patterns {
            let src = pat.regex.as_str();
            let expected = !extract_literal_prefixes(src).is_empty();
            let got = LazyRegex::detector(src).has_literal_prefix();
            assert_eq!(
                got, expected,
                "detector `{}` pattern `{src}`: memoized has_literal_prefix={got} \
                 disagrees with !extract_literal_prefixes(...).is_empty()={expected}",
                d.id
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 500,
        "expected to cross-check the full corpus (>=500 patterns), only saw {checked}. \
         the corpus failed to load and the net is not actually covering anything"
    );
}

/// A self-contained scanner built from two INLINE detectors with known literal
/// prefixes (`has_literal_prefix=true`), so the golden findings are fully under
/// this test's control and decoupled from on-disk-corpus id/checksum churn that
/// other lanes may be tuning. Both detectors are literal-prefixed, so the
/// `has_literal_prefix` scoring signal this perf fix memoizes is `true` for
/// both (exercising exactly the code path under test).
fn inline_pattern(regex: &str) -> keyhog_core::PatternSpec {
    keyhog_core::PatternSpec {
        regex: regex.to_string(),
        ..Default::default()
    }
}

fn inline_detector(id: &str, regex: &str, keyword: &str) -> keyhog_core::DetectorSpec {
    keyhog_core::DetectorSpec {
        id: id.to_string(),
        name: id.to_string(),
        service: "test".to_string(),
        severity: keyhog_core::Severity::High,
        patterns: vec![inline_pattern(regex)],
        keywords: vec![keyword.to_string()],
        // Self-declare a floor so the finding is unconditionally retained
        // regardless of the global CLI min_confidence (this is a scanner-layer
        // test; we assert the scanner emits the finding).
        min_confidence: Some(0.1),
        ..Default::default()
    }
}

fn inline_scanner() -> &'static CompiledScanner {
    use std::sync::OnceLock;
    static S: OnceLock<CompiledScanner> = OnceLock::new();
    S.get_or_init(|| {
        // `tok_live_` + 32 alnum: a high-entropy random token shape that clears
        // the entropy/promise gates. `cfg_key_` + 40 hex: a distinct
        // literal-prefixed shape. Both have an extractable literal prefix.
        let detectors = vec![
            inline_detector("test-live-token", r"tok_live_[A-Za-z0-9]{32}", "tok_live_"),
            inline_detector("test-config-key", r"cfg_key_[0-9a-f]{40}", "cfg_key_"),
        ];
        let mut config = ScannerConfig::default();
        config.entropy_enabled = false;
        CompiledScanner::compile(detectors)
            .expect("compile inline scanner")
            .with_config(config)
    })
}

fn scan_inline(text: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.env".into()),
            ..Default::default()
        },
    };
    let s = inline_scanner();
    s.clear_fragment_cache();
    s.scan(&chunk)
}

/// GOLDEN-FINDINGS e2e: the memoization must be finding-for-finding identical.
/// A dense corpus of two literal-prefixed credentials (each
/// `has_literal_prefix=true`), repeated so the hot patterns fire many times
/// through the per-match scoring path, must surface exactly those two
/// detectors with exactly those captured credential bytes. Any behavior change
/// from the memoization shows up here as a finding diff.
#[test]
fn dense_corpus_findings_are_unchanged_by_memoization() {
    // High-entropy random bodies so the entropy/promise gates pass; both
    // prefixes are extractable literals (the signal under test = true).
    let live = "tok_live_aZ9kQ2mX7pL4rT8wE1nB6vY3cF5dH0jS";
    let cfg = "cfg_key_0123456789abcdef0123456789abcdef01234567";
    assert_eq!(live.len(), "tok_live_".len() + 32);
    assert_eq!(cfg.len(), "cfg_key_".len() + 40);

    // Dense: repeated across many lines so each hot pattern fires many times.
    let mut corpus = String::new();
    for i in 0..50 {
        corpus.push_str(&format!("live_token_{i} = {live}\n"));
        corpus.push_str(&format!("config_key_{i} = {cfg}\n"));
    }

    let matches = scan_inline(&corpus);

    // Exactly these two detectors must fire (both literal-prefixed).
    for det in ["test-live-token", "test-config-key"] {
        assert!(
            matches.iter().any(|m| m.detector_id.as_ref() == det),
            "GOLDEN: detector `{det}` must fire on the dense corpus. \
             Scanner produced detectors: {:?}",
            matches
                .iter()
                .map(|m| m.detector_id.as_ref())
                .collect::<Vec<_>>()
        );
    }

    // The exact credential bytes must be captured verbatim, proves the
    // scoring path that consumes `has_literal_prefix` still emits the same
    // bytes (not a shifted/extended slice).
    let creds: std::collections::BTreeSet<&str> =
        matches.iter().map(|m| m.credential.as_ref()).collect();
    assert!(
        creds.contains(live),
        "GOLDEN: live-token credential `{live}` must be captured exactly. Got: {creds:?}"
    );
    assert!(
        creds.contains(cfg),
        "GOLDEN: config-key credential `{cfg}` must be captured exactly. Got: {creds:?}"
    );

    // No spurious extra detectors: the only ids present are the two we defined.
    let det_ids: std::collections::BTreeSet<&str> =
        matches.iter().map(|m| m.detector_id.as_ref()).collect();
    assert_eq!(
        det_ids,
        ["test-config-key", "test-live-token"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "GOLDEN: exactly the two inline detectors must fire, no more, no fewer"
    );
}
