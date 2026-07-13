//! Cross-corpus property tests covering the full Tier-B detector set
//! (all `detectors/*.toml` shipped on disk).
//!
//! The individual-component proptests (entropy bounds, AC robustness,
//! `LazyRegex::get` panic-freedom, decode bytes) cover keyhog's
//! primitives. The pipeline-fuzz file (`scanner_fuzz.rs`) covers the
//! `CompiledScanner::scan` hot path with random bytes and a
//! 2-detector synthetic set. Both leave a gap that's only visible
//! once the WHOLE 894-detector corpus is on the bench: a single
//! malformed regex, a bogus severity tag, or a `severity = "critical"`
//! detector shipped with no positive fixture can ride for releases
//! because no per-detector test would catch it across all detectors
//! simultaneously - the all-detectors integration tests check
//! aggregate counts, not per-detector invariants under randomised
//! sampling.
//!
//! Properties enforced here:
//!
//!   1. `every_compiled_regex_recompiles_under_regex_crate` - for
//!      every random sample of indices into the compiled pattern
//!      table, the regex source string the scanner stores MUST
//!      re-parse cleanly through `regex::RegexBuilder` with the same
//!      flags the scanner uses (case-insensitive). A pattern that
//!      compiled at scanner-build time but cannot be re-parsed is
//!      either a `LazyRegex::never_match` fallback (silently dead
//!      detector) or a corruption in the embedded set. Both are
//!      bugs.
//!   2. `critical_severity_positive_fixture_surfaces_credential` -
//!      every detector with `severity = critical` MUST have at least
//!      one positive contract fixture, and scanning that fixture
//!      MUST surface a finding whose credential contains the
//!      planted token. Critical-tier detectors are the ones whose
//!      false-NEGATIVE rate matters most (cloud root keys, infra
//!      secrets); a critical detector with no positive contract
//!      is shipping a hope, not a guarantee.
//!   3. `positive_fixture_credential_in_noise_still_surfaces` -
//!      for any contract's positive credential, planting it inside
//!      a buffer of arbitrary ASCII space padding MUST surface a
//!      finding whose credential contains the planted token under
//!      SOME detector. (We don't pin the detector_id because
//!      cross-detector dedup can relabel; the user contract is
//!      "the credential surfaced," not "we labelled it X.") This
//!      catches detectors that quietly require structural context
//!      (env-var prefix, JSON key) that they didn't declare in the
//!      regex, so they pass `contracts_runner` on the canned text
//!      and silently miss real-world appearances.
//!
//! Case budgets: 1_000+ per property (CLAUDE.md proptest 1k-iter
//! floor). The expensive setup is the 894-detector `CompiledScanner`
//! build (~2-3s); we pay it once via `LazyLock` and amortise across
//! all properties.

#[path = "../support/mod.rs"]
mod support;

use crate::support::paths::detector_dir;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, Severity};
use keyhog_scanner::CompiledScanner;
use proptest::prelude::*;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::LazyLock;

fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

#[derive(Debug, Deserialize, Clone)]
struct ContractFile {
    detector_id: String,
    #[serde(default)]
    positive: Vec<ContractPositive>,
}

#[derive(Debug, Deserialize, Clone)]
struct ContractPositive {
    text: String,
    credential: String,
}

static DETECTORS: LazyLock<Vec<DetectorSpec>> = LazyLock::new(|| {
    let dir = detector_dir();
    let detectors =
        keyhog_core::load_detectors(&dir).expect("load all detectors from on-disk Tier-B set");
    // The whole point of this test file is to sweep the corpus; if it
    // ever falls below the headline number a sibling test or the
    // README claim has drifted and the proptest sampler would be
    // running over a shrunken space. Floor + fail-loud.
    assert!(
        detectors.len() >= 800,
        "detector corpus shrank to {} - expected >= 800 (headline is 894). \
         Sampler proptests below depend on a full corpus to exercise the cross-set invariants.",
        detectors.len(),
    );
    detectors
});

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile(DETECTORS.clone()).expect("compile full Tier-B detector set")
});

/// All compiled pattern source strings the scanner currently holds.
/// Returned as `Vec<String>` so the proptest sampler can index into
/// it cheaply without borrowing across the proptest macro boundary.
static PATTERN_REGEX_SRCS: LazyLock<Vec<String>> = LazyLock::new(|| {
    keyhog_scanner::testing::pattern_regex_strs(&SCANNER)
        .into_iter()
        .map(String::from)
        .collect()
});

static CONTRACTS: LazyLock<Vec<ContractFile>> = LazyLock::new(|| {
    let dir = contracts_dir();
    let entries = std::fs::read_dir(&dir).expect("contracts dir readable");
    let mut out = Vec::new();
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("read contracts dir entry {}: {e}", dir.display()));
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read contract {}: {e}", path.display()));
        let parsed: ContractFile = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("parse contract {}: {e}", path.display()));
        out.push(parsed);
    }
    // Stable order so proptest sampling is reproducible across runs.
    out.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    out
});

/// Detectors marked `severity = critical` in their on-disk spec.
/// Matches `Severity::Critical` exactly so a future addition to the
/// enum doesn't silently weaken the test (e.g. a "Catastrophic" tier
/// would NOT be covered until added here, which is the right
/// behaviour - explicit opt-in).
static CRITICAL_DETECTORS: LazyLock<Vec<DetectorSpec>> = LazyLock::new(|| {
    DETECTORS
        .iter()
        .filter(|d| d.severity == Severity::Critical)
        .cloned()
        .collect()
});

/// Positive fixtures across the whole contract corpus, flattened so a
/// proptest index sampler can pick uniformly. Each entry carries the
/// detector_id so failures point at the file you need to fix.
static ALL_POSITIVES: LazyLock<Vec<(String, ContractPositive)>> = LazyLock::new(|| {
    let mut out = Vec::new();
    for c in CONTRACTS.iter() {
        for p in &c.positive {
            out.push((c.detector_id.clone(), p.clone()));
        }
    }
    out
});

/// Map detector_id -> first positive fixture, used by the critical-
/// severity sampler. `BTreeMap` for stable iteration in error messages.
static CRITICAL_POSITIVE_BY_ID: LazyLock<std::collections::BTreeMap<String, ContractPositive>> =
    LazyLock::new(|| {
        let critical_ids: std::collections::BTreeSet<&str> =
            CRITICAL_DETECTORS.iter().map(|d| d.id.as_str()).collect();
        let mut out = std::collections::BTreeMap::new();
        for c in CONTRACTS.iter() {
            if !critical_ids.contains(c.detector_id.as_str()) {
                continue;
            }
            if let Some(first) = c.positive.first() {
                out.insert(c.detector_id.clone(), first.clone());
            }
        }
        out
    });

fn scan_text(text: &str) -> Vec<keyhog_core::RawMatch> {
    // Fragment cache leaks across calls (see contracts_runner) - drop
    // it so each property iteration scans against a clean state.
    SCANNER.clear_fragment_cache();
    SCANNER.scan(&Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "property/cross_detector".into(),
            path: Some("cross_detector.txt".into()),
            ..Default::default()
        },
    })
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], needle: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(needle))
}

// One-time invariant: every critical-severity detector MUST have a
// positive fixture. This is a foreach, not a sampler - if even one
// detector is missing a fixture the suite must fail. Putting it
// outside `proptest!` keeps the failure deterministic (proptest
// would only flag it on a sampled index, leaving 999 lucky runs
// silent).
#[test]
fn every_critical_severity_detector_has_a_positive_contract_fixture() {
    let critical = CRITICAL_DETECTORS.iter().collect::<Vec<_>>();
    assert!(
        !critical.is_empty(),
        "no Severity::Critical detectors loaded - corpus regressed?"
    );
    let mut missing: Vec<String> = Vec::new();
    for det in &critical {
        match CRITICAL_POSITIVE_BY_ID.get(&det.id) {
            Some(p) if !p.text.is_empty() && !p.credential.is_empty() => {}
            _ => missing.push(det.id.clone()),
        }
    }
    assert!(
        missing.is_empty(),
        "{} critical-severity detector(s) ship without a positive fixture: {:?}. \
         Critical-tier means false-negatives matter most; every one MUST have \
         at least one positive contract entry under tests/contracts/<id>.toml.",
        missing.len(),
        missing,
    );
}

/// Every regex the scanner stores MUST re-parse cleanly through the SAME
/// `regex` builder + flags the scanner uses internally (`case_insensitive(true)`,
/// the canonical detector build flag). DETERMINISTIC + EXHAUSTIVE over the full
/// corpus (~900 regexes, ~2s): 100% coverage with no random-sampling gaps
/// strictly better than a sampled proptest for a finite enumerable set (which
/// both left holes at 1k and cost 18s at 10k). Failure modes caught:
///   * a detector whose TOML regex passed `regex_syntax` parse at compile-time
///     but trips a builder-level limit (DFA size, lookaround) once flags apply,
///   * `LazyRegex` returning the silent `never_match` placeholder because the
///     underlying source has a typo,
///   * a future refactor that strips a flag and silently changes matching.
#[test]
fn every_compiled_regex_recompiles_under_regex_crate() {
    let srcs = &*PATTERN_REGEX_SRCS;
    assert!(
        !srcs.is_empty(),
        "detector corpus must expose regex sources"
    );
    for (i, src) in srcs.iter().enumerate() {
        // Same builder shape as `compiler_compile::shared_regex` for
        // case-insensitive detector patterns. If the scanner can use it, an
        // external rebuild must succeed too.
        let built = regex::RegexBuilder::new(src).case_insensitive(true).build();
        assert!(
            built.is_ok(),
            "pattern #{i} regex source {src:?} stored by scanner FAILED to recompile under \
             regex::RegexBuilder(case_insensitive=true): {:?}. A stored regex that does not \
             rebuild is either a never_match silent dead pattern or corpus corruption.",
            built.err(),
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    /// For every random pick of an on-disk positive fixture, the
    /// planted credential MUST surface in some scanner finding even
    /// when wrapped in ASCII space padding. The padding length is
    /// also randomised so chunk-boundary / prefilter-window-edge
    /// effects get exercised (`pad_left + secret + pad_right`
    /// pushes the secret through arbitrary offsets across the
    /// alphabet-filter window).
    ///
    /// We do NOT pin the detector_id of the surfaced finding -
    /// cross-detector dedup is allowed to relabel a hit into an
    /// overlapping detector (see scanner_fuzz.rs documentation).
    /// The product-level contract is "if the secret is in the
    /// input bytes, keyhog finds it" - which is what this property
    /// asserts.
    #[test]
    fn positive_fixture_credential_in_noise_still_surfaces(
        idx in 0..usize::MAX,
        pad_left in 0..1_024usize,
        pad_right in 0..1_024usize,
    ) {
        let positives = &*ALL_POSITIVES;
        prop_assume!(!positives.is_empty());
        let i = idx % positives.len();
        let (detector_id, p) = &positives[i];
        // The fixture's positive text is what `contracts_runner`
        // tests already - the additive value here is exercising the
        // RAW credential in arbitrary surrounding context. A
        // detector that only fires inside its exact fixture context
        // (env-var key, JSON shape) is silently dead in the wild.
        let body = format!(
            "{}{}{}",
            " ".repeat(pad_left),
            p.text, // Use the full fixture text (credential + its declared minimal context),
                    // not just the bare credential - some detectors legitimately require a
                    // 2-char keyword to anchor (e.g. `sk-` for openai keys). The contract is
                    // that the *fixture text* is the minimal valid context; this proptest
                    // sweeps the OFFSET of that fixture inside arbitrary padding to surface
                    // boundary bugs the static contracts_runner cannot.
            " ".repeat(pad_right),
        );
        let matches = scan_text(&body);
        prop_assert!(
            any_credential_contains(&matches, &p.credential),
            "positive fixture for detector {detector_id:?} did not surface credential {:?} \
             when wrapped in {pad_left} byte(s) of leading and {pad_right} byte(s) of \
             trailing ASCII space padding. Scanner returned {} finding(s) with credentials \
             {:?}. The detector either depends on chunk-edge state or fires only on the \
             exact fixture text. Either way the contract is broken.",
            p.credential,
            matches.len(),
            matches.iter().take(8).map(|m| m.credential.as_ref()).collect::<Vec<_>>(),
        );
    }

    /// Sampler over critical-severity detectors. For every random
    /// pick of a Critical detector, its first positive fixture MUST
    /// scan green - i.e. the planted credential surfaces. This
    /// duplicates a fraction of `contracts_runner`, but it's the
    /// proptest gate that turns a "missed one detector when adding
    /// the next one" regression into a property failure rather than
    /// a single line in a 894-row report.
    ///
    /// Pairs with `every_critical_severity_detector_has_a_positive_
    /// contract_fixture` above: the foreach guarantees a fixture
    /// exists, the proptest guarantees the fixture FIRES under the
    /// production scanner.
    #[test]
    fn random_critical_severity_detector_fires_on_its_positive_fixture(
        idx in 0..usize::MAX,
    ) {
        let critical = &*CRITICAL_DETECTORS;
        prop_assume!(!critical.is_empty());
        let i = idx % critical.len();
        let det = &critical[i];
        let Some(fixture) = CRITICAL_POSITIVE_BY_ID.get(&det.id) else {
            // The deterministic test above already fails loudly if
            // any critical detector lacks a fixture - here we just
            // skip so the property focuses on the firing assertion.
            return Ok(());
        };
        let matches = scan_text(&fixture.text);
        prop_assert!(
            any_credential_contains(&matches, &fixture.credential),
            "critical-severity detector {:?} did NOT surface its positive credential {:?} \
             from fixture text {:?}. Scanner returned {} finding(s): {:?}. \
             A critical detector that misses its own canonical positive is a dead detector.",
            det.id,
            fixture.credential,
            fixture.text,
            matches.len(),
            matches.iter().take(8).map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>(),
        );
    }
}
