//! Regression: the phase-1 **trigger bitmap** is recall-load-bearing and MUST
//! be the *union* of the AC-literal pass and the Hyperscan (HS) pass.
//!
//! Two structurally different detector classes reach the confirmed-extraction
//! path through the same `Vec<u64>` trigger bitmap:
//!
//!   * **AC-literal detectors** — e.g. `aws-access-key`, whose regex begins with
//!     the fixed literal `AKIA`/`ASIA`. The Aho-Corasick literal pass
//!     (`collect_triggered_patterns_cpu`) sets their bit directly.
//!   * **No-usable-literal detectors** — e.g. `twilio-auth-token`, a context-
//!     anchored `…auth…token…=(hex32)` shape with no distinctive literal prefix
//!     the AC pass can key on. Their bit is set ONLY by the Hyperscan pass, and
//!     the SIMD/GPU trigger collectors must OR that into the AC bitmap
//!     (`collect_triggered_patterns_simd`). Prior sessions proved ~49 such
//!     detectors go silently dead if the union is dropped
//!     (`SIMD trigger union is recall-load-bearing`, fixed @3ccad545).
//!
//! Every assertion pins a concrete value — an exact `usize` word count, an exact
//! finding count, the exact credential bytes, and the exact byte offset the
//! credential is reported at — never `is_empty()`/`is_ok()`. Positive, negative
//! twin, boundary, and adversarial cases are all covered.
//!
//! HS-dependent cases are `#[cfg(feature = "simd")]`: the `twilio-auth-token`
//! HS-only firing exists only when Hyperscan is compiled in (the default feature
//! set). The trigger-bitmap sizing primitives and the AC-literal `aws-access-key`
//! cases are backend-agnostic and always compile.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{testing, CompiledScanner};
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

#[cfg(feature = "simd")]
use keyhog_scanner::ScanBackend;

/// One shared full-detector scanner. `scanner()` recompiles every on-disk
/// detector per call, so caching keeps the suite fast. The harness runs these
/// `#[test]`s serially, and each scan clears the fragment cache, so no state
/// leaks between cases.
fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

// A real, entropy-bearing AWS access-key id (`AKIA` + 16 uppercase alnum). The
// `aws-access-key` regex `(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b` matches it directly;
// it surfaces via the AC-literal trigger on every backend.
const AWS_KEY: &str = "AKIAZ7QH4XNB2WKLP3RV";

// The canonical Twilio auth-token contract positive (see
// `tests/contracts/twilio-auth-token.toml`): a 32-hex token that fires ONLY
// once its `account_sid` companion (`AC` + 32 hex) is present within 5 lines.
// `twilio-auth-token` has no AC-usable literal, so its trigger bit is set only
// by the Hyperscan pass — the exact union invariant this file locks.
#[cfg(feature = "simd")]
const TWILIO_TOKEN: &str = "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f";
#[cfg(feature = "simd")]
const TWILIO_ACCOUNT_SID: &str = "AC7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d";

/// Build a Twilio env-var pair whose `account_sid` companion sits within the
/// required 5-line window of the auth token.
#[cfg(feature = "simd")]
fn twilio_pair() -> String {
    format!("TWILIO_ACCOUNT_SID={TWILIO_ACCOUNT_SID}\nTWILIO_AUTH_TOKEN={TWILIO_TOKEN}\n")
}

// ===========================================================================
// Group A — trigger-bitmap sizing primitives (backend-agnostic, exact usize).
//
// `words_for` and `new_trigger_bitmap` are the single owner of the
// `div_ceil(64)` sizing every trigger bitmap (AC, SIMD, and pooled scratch)
// derives from. A word-width or ceil regression here silently mis-sizes the
// bitmap and drops or overruns pattern bits.
// ===========================================================================

#[test]
fn words_for_boundaries_are_exact_div_ceil_64() {
    // 0 patterns need 0 words; a single pattern needs a whole word.
    assert_eq!(testing::trigger_bitmap_words_for_test(0), 0);
    assert_eq!(testing::trigger_bitmap_words_for_test(1), 1);
    // A full word holds exactly 64 bits.
    assert_eq!(testing::trigger_bitmap_words_for_test(63), 1);
    assert_eq!(testing::trigger_bitmap_words_for_test(64), 1);
    // One bit past a word boundary rolls into a second word.
    assert_eq!(testing::trigger_bitmap_words_for_test(65), 2);
    assert_eq!(testing::trigger_bitmap_words_for_test(128), 2);
    assert_eq!(testing::trigger_bitmap_words_for_test(129), 3);
}

#[test]
fn words_for_large_values_are_exact() {
    // 4096 patterns == 64 full words, exactly.
    assert_eq!(testing::trigger_bitmap_words_for_test(4096), 64);
    // 4097 rolls into a 65th word.
    assert_eq!(testing::trigger_bitmap_words_for_test(4097), 65);
    // 4095 still fits in 64 words (63 full + 63 bits of the 64th).
    assert_eq!(testing::trigger_bitmap_words_for_test(4095), 64);
}

#[test]
fn new_trigger_bitmap_length_equals_words_for() {
    // A fresh bitmap for N patterns is exactly `words_for(N)` words long.
    assert_eq!(testing::new_trigger_bitmap_for_test(0).len(), 0);
    assert_eq!(testing::new_trigger_bitmap_for_test(1).len(), 1);
    assert_eq!(testing::new_trigger_bitmap_for_test(64).len(), 1);
    assert_eq!(testing::new_trigger_bitmap_for_test(65).len(), 2);
    assert_eq!(testing::new_trigger_bitmap_for_test(130).len(), 3);
}

#[test]
fn new_trigger_bitmap_is_fully_zeroed() {
    // Every word of a fresh bitmap is zero — no pattern is spuriously triggered
    // before the AC/HS passes run.
    let bitmap = testing::new_trigger_bitmap_for_test(200);
    assert_eq!(bitmap.len(), 4); // 200.div_ceil(64) == 4
    assert_eq!(bitmap.iter().filter(|&&w| w != 0).count(), 0);
    assert_eq!(bitmap.iter().copied().sum::<u64>(), 0u64);
}

#[test]
fn words_for_and_bitmap_len_agree_over_range() {
    // The two owners must never disagree on sizing for any pattern count.
    for n in 0usize..300 {
        let words = testing::trigger_bitmap_words_for_test(n);
        let bitmap = testing::new_trigger_bitmap_for_test(n);
        assert_eq!(bitmap.len(), words, "sizing disagreement at n={n}");
        // Capacity (in bits) is always >= n and < n + 64.
        let capacity_bits = words * 64;
        assert!(
            capacity_bits >= n,
            "under-sized at n={n}: {capacity_bits} bits"
        );
        assert!(
            capacity_bits < n + 64,
            "over-sized at n={n}: {capacity_bits} bits"
        );
    }
}

// ===========================================================================
// Group B — AC-literal trigger path (backend-agnostic; `aws-access-key`).
// ===========================================================================

#[test]
fn aws_access_key_ac_literal_surfaces_at_exact_offset() {
    let text = format!("aws_access_key_id = {AWS_KEY}\n");
    let expected_offset = text.find(AWS_KEY).expect("key present in fixture");
    let chunk = make_chunk(&text, "filesystem", "aws.conf");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);

    let aws: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .collect();
    assert_eq!(
        aws.len(),
        1,
        "exactly one aws-access-key finding; got {matches:?}"
    );
    assert_eq!(aws[0].credential.as_ref(), AWS_KEY);
    // Offset is the credential start byte within the chunk (base_offset == 0).
    assert_eq!(aws[0].location.offset, expected_offset);
}

#[test]
fn aws_access_key_nonzero_base_offset_reports_absolute() {
    // The AC-literal trigger path must add the chunk `base_offset` so a secret
    // deep inside a windowed file reports its absolute byte offset.
    let text = format!("aws_access_key_id = {AWS_KEY}\n");
    let local_offset = text.find(AWS_KEY).expect("key present");
    let base_offset = 4096usize;
    let base_line = 23usize;
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("windowed-aws.conf".into()),
            base_offset,
            base_line,
            ..Default::default()
        },
    };

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);
    let aws: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .collect();
    assert_eq!(
        aws.len(),
        1,
        "exactly one aws-access-key finding; got {matches:?}"
    );
    assert_eq!(aws[0].location.offset, base_offset + local_offset);
    assert_eq!(aws[0].location.line, Some(base_line + 1));
}

#[test]
fn false_prefix_storm_confirms_exactly_one_key() {
    // Adversarial: 400 `AKIA_…` decoys (the `_` breaks the `[0-9A-Z]{16}`
    // body, so the regex rejects each) surround ONE real key. The AC pass sets
    // the aws-access-key trigger bit for every `AKIA` occurrence; the confirmed
    // regex must still emit exactly ONE finding — the real key. A regression
    // that emitted a finding per prefix-hit (or dropped the trigger) fails here.
    let mut text = String::with_capacity(16_384);
    for i in 0..200 {
        text.push_str(&format!("noise AKIA_{i:08}_short\n"));
    }
    text.push_str(&format!("const KEY = \"{AWS_KEY}\";\n"));
    for i in 0..200 {
        text.push_str(&format!("more  AKIA_{i:08}_short\n"));
    }
    let expected_offset = text.find(AWS_KEY).expect("real key present");
    let chunk = make_chunk(&text, "filesystem", "storm.txt");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);
    let aws: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .collect();
    assert_eq!(
        aws.len(),
        1,
        "AC-literal prefix storm must confirm exactly one real key, not one-per-prefix"
    );
    assert_eq!(aws[0].credential.as_ref(), AWS_KEY);
    assert_eq!(aws[0].location.offset, expected_offset);
}

#[test]
fn clean_region_is_not_triggered() {
    // Negative twin: prose with no credential. The trigger bitmap stays zero for
    // the credential detectors, so nothing is confirmed. Assert exact zero
    // counts for the two detectors this file exercises AND an empty finding set.
    let text = "// pure prose, no credentials here at all\n\
                fn hello() -> Result<(), Error> { Ok(()) }\n";
    let chunk = make_chunk(text, "filesystem", "clean.rs");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);

    let aws_count = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .count();
    let twilio_count = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "twilio-auth-token")
        .count();
    assert_eq!(aws_count, 0, "clean region must not trigger aws-access-key");
    assert_eq!(
        twilio_count, 0,
        "clean region must not trigger twilio-auth-token"
    );
    assert_eq!(
        matches.len(),
        0,
        "clean region must yield zero findings; got {matches:?}"
    );
}

// ===========================================================================
// Group C — Hyperscan-only trigger path + AC∪HS union (`twilio-auth-token`).
// ===========================================================================

#[cfg(feature = "simd")]
#[test]
fn twilio_auth_token_hs_only_surfaces_exact_credential() {
    // `twilio-auth-token` has no AC-usable literal prefix; its trigger bit is set
    // ONLY by the Hyperscan pass. If the SIMD collector failed to union the HS
    // hits into the AC bitmap, this detector would be silently dead.
    let text = twilio_pair();
    let chunk = make_chunk(&text, "filesystem", "twilio.env");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);

    let token_hit = matches
        .iter()
        .find(|m| {
            m.detector_id.as_ref() == "twilio-auth-token" && m.credential.as_ref() == TWILIO_TOKEN
        })
        .unwrap_or_else(|| panic!("twilio-auth-token must surface via HS union; got {matches:?}"));
    assert_eq!(token_hit.detector_id.as_ref(), "twilio-auth-token");
    assert_eq!(token_hit.credential.as_ref(), TWILIO_TOKEN);
}

#[cfg(feature = "simd")]
#[test]
fn twilio_auth_token_reported_at_credential_offset() {
    // The HS-triggered region must be reported at the exact byte offset of the
    // captured credential (group start), not the match/anchor start.
    let text = twilio_pair();
    let expected_offset = text.find(TWILIO_TOKEN).expect("token present");
    let chunk = make_chunk(&text, "filesystem", "twilio.env");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);

    let token_hit = matches
        .iter()
        .find(|m| {
            m.detector_id.as_ref() == "twilio-auth-token" && m.credential.as_ref() == TWILIO_TOKEN
        })
        .unwrap_or_else(|| panic!("twilio-auth-token must surface; got {matches:?}"));
    assert_eq!(token_hit.location.offset, expected_offset);
}

#[cfg(feature = "simd")]
#[test]
fn twilio_missing_companion_is_suppressed() {
    // Negative twin: the auth token WITHOUT its `account_sid` companion. The
    // required-companion gate suppresses the finding even though the HS trigger
    // fires — proving the trigger union does not overreach into a false positive.
    let text = format!("TWILIO_AUTH_TOKEN={TWILIO_TOKEN}\n");
    let chunk = make_chunk(&text, "filesystem", "twilio-lonely.env");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);

    let twilio_count = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "twilio-auth-token")
        .count();
    assert_eq!(
        twilio_count, 0,
        "auth token with no account_sid companion must be suppressed; got {matches:?}"
    );
}

#[cfg(feature = "simd")]
#[test]
fn union_ac_literal_and_hs_only_both_surface_same_chunk() {
    // THE union invariant: one chunk carrying BOTH an AC-literal secret
    // (aws-access-key via AKIA) AND an HS-only secret (twilio-auth-token) must
    // surface BOTH from a single scan. If the trigger bitmap were AC-only the
    // twilio token vanishes; if it dropped the AC pass the aws key vanishes.
    let text = format!("aws_access_key_id = {AWS_KEY}\n{}", twilio_pair());
    let aws_offset = text.find(AWS_KEY).expect("aws key present");
    let twilio_offset = text.find(TWILIO_TOKEN).expect("twilio token present");
    let chunk = make_chunk(&text, "filesystem", "union.env");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan(&chunk);

    let aws: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == AWS_KEY)
        .collect();
    assert_eq!(
        aws.len(),
        1,
        "AC-literal aws-access-key must survive the union; got {matches:?}"
    );
    assert_eq!(aws[0].location.offset, aws_offset);

    let twilio: Vec<_> = matches
        .iter()
        .filter(|m| {
            m.detector_id.as_ref() == "twilio-auth-token" && m.credential.as_ref() == TWILIO_TOKEN
        })
        .collect();
    assert_eq!(
        twilio.len(),
        1,
        "HS-only twilio-auth-token must survive the union; got {matches:?}"
    );
    assert_eq!(twilio[0].location.offset, twilio_offset);
}

#[cfg(feature = "simd")]
#[test]
fn union_holds_on_explicit_simdcpu_backend() {
    // Pin the union on the exact backend that runs the SIMD trigger collector.
    // `SimdCpu` unions `collect_triggered_patterns_cpu` (AC) with the Hyperscan
    // confirmed-trigger pass; both secrets must appear.
    let text = format!("aws_access_key_id = {AWS_KEY}\n{}", twilio_pair());
    let chunk = make_chunk(&text, "filesystem", "union-simdcpu.env");

    let s = shared();
    s.clear_fragment_cache();
    let matches = s.scan_with_backend(&chunk, ScanBackend::SimdCpu);

    let aws_count = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == AWS_KEY)
        .count();
    let twilio_count = matches
        .iter()
        .filter(|m| {
            m.detector_id.as_ref() == "twilio-auth-token" && m.credential.as_ref() == TWILIO_TOKEN
        })
        .count();
    assert_eq!(
        aws_count, 1,
        "SimdCpu must surface the AC-literal aws key; got {matches:?}"
    );
    assert_eq!(
        twilio_count, 1,
        "SimdCpu must surface the HS-only twilio token; got {matches:?}"
    );
}

#[cfg(feature = "simd")]
#[test]
fn union_scan_is_deterministic_across_two_runs() {
    // Running the same union chunk twice yields byte-identical
    // (detector_id, credential, offset) triples — no HS/AC iteration-order or
    // trigger-bitmap nondeterminism.
    let text = format!("aws_access_key_id = {AWS_KEY}\n{}", twilio_pair());
    let chunk = make_chunk(&text, "filesystem", "union-determinism.env");

    let keys = |scanner: &CompiledScanner| -> Vec<(String, String, usize)> {
        scanner.clear_fragment_cache();
        let mut v: Vec<_> = scanner
            .scan(&chunk)
            .iter()
            .map(|m| {
                (
                    m.detector_id.as_ref().to_string(),
                    m.credential.as_ref().to_string(),
                    m.location.offset,
                )
            })
            .collect();
        v.sort();
        v
    };

    let s = shared();
    let run_a = keys(s);
    let run_b = keys(s);
    assert_eq!(run_a, run_b, "union scan must be deterministic");
    // And both runs must actually contain the two load-bearing findings.
    assert!(
        run_a
            .iter()
            .any(|(d, c, _)| d == "aws-access-key" && c == AWS_KEY),
        "aws key missing from union run: {run_a:?}"
    );
    assert!(
        run_a
            .iter()
            .any(|(d, c, _)| d == "twilio-auth-token" && c == TWILIO_TOKEN),
        "twilio token missing from union run: {run_a:?}"
    );
}
