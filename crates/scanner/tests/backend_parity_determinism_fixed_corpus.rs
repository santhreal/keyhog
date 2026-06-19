//! Backend-parity determinism on a FIXED corpus with EXPECTED detectors
//! (TESTING vector 12, lane 9).
//!
//! The sibling `backend_parity_matrix.rs` proves SimdCpu == CpuFallback == GPU
//! by comparing each backend's finding set to SimdCpu's. That is necessary but
//! NOT sufficient: if BOTH the reference and the candidate regressed to the
//! same wrong answer (e.g. both surfaced zero findings after a prefilter bug),
//! an A==B equality check passes green while recall is silently zero. The
//! matrix's own `false_prefix_storm` SKIP path even tolerates an empty GPU set.
//!
//! This suite pins POSITIVE TRUTH first, then parity:
//!   1. A fixed corpus of credentials with VALID checksums (so the github CRC
//!      gate and AWS shape gate hold) must surface an EXACT, named set of
//!      detector ids — asserted against a hard-coded expectation, so a recall
//!      regression that drops one detector flips this red even if every backend
//!      agrees on the wrong (smaller) set.
//!   2. SimdCpu and CpuFallback must then produce field-by-field identical
//!      `RawMatch` records — detector_id, service, severity, credential, and
//!      byte offset — not just matching `(id, credential)` keys. A backend that
//!      mis-tiers severity or mis-attributes service on one path is a real
//!      divergence the looser key-set comparison cannot see.
//!   3. Re-running the same backend twice yields byte-identical records
//!      (determinism): no hash-set iteration order, no fragment-cache bleed.
//!
//! Deterministic and host-independent: only the two CPU backends are compared
//! (both always available); GPU parity lives in the matrix + `gpu_simd_parity`.

#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

/// A fully-comparable projection of a `RawMatch`: every field a parity check
/// cares about, in a deterministically-orderable tuple. Severity is rendered
/// via its canonical `as_str` (the single source of truth) so a re-tiering is
/// visible as a string change.
type MatchRecord = (
    String, // detector_id
    String, // service
    String, // severity (canonical str)
    String, // credential
    usize,  // chunk offset
);

fn project(m: &RawMatch) -> MatchRecord {
    (
        m.detector_id.as_ref().to_string(),
        m.service.as_ref().to_string(),
        m.severity.to_string(),
        m.credential.as_ref().to_string(),
        m.location.offset,
    )
}

fn records(results: &[Vec<RawMatch>]) -> BTreeSet<MatchRecord> {
    results.iter().flatten().map(project).collect()
}

fn detector_ids(results: &[Vec<RawMatch>]) -> BTreeSet<String> {
    results
        .iter()
        .flatten()
        .map(|m| m.detector_id.as_ref().to_string())
        .collect()
}

fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "parity-fixed".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

fn scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory loadable");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

/// The fixed corpus. Each line plants ONE credential whose shape and checksum
/// pass the production gates, so the detector reliably fires on BOTH CPU
/// backends. Credentials reuse the exact tokens proven in the sibling boundary/
/// matrix tests (valid AWS shape, valid github CRC32 tail).
fn fixed_corpus() -> Vec<Chunk> {
    vec![
        chunk(
            "const AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\";\n",
            "fixed/aws.tf",
        ),
        // github PAT with a VALID trailing CRC32 (same token as the boundary
        // parity test); a random tail would be silently dropped by the checksum
        // gate (memory: checksum-invalidates-fabricated-token-fixtures).
        chunk(
            "GITHUB_TOKEN=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\n",
            "fixed/github.env",
        ),
        chunk(
            "stripe_secret = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n",
            "fixed/stripe.ini",
        ),
    ]
}

/// The EXACT detector ids the fixed corpus must surface. Hard-coded so a recall
/// regression that drops any of these (or an over-broad change that adds a
/// spurious one) flips this red — independently of cross-backend agreement.
fn expected_detector_ids() -> BTreeSet<String> {
    ["aws-access-key", "github-classic-pat", "stripe-secret-key"]
        .into_iter()
        .map(String::from)
        .collect()
}

#[test]
fn fixed_corpus_surfaces_exactly_the_expected_detectors_on_simd() {
    let scanner = scanner();
    let corpus = fixed_corpus();
    scanner.clear_fragment_cache();
    let results = scanner.scan_chunks_with_backend(&corpus, ScanBackend::SimdCpu);
    let got = detector_ids(&results);
    let expected = expected_detector_ids();

    let missing: Vec<&String> = expected.difference(&got).collect();
    assert!(
        missing.is_empty(),
        "SimdCpu missed expected detector(s) on the fixed corpus: {missing:?}\n\
         (a recall regression — one of these credentials stopped firing). got={got:?}"
    );

    // Every expected credential value must be present verbatim, proving the
    // finding is the planted secret, not an incidental match.
    let creds: BTreeSet<String> = results
        .iter()
        .flatten()
        .map(|m| m.credential.as_ref().to_string())
        .collect();
    for want in [
        "AKIAQYLPMN5HFIQR7XYA",
        "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",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    ] {
        assert!(
            creds.iter().any(|c| c.contains(want)),
            "expected credential {want:?} not surfaced; got creds={creds:?}"
        );
    }
}

#[test]
fn simd_and_cpu_fallback_produce_identical_match_records() {
    let scanner = scanner();
    let corpus = fixed_corpus();

    scanner.clear_fragment_cache();
    let simd = records(&scanner.scan_chunks_with_backend(&corpus, ScanBackend::SimdCpu));

    scanner.clear_fragment_cache();
    let cpu = records(&scanner.scan_chunks_with_backend(&corpus, ScanBackend::CpuFallback));

    // Positive floor first: neither path may be empty (guards the "both
    // regressed to zero, so equality is vacuously true" failure mode).
    assert!(
        simd.len() >= expected_detector_ids().len(),
        "SimdCpu produced too few records ({}) — expected at least {}",
        simd.len(),
        expected_detector_ids().len()
    );

    let only_simd: Vec<&MatchRecord> = simd.difference(&cpu).collect();
    let only_cpu: Vec<&MatchRecord> = cpu.difference(&simd).collect();
    assert!(
        only_simd.is_empty() && only_cpu.is_empty(),
        "SimdCpu and CpuFallback diverged on the fixed corpus.\n  \
         only in SimdCpu: {only_simd:?}\n  only in CpuFallback: {only_cpu:?}"
    );

    // Exact-equality pin: the full record sets are identical, field for field.
    assert_eq!(
        simd, cpu,
        "the two CPU backends must agree on detector_id, service, severity, \
         credential, and offset for every finding"
    );
}

#[test]
fn each_cpu_backend_is_deterministic_across_two_runs() {
    let scanner = scanner();
    let corpus = fixed_corpus();
    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        scanner.clear_fragment_cache();
        let first = records(&scanner.scan_chunks_with_backend(&corpus, backend));
        scanner.clear_fragment_cache();
        let second = records(&scanner.scan_chunks_with_backend(&corpus, backend));
        assert!(
            !first.is_empty(),
            "{backend:?} surfaced nothing on the fixed corpus — recall floor breached"
        );
        assert_eq!(
            first, second,
            "{backend:?} is non-deterministic: two runs of the same corpus \
             produced different record sets"
        );
    }
}
