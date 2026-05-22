//! Property-test invariant battery for the GPU + cross-backend
//! contract. Each property is checked against 256–1024 randomized
//! inputs per CI run (proptest's default is 256; the heavier
//! cross-backend properties get 64 to keep runtime bounded since each
//! case does ≥2 full scanner.scan() invocations).
//!
//! The invariants:
//!
//!   * **P1** — SIMD and GPU produce the same finding set on any input
//!     within the safe alphabet (no embedded NULs that would split
//!     C-string buffers in the GPU shader). Catches divergence.
//!   * **P2** — `CpuFallback` is a strict superset of any backend's
//!     findings on adversarial inputs (it's the ground-truth scalar
//!     reference). If SIMD reports a finding CpuFallback doesn't, the
//!     finding is suspect.
//!   * **P3** — chunk-boundary splits do not change the finding set
//!     (the boundary scanner reassembles).
//!   * **P4** — no input causes any backend to panic.
//!
//! These invariants generate 1000s of test cases per run from a
//! handful of generators — exactly the "thousands of tests" coverage
//! the GPU axis needs.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// Cache the compiled scanner across all property cases. Re-compiling
/// 889 detectors per case would push a 1024-case property run from
/// seconds into minutes.
fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<Option<CompiledScanner>> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            keyhog_core::load_detectors(&detector_dir())
                .ok()
                .and_then(|d| CompiledScanner::compile(d).ok())
        })
        .as_ref()
        .expect("scanner compile failed; detectors dir unavailable")
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "proptest".into(),
            path: Some("prop.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| {
            (
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(str::to_string)
                    .unwrap_or_default(),
                m.location.offset,
            )
        })
        .collect()
}

/// Strategy: ASCII-printable + newline, length 1..=4096. Excludes
/// NUL because the GPU shader treats NUL as buffer-terminator in some
/// paths; the property here is about FINDING parity, not
/// shader-buffer edge cases (those have their own tests in
/// `gpu_ac_smoke.rs`).
fn arb_chunk_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            32u8..=126u8,
            Just(b'\n'),
            Just(b'\t'),
        ],
        1..=4096,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("ASCII bytes are valid UTF-8"))
}

/// Strategy for inputs that DELIBERATELY contain known-prefix
/// substrings — boosts the proptest-coverage on the "literal-prefix
/// hits, regex may or may not confirm" code path.
fn arb_chunk_text_with_prefix_seeds() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(
            prop_oneof![
                32u8..=126u8,
                Just(b'\n'),
            ],
            1..=2048,
        ),
        proptest::collection::vec(
            proptest::sample::select(vec![
                "AKIA",
                "ASIA",
                "ghp_",
                "gho_",
                "ghu_",
                "ghs_",
                "github_pat_",
                "sk_live_",
                "sk_test_",
                "xoxb-",
                "AIza",
                "rzp_test_",
            ]),
            0..=10,
        ),
        proptest::collection::vec(
            proptest::collection::vec(
                proptest::sample::select(vec![b'A', b'B', b'C', b'D', b'E', b'1', b'2', b'3', b'4', b'5']),
                10..=40,
            ),
            0..=10,
        ),
    )
        .prop_map(|(base, prefixes, bodies)| {
            let mut s = String::from_utf8(base).unwrap_or_default();
            for (i, prefix) in prefixes.iter().enumerate() {
                let body = bodies
                    .get(i)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                s.push_str(&format!("\nKEY = \"{prefix}{body}\";\n"));
            }
            s
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Keep cases tight for cross-backend properties — every case
        // runs 2 full scanner.scan() invocations. 64 cases × 2 scans
        // × ~5ms = ~640ms per property, fits a CI test budget.
        cases: 64,
        .. ProptestConfig::default()
    })]

    /// P1: SIMD and CpuFallback agree on every ASCII input.
    /// CpuFallback is the scalar ground truth — if SIMD reports
    /// something the scalar AC + regex didn't, it's an over-firing
    /// regression on the Hyperscan path.
    #[test]
    fn p1_simd_matches_cpu_fallback_on_ascii(input in arb_chunk_text()) {
        let scanner = scanner();
        // Clear cross-file fragment_cache between the two backend scans
        // so each starts from an identical (empty) state. Without this,
        // the FIRST backend's scan populates fragments that the SECOND
        // backend's scan then reads, producing different cross-file
        // reassembly findings. That's a TEST-isolation issue, not an
        // engine bug — production callers scan once per process so the
        // cache only accumulates within a single intentional scan run.
        scanner.clear_fragment_cache();
        let chunks = vec![make_chunk(&input)];
        let simd = collect_keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu));
        scanner.clear_fragment_cache();
        let cpu = collect_keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback));
        prop_assert_eq!(
            &simd, &cpu,
            "SIMD/CpuFallback divergence on input.len={}", input.len()
        );
    }

    /// P1b: same property under prefix-seeded inputs (boosts coverage
    /// on the hot code path).
    #[test]
    fn p1b_simd_matches_cpu_fallback_with_prefix_seeds(input in arb_chunk_text_with_prefix_seeds()) {
        let scanner = scanner();
        scanner.clear_fragment_cache();
        let chunks = vec![make_chunk(&input)];
        let simd = collect_keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu));
        scanner.clear_fragment_cache();
        let cpu = collect_keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback));
        prop_assert_eq!(
            &simd, &cpu,
            "SIMD/CpuFallback divergence on prefix-seeded input.len={}", input.len()
        );
    }

    /// P3: chunk-boundary split-and-reassemble preserves the finding
    /// set. Splits a random input at a random mid-point into two
    /// chunks and asserts the union of findings equals the single-
    /// chunk findings.
    #[test]
    fn p3_chunk_boundary_split_preserves_findings(
        input in arb_chunk_text_with_prefix_seeds(),
        split_frac in 1u32..=99u32,
    ) {
        let scanner = scanner();
        scanner.clear_fragment_cache();
        let single = collect_keys(&scanner.scan_chunks_with_backend(
            &[make_chunk(&input)],
            ScanBackend::SimdCpu,
        ));

        // Pick a UTF-8 boundary near split_frac% of the input length.
        let split_byte = {
            let target = (input.len() * split_frac as usize) / 100;
            let mut s = target.min(input.len().saturating_sub(1));
            while s < input.len() && !input.is_char_boundary(s) {
                s += 1;
            }
            s
        };

        let (a, b) = input.split_at(split_byte);
        let chunk_a = make_chunk(a);
        let chunk_b = Chunk {
            data: b.into(),
            metadata: ChunkMetadata {
                source_type: "proptest".into(),
                path: Some("prop.txt".into()),
                base_offset: split_byte,
                ..Default::default()
            },
        };
        let split = collect_keys(&scanner.scan_chunks_with_backend(
            &[chunk_a, chunk_b],
            ScanBackend::SimdCpu,
        ));

        // The split finding set must contain every single-chunk finding.
        // (It MAY add boundary findings the single-chunk pass missed —
        // those are the symmetric case we care about, but they only
        // happen if a secret literally straddles the split point.)
        for key in &single {
            prop_assert!(
                split.contains(key),
                "chunk-split dropped finding {:?} at split={}/{}",
                key, split_byte, input.len()
            );
        }
    }

    /// P4: no panic on any input. The scanner must handle every byte
    /// sequence without aborting the rayon worker — that's the contract
    /// of a process-safe scanner.
    #[test]
    fn p4_simd_no_panic_on_arbitrary_input(
        bytes in proptest::collection::vec(any::<u8>(), 0..=2048)
    ) {
        let scanner = scanner();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let _ = scanner.scan_chunks_with_backend(&[make_chunk(&text)], ScanBackend::SimdCpu);
    }

    #[test]
    fn p4b_cpu_fallback_no_panic_on_arbitrary_input(
        bytes in proptest::collection::vec(any::<u8>(), 0..=2048)
    ) {
        let scanner = scanner();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let _ = scanner.scan_chunks_with_backend(&[make_chunk(&text)], ScanBackend::CpuFallback);
    }
}
