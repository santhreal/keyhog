//! SOUNDNESS + DETERMINISM gate for the Hyperscan always-active prefilter on
//! LARGE (windowed) chunks, the regime the `hs_prefilter_max_len` default gate
//! used to keep on the slow `regex::RegexSet` path.
//!
//! `phase2_prefilter_hs_findings_parity` only covers ≤4 KiB mirror files, so
//! the >1 MiB windowed regime, where the prefilter runs HS over the whole
//! preprocessed window, including the appended synthetic region (was UNTESTED).
//! That is exactly where raising the gate had been blocked: a match in the
//! preprocessor's appended synthetic region aliases the real match at a second
//! offset, and which alias survived the per-chunk cap / dedup flipped run to run
//! (a non-total `RawMatch`/dedup order). With ordering made total, HS-large is
//! byte-identical to the RegexSet reference AND deterministic.
//!
//! This builds one ~2 MiB chunk dense with repeated, diverse secrets and asserts:
//!   1. PARITY: HS-large finding set == RegexSet finding set (raw + deduped).
//!   2. DETERMINISM: HS-large produces an identical set across repeated scans.
//! A regression in either is a Law 6 / Law 10 failure and fails the gate.
#![cfg(feature = "simd")]

use std::collections::BTreeSet;
use std::sync::Mutex;

use keyhog_core::{dedup_matches, Chunk, ChunkMetadata, DedupScope, RawMatch};
use keyhog_scanner::{resolution::resolve_matches, CompiledScanner, ScanBackend};

use super::support;
use support::paths::detector_dir;

/// Serialize the two process-global prefilter toggles this test drives so its
/// own A/B/determinism phases never read a half-set state. (The selection is
/// recall-identical either way, so a concurrent reader in another test is
/// harmless, but keeping this test's phases ordered makes its asserts exact.)
static TOGGLE_LOCK: Mutex<()> = Mutex::new(());

/// `(detector_id, credential, offset)`: the raw-match identity the prefilter
/// swap must preserve exactly.
type RawKey = (String, String, usize);

/// Build a ~2 MiB chunk (> `MAX_SCAN_CHUNK_BYTES`, so the scanner WINDOWS it)
/// dense with diverse, deliberately-repeated secret shapes. Repetition is the
/// point: a value that recurs at many offsets is what exercises the synthetic
/// alias / dedup-survivor path that the gate change touches.
fn build_large_corpus() -> String {
    // Shapes chosen to fire without checksum gating: AWS access key (AKIA + 16
    // base32, len 20), and the keyword-form google-forms credential. Half the
    // blocks reuse a FIXED credential (forces cross-offset aliasing); half vary
    // by index (distinct findings).
    const FIXED_GF: &str = "google forms api key abcdefghijklmnopqrstuvwxyz123456";
    let mut buf = String::with_capacity(1_400_000);
    let mut i = 0u32;
    // Just over MAX_SCAN_CHUNK_BYTES (1 MiB) so the scanner windows the chunk
    // while keeping the (debug-slow) RegexSet reference arm tractable.
    while buf.len() < 1_200_000 {
        // AKIA + 16 chars from a fixed alphabet, varied by index.
        let body: String = (0..16)
            .map(|k| {
                let n = (i.wrapping_mul(2_654_435_761).wrapping_add(k)) % 32;
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[n as usize] as char
            })
            .collect();
        buf.push_str(&format!("aws_key_{i} = \"AKIA{body}\"\n"));
        if i % 2 == 0 {
            buf.push_str(&format!("gf_{i} = \"{FIXED_GF}\"\n"));
        } else {
            buf.push_str(&format!("gf_{i} = \"google forms api key zzzz{i:028}\"\n"));
        }
        // Filler so windows are realistically sparse and boundaries vary.
        buf.push_str("    # padding line to space out secrets across the window\n");
        buf.push_str("    const note = \"nothing to see here, ordinary config text\";\n");
        i += 1;
    }
    buf
}

fn scan_raw(scanner: &CompiledScanner, text: &str) -> Vec<RawMatch> {
    // The cross-fragment reassembly cache is a per-scanner field that ACCUMULATES
    // across scans; in production each `keyhog scan` is a fresh process with an
    // empty cache. Reset it before every scan so an in-process A/B comparison
    // mirrors fresh-process semantics (otherwise arm-A fragments pollute arm-B's
    // reassembly and the comparison is meaningless).
    scanner.clear_fragment_cache();
    let chunk = Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "hs-large-parity".into(),
            path: Some("/synthetic/large.cfg".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::SimdCpu)
        .into_iter()
        .flatten()
        .collect()
}

fn raw_keys(matches: &[RawMatch]) -> BTreeSet<RawKey> {
    matches
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

/// Run the full user-visible pipeline (resolve → cross-scan credential dedup)
/// and key on `(detector, credential, primary_offset)`: the reported finding.
fn pipeline_keys(matches: Vec<RawMatch>) -> BTreeSet<RawKey> {
    let resolved = resolve_matches(matches);
    dedup_matches(resolved, &DedupScope::Credential)
        .into_iter()
        .map(|d| {
            (
                d.detector_id.as_ref().to_string(),
                d.credential.as_ref().to_string(),
                d.primary_location.offset,
            )
        })
        .collect()
}

// `#[ignore]` to match `phase2_prefilter_hs_findings_parity`: the RegexSet
// reference arm over a >1 MiB chunk is debug-slow, so this heavy soundness gate
// runs in the dedicated lane (`-- --ignored`, ideally `--release`), not on every
// quick `cargo test`. Run:
//   cargo test -p keyhog-scanner --features ci-lean --release \
//     --test phase2_prefilter_hs_large_parity -- --ignored --nocapture
#[test]
#[ignore = "heavy large-chunk soundness gate; run with --ignored (prefer --release)"]
fn hs_large_prefilter_identical_to_regexset_and_deterministic() {
    let _guard = TOGGLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let text = build_large_corpus();
    assert!(
        text.len() > 1024 * 1024,
        "corpus must exceed MAX_SCAN_CHUNK_BYTES so the scanner windows it (got {})",
        text.len()
    );

    // Force the HS engine for both arms; the ONLY difference is the size gate.
    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(true));

    // Arm A: FORCE HS at every size via a finite gate above any chunk. `None`
    // (and `usize::MAX`) is the follow-env sentinel, and the env default is now
    // the 4096 RegexSet gate (HS scans the full always-active superset → 2.4x
    // slower on large chunks), so Arm A must pin an explicit large gate to still
    // exercise the HS path. Keep the raw matches so the raw- and pipeline-parity
    // asserts reuse one scan each (no extra passes).
    keyhog_scanner::testing::set_hs_prefilter_max_len(&scanner, Some(usize::MAX - 1));
    let hs_raw = scan_raw(&scanner, &text);
    // Arm B: pin the historical 4 KiB gate so the >1 MiB chunk takes the slow
    // RegexSet reference. This is the one expensive scan, reuse it for both
    // parity asserts.
    keyhog_scanner::testing::set_hs_prefilter_max_len(&scanner, Some(4096));
    let regex_raw = scan_raw(&scanner, &text);
    keyhog_scanner::testing::set_hs_prefilter_max_len(&scanner, None);

    let hs_keys = raw_keys(&hs_raw);
    let regex_keys = raw_keys(&regex_raw);

    // Non-trivial coverage: the large regime must actually produce many findings,
    // otherwise the gate proves nothing.
    assert!(
        hs_keys.len() > 500,
        "expected a dense large-chunk finding set, got {} (corpus too sparse?)",
        hs_keys.len()
    );

    // 1. PARITY (raw matches).
    if hs_keys != regex_keys {
        let only_hs: Vec<_> = hs_keys.difference(&regex_keys).take(8).collect();
        let only_rx: Vec<_> = regex_keys.difference(&hs_keys).take(8).collect();
        panic!(
            "HS-large vs RegexSet raw-finding divergence: HS={} RegexSet={}\n  only-HS={:?}\n  only-RegexSet={:?}",
            hs_keys.len(),
            regex_keys.len(),
            only_hs,
            only_rx
        );
    }

    // 1b. PARITY through the full pipeline (resolve + credential dedup), reusing
    // the two scans above.
    let hs_pipe = pipeline_keys(hs_raw.clone());
    let regex_pipe = pipeline_keys(regex_raw);
    assert_eq!(
        hs_pipe,
        regex_pipe,
        "HS-large vs RegexSet deduped-finding divergence ({} vs {})",
        hs_pipe.len(),
        regex_pipe.len()
    );

    // 2. DETERMINISM: HS-large must produce an identical deduped set on every
    // scan. `run_a` reuses the first HS scan; `run_b`/`run_c` are fresh HS scans.
    let run_a = pipeline_keys(hs_raw);
    let run_b = pipeline_keys(scan_raw(&scanner, &text));
    let run_c = pipeline_keys(scan_raw(&scanner, &text));
    assert_eq!(run_a, run_b, "HS-large nondeterministic across runs (a!=b)");
    assert_eq!(run_b, run_c, "HS-large nondeterministic across runs (b!=c)");

    // Restore this scanner's overrides to "follow env" (instance-local).
    keyhog_scanner::testing::set_hs_prefilter_max_len(&scanner, None);
    keyhog_scanner::testing::set_phase2_hs(&scanner, None);
}
