//! Regression: recursive (base64-in-base64) decode-through depth handling in
//! the decode pipeline (`crates/scanner/src/decode/pipeline.rs`) and the full
//! scan post-process (`engine/scan_postprocess.rs`).
//!
//! Contract under test — every assertion pins a CONCRETE value (exact decoded
//! bytes, exact detector id, exact credential string, exact finding count,
//! exact "no-decode" empty set):
//!   * A single base64 layer over a secret is peeled and the EXACT plaintext
//!     bytes are recovered (`base64(secret)` -> `secret`).
//!   * A DOUBLE-wrapped secret `base64(base64(secret))` is recovered at decode
//!     DEPTH 2 — both the intermediate encoding AND the innermost plaintext
//!     appear in the decoded set.
//!   * The depth cap is a hard `depth >= max_depth { continue }` bound: with a
//!     budget of 1 the double-wrapped secret is NOT recovered (only the
//!     intermediate layer surfaces); a triple wrap needs depth 3, not 2.
//!   * A too-deep wrap (more layers than the budget) is NOT infinitely recursed
//!     — the call returns promptly without panicking and does NOT surface the
//!     base payload.
//!   * `max_depth == 0` performs NO decode at all (the fast-preset contract).
//!   * End to end, a nested-base64-wrapped AWS access key is recovered by the
//!     real `aws-access-key` detector with the exact credential bytes, and a
//!     wrap deeper than the shipped `MAX_DECODE_DEPTH_LIMIT` (10) yields no such
//!     finding. A per-scanner `max_decode_depth` config bounds the peel count
//!     precisely (depth 1 misses the double wrap, depth 2 recovers it).
//!
//! HOST-INDEPENDENCE: every assertion here is the CPU/scalar decode + scan
//! contract. `decode_chunk` is the pure BFS decode pipeline and `CompiledScanner`
//! auto-selects whatever backend the host has; the recovered bytes, detector id,
//! and finding counts are the backend-invariant result every backend must
//! reproduce. No Hyperscan/SIMD/GPU accelerator is assumed or required, and no
//! backend is forced.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::testing::decode_chunk;
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A real, detector-recognised AWS access key (the `aws-access-key` detector's
/// `AKIA` + 16 uppercase-alnum shape). Reused across every recovery assertion so
/// the recovered bytes are checked against one exact, known value.
const SECRET: &str = "AKIAQYLPMN5HFIQR7XYA";

/// Standard-alphabet base64 of `bytes` (the encoder the pipeline's base64
/// decoder inverts).
fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

/// `base64` applied `layers` times over `secret` (layer 0 = the raw secret).
fn nest(secret: &str, layers: usize) -> String {
    let mut s = secret.to_string();
    for _ in 0..layers {
        s = b64(s.as_bytes());
    }
    s
}

/// A whole-string chunk with no path (the decode pipeline scans `data` directly).
fn bare_chunk(data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

/// True when some decoded sub-chunk's bytes equal `expected` exactly.
fn decoded_contains(chunks: &[Chunk], expected: &str) -> bool {
    chunks.iter().any(|c| &*c.data == expected)
}

/// Compile the shipped detector set (repo-root `detectors/`) with the default
/// scanner config (`max_decode_depth == 10`).
fn shipped_scanner() -> CompiledScanner {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop(); // crates/
    dir.pop(); // repo root
    dir.push("detectors");
    let detectors = keyhog_core::load_detectors(&dir).expect("load shipped detectors");
    CompiledScanner::compile(detectors).expect("compile shipped detectors")
}

/// A path-bearing chunk that carries `data` through the full scan (decode-through
/// runs in `scan_postprocess`). `CONFIG_B64=` gives the encoded run an
/// assignment anchor exactly as the real front door sees it.
fn scan_chunk(data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("config.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// The `aws-access-key` findings whose credential is EXACTLY `SECRET`.
fn aws_secret_hits(matches: &[RawMatch]) -> Vec<&RawMatch> {
    matches
        .iter()
        .filter(|m| &*m.detector_id == "aws-access-key" && &*m.credential == SECRET)
        .collect()
}

// ── decode-pipeline depth handling (pure BFS decode, no scan) ────────────────

#[test]
fn single_layer_recovers_exact_secret_bytes() {
    // base64(secret) with a decode budget of 1 peels the one layer and yields
    // the EXACT plaintext bytes.
    let e1 = nest(SECRET, 1);
    assert_ne!(
        e1, SECRET,
        "the encoded form must differ from the plaintext"
    );
    let decoded = decode_chunk(&bare_chunk(e1), 1, true, None, None);
    assert!(
        decoded_contains(&decoded, SECRET),
        "single base64 layer must decode to exactly {SECRET:?}; got {:?}",
        decoded
            .iter()
            .map(|c| c.data.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn depth1_cap_stops_before_double_wrapped_secret() {
    // Negative twin of the depth-2 recovery: base64(base64(secret)) with a
    // budget of 1 peels exactly ONE layer. The intermediate encoding surfaces,
    // the innermost plaintext does NOT — the `depth >= max_depth` guard stops
    // the second peel.
    let e1 = nest(SECRET, 1);
    let e2 = nest(SECRET, 2);
    let decoded = decode_chunk(&bare_chunk(e2), 1, true, None, None);
    assert!(
        decoded_contains(&decoded, &e1),
        "depth-1 decode must surface the intermediate layer {e1:?}"
    );
    assert!(
        !decoded_contains(&decoded, SECRET),
        "depth-1 decode MUST NOT reach the double-wrapped secret (needs depth 2)"
    );
}

#[test]
fn nested_depth2_recovers_exact_secret_bytes_and_intermediate() {
    // The core contract: base64(base64(secret)) recovered at DEPTH 2. Both the
    // intermediate encoding (produced at depth 1) and the innermost plaintext
    // (produced at depth 2) appear in the decoded set with exact bytes.
    let e1 = nest(SECRET, 1);
    let e2 = nest(SECRET, 2);
    let decoded = decode_chunk(&bare_chunk(e2), 2, true, None, None);
    assert!(
        decoded_contains(&decoded, &e1),
        "depth-2 decode must include the intermediate layer {e1:?}"
    );
    assert!(
        decoded_contains(&decoded, SECRET),
        "depth-2 decode must recover exactly {SECRET:?}; got {:?}",
        decoded
            .iter()
            .map(|c| c.data.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn triple_wrap_not_recovered_at_depth2_but_recovered_at_depth3() {
    // Boundary: a triple-wrapped secret needs THREE peels. Depth 2 is one short
    // (secret absent); depth 3 recovers it exactly. Pins that the cap counts
    // peels, not a fixed constant.
    let e3 = nest(SECRET, 3);
    let at2 = decode_chunk(&bare_chunk(e3.clone()), 2, true, None, None);
    assert!(
        !decoded_contains(&at2, SECRET),
        "a triple wrap must NOT be recovered at depth 2"
    );
    let at3 = decode_chunk(&bare_chunk(e3), 3, true, None, None);
    assert!(
        decoded_contains(&at3, SECRET),
        "a triple wrap must be recovered at depth 3 as exactly {SECRET:?}"
    );
}

#[test]
fn max_depth_zero_performs_no_decode() {
    // The fast-preset contract (`max_decode_depth = 0`): the root chunk is
    // dequeued, `0 >= 0` trips the cap immediately, and NOTHING is decoded.
    let e1 = nest(SECRET, 1);
    let decoded = decode_chunk(&bare_chunk(e1), 0, true, None, None);
    assert!(
        decoded.is_empty(),
        "max_depth 0 must decode nothing; got {} chunk(s)",
        decoded.len()
    );
    assert!(
        !decoded_contains(&decoded, SECRET),
        "max_depth 0 must not surface the secret"
    );
}

#[test]
fn overdeep_wrap_is_capped_no_panic_and_secret_absent() {
    // Adversarial: 12 base64 layers with a budget of 3 must NOT recurse forever.
    // The call returns (no panic — reaching the assertions proves it), promptly,
    // and the deeply-buried secret never surfaces past the cap.
    let bomb = nest(SECRET, 12);
    let start = Instant::now();
    let decoded = decode_chunk(&bare_chunk(bomb), 3, true, None, None);
    let elapsed = start.elapsed();
    assert!(
        !decoded_contains(&decoded, SECRET),
        "a 12-layer wrap must not be recovered under a depth-3 budget"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "capped decode must finish promptly; took {elapsed:?}"
    );
}

#[test]
fn twenty_layer_bomb_finishes_and_base_payload_not_surfaced() {
    // 20 layers with a budget of 10: the BFS peels at most 10 times, so the base
    // payload (20 layers down) is unreachable. Pins that the depth cap bounds
    // work even at the shipped max budget, without hanging.
    let base = "payload";
    let bomb = nest(base, 20);
    let start = Instant::now();
    let decoded = decode_chunk(&bare_chunk(bomb), 10, true, None, None);
    let elapsed = start.elapsed();
    assert!(
        !decoded_contains(&decoded, base),
        "a 20-layer wrap must not surface {base:?} under a depth-10 budget"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "depth-10 decode bomb must finish promptly; took {elapsed:?}"
    );
}

// ── full scan: detector id + exact credential over nested base64 ─────────────

#[test]
fn scan_unencoded_akia_baseline_detector_and_bytes() {
    // Control: the un-encoded secret must fire the aws-access-key detector with
    // the exact credential, so the nested-recovery tests below are meaningful.
    let scanner = shipped_scanner();
    let matches = scanner.scan(&scan_chunk(format!("CONFIG={SECRET}")));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        1,
        "plain AKIA must yield exactly one aws-access-key finding; matches: {matches:#?}"
    );
    assert_eq!(&*hits[0].credential, SECRET);
}

#[test]
fn scan_single_layer_base64_yields_aws_detector_and_bytes() {
    // Single base64 layer through the real scan front door: decode-through peels
    // it and the aws-access-key detector fires on the exact plaintext.
    let scanner = shipped_scanner();
    let data = format!("CONFIG_B64={}", nest(SECRET, 1));
    let matches = scanner.scan(&scan_chunk(data));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        1,
        "single-layer base64 must yield exactly one aws-access-key finding; matches: {matches:#?}"
    );
    assert_eq!(&*hits[0].detector_id, "aws-access-key");
    assert_eq!(&*hits[0].credential, SECRET);
}

#[test]
fn scan_nested_depth2_yields_aws_detector_and_bytes() {
    // Core end-to-end contract: base64(base64(AKIA)) is peeled twice by
    // decode-through and surfaces as the aws-access-key detector with the exact
    // credential bytes.
    let scanner = shipped_scanner();
    let data = format!("CONFIG_B64={}", nest(SECRET, 2));
    let matches = scanner.scan(&scan_chunk(data));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        1,
        "double-wrapped base64 must yield exactly one aws-access-key finding; matches: {matches:#?}"
    );
    assert_eq!(&*hits[0].detector_id, "aws-access-key");
    assert_eq!(&*hits[0].credential, SECRET);
}

#[test]
fn scan_shallow_wrap_within_default_depth_recovers() {
    // A 3-layer wrap is well within the shipped default budget (10) and is
    // recovered as the exact credential.
    let scanner = shipped_scanner();
    let data = format!("CONFIG_B64={}", nest(SECRET, 3));
    let matches = scanner.scan(&scan_chunk(data));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        1,
        "a 3-layer wrap must be recovered under the default depth; matches: {matches:#?}"
    );
    assert_eq!(&*hits[0].credential, SECRET);
}

#[test]
fn scan_wrap_beyond_default_depth_limit_finds_nothing() {
    // 12 layers exceeds the shipped MAX_DECODE_DEPTH_LIMIT (10), so decode-through
    // cannot reach the plaintext. No aws-access-key finding, and no panic /
    // runaway recursion (the scan returns).
    let scanner = shipped_scanner();
    let data = format!("CONFIG_B64={}", nest(SECRET, 12));
    let matches = scanner.scan(&scan_chunk(data));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        0,
        "a 12-layer wrap exceeds the depth limit and must yield no aws-access-key finding; \
         matches: {matches:#?}"
    );
}

#[test]
fn scan_depth1_config_does_not_recover_double_wrapped() {
    // A scanner explicitly configured with max_decode_depth = 1 peels exactly one
    // layer, so a double-wrapped secret is NOT recovered.
    let mut config = ScannerConfig::default();
    config.max_decode_depth = 1;
    let scanner = shipped_scanner().with_config(config);
    let data = format!("CONFIG_B64={}", nest(SECRET, 2));
    let matches = scanner.scan(&scan_chunk(data));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        0,
        "max_decode_depth=1 must not recover a double-wrapped secret; matches: {matches:#?}"
    );
}

#[test]
fn scan_depth2_config_recovers_double_wrapped() {
    // Positive twin: max_decode_depth = 2 peels both layers and recovers the
    // exact credential. Paired with the depth-1 test this pins the cap precisely
    // at the scan level, independent of the shipped default.
    let mut config = ScannerConfig::default();
    config.max_decode_depth = 2;
    let scanner = shipped_scanner().with_config(config);
    let data = format!("CONFIG_B64={}", nest(SECRET, 2));
    let matches = scanner.scan(&scan_chunk(data));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        1,
        "max_decode_depth=2 must recover a double-wrapped secret; matches: {matches:#?}"
    );
    assert_eq!(&*hits[0].credential, SECRET);
}

#[test]
fn scan_corrupted_inner_layer_does_not_surface_real_secret() {
    // Adversarial: base64 wrap whose INNER layer is corrupted (one base64 char
    // flipped) must NOT reconstruct the real AKIA secret. The outer layer still
    // decodes, but the inner bytes are garbage — decode-through must not
    // hallucinate the plaintext, and must not panic.
    let e1 = nest(SECRET, 1);
    let mut chars: Vec<char> = e1.chars().collect();
    // Flip the first char to another base64-alphabet char so the string is still
    // a base64 candidate but decodes to different bytes.
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    let e1_corrupt: String = chars.into_iter().collect();
    assert_ne!(
        e1_corrupt, e1,
        "corruption must actually change the inner layer"
    );
    let e2_corrupt = b64(e1_corrupt.as_bytes());

    let scanner = shipped_scanner();
    let matches = scanner.scan(&scan_chunk(format!("CONFIG_B64={e2_corrupt}")));
    let hits = aws_secret_hits(&matches);
    assert_eq!(
        hits.len(),
        0,
        "a corrupted inner layer must not surface the real secret; matches: {matches:#?}"
    );
}
