//! Regression: decode-pipeline resource caps
//! (`crates/scanner/src/decode/pipeline.rs`).
//!
//! Pins the two DoS / OOM guards enforced by `decode_chunk`'s BFS fan-out loop:
//!
//!   * `MAX_DECODED_CHUNKS_PER_ROOT` (1000): the number of unique decoded
//!     sub-chunks produced from ONE root chunk is bounded, so a high-fan-out
//!     input (thousands of distinct base64 blobs) can never make the pipeline
//!     emit an unbounded chunk stream. On the screen-`None` path every produced
//!     chunk is returned, so the returned count is EXACTLY the cap (1000) once
//!     the fan-out would cross it — never 1001+, never a panic.
//!   * `MAX_DECODED_TOTAL_BYTES` (64 MiB): the summed byte length of the
//!     returned decoded chunks never exceeds 64 MiB, even when the decodable
//!     input (base64-of-gzip that inflates to 16 MiB per blob) would otherwise
//!     expand to > 64 MiB. The over-cap chunk is dropped BEFORE being pushed,
//!     so the returned total is `<= 64 MiB` with no OOM.
//!
//! Every assertion pins a concrete value (exact count 1000 / 5 / 3 / 0, a hard
//! byte bound, a decoded-plaintext substring), never a bare `is_empty()` /
//! `len() > 0` shape check.
//!
//! HOST-INDEPENDENCE: these caps live in the scalar BFS pipeline itself; they
//! do not depend on Hyperscan/SIMD/GPU. The base64 / gzip-inflate decoders
//! exercised here run identically on every host, so the exact counts below hold
//! on an accelerator-less CI runner just as on a GPU box.

use std::io::Write;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_chunk;

// The caps mirrored from `decode/pipeline.rs` (private consts). Pinned here so a
// silent widening/narrowing of either guard fails this file.
const MAX_DECODED_CHUNKS_PER_ROOT: usize = 1000;
const MAX_DECODED_TOTAL_BYTES: usize = 64 * 1024 * 1024;

// ── helpers ──────────────────────────────────────────────────────────

fn root_chunk(text: String) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decodecap".into(),
            path: Some("decodecap.txt".into()),
            ..Default::default()
        },
    }
}

/// One quoted standard-base64 token per line, so the extractor's quoted-string
/// path yields exactly one decode candidate per line (the `=` padding never
/// trips the assignment path when it is inside quotes).
fn quoted_b64_lines(plaintexts: impl IntoIterator<Item = String>) -> String {
    let mut out = String::new();
    for pt in plaintexts {
        out.push('"');
        out.push_str(&B64.encode(pt.as_bytes()));
        out.push('"');
        out.push('\n');
    }
    out
}

/// gzip a single filler byte repeated `size` times, base64-encode the gzip
/// stream, and wrap it in quotes. The base64 decoder recovers the gzip bytes,
/// inflates them (bounded to 16 MiB) and emits a ~16 MiB decoded text chunk.
fn quoted_b64_of_gzip(filler: u8, size: usize) -> String {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&vec![filler; size]).expect("gzip write");
    let gz = enc.finish().expect("gzip finish");
    // Confirm we built a real gzip stream (magic 0x1f 0x8b) so the decoder's
    // inflate stage engages rather than treating the bytes as plain base64.
    assert_eq!(&gz[..2], &[0x1fu8, 0x8b], "gzip magic header");
    format!("\"{}\"\n", B64.encode(&gz))
}

fn total_bytes(chunks: &[Chunk]) -> usize {
    chunks.iter().map(|c| c.data.as_bytes().len()).sum()
}

fn count_source_suffix(chunks: &[Chunk], suffix: &str) -> usize {
    chunks
        .iter()
        .filter(|c| c.metadata.source_type.ends_with(suffix))
        .count()
}

fn count_ge_bytes(chunks: &[Chunk], min: usize) -> usize {
    chunks
        .iter()
        .filter(|c| c.data.as_bytes().len() >= min)
        .count()
}

// ── chunk-count cap (MAX_DECODED_CHUNKS_PER_ROOT = 1000) ─────────────

#[test]
fn chunk_cap_returns_exactly_1000_on_high_fanout() {
    // 1300 distinct base64 candidates > the 1000 cap. On the screen-`None`
    // path every produced chunk is returned until the (1001st) increment trips
    // the guard and returns WITHOUT pushing, so the returned count is exactly
    // the cap — deterministic regardless of decoder ordering.
    let text = quoted_b64_lines((0..1300).map(|i| format!("SECRETPAYLOAD{i:05}")));
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert_eq!(out.len(), MAX_DECODED_CHUNKS_PER_ROOT);
    assert_eq!(out.len(), 1000);
}

#[test]
fn chunk_cap_bounds_total_bytes_far_under_byte_cap() {
    // The SAME high-fan-out input: because each decoded chunk is small (a
    // bounded ±512B splice window around a ~18-byte plaintext), the CHUNK cap —
    // not the 64 MiB byte cap — is the binding limit here. The returned bytes
    // stay far under 64 MiB (a few MiB at most for 1000 small chunks).
    let text = quoted_b64_lines((0..1300).map(|i| format!("SECRETPAYLOAD{i:05}")));
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    let bytes = total_bytes(&out);
    assert!(bytes > 0, "the 1000 returned chunks carry real bytes");
    assert!(
        bytes < 8 * 1024 * 1024,
        "chunk cap (not the 64MiB byte cap) bound the fan-out; got {bytes} bytes"
    );
}

#[test]
fn chunk_cap_every_returned_chunk_is_a_decoded_variant() {
    // The root chunk itself is never returned: `decode_chunk` returns ONLY
    // decoder outputs, whose source_type is `"decodecap/<decoder>"`. Every
    // returned chunk therefore carries a `/` and none equals the bare root
    // source_type.
    let text = quoted_b64_lines((0..1300).map(|i| format!("SECRETPAYLOAD{i:05}")));
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert_eq!(out.len(), 1000);
    let non_decoded = out
        .iter()
        .filter(|c| {
            !c.metadata.source_type.contains('/') || c.metadata.source_type.as_ref() == "decodecap"
        })
        .count();
    assert_eq!(non_decoded, 0, "no root/undecoded chunk may be returned");
}

#[test]
fn chunk_cap_holds_under_pathological_caesar_fanout() {
    // Adversarial: 200 quoted alphabetic words drive the Caesar decoder's 25x
    // per-candidate fan-out (up to ~5000 sub-chunks) plus every other decoder.
    // The cap must still bound the returned stream to <= 1000 with no panic.
    let text = quoted_b64_lines((0..200).map(|i| format!("AlphabeticWordNumber{i:04}")));
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert!(
        out.len() <= MAX_DECODED_CHUNKS_PER_ROOT,
        "fan-out cap must hold; got {}",
        out.len()
    );
}

#[test]
fn within_chunk_cap_fifty_candidates_all_decode() {
    // 50 distinct base64 candidates are well under the 1000 cap, so NONE are
    // dropped: exactly 50 chunks carry the `/base64` decoder suffix and every
    // plaintext is recovered verbatim.
    let plaintexts: Vec<String> = (0..50).map(|i| format!("APIKEYVALUE{i:04}")).collect();
    let text = quoted_b64_lines(plaintexts.iter().cloned());
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert!(
        out.len() < MAX_DECODED_CHUNKS_PER_ROOT,
        "50 candidates stay under the cap"
    );
    assert_eq!(
        count_source_suffix(&out, "/base64"),
        50,
        "each of the 50 base64 candidates decodes to exactly one chunk"
    );
    for pt in &plaintexts {
        assert!(
            out.iter().any(|c| c
                .data
                .as_bytes()
                .windows(pt.len())
                .any(|w| w == pt.as_bytes())),
            "plaintext {pt} must be recovered by decode-through"
        );
    }
}

#[test]
fn sub_cap_base64_chunk_count_equals_distinct_inputs() {
    // Five distinct base64 candidates -> exactly five `/base64` decoded chunks
    // at depth 0 (max_depth=1 stops any depth-1 re-decode from adding more).
    let plaintexts = [
        "alpha-credential-01",
        "bravo-credential-02",
        "charlie-credential-3",
        "delta-credential-04",
        "echo-credential-005",
    ];
    let text = quoted_b64_lines(plaintexts.iter().map(|s| s.to_string()));
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert_eq!(count_source_suffix(&out, "/base64"), 5);
}

// ── total-byte cap (MAX_DECODED_TOTAL_BYTES = 64 MiB) ────────────────

const INFLATE_BLOB_BYTES: usize = 16 * 1024 * 1024; // matches MAX_INFLATE_BYTES

#[test]
fn byte_cap_total_returned_never_exceeds_64mib() {
    // Six distinct base64-of-gzip blobs, each inflating to 16 MiB => 96 MiB of
    // decodable content, well over the 64 MiB budget. The chunk that would push
    // the running total past 64 MiB is dropped BEFORE being pushed, so the
    // returned total is bounded by the cap.
    let mut text = String::new();
    for filler in b'A'..b'G' {
        text.push_str(&quoted_b64_of_gzip(filler, INFLATE_BLOB_BYTES));
    }
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    let bytes = total_bytes(&out);
    assert!(
        bytes <= MAX_DECODED_TOTAL_BYTES,
        "returned bytes {bytes} must not exceed the 64MiB decode budget"
    );
}

#[test]
fn byte_cap_truncates_large_fanout() {
    // Same 6-blob (96 MiB) input: fewer than the 6 supplied 16-MiB blobs are
    // returned (the byte cap trips after ~3-4), proving truncation. At least 2
    // large blobs DO decode (the cap is a bound, not an early bail).
    let mut text = String::new();
    for filler in b'A'..b'G' {
        text.push_str(&quoted_b64_of_gzip(filler, INFLATE_BLOB_BYTES));
    }
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    let large = count_ge_bytes(&out, 8 * 1024 * 1024);
    assert!(
        (2..6).contains(&large),
        "expected 2..=5 large blobs returned (truncated below the 6 supplied); got {large}"
    );
}

#[test]
fn byte_cap_decodes_substantial_content_before_tripping() {
    // The cap is not an early-out: it decodes real content right up to the
    // budget. With 6 x 16 MiB supplied, the returned bytes exceed 32 MiB before
    // the guard trips (and still stay within the 64 MiB cap).
    let mut text = String::new();
    for filler in b'A'..b'G' {
        text.push_str(&quoted_b64_of_gzip(filler, INFLATE_BLOB_BYTES));
    }
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    let bytes = total_bytes(&out);
    assert!(
        bytes > 32 * 1024 * 1024,
        "substantial content must decode before the cap trips; got {bytes} bytes"
    );
    assert!(bytes <= MAX_DECODED_TOTAL_BYTES);
}

#[test]
fn within_byte_cap_three_large_blobs_all_decode() {
    // Three distinct 16-MiB-inflating blobs => 48 MiB, under the 64 MiB cap, so
    // all three decode: exactly three chunks are >= 8 MiB and the total stays in
    // (32 MiB, 64 MiB].
    let mut text = String::new();
    for filler in b'A'..b'D' {
        text.push_str(&quoted_b64_of_gzip(filler, INFLATE_BLOB_BYTES));
    }
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    let large = count_ge_bytes(&out, 8 * 1024 * 1024);
    assert_eq!(large, 3, "all three under-cap large blobs decode");
    let bytes = total_bytes(&out);
    assert!(bytes > 32 * 1024 * 1024, "got {bytes} bytes");
    assert!(bytes <= MAX_DECODED_TOTAL_BYTES, "got {bytes} bytes");
}

// ── positive / negative / boundary ──────────────────────────────────

#[test]
fn single_base64_secret_decodes_through() {
    // Positive: a lone valid base64 blob decodes to its exact plaintext, in
    // exactly one `/base64` chunk.
    let secret = "SUPERSECRETKEY42XYZ";
    let text = format!("\"{}\"\n", B64.encode(secret.as_bytes()));
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert_eq!(count_source_suffix(&out, "/base64"), 1);
    let carriers = out
        .iter()
        .filter(|c| {
            c.data
                .as_bytes()
                .windows(secret.len())
                .any(|w| w == secret.as_bytes())
        })
        .count();
    assert_eq!(carriers, 1, "exactly one chunk carries the decoded secret");
}

#[test]
fn invalid_base64_value_yields_no_base64_chunk() {
    // Negative twin: a quoted value with a non-base64 char (`!`) is rejected by
    // the base64 candidate filter, so ZERO `/base64` chunks are emitted.
    let text = "\"not-base64-token!!!!\"\n".to_string();
    let out = decode_chunk(&root_chunk(text), 1, false, None, None);
    assert_eq!(count_source_suffix(&out, "/base64"), 0);
}

#[test]
fn max_depth_zero_yields_no_decoded_chunks() {
    // Boundary: with `max_depth = 0` the root is dequeued and immediately
    // skipped (`depth >= max_depth`), so nothing is decoded.
    let text = format!("\"{}\"\n", B64.encode(b"WOULD-DECODE-BUT-DEPTH-0"));
    let out = decode_chunk(&root_chunk(text), 0, false, None, None);
    assert_eq!(out.len(), 0);
}

#[test]
fn already_expired_deadline_yields_no_decoded_chunks() {
    // Boundary/adversarial: a deadline already in the past trips the top-of-loop
    // `expired` check before any decoding, returning an empty result (no panic,
    // no partial fan-out).
    let text = quoted_b64_lines((0..100).map(|i| format!("DEADLINEPAYLOAD{i:04}")));
    let past = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now);
    let out = decode_chunk(&root_chunk(text), 3, false, Some(past), None);
    assert_eq!(out.len(), 0);
}
