//! Differential parity for the coalesced GPU region-presence batch (bug 6314).
//!
//! `with_region_presence_batch` has TWO byte-view construction paths:
//!   * a fast BORROW path for a single already-lowercase chunk (hands the GPU DFA
//!     the chunk bytes directly, no copy), and
//!   * a folded SCRATCH path for everything else (lowercases into a scratch buffer,
//!     inserting NUL separators between multiple chunks).
//! If those two paths ever presented DIFFERENT bytes for the same logical content
//! (e.g. a stray trailing NUL separator on a single-chunk scratch build, or a
//! lowercasing mismatch), the GPU literal DFA would see different input than the
//! borrow path and emit different presence bits — a silent GPU/CPU parity break
//! invisible to any test that only exercises one path.
//!
//! This proves the invariant: for a single already-lowercase chunk, the borrow
//! path and the scratch path (forced by uppercasing the SAME content, which the
//! scratch builder lowercases back) produce BYTE-IDENTICAL `(haystack, starts)`.
//! Runs on CPU — no GPU adapter required (it inspects the coalesced input the GPU
//! path would consume, not a GPU dispatch) — but the region-presence batch path
//! itself only exists in the `gpu` build, so this file is gated to that feature
//! (the `ci-lean`/`portable` binaries have no GPU region path to test).
#![cfg(feature = "gpu")]

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::region_presence_batch_capture;

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "gpu-region-parity".into(),
            path: Some("fixtures/region.txt".into()),
            ..Default::default()
        },
    }
}

/// For an already-lowercase single chunk, the borrowed-single-chunk fast path and
/// the folded-scratch path must present identical bytes and region starts.
fn assert_single_chunk_path_parity(lower: &str) {
    // Borrow path: a single chunk with NO ASCII uppercase takes the fast borrow.
    let (borrow_hay, borrow_starts, borrow_is_borrowed) =
        region_presence_batch_capture(&[chunk(lower)]).expect("borrow-path capture");
    assert!(
        borrow_is_borrowed,
        "an already-lowercase single chunk must take the borrowed-single-chunk path: {lower:?}"
    );

    // Scratch path: uppercasing the SAME content forces `has_ascii_uppercase`, so
    // the folded-scratch builder runs and lowercases it back to `lower`.
    let upper = lower.to_ascii_uppercase();
    let (scratch_hay, scratch_starts, scratch_is_borrowed) =
        region_presence_batch_capture(&[chunk(&upper)]).expect("scratch-path capture");
    assert!(
        !scratch_is_borrowed,
        "an ASCII-uppercase single chunk must take the folded-scratch path: {upper:?}"
    );

    // The core parity: both paths must hand the GPU DFA identical bytes + starts.
    assert_eq!(
        borrow_hay, scratch_hay,
        "borrow and scratch haystacks diverged for {lower:?}"
    );
    assert_eq!(
        borrow_starts, scratch_starts,
        "borrow and scratch region_starts diverged for {lower:?}"
    );

    // Concrete anchors (not just path-equality): a single chunk starts at offset 0,
    // carries NO NUL separator on either path, and the borrow haystack is exactly
    // the raw lowercase bytes.
    assert_eq!(
        borrow_starts,
        vec![0u32],
        "single chunk must start at offset 0"
    );
    assert!(
        !borrow_hay.contains(&0),
        "single-chunk borrow haystack must carry no NUL separator: {lower:?}"
    );
    assert!(
        !scratch_hay.contains(&0),
        "single-chunk scratch haystack must carry no NUL separator: {lower:?}"
    );
    assert_eq!(
        borrow_hay,
        lower.as_bytes(),
        "borrow haystack must be the raw lowercase chunk bytes: {lower:?}"
    );
}

#[test]
fn single_chunk_borrow_and_scratch_paths_present_identical_bytes() {
    for lower in [
        "aws_secret_access_key=wjalrxutnfemik7mdengbpxrficyexamplekey",
        "ghp_abcdef0123456789abcdef0123456789abcd",
        "token = \"abcdef1234567890\"",
        "a",
        "config value with spaces and 1234 digits",
        // Mixed ASCII letters + non-letter bytes: uppercase/lowercase round-trips
        // only the letters; non-letters must survive identically on both paths.
        "x-api-key: sk_live_51h8q2p.9k-_test",
    ] {
        assert_single_chunk_path_parity(lower);
    }
}

/// A multi-chunk batch always uses the folded-scratch path (never the single-chunk
/// borrow) and must interleave chunks with exactly one NUL separator between them,
/// with region starts landing immediately after each separator.
#[test]
fn multi_chunk_scratch_batch_uses_nul_separated_layout() {
    let a = "first_secret_value_here";
    let b = "second_secret_value";
    let (hay, starts, is_borrowed) =
        region_presence_batch_capture(&[chunk(a), chunk(b)]).expect("multi-chunk capture");

    assert!(
        !is_borrowed,
        "a multi-chunk batch must take the folded-scratch path"
    );
    assert_eq!(
        starts,
        vec![0u32, (a.len() + 1) as u32],
        "second region must start one byte (the NUL separator) after the first"
    );
    // Layout: <a bytes> NUL <b bytes>, exactly one separator, both regions intact.
    let mut expected = Vec::new();
    expected.extend_from_slice(a.as_bytes());
    expected.push(0);
    expected.extend_from_slice(b.as_bytes());
    assert_eq!(
        hay, expected,
        "coalesced haystack must be a<NUL>b with one separator"
    );
    assert_eq!(
        hay.iter().filter(|&&byte| byte == 0).count(),
        1,
        "exactly one NUL separator between two chunks"
    );
}
