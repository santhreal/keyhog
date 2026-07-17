//! Differential parity for the coalesced GPU region-presence batch (bug 6314).
//!
//! Single chunks are borrowed and multi-chunk batches are copied with separators,
//! but both paths preserve raw bytes. ASCII folding belongs to VYRE's compiled
//! case-insensitive DFA, so source copying cannot drift from matcher semantics.
//! Runs on CPU, no GPU adapter required (it inspects the coalesced input the GPU
//! path would consume, not a GPU dispatch), but the region-presence batch path
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

fn assert_single_chunk_preserves_raw_bytes(text: &str) {
    let (borrow_hay, borrow_starts, borrow_is_borrowed) =
        region_presence_batch_capture(&[chunk(text)]).expect("borrow-path capture");
    assert!(
        borrow_is_borrowed,
        "every single chunk must take the borrowed path: {text:?}"
    );
    assert_eq!(
        borrow_starts,
        vec![0u32],
        "single chunk must start at offset 0"
    );
    assert!(
        !borrow_hay.contains(&0),
        "single-chunk borrow haystack must carry no NUL separator: {text:?}"
    );
    assert_eq!(
        borrow_hay,
        text.as_bytes(),
        "borrow haystack must preserve the raw chunk bytes: {text:?}"
    );
}

#[test]
fn single_chunk_borrow_preserves_case_and_offsets() {
    for text in [
        "aws_secret_access_key=wjalrxutnfemik7mdengbpxrficyexamplekey",
        "AWS_SECRET_ACCESS_KEY=WJALRXUTNFEMIK7MDENGBPXRFiCYEXAMPLEKEY",
        "ghp_abcdef0123456789abcdef0123456789abcd",
        "GhP_ABCDEF0123456789ABCDEF0123456789ABCD",
        "token = \"abcdef1234567890\"",
        "a",
        "config value with spaces and 1234 digits",
        "x-api-key: sk_live_51h8q2p.9k-_test",
    ] {
        assert_single_chunk_preserves_raw_bytes(text);
    }
}

/// A multi-chunk batch always uses the raw-scratch path (never the single-chunk
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
        "a multi-chunk batch must take the raw-scratch path"
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
