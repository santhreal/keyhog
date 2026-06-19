//! Regression test for decode fan-out DoS guards (findings C9 + M2).
//!
//! C9: the per-chunk wall-clock budget was only checked once per BFS
//! dequeue, so a single dense chunk's per-decoder candidate fan-out
//! (especially Caesar's 25x shift loop over every un-deduped candidate)
//! ran to completion with no mid-fan-out budget check, pinning a core
//! far past the intended `DEFAULT_DECODE_WALL_BUDGET_MS` ceiling.
//!
//! M2: `MAX_DECODED_CHUNKS_PER_ROOT` was tested against `decoded_chunks`,
//! which only collected screen-passing chunks. Screen-failing decoded
//! chunks were queued and recursively re-decoded but never counted toward
//! the cap, so on the live (screen-enabled) path the 1000-chunk fan-out
//! guard never bound recursion.
//!
//! Both are observable through the public `decode_chunk` API: a
//! pathological input must return within a bounded wall-clock time even
//! when the alphabet screen rejects every decoded chunk.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_chunk;
use keyhog_scanner::testing::AlphabetScreen;
use std::time::{Duration, Instant};

/// Build a ~512KB chunk of dense 16-char alphanumeric tokens. Each token
/// is a Caesar/base64/hex candidate, so the decoder fan-out is enormous;
/// this is the C9/M2 failing-input shape (no real credential, pure DoS).
fn dense_token_chunk() -> Chunk {
    // 16 alphanumeric chars + a delimiter the extractor treats as a break.
    let token = "a1b2c3d4e5f6g7h8,";
    let target = 512 * 1024;
    let mut data = String::with_capacity(target + token.len());
    while data.len() < target {
        data.push_str(token);
    }
    Chunk {
        data: data.into(),
        // A neutral, non-source path so the Caesar source-code gate does
        // not short-circuit the fan-out we are trying to exercise.
        metadata: ChunkMetadata {
            path: Some("audit.log".into()),
            ..Default::default()
        },
    }
}

/// The wall budget is `DEFAULT_DECODE_WALL_BUDGET_MS` (50ms). With the C9
/// fix, after the deadline trips we bail before the next decoder's
/// fan-out, so the worst case is roughly one decoder's fan-out past the
/// deadline. A generous multiple of the budget guards against both the
/// pre-fix unbounded behavior (seconds-to-minutes per chunk) and CI jitter.
const MAX_DECODE_WALL: Duration = Duration::from_secs(5);

#[test]
fn dense_chunk_decode_stays_within_wall_budget_with_rejecting_screen() {
    let chunk = dense_token_chunk();

    // A screen whose target alphabet is a single rare character means
    // virtually every decoded variant FAILS the screen. Pre-M2 those
    // screen-failing chunks were queued + recursively re-decoded without
    // ever counting toward MAX_DECODED_CHUNKS_PER_ROOT, so recursion was
    // effectively unbounded. The screen must gate what is RETURNED, not
    // what counts against the recursion budget.
    let screen = AlphabetScreen::new(&["q".to_string()]);

    let start = Instant::now();
    // depth 3 mirrors the production decode-through depth; no caller
    // deadline so the internal DEFAULT_DECODE_WALL_BUDGET_MS ceiling is
    // the only wall guard under test.
    let out = decode_chunk(&chunk, 3, false, None, Some(&screen));
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_DECODE_WALL,
        "decode_chunk ran {elapsed:?} on a dense fan-out chunk; the per-chunk \
         wall budget (C9) and produced-chunk cap (M2) must bound it well under \
         {MAX_DECODE_WALL:?}"
    );

    // The rejecting screen should suppress essentially all returns, and the
    // cap bounds collected chunks; the load-bearing assertion is the time
    // bound above. This just pins that returns stay bounded too.
    assert!(
        out.len() <= 1000,
        "returned {} chunks; must not exceed the per-root fan-out cap",
        out.len()
    );
}

#[test]
fn dense_chunk_decode_stays_within_wall_budget_no_screen() {
    // Same pathological input with no screen (every decoded chunk passes
    // and is collected). The C9 mid-fan-out deadline check must still bound
    // total wall time regardless of how many candidates each decoder emits.
    let chunk = dense_token_chunk();

    let start = Instant::now();
    let out = decode_chunk(&chunk, 3, false, None, None);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_DECODE_WALL,
        "decode_chunk ran {elapsed:?} on a dense fan-out chunk with no screen; \
         the per-chunk wall budget (C9) must bound it well under {MAX_DECODE_WALL:?}"
    );

    // With produced counted for every unique chunk, the per-root cap is a
    // hard ceiling on collected chunks (M2).
    assert!(
        out.len() <= 1000,
        "returned {} chunks; the per-root fan-out cap (1000) must hold",
        out.len()
    );
}
