//! Regression test for finding C9: the decode wall-clock budget was checked
//! once per BFS dequeue (and, after a prior partial fix, once per decoder),
//! but NEVER while consuming a single decoder's output. Because the `Decoder`
//! trait returns a fully materialized `Vec<Chunk>` whose length is O(chunk
//! size) (`extract_encoded_values` yields one candidate per quoted string /
//! `key=value` / base64 run, and Caesar fans each out 25x), the pipeline would
//! hash, screen, clone, and queue EVERY one of those results after the deadline
//! had already passed. The per-decode fan-out was therefore effectively
//! unbounded: a single dense chunk pinned a core processing tens of thousands
//! of decoded results long past `DEFAULT_DECODE_WALL_BUDGET_MS`.
//!
//! The fix adds a budget check at the top of the inner
//! `for decoded in decoder.decode_chunk(&current)` loop in
//! `crates/scanner/src/decode/pipeline.rs`, so once the deadline trips the
//! pipeline stops consuming that decoder's output immediately (at most one more
//! result is touched).
//!
//! How this test makes the bug observable DETERMINISTICALLY (no flaky
//! wall-clock thresholds): we register a custom decoder whose `decode_chunk`
//!   1. sleeps well past the supplied deadline (when the chunk path opts in),
//!      so the deadline is guaranteed to have tripped by the time it returns,
//!   2. then returns a large, fixed number of unique decoded chunks tagged with
//!      a recognizable `source_type`.
//! The decoder runs LAST in the registry, and the (plain-text) root chunk
//! produces nothing from the 14 built-in decoders, so the count of returned
//! chunks bearing our tag is exactly the number the pipeline processed from our
//! decoder AFTER the deadline:
//!   * OLD behavior: all `FANOUT` chunks (the inner loop ran to completion).
//!   * NEW behavior: zero (the inner loop bailed on its first iteration once it
//!     saw the deadline had passed).
//!
//! `register_decoder` initializes a process-global `OnceLock`, so this whole
//! test binary shares ONE custom decoder. We therefore parameterize behavior
//! through the chunk `path` and drive every scenario (positive, negative twin,
//! boundary, adversarial, and a property-style loop) through that single
//! registered decoder from one `#[test]` to keep registry init ordered.

use keyhog_core::{Chunk, ChunkMetadata, SensitiveString};
use keyhog_scanner::decode::{register_decoder, Decoder};
use keyhog_scanner::telemetry::{decode_truncation_count, reset_for_scan, testing::reset};
use keyhog_scanner::testing::decode_chunk;
use std::time::{Duration, Instant};

/// Recognizable marker the custom decoder stamps into each result's
/// `source_type`. Counting chunks whose `source_type` contains this string
/// isolates OUR decoder's contribution from any built-in decoder output.
const TAG: &str = "c9probe";

/// Number of unique decoded chunks the custom decoder emits per call. Kept
/// below `MAX_DECODED_CHUNKS_PER_ROOT` (1000) so the per-root fan-out cap is
/// NOT what bounds the count - the wall-budget check is the only thing that can
/// reduce it from `FANOUT` to 0. (If this exceeded 1000, the OLD path would
/// also stop at the cap and the test couldn't distinguish the bug.)
const FANOUT: usize = 400;

/// Path substring that opts a chunk into the "sleep past the deadline" behavior.
const SLEEP_MARKER: &str = "c9-sleep";

/// How long the decoder sleeps when opted in. Must dwarf the deadline offsets
/// the test uses (<=50ms) so "we are past the deadline after the sleep" holds
/// on any CI host regardless of scheduler jitter.
const SLEEP: Duration = Duration::from_millis(300);

/// A decoder that emits `FANOUT` unique, recognizable chunks. When the parent
/// chunk's path contains `SLEEP_MARKER` it first sleeps `SLEEP`, guaranteeing
/// the caller's deadline has elapsed before it returns - the exact condition
/// the C9 fix must catch inside the result-consuming loop.
struct FanoutDecoder;

impl Decoder for FanoutDecoder {
    fn name(&self) -> &'static str {
        // Distinct from every built-in name; the fix uses this only via the
        // chunks WE build, but keeping it unique avoids any registry confusion.
        "c9probe_decoder"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        // Never recurse on our own output: results we emit carry TAG in their
        // source_type, so a re-decode pass at depth>0 would otherwise multiply
        // the count and muddy the assertion.
        if chunk.metadata.source_type.contains(TAG) {
            return Vec::new();
        }
        let should_sleep = chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains(SLEEP_MARKER));
        if should_sleep {
            std::thread::sleep(SLEEP);
        }
        let mut out = Vec::with_capacity(FANOUT);
        for i in 0..FANOUT {
            // Each result is unique (so the pipeline's `seen` dedup keeps all of
            // them) and tagged so the test can count our contribution exactly.
            //
            // Payload shape is deliberately INERT to the built-in decoders:
            // `.`-delimited short segments with no quote, no `:`/`=` assignment,
            // and no `%` run means `extract_encoded_values` yields zero
            // candidates, so re-decoding our output at depth>0 produces nothing.
            // That keeps the tagged count exactly `FANOUT` (no recursive
            // inflation toward MAX_DECODED_CHUNKS_PER_ROOT) on the no-sleep path.
            out.push(Chunk {
                data: SensitiveString::from(format!("c9.tok.{i:05}.end")),
                metadata: ChunkMetadata {
                    source_type: format!("{}/{TAG}", chunk.metadata.source_type),
                    path: chunk.metadata.path.clone(),
                    ..Default::default()
                },
            });
        }
        out
    }
}

/// A plain-text root chunk that the 14 built-in decoders extract NOTHING from:
/// no quotes, no `:`/`=` assignment, no `%` percent runs, and every
/// alphanumeric run is broken by `.` (not a base64 char, not whitespace) so the
/// base64 accumulator never reaches its 16-char floor. The only decoded output
/// can therefore come from our registered `FanoutDecoder`.
fn inert_root(path: &str) -> Chunk {
    Chunk {
        data: SensitiveString::from("alpha.bravo.charlie.delta.echo.foxtrot"),
        metadata: ChunkMetadata {
            path: Some(path.to_string()),
            ..Default::default()
        },
    }
}

/// Count returned chunks that came from our `FanoutDecoder` (tagged source_type).
fn tagged(out: &[Chunk]) -> usize {
    out.iter()
        .filter(|c| c.metadata.source_type.contains(TAG))
        .count()
}

#[test]
fn decode_budget_is_enforced_inside_a_single_decoder_fanout() {
    reset();
    // Register our custom decoder ONCE for this whole test binary, before any
    // call to `decode_chunk` initializes the registry. Built-ins run first;
    // ours runs last.
    register_decoder(Box::new(FanoutDecoder));

    // ---- Negative twin: generous deadline, decoder does NOT sleep ----------
    // With the deadline far in the future and no sleep, every inner-loop budget
    // check passes, so ALL FANOUT results must flow through under BOTH the old
    // and new code. This proves the fix does not over-cut the normal path.
    {
        let root = inert_root("benign/audit.log");
        let generous = Instant::now() + Duration::from_secs(60);
        let out = decode_chunk(&root, 2, false, Some(generous), None);
        assert_eq!(
            tagged(&out),
            FANOUT,
            "with a generous deadline and no sleep, all {FANOUT} decoded chunks \
             must be returned; the budget check must not drop work early"
        );
        assert_eq!(
            decode_truncation_count(),
            0,
            "normal decode completion must not report a coverage truncation"
        );
    }

    // ---- Positive (the C9 bug): deadline trips DURING the decoder's run -----
    // The decoder sleeps 300ms; the deadline is only 50ms out, so by the time
    // its FANOUT-element Vec is returned the deadline has long passed. The fixed
    // pipeline must bail at the first inner-loop iteration and return ZERO of
    // our tagged chunks. The OLD pipeline returned all FANOUT of them because
    // the inner consume-loop had no budget check.
    {
        let root = inert_root("c9-sleep/explosion.bin");
        let deadline = Instant::now() + Duration::from_millis(50);
        let out = decode_chunk(&root, 2, false, Some(deadline), None);
        assert_eq!(
            tagged(&out),
            0,
            "deadline elapsed before the decoder returned its {FANOUT}-element \
             fan-out; the pipeline MUST stop consuming that output (C9). Got {} \
             tagged chunks - the inner-loop budget check is missing or ineffective",
            tagged(&out)
        );
        assert_eq!(
            decode_truncation_count(),
            1,
            "a budget-forced decode cut must be operator-visible telemetry"
        );
    }

    // ---- Boundary: an already-elapsed deadline -----------------------------
    // A deadline in the past means the very first top-of-BFS check fires before
    // any decoder runs, so nothing is decoded at all. This pins the boundary
    // where the budget is exactly/already exhausted at entry.
    {
        let root = inert_root("benign/audit.log");
        let past = Instant::now() - Duration::from_millis(1);
        let out = decode_chunk(&root, 2, false, Some(past), None);
        assert_eq!(
            tagged(&out),
            0,
            "an already-elapsed deadline must decode nothing"
        );
        assert!(
            out.is_empty(),
            "an already-elapsed deadline must return an empty result set, got {} chunks",
            out.len()
        );
        assert_eq!(
            decode_truncation_count(),
            2,
            "top-of-loop decode budget exhaustion must also be counted"
        );
    }

    // ---- Adversarial: the implicit DEFAULT_DECODE_WALL_BUDGET_MS ceiling ----
    // No caller deadline at all. The pipeline's own 50ms ceiling
    // (DEFAULT_DECODE_WALL_BUDGET_MS) must still bound a decoder that sleeps
    // 300ms past it: a None deadline must NOT defeat the wall budget. The fixed
    // inner-loop check enforces the implicit ceiling exactly like an explicit
    // one, so our tagged contribution is dropped.
    {
        let root = inert_root("c9-sleep/explosion.bin");
        let out = decode_chunk(&root, 2, false, None, None);
        assert_eq!(
            tagged(&out),
            0,
            "with no caller deadline, the implicit 50ms wall ceiling must still \
             stop the post-deadline fan-out; got {} tagged chunks",
            tagged(&out)
        );
        assert_eq!(
            decode_truncation_count(),
            3,
            "implicit wall-budget truncation must be counted"
        );
    }

    // ---- Property-style loop: across depths and the validate flag, the two
    // invariants hold for every combination ---------------------------------
    //   (a) generous deadline + no sleep  => exactly FANOUT tagged results
    //   (b) tight deadline + sleep        => exactly 0 tagged results
    // This sweeps the orthogonal pipeline knobs (max_depth, validate) to show
    // the budget enforcement is independent of them.
    for max_depth in 1usize..=4 {
        for validate in [false, true] {
            // (a) no-sleep, generous deadline -> all pass.
            let root_ok = inert_root("benign/audit.log");
            let generous = Instant::now() + Duration::from_secs(60);
            let out_ok = decode_chunk(&root_ok, max_depth, validate, Some(generous), None);
            assert_eq!(
                tagged(&out_ok),
                FANOUT,
                "property (a) failed at max_depth={max_depth} validate={validate}: \
                 generous deadline must return all {FANOUT} chunks"
            );

            // (b) sleep past a tight deadline -> none pass.
            let root_bomb = inert_root("c9-sleep/explosion.bin");
            let deadline = Instant::now() + Duration::from_millis(50);
            let out_bomb = decode_chunk(&root_bomb, max_depth, validate, Some(deadline), None);
            assert_eq!(
                tagged(&out_bomb),
                0,
                "property (b) failed at max_depth={max_depth} validate={validate}: \
                 a deadline that elapses during the fan-out must drop all tagged \
                 chunks (C9)"
            );
        }
    }

    assert!(
        decode_truncation_count() > 0,
        "test setup must have recorded real decode truncation telemetry"
    );
    reset_for_scan();
    assert_eq!(
        decode_truncation_count(),
        0,
        "the production per-scan telemetry reset must clear decode coverage-gap counters"
    );
}
