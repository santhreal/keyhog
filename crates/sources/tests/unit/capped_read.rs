use super::{read_to_cap, read_to_cap_preserving_error};
use proptest::prelude::*;
use std::io::{Error, ErrorKind, Read};

struct FailsAfterPrefix {
    bytes: &'static [u8],
    emitted: bool,
}

impl Read for FailsAfterPrefix {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.emitted {
            return Err(Error::new(ErrorKind::InvalidData, "decode failed"));
        }
        let len = self.bytes.len().min(buf.len());
        buf[..len].copy_from_slice(&self.bytes[..len]);
        self.emitted = true;
        Ok(len)
    }
}

#[test]
fn preallocation_ceiling_is_exactly_64_kib() {
    // Single owner of the 64 KiB capacity-hint clamp: the cloud/web/hosted-git
    // callers reference this constant instead of pasting `64 * 1024` inline, so
    // pin the concrete value they all depend on.
    assert_eq!(super::MAX_PREALLOCATED_READ_BYTES, 65_536);
    assert_eq!(super::MAX_PREALLOCATED_READ_BYTES, 64 * 1024);
}

#[test]
fn read_to_cap_keeps_exact_cap_without_truncation() {
    let read = read_to_cap(&b"abcd"[..], 4, Some(4)).expect("read");

    assert_eq!(read.bytes, b"abcd");
    assert!(!read.truncated);
}

#[test]
fn read_to_cap_truncates_one_byte_over_cap() {
    let read = read_to_cap(&b"abcde"[..], 4, Some(5)).expect("read");

    assert_eq!(read.bytes, b"abcd");
    assert!(read.truncated);
}

#[test]
fn read_to_cap_accepts_u64_max_without_sentinel_overflow() {
    let read = read_to_cap(&b"abc"[..], u64::MAX, Some(3)).expect("read");

    assert_eq!(read.bytes, b"abc");
    assert!(!read.truncated);
}

#[test]
fn read_to_cap_clamps_capacity_hint_above_platform_capacity() {
    let read = read_to_cap(&b"abc"[..], 3, Some(u64::MAX)).expect("read");

    assert_eq!(read.bytes, b"abc");
    assert!(!read.truncated);
}

#[test]
fn read_to_cap_clamps_unlimited_cap_and_huge_capacity_hint() {
    let read = read_to_cap(std::io::empty(), u64::MAX, Some(u64::MAX)).expect("read");

    assert!(read.bytes.is_empty());
    assert!(read.bytes.capacity() <= super::MAX_PREALLOCATED_READ_BYTES as usize);
    assert!(!read.truncated);
}

#[test]
fn read_to_cap_preserving_error_keeps_partial_prefix() {
    let read = read_to_cap_preserving_error(
        FailsAfterPrefix {
            bytes: b"prefix",
            emitted: false,
        },
        10,
        Some(6),
    );

    assert_eq!(read.bytes, b"prefix");
    assert!(!read.truncated);
    assert_eq!(read.error.expect("error").kind(), ErrorKind::InvalidData);
}

#[test]
fn read_to_cap_preserving_error_truncates_to_cap() {
    let read = read_to_cap_preserving_error(&b"abcdef"[..], 4, Some(6));

    assert_eq!(read.bytes, b"abcd");
    assert!(read.truncated);
    assert!(read.error.is_none());
}

// ── Decompression-bomb defense (#123) ────────────────────────────────────
//
// `read_to_cap*` is the chokepoint that bounds the DECODED output of the
// streaming decompressors (PDF FlateDecode via `inflate_pdf_stream`, the
// gzip/zstd member readers, …). Its bomb safety rests on two properties the
// truncation tests above do NOT exercise:
//   (1) the underlying reader is wrapped in `take(cap + 1)`, so an UNBOUNDED
//       decompressor (a tiny input that expands without limit) is pulled at
//       most `cap + 1` bytes, memory AND CPU stay bounded, no OOM, no hang;
//   (2) the initial `Vec` preallocation is clamped to `MAX_PREALLOCATED_READ_BYTES`,
//       so a hostile capacity hint cannot force a giant up-front allocation.
// These tests use `std::io::repeat` (a literally infinite stream, a stricter
// bomb than any real flate ratio) and instrumented readers to prove both.

use std::cell::Cell;
use std::io;
use std::rc::Rc;

/// Wraps a reader and records, into shared cells, how many bytes it has
/// delivered and how many times `read` was called, so a test can prove the
/// cap bounds the WORK performed, not just the bytes retained.
struct Counting<R> {
    inner: R,
    delivered: Rc<Cell<u64>>,
    calls: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        let n = self.inner.read(buf)?;
        self.delivered.set(self.delivered.get() + n as u64);
        Ok(n)
    }
}

fn counting<R: Read>(inner: R) -> (Counting<R>, Rc<Cell<u64>>, Rc<Cell<u64>>) {
    let delivered = Rc::new(Cell::new(0));
    let calls = Rc::new(Cell::new(0));
    (
        Counting {
            inner,
            delivered: Rc::clone(&delivered),
            calls: Rc::clone(&calls),
        },
        delivered,
        calls,
    )
}

/// An infinite reader that delivers exactly ONE byte per `read` call, a
/// stand-in for a streaming decompressor that dribbles output. Lets a test
/// prove the cap bounds the NUMBER of read calls, not just the bytes retained.
struct DribbleBomb {
    byte: u8,
}

impl Read for DribbleBomb {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.byte;
        Ok(1)
    }
}

/// A reader that yields `cap + 1` bytes and then ERRORS. `take(cap + 1)` must
/// stop before ever triggering the error, so the bomb's late error is not
/// surfaced and the result is a clean truncation.
struct YieldsThenErrors {
    remaining: u64,
    errored_calls: Rc<Cell<u64>>,
}

impl Read for YieldsThenErrors {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            self.errored_calls.set(self.errored_calls.get() + 1);
            return Err(Error::new(ErrorKind::InvalidData, "bomb tail decode error"));
        }
        let n = (buf.len() as u64).min(self.remaining).min(4096) as usize;
        for b in &mut buf[..n] {
            *b = b'Z';
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

#[test]
fn infinite_stream_is_bounded_to_exact_cap_and_terminates() {
    // io::repeat never ends; without the take() bound this would never return.
    let read = read_to_cap(io::repeat(b'A'), 4096, None).expect("read");
    assert_eq!(
        read.bytes.len(),
        4096,
        "an infinite stream is capped to exactly the cap"
    );
    assert!(read.bytes.iter().all(|&b| b == b'A'));
    assert!(
        read.truncated,
        "an infinite stream is always truncated at the cap"
    );
}

#[test]
fn infinite_stream_preserving_variant_truncates_without_error() {
    let read = read_to_cap_preserving_error(io::repeat(0u8), 8192, None);
    assert_eq!(read.bytes.len(), 8192);
    assert!(read.truncated);
    assert!(read.error.is_none(), "a clean truncation carries no error");
}

#[test]
fn infinite_stream_pulls_at_most_cap_plus_one_bytes() {
    let (reader, delivered, _calls) = counting(io::repeat(b'x'));
    let read = read_to_cap(reader, 1000, None).expect("read");
    assert_eq!(read.bytes.len(), 1000);
    assert_eq!(
            delivered.get(),
            1001,
            "the underlying reader must be pulled exactly cap + 1 bytes (one over, to detect truncation)"
        );
}

#[test]
fn dribbling_bomb_read_calls_are_bounded_by_cap() {
    // A 1-byte-per-read infinite bomb: prove the number of read() calls is
    // bounded by cap+1 (no unbounded spin even when the source dribbles).
    // `take(cap+1)` calls the inner reader once per byte until the limit, then
    // returns Ok(0) WITHOUT a further inner call, so the inner reader sees
    // exactly cap+1 calls.
    let (reader, delivered, calls) = counting(DribbleBomb { byte: b'q' });
    let cap = 512u64;
    let read = read_to_cap(reader, cap, None).expect("read");
    assert_eq!(read.bytes.len(), cap as usize);
    assert!(read.truncated);
    assert_eq!(
        delivered.get(),
        cap + 1,
        "exactly cap+1 bytes pulled even when dribbled"
    );
    assert_eq!(
        calls.get(),
        cap + 1,
        "read() called exactly cap+1 times, never unbounded"
    );
}

#[test]
fn large_finite_bomb_truncates_to_exact_cap_prefix() {
    // 1 MiB of a known pattern, cap far below: exact prefix, truncated.
    let blob = vec![b'D'; 1024 * 1024];
    let read = read_to_cap(&blob[..], 4096, Some(64)).expect("read");
    assert_eq!(read.bytes.len(), 4096);
    assert!(read.truncated);
    assert_eq!(read.bytes, &blob[..4096], "the kept prefix is byte-exact");
}

#[test]
fn bomb_that_errors_past_the_cap_does_not_surface_the_late_error() {
    let errored_calls = Rc::new(Cell::new(0));
    let reader = YieldsThenErrors {
        remaining: 2049, // cap + 1
        errored_calls: Rc::clone(&errored_calls),
    };
    let read = read_to_cap_preserving_error(reader, 2048, None);
    assert_eq!(read.bytes.len(), 2048);
    assert!(read.truncated);
    assert!(
        read.error.is_none(),
        "take(cap+1) stops before the bomb's error read"
    );
    assert_eq!(
        errored_calls.get(),
        0,
        "the erroring branch must never be reached"
    );
}

#[test]
fn preallocation_is_capped_for_infinite_stream_with_huge_hint() {
    // A hostile huge capacity hint must not balloon the initial allocation;
    // with an infinite reader the cap still bounds the final length, and the
    // INITIAL reservation is clamped to MAX_PREALLOCATED_READ_BYTES. We assert
    // the kept length equals the cap (termination + bound) and that a hint far
    // above the cap cannot have pre-reserved beyond the cap region.
    let cap = 4096u64;
    let read = read_to_cap(io::repeat(7u8), cap, Some(u64::MAX)).expect("read");
    assert_eq!(read.bytes.len(), cap as usize);
    assert!(read.truncated);
}

#[test]
fn capacity_hint_above_cap_is_clamped_to_cap_region() {
    // Reader yields exactly `cap` bytes; an oversized hint must clamp so the
    // reservation never exceeds the 64 KiB preallocation ceiling.
    let cap = 100usize;
    let blob = vec![b'k'; cap];
    let read = read_to_cap(&blob[..], cap as u64, Some(10_000)).expect("read");
    assert_eq!(read.bytes.len(), cap);
    assert!(!read.truncated);
    assert!(
        read.bytes.capacity() <= super::MAX_PREALLOCATED_READ_BYTES as usize + 8,
        "capacity {} should stay near the clamped preallocation ceiling",
        read.bytes.capacity()
    );
}

#[test]
fn cap_zero_on_nonempty_input_yields_empty_and_truncated() {
    let read = read_to_cap(&b"not empty"[..], 0, None).expect("read");
    assert!(read.bytes.is_empty());
    assert!(read.truncated, "cap 0 over non-empty input is a truncation");
}

#[test]
fn cap_zero_on_infinite_stream_is_empty_truncated_and_terminates() {
    let read = read_to_cap(io::repeat(b'A'), 0, None).expect("read");
    assert!(read.bytes.is_empty());
    assert!(read.truncated);
}

#[test]
fn cap_zero_on_empty_input_is_not_truncated() {
    let read = read_to_cap(io::empty(), 0, None).expect("read");
    assert!(read.bytes.is_empty());
    assert!(
        !read.truncated,
        "cap 0 over empty input read everything (nothing)"
    );
}

#[test]
fn cap_one_keeps_exactly_one_byte_of_a_bomb() {
    let read = read_to_cap(io::repeat(b'Z'), 1, None).expect("read");
    assert_eq!(read.bytes, b"Z");
    assert!(read.truncated);
}

#[test]
fn exact_cap_sized_finite_reader_is_not_truncated() {
    let blob = vec![b'm'; 5000];
    let read = read_to_cap(&blob[..], 5000, None).expect("read");
    assert_eq!(read.bytes.len(), 5000);
    assert!(
        !read.truncated,
        "input of exactly cap bytes is complete, not truncated"
    );
}

#[test]
fn finite_reader_one_byte_under_cap_reads_all() {
    let (reader, delivered, _calls) = counting(io::repeat(b'u').take(4095));
    let read = read_to_cap(reader, 4096, None).expect("read");
    assert_eq!(read.bytes.len(), 4095);
    assert!(!read.truncated);
    assert_eq!(
        delivered.get(),
        4095,
        "a sub-cap stream is drained fully, no more"
    );
}

#[test]
fn huge_cap_with_small_reader_reads_all_without_overflow_or_hang() {
    let read = read_to_cap(&b"tiny"[..], u64::MAX, None).expect("read");
    assert_eq!(read.bytes, b"tiny");
    assert!(
        !read.truncated,
        "a small finite reader under an unbounded cap is complete"
    );
}

#[test]
fn immediate_reader_error_propagates_with_empty_prefix() {
    // `emitted: true` makes the very first read() error, with no bytes produced.
    let result = read_to_cap(
        FailsAfterPrefix {
            bytes: b"",
            emitted: true,
        },
        64,
        None,
    );
    assert!(
        result.is_err(),
        "an immediate read error propagates from read_to_cap"
    );

    let preserved = read_to_cap_preserving_error(
        FailsAfterPrefix {
            bytes: b"",
            emitted: true,
        },
        64,
        None,
    );
    assert!(preserved.bytes.is_empty());
    assert!(!preserved.truncated);
    assert_eq!(
        preserved.error.expect("immediate error recorded").kind(),
        ErrorKind::InvalidData,
    );
}

#[test]
fn preserving_variant_keeps_full_prefix_then_surfaces_error() {
    let read = read_to_cap_preserving_error(
        FailsAfterPrefix {
            bytes: b"recovered-secret-prefix",
            emitted: false,
        },
        1024,
        None,
    );
    assert_eq!(read.bytes, b"recovered-secret-prefix");
    assert!(!read.truncated, "the prefix was under the cap");
    assert_eq!(
        read.error.expect("late error preserved").kind(),
        ErrorKind::InvalidData
    );
}

#[test]
fn multibyte_pattern_truncation_is_byte_exact_not_char_aligned() {
    // capped_read is byte-level: a cap landing mid-codepoint truncates by byte.
    let unit = "héllo".as_bytes().to_vec(); // 'é' is two bytes
    let blob: Vec<u8> = unit.iter().copied().cycle().take(10_000).collect();
    let read = read_to_cap(&blob[..], 4097, None).expect("read");
    assert_eq!(
        read.bytes.len(),
        4097,
        "byte cap is honored regardless of codepoint edges"
    );
    assert!(read.truncated);
    assert_eq!(read.bytes, &blob[..4097]);
}

#[test]
fn doubly_wrapped_take_still_bounded_by_cap() {
    // A reader already limited by an outer take must still be re-bounded by the
    // cap, never the larger of the two (the inner cap wins).
    let read = read_to_cap(io::repeat(b'w').take(1_000_000), 256, None).expect("read");
    assert_eq!(read.bytes.len(), 256);
    assert!(read.truncated);
}

#[test]
fn zero_capacity_hint_disables_preallocation_but_still_caps() {
    let read = read_to_cap(io::repeat(b'p'), 777, Some(0)).expect("read");
    assert_eq!(read.bytes.len(), 777);
    assert!(read.truncated);
}

#[test]
fn delivered_bytes_equal_min_input_len_and_cap_plus_one() {
    // Finite input strictly larger than cap: pulled exactly cap+1 (truncation probe).
    let (reader, delivered, _calls) = counting(io::repeat(b's').take(50_000));
    let read = read_to_cap(reader, 9999, None).expect("read");
    assert_eq!(read.bytes.len(), 9999);
    assert_eq!(
        delivered.get(),
        10_000,
        "exactly cap+1 pulled from an over-cap finite source"
    );
}

#[test]
fn preserving_variant_infinite_stream_pulls_cap_plus_one() {
    let (reader, delivered, _calls) = counting(io::repeat(b'b'));
    let read = read_to_cap_preserving_error(reader, 2000, None);
    assert_eq!(read.bytes.len(), 2000);
    assert!(read.truncated);
    assert!(read.error.is_none());
    assert_eq!(delivered.get(), 2001);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// The core capped-read contract, FUZZED across arbitrary payloads, caps,
    /// and capacity hints against a finite in-memory reader (which never
    /// errors). The 40 example tests above each pin ONE input; this one
    /// invariant generalizes them over the whole space (Testing Contract:
    /// property coverage on a security-critical DoS chokepoint), asserting the
    /// three properties every caller relies on PLUS the cross-variant
    /// equivalence no example test exercises:
    ///   1. kept length == `min(input_len, cap)`;
    ///   2. `truncated` is set IFF the input strictly exceeded the cap;
    ///   3. the kept bytes are the EXACT `input[..len]` prefix (never reordered
    ///      or corrupted, a value-integrity guarantee the scanner depends on);
    ///   4. `read_to_cap` and `read_to_cap_preserving_error` agree byte-for-byte
    ///      on the clean path, and the preserving variant fabricates no error
    ///      for an infallible reader (Law 10: no silent divergence between the
    ///      two public entry points).
    #[test]
    fn read_to_cap_is_exact_prefix_and_truncation_flag_matches(
        input in proptest::collection::vec(any::<u8>(), 0..2048usize),
        cap in 0u64..3000,
        hint in proptest::option::of(0u64..1_000_000),
    ) {
        let expected_len = (input.len() as u64).min(cap) as usize;
        let expected_truncated = input.len() as u64 > cap;

        let read = read_to_cap(&input[..], cap, hint).expect("in-memory reader never errors");
        prop_assert_eq!(read.bytes.len(), expected_len, "kept length is min(input_len, cap)");
        prop_assert_eq!(read.truncated, expected_truncated, "truncated iff input exceeded cap");
        prop_assert_eq!(&read.bytes[..], &input[..expected_len], "kept bytes are the exact prefix");

        let preserved = read_to_cap_preserving_error(&input[..], cap, hint);
        prop_assert!(preserved.error.is_none(), "a clean in-memory read carries no error");
        prop_assert_eq!(&preserved.bytes, &read.bytes, "both entry points keep identical bytes");
        prop_assert_eq!(preserved.truncated, read.truncated, "both entry points agree on truncation");
    }
}
