//! Property tier for `slice_into_windows` (reached via the `SourceTestApi`
//! facade) — the overlapping-window slicer the large-file mmap scan path
//! delegates its boundary arithmetic to. The fixed-vector unit twins
//! (`tests/unit/a5_lr2/read_slice_*`) pin only the window COUNT for three hand
//! sizes (empty, one window, two windows). None of them prove the property that
//! actually makes windowing correct: that the windows COVER the whole input and
//! SHARE exactly `overlap` bytes with their neighbour — the reason overlap
//! exists at all is that a secret straddling a window cut would otherwise be
//! sliced in half and missed by every window. A silent regression in the stride
//! or overlap arithmetic would drop real credentials at window seams while every
//! count-only test stayed green.
//!
//! Invariants proved here:
//!   * EXACT RECONSTRUCTION (ASCII) — `window[0]` followed by every later
//!     window with its leading `overlap` bytes removed reconstructs the input
//!     byte-for-byte. This simultaneously proves full coverage (no gap) AND the
//!     exact `overlap` share (no more, no less): the recall guarantee that any
//!     token of length `<= overlap` sits wholly inside at least one window.
//!   * NEIGHBOUR OVERLAP (ASCII) — the leading `overlap` bytes of window `k`
//!     equal the trailing `overlap` bytes of window `k-1`.
//!   * SIZE SHAPE (ASCII) — every non-final window is exactly `window_size`
//!     bytes; the final window is in `(overlap, window_size]`.
//!   * COUNT FORMULA (any bytes) — the number of windows depends only on the
//!     byte length and the size/overlap, never on content, and equals the
//!     closed form `1 + ceil((len - window_size) / stride)` (or 1 / 0 for the
//!     small / empty cases). Content-independent, so it also covers multi-byte
//!     and invalid-UTF-8 input, where lossy decoding changes byte lengths but
//!     never the window boundaries.
//!   * ROBUSTNESS — never panics on arbitrary bytes; empty in ⇔ empty out.
//!
//! `window_size > overlap` is the slicer's own hard precondition (it asserts
//! otherwise), so every generated `(window_size, overlap)` pair honours it —
//! feeding an inverted pair would test the panic, not the arithmetic.
//! Base build: the slicer facade needs no cargo feature.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use proptest::prelude::*;

/// A valid `(window_size, overlap)` pair with `1 <= overlap < window_size`.
fn size_and_overlap() -> impl Strategy<Value = (usize, usize)> {
    (2usize..=64).prop_flat_map(|ws| (Just(ws), 1usize..ws))
}

/// Printable-ASCII bytes: every byte is its own UTF-8 char, so a window's
/// decoded `String` is byte-identical to its source slice and `[overlap..]`
/// slicing lands on a char boundary. Reconstruction reasoning needs that.
fn ascii_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0x20u8..=0x7e, 0..=400)
}

/// The content-independent window count: offsets are `0, stride, 2*stride, …`
/// and emission stops at the first window that reaches EOF.
fn expected_window_count(len: usize, window_size: usize, overlap: usize) -> usize {
    let stride = window_size - overlap;
    if len == 0 {
        0
    } else if len <= window_size {
        1
    } else {
        1 + (len - window_size).div_ceil(stride)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// The empty input produces no windows; a single non-empty window in and
    /// out for any input that fits one window.
    #[test]
    fn small_inputs_have_the_documented_shape((ws, ov) in size_and_overlap()) {
        prop_assert!(TestApi.slice_into_windows(&[], ws, ov).is_empty());

        // An input no larger than one window is returned as exactly one window
        // that equals the whole input (ASCII ⇒ byte-identical). Keep every byte
        // printable (`a..z`) so lossy decoding cannot inject U+FFFD.
        let n = ws.min(26) as u8;
        let one: Vec<u8> = (b'a'..b'a' + n).collect();
        let w = TestApi.slice_into_windows(&one, ws, ov);
        prop_assert_eq!(w.len(), 1);
        prop_assert_eq!(w[0].as_bytes(), &one[..]);
    }

    /// Windows reconstruct the input with EXACT overlap, and carry the
    /// documented size shape. The load-bearing correctness property.
    #[test]
    fn windows_reconstruct_the_input_with_exact_overlap(
        bytes in ascii_bytes(),
        (ws, ov) in size_and_overlap(),
    ) {
        let windows = TestApi.slice_into_windows(&bytes, ws, ov);

        prop_assert_eq!(windows.len(), expected_window_count(bytes.len(), ws, ov));
        if bytes.is_empty() {
            prop_assert!(windows.is_empty());
        } else {
            // De-overlap reconstruction: window[0] ++ window[k][overlap..].
            let mut rebuilt: Vec<u8> = Vec::with_capacity(bytes.len());
            for (k, w) in windows.iter().enumerate() {
                let wb = w.as_bytes();
                if k == 0 {
                    rebuilt.extend_from_slice(wb);
                } else {
                    // Every non-first window is strictly longer than `overlap`,
                    // so this slice is always in range.
                    prop_assert!(wb.len() > ov, "window {k} shorter than overlap {ov}");
                    rebuilt.extend_from_slice(&wb[ov..]);
                }
            }
            prop_assert_eq!(&rebuilt, &bytes, "de-overlap concat must equal the input");

            // Size shape + neighbour overlap.
            for (k, w) in windows.iter().enumerate() {
                let wb = w.as_bytes();
                if k + 1 < windows.len() {
                    prop_assert_eq!(wb.len(), ws, "non-final window {} must be full width", k);
                    // Trailing `overlap` bytes of window k == leading `overlap`
                    // bytes of window k+1.
                    let next = windows[k + 1].as_bytes();
                    prop_assert_eq!(&wb[ws - ov..], &next[..ov], "seam {} overlap mismatch", k);
                } else {
                    // Final window never exceeds `window_size`. Its lower bound
                    // depends on shape: with >= 2 windows it followed a stride
                    // step and is strictly longer than `overlap`; a lone window
                    // (input <= window_size) is just the whole input and may be
                    // as short as one byte (e.g. 1 byte, ws=2, ov=1).
                    prop_assert!(wb.len() <= ws, "final window exceeds window_size");
                    if windows.len() >= 2 {
                        prop_assert!(wb.len() > ov, "multi-window final window must exceed overlap");
                    }
                }
            }
        }
    }

    /// The window count is content-independent — identical for arbitrary bytes
    /// (multi-byte, invalid UTF-8) as for the byte length alone, and never
    /// panics. Lossy decoding changes byte lengths but never boundaries.
    #[test]
    fn window_count_is_content_independent(
        bytes in prop::collection::vec(any::<u8>(), 0..=400),
        (ws, ov) in size_and_overlap(),
    ) {
        let windows = TestApi.slice_into_windows(&bytes, ws, ov);
        prop_assert_eq!(windows.len(), expected_window_count(bytes.len(), ws, ov));
        prop_assert_eq!(windows.is_empty(), bytes.is_empty());
    }
}
