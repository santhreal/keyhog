//! Regression: the keyword-nearby probe computes its preprocessed-vs-chunk
//! buffer comparison ONCE, not once per keyword.
//!
//! `compute_pattern_signals` checks whether any detector keyword appears in the
//! chunk (or in the synthesized preprocessed text, when that differs from the
//! raw chunk). The "does the preprocessed buffer differ from chunk.data?" test
//! is invariant across keywords, but it used to live INSIDE the per-keyword
//! `any(...)` closure, so on the passthrough path (where the two buffers are
//! the same `Cow::Borrowed` bytes) every keyword triggered a full-length slice
//! `memcmp`, making the probe O(keywords × len).
//!
//! It is now hoisted to a single `let text_differs = ...` before the loop. This
//! gate pins that hoist: the buffer comparison must appear exactly once in the
//! file (the binding), and the closure must consume the hoisted `text_differs`
//! flag (so a future edit cannot silently re-inline the per-keyword memcmp).

#[test]
fn keyword_nearby_buffer_comparison_is_hoisted_out_of_the_loop() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/detector_execution_policy.rs"))
        .expect("detector_execution_policy.rs readable");

    assert_eq!(
        src.matches("preprocessed != chunk_data").count(),
        1,
        "the preprocessed-vs-source comparison must remain hoisted"
    );
    assert!(
        src.contains("let same_buffer = chunk_data.len() == preprocessed.len()")
            && src.contains("let text_differs = !same_buffer && preprocessed != chunk_data;")
            && src.contains(
                "self.keywords.is_match(chunk_data) || (text_differs && self.keywords.is_match(preprocessed))",
            ),
        "compiled keyword probes must compare buffers once and reuse the result"
    );
}
