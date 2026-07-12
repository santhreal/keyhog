#![no_main]
use keyhog_core::Chunk;
// Drive the decode pipeline through the crate's public test/fuzz surface
// (`keyhog_scanner::testing`): `decode` and `alphabet_filter` are `pub(crate)`.
// `testing::decode_chunk` is the same pipeline entry, and
// `testing::AlphabetScreen::new(&[String])` wraps the inner screen identically.
use keyhog_scanner::testing::{decode_chunk, AlphabetScreen};
use libfuzzer_sys::fuzz_target;

/// Build a `Chunk` from raw text. `Chunk.data` is a `SensitiveString`, so the
/// `String` is converted via `.into()`.
fn chunk_from(text: &str) -> Chunk {
    Chunk {
        data: text.to_string().into(),
        metadata: Default::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Treat the first 2 bytes as parameters.
    if data.len() < 2 {
        return;
    }

    let depth = (data[0] % 12) as usize;
    let validate = (data[1] % 2) == 0;
    let payload = &data[2..];

    if let Ok(text) = std::str::from_utf8(payload) {
        let chunk = chunk_from(text);

        // Drive both the no-screen path and the screen-enabled path (the
        // screen is the last parameter of `decode_chunk`).
        let _ = decode_chunk(&chunk, depth, validate, None, None);

        let screen = AlphabetScreen::new(&[text.to_string()]);
        let _ = decode_chunk(&chunk, depth, validate, None, Some(&screen));
    }
});

#[cfg(test)]
mod regression {
    //! Regression coverage pinning the `decode_chunk` contract the fuzz body
    //! exercises: the `screen: Option<&AlphabetScreen>` parameter and the
    //! `SensitiveString` `Chunk.data` field, asserted with concrete,
    //! code-derived values.

    use super::*;

    // `AKIAIOSFODNN7EXAMPLE1234` base64-encoded. 32 base64 chars, well over
    // `find_base64_strings`' 12-char floor; decodes to valid UTF-8 with no
    // control bytes, so it survives `push_decoded_text_chunk_spliced`.
    const B64: &str = "QUtJQUlPU0ZPRE5ON0VYQU1QTEUxMjM0";
    const PLAINTEXT: &str = "AKIAIOSFODNN7EXAMPLE1234";

    /// Positive: a bare base64 blob decodes through the pipeline at depth >= 1.
    /// With no surrounding parent context, the spliced payload is exactly the
    /// decoded plaintext, so one of the returned chunks carries it verbatim.
    #[test]
    fn decodes_base64_blob_to_plaintext() {
        let chunk = chunk_from(B64);

        let decoded = decode_chunk(&chunk, 4, false, None, None);

        assert!(
            decoded.iter().any(|c| c.data.as_str() == PLAINTEXT),
            "expected a decoded chunk equal to {PLAINTEXT:?}, got: {:?}",
            decoded.iter().map(|c| c.data.as_str()).collect::<Vec<_>>()
        );
        // The decoded chunk's source_type records the base64 decoder hop.
        assert!(
            decoded
                .iter()
                .any(|c| c.data.as_str() == PLAINTEXT
                    && c.metadata.source_type.ends_with("/base64")),
            "decoded chunk must record the base64 decoder in source_type"
        );
    }

    /// Boundary: `max_depth == 0` short-circuits before any decoder runs
    /// (`if depth >= max_depth { continue }` with the root at depth 0), so the
    /// result is exactly empty.
    #[test]
    fn depth_zero_yields_no_chunks() {
        let chunk = chunk_from(B64);

        let decoded = decode_chunk(&chunk, 0, false, None, None);

        assert_eq!(
            decoded.len(),
            0,
            "depth 0 must produce zero decoded chunks, got {}",
            decoded.len()
        );
    }

    /// Negative twin: plain prose with no >=12-char base64/hex run produces no
    /// decoded variant that resurrects the AWS-shaped plaintext.
    #[test]
    fn plain_text_decodes_to_nothing_secretlike() {
        let chunk = chunk_from("the quick brown fox jumps over the lazy dog");

        let decoded = decode_chunk(&chunk, 6, true, None, None);

        assert!(
            decoded.iter().all(|c| c.data.as_str() != PLAINTEXT),
            "plain prose must not decode to {PLAINTEXT:?}"
        );
    }

    /// The 5th `screen` argument is honored: a screen built from an alphabet
    /// that the decoded plaintext shares still returns it, while the call shape
    /// itself (Some(&AlphabetScreen)) is the contract under test.
    #[test]
    fn screen_argument_is_accepted_and_filters() {
        let chunk = chunk_from(B64);

        // Screen seeded with the plaintext's own bytes: the decoded chunk
        // passes the alphabet intersection and is returned.
        let permissive = AlphabetScreen::new(&[PLAINTEXT.to_string()]);
        let with_screen = decode_chunk(&chunk, 4, false, None, Some(&permissive));
        assert!(
            with_screen.iter().any(|c| c.data.as_str() == PLAINTEXT),
            "a permissive screen must still return the decoded plaintext"
        );
    }

    /// Adversarial / property-style loop: the decoder must never panic and must
    /// always honor the depth-0 empty-output invariant across a swept space of
    /// byte payloads, depths, and the validate flag (mirrors the fuzz body but
    /// deterministic). Asserts a concrete invariant, not just absence of panic.
    #[test]
    fn swept_inputs_uphold_depth_zero_and_no_panic() {
        let payloads: &[&[u8]] = &[
            b"",
            b"A",
            B64.as_bytes(),
            b"=====",
            b"\x00\x01\x02 not utf-controlled",
            b"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=", // base64("hello world hello world")
            b"deadbeefdeadbeefdeadbeefdeadbeef",  // hex run
        ];

        for payload in payloads {
            if let Ok(text) = std::str::from_utf8(payload) {
                let chunk = chunk_from(text);
                for validate in [false, true] {
                    // depth 0 is always empty.
                    assert!(
                        decode_chunk(&chunk, 0, validate, None, None).is_empty(),
                        "depth 0 must be empty for payload {payload:?}"
                    );
                    // Higher depths must not panic; result is well-formed.
                    for depth in [1usize, 3, 11] {
                        let out = decode_chunk(&chunk, depth, validate, None, None);
                        // Every produced chunk carries its parent's (empty) path.
                        assert!(out.iter().all(|c| c.metadata.path.is_none()));
                    }
                }
            }
        }
    }
}
