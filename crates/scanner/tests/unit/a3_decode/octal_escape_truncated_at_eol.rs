//! Octal escape decoder must reject truncated sequences (e.g., `\0` with no digits).

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn octal_escape_requires_three_digits() {
    // A single backslash followed by one octal digit is NOT a valid octal escape.
    // The decoder should require exactly 3 octal digits: `\000` through `\377`.
    // Input `\0` alone should be treated as backslash followed by literal `0`,
    // NOT as an octal escape, and thus decode_chunk should NOT emit a chunk
    // with octal in its source_type.
    let text = r"prefix\0suffix";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // No octal-escape decoded chunk should be emitted.
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("octal")),
        "single-digit \\0 must not trigger octal-escape decoder"
    );
}

#[test]
fn octal_escape_truncated_at_eol() {
    // Octal escape that starts but cannot complete (not enough chars at EOF).
    let text = r"secret=\07";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should not emit octal chunk; the truncated sequence is invalid.
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("octal")),
        "truncated octal escape at EOF must be rejected"
    );
}

#[test]
fn octal_escape_requires_all_three_digits_valid() {
    // `\089` is invalid: 8 and 9 are not octal digits.
    let text = r"value=\089";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should not emit octal chunk.
    assert!(
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("octal")),
        "octal escape with invalid digits (8,9) must be rejected"
    );
}
