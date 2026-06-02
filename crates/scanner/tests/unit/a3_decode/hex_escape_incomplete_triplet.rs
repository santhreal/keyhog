//! Hex escape `\xNN` decoder must reject incomplete sequences.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn hex_escape_backslash_x_alone() {
    // `\x` at EOF with no following hex digits is invalid.
    let text = r"token=test\x";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should not emit hex-escape chunk.
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("hex-escape")),
        "bare \\x at EOF must not decode"
    );
}

#[test]
fn hex_escape_single_hex_digit() {
    // `\xA` is incomplete; needs `\xAB`.
    let text = r"code=\xA";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("hex-escape")),
        "\\xA (one hex digit) must not trigger hex-escape decode"
    );
}

#[test]
fn hex_escape_non_hex_after_backslash_x() {
    // `\xGG` has no hex digits after `x`.
    let text = r"secret=\xGG";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("hex-escape")),
        "\\xGG (no hex digits) must not decode"
    );
}

#[test]
fn hex_escape_valid_pair_decodes() {
    // `\x41` is valid ('A' = 0x41) and must produce a decoded chunk.
    let text = r"key=\x41\x42\x43";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        decoded.iter().any(|c| c.metadata.source_type.contains("hex-escape") && c.data.contains("ABC")),
        "valid \\xHH pairs must decode to characters"
    );
}
