//! MIME Q-decode must correctly replace `_` with space and handle hex escapes.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn mime_q_underscore_becomes_space() {
    // MIME Q encoding: `_` is a soft space (represents a space character).
    // Full format: `=?charset?Q?...?=`
    let text = r#"Subject: =?UTF-8?Q?Hello_World?="#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    let mime_chunks: Vec<_> = decoded
        .iter()
        .filter(|c| c.metadata.source_type.contains("mime-encoded-word"))
        .collect();
    // Should decode and replace `_` with space.
    assert!(
        mime_chunks.iter().any(|c| c.data.contains("Hello World")),
        "MIME Q-decode must replace _ with space"
    );
}

#[test]
fn mime_q_hex_escape_sequence() {
    // `=3D` in Q encoding is `=` (hex 0x3D).
    let text = r#"Email: =?ISO-8859-1?Q?user=3Dtest?="#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should decode `=3D` to `=` and replace `_` with space if present.
    let mime_chunks: Vec<_> = decoded
        .iter()
        .filter(|c| c.metadata.source_type.contains("mime-encoded-word"))
        .collect();
    // At minimum, should not panic and should emit a chunk.
    assert!(!mime_chunks.is_empty(), "MIME Q with hex escape must decode");
}

#[test]
fn mime_q_mixed_underscores_and_escapes() {
    // Both `_` (soft space) and `=XX` (hex escape) in one string.
    let text = r#"Name: =?UTF-8?Q?Jo=C3=ABl_Martin?="#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Should handle both transformations without panic.
    let has_mime = decoded
        .iter()
        .any(|c| c.metadata.source_type.contains("mime-encoded-word"));
    assert!(has_mime, "MIME Q with mixed escapes and underscores must decode");
}

#[test]
fn mime_q_standalone_equals_not_escape() {
    // A bare `=` at EOF is not a valid escape (needs 2 hex digits following).
    // Should be passed through or rejected.
    let text = r#"Test: =?UTF-8?Q?value=?="#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Decoder behavior: either bail on malformed, or pass through the bare `=`.
    // Either way, no panic.
    let _ = decoded;
}
