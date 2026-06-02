//! URL percent-decoder must handle truncated and double-percent sequences correctly.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn url_percent_truncated_triplet_at_eof() {
    // `%2` at EOF is incomplete; only `%2F` (solidus) is valid.
    let text = "path=%2";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // Truncated triplet must NOT decode as URL.
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("url")),
        "truncated percent triplet %2 must not trigger URL decode"
    );
}

#[test]
fn url_percent_single_char_after_percent() {
    // `%2X` where X is non-hex is invalid.
    let text = "token=%2G";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("url")),
        "%2G (second char not hex) must not decode"
    );
}

#[test]
fn url_percent_valid_then_invalid() {
    // `%41%2` - first triplet valid (`%41` = 'A'), second is truncated.
    let text = "key=%41%2";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    // The decoder must try to decode but bail on the incomplete second triplet.
    // The result should NOT contain a decoded chunk or should contain only the
    // first byte ('A') on a best-effort basis (decoder returns Err on incomplete).
    let has_url = decoded.iter().any(|c| c.metadata.source_type.contains("url"));
    // Most robust: bail on the entire candidate if it has a truncated triplet.
    assert!(
        !has_url,
        "percent-run with truncated final triplet must be rejected"
    );
}

#[test]
fn url_percent_bare_percent_not_escape() {
    // A bare `%` without two hex digits following is not an escape.
    let text = "token=%";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    assert!(
        !decoded.iter().any(|c| c.metadata.source_type.contains("url")),
        "bare % without hex digits must not decode"
    );
}

#[test]
fn url_percent_valid_double_encoding_decodes_twice() {
    // `%252F` is double-encoded: first decode → `%2F`, second → `/`.
    // The URL decoder applies one layer at a time, checking if the result
    // still contains escape sequences and recursively decoding.
    let text = "path=%252F";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 3, false, None, None);
    // Should see both single and double decode levels.
    let decoded_strings: Vec<_> = decoded
        .iter()
        .filter(|c| c.metadata.source_type.contains("url"))
        .map(|c| c.data.as_str())
        .collect();
    // At minimum, one should be `%2F` (single decode).
    assert!(
        decoded_strings.iter().any(|s| s.contains("%2F")),
        "double-encoded %252F must yield intermediate %2F after first decode"
    );
}
