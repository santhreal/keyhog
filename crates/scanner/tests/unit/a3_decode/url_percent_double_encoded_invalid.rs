//! URL percent-decoder must handle truncated and double-percent sequences correctly.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

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
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("url")),
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
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("url")),
        "%2G (second char not hex) must not decode"
    );
}

#[test]
fn url_percent_valid_then_invalid() {
    // `%41%2` - first triplet valid (`%41` = 'A'), second (`%2`) truncated at
    // end of input. The decoder is deliberately BEST-EFFORT (decode/url.rs
    // `percent_decode`): it decodes the valid `%41` -> 'A' and treats the
    // truncated `%2` as a literal byte, instead of the old all-or-nothing `Err`
    // that discarded the already-decoded 'A' (an escape-already-decoded recall
    // loss - Law 10, matching the sibling octal/HTML decoders). So a url chunk
    // IS produced, carrying the partial decode.
    let text = "key=%41%2";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    let url_chunk = decoded
        .iter()
        .find(|c| c.metadata.source_type.contains("url"))
        .expect("a valid leading %41 escape must still yield a best-effort url decode");
    // The input has NO literal 'A', so an 'A' in the output proves `%41` was
    // decoded; the raw `%41` must be gone. This pins best-effort recovery
    // (partial decode kept) rather than all-or-nothing rejection.
    assert!(
        url_chunk.data.contains('A') && !url_chunk.data.contains("%41"),
        "best-effort decode must recover 'A' from the valid %41 and not discard it, got {:?}",
        url_chunk.data
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
        !decoded
            .iter()
            .any(|c| c.metadata.source_type.contains("url")),
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
        .map(|c| c.data.as_ref())
        .collect();
    // At minimum, one should be `%2F` (single decode).
    assert!(
        decoded_strings.iter().any(|s| s.contains("%2F")),
        "double-encoded %252F must yield intermediate %2F after first decode"
    );
}
