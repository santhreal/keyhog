//! Coverage for the encoded-blob DISCOVERY primitives (#177): the candidate
//! predicate and the `find_*_strings` scanners that locate embedded base64/hex
//! runs in free text (the front door of the decode-and-rescan pipeline).

use keyhog_scanner::decode::{
    base64_decode, find_base64_strings, find_hex_strings, hex_decode, is_base64_candidate_byte,
};

#[test]
fn base64_candidate_byte_accepts_the_full_alphabet_and_rejects_others() {
    // Standard + URL-safe alphabet + padding.
    for b in [
        b'A', b'Z', b'a', b'z', b'0', b'9', b'+', b'/', b'=', b'-', b'_',
    ] {
        assert!(
            is_base64_candidate_byte(b),
            "{} must be a candidate",
            b as char
        );
    }
    // Clear non-alphabet bytes.
    for b in [b' ', b'!', b'.', b'\n', b'#', b'@', b':', b'"'] {
        assert!(
            !is_base64_candidate_byte(b),
            "{} must NOT be a candidate",
            b as char
        );
    }
}

#[test]
fn find_base64_strings_extracts_the_value_of_an_assignment() {
    // `find_base64_strings` runs STRUCTURAL value extraction, not naive run
    // finding: it pulls the base64 VALUE out of a `key=value` assignment. So
    // `token=aGVsbG8=` yields the payload `aGVsbG8=` (→ "hello"), not the merged
    // `token=aGVsbG8=` run.
    let found = find_base64_strings("token=aGVsbG8= end", 8);
    assert!(
        found
            .iter()
            .any(|e| base64_decode(&e.value).ok().as_deref() == Some(&b"hello"[..])),
        "expected the assignment value to decode to `hello`, got: {:?}",
        found.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn find_base64_strings_honors_the_min_length_floor() {
    // "YWI=" decodes to "ab" (a 4-char base64 run). With a high floor it must
    // not be reported.
    let short = find_base64_strings("x YWI= y", 32);
    assert!(
        !short
            .iter()
            .any(|e| base64_decode(&e.value).ok().as_deref() == Some(&b"ab"[..])),
        "a 4-char run must be filtered out by min_length=32"
    );
}

#[test]
fn find_hex_strings_locates_an_embedded_token_that_round_trips() {
    // 48656c6c6f = "Hello".
    let text = "sha=48656c6c6f;";
    let found = find_hex_strings(text, 8);
    assert!(
        found
            .iter()
            .any(|e| hex_decode(&e.value).ok().as_deref() == Some(&b"Hello"[..])),
        "expected a discovered hex run decoding to `Hello`, got: {:?}",
        found.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn find_strings_return_nothing_for_text_without_encoded_runs() {
    assert!(find_base64_strings("just some plain english words here", 16).is_empty());
    assert!(find_hex_strings("no hex digits in this sentence!!", 16).is_empty());
}
