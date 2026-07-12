//! Re-homed from the inline `uri_encode_tests` in `crates/verifier/src/sigv4.rs`
//! (the `no_inline_tests_in_verifier_src` gate forbids inline `#[cfg(test)]`).
//! Pins the SigV4 canonical-URI byte-exact percent-encoding contract: unreserved
//! chars pass through, every other byte becomes `%XX` UPPERCASE hex, and the
//! canonical query string sorts by the encoded pair — a single wrong byte here
//! corrupts the canonical request and every downstream signature. Exercised
//! through the `testing` facade so `aws_uri_encode`/`canonical_query_string`
//! stay `pub(crate)`.

use keyhog_verifier::testing::{aws_uri_encode, canonical_query_string};

/// SigV4 canonical-URI encoding is byte-exact by contract: unreserved chars
/// pass through untouched, every other byte becomes `%XX` with UPPERCASE
/// hex. These vectors pin that contract so the table-based encoder can never
/// silently diverge from the old `format!("%{byte:02X}")` output — a single
/// wrong byte here corrupts the canonical request and every downstream
/// signature.
#[test]
fn unreserved_set_passes_through_untouched() {
    // RFC 3986 unreserved set AWS preserves: ALPHA / DIGIT / - _ . ~
    assert_eq!(
        aws_uri_encode("azAZ09-_.~"),
        "azAZ09-_.~",
        "unreserved chars must never be percent-encoded"
    );
}

#[test]
fn reserved_bytes_encode_to_uppercase_hex() {
    assert_eq!(aws_uri_encode(" "), "%20", "space");
    assert_eq!(aws_uri_encode("/"), "%2F", "slash uses UPPER hex F");
    assert_eq!(aws_uri_encode("?"), "%3F");
    assert_eq!(aws_uri_encode("="), "%3D");
    assert_eq!(aws_uri_encode("&"), "%26");
    assert_eq!(aws_uri_encode("+"), "%2B");
    // Control byte with a leading-zero nibble: proves the `02X` width and
    // the zero pad survive the table rewrite.
    assert_eq!(aws_uri_encode("\n"), "%0A");
}

#[test]
fn multibyte_utf8_encodes_each_byte_uppercase() {
    // `é` = U+00E9 = UTF-8 0xC3 0xA9. Exercises both nibbles across the
    // a-f range (C, A) and the digit range (3, 9), all UPPERCASE.
    assert_eq!(aws_uri_encode("é"), "%C3%A9");
    // `€` = U+20AC = UTF-8 0xE2 0x82 0xAC.
    assert_eq!(aws_uri_encode("€"), "%E2%82%AC");
}

#[test]
fn every_byte_matches_reference_uppercase_format() {
    // Differential vs the exact former implementation over all 256 byte
    // values (as single-byte latin-1 -> str where valid): the table path
    // must equal `format!("%{b:02X}")` for every escaped byte.
    for b in 0u8..=255 {
        let s = String::from_utf8(vec![b]).ok();
        let Some(s) = s else { continue }; // skip non-UTF8 lone bytes (>=0x80)
        let got = aws_uri_encode(&s);
        let expected = match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        };
        assert_eq!(got, expected, "byte {b:#04X} must encode identically");
    }
}

#[test]
fn canonical_query_string_sorts_by_encoded_pair_and_escapes_values() {
    // Routes through `aws_uri_encode` for both key and value, then sorts by
    // the ENCODED pair and joins with `&` — the canonical query contract.
    let q = canonical_query_string(&[
        ("b".to_string(), "2".to_string()),
        ("a".to_string(), "1 ".to_string()), // trailing space -> %20
    ]);
    assert_eq!(q, "a=1%20&b=2");
}
