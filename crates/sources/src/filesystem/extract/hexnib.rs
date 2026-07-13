//! Canonical single-nibble hex decoder shared by the extraction readers.
//!
//! The archive entry-name percent-decoder and the PDF hex-string decoder both
//! need to map one ASCII hex-digit byte to its `0..=15` value. This module owns
//! that primitive so the two readers cannot silently drift apart.

/// Decode a single ASCII hex-digit byte (`0-9`, `a-f`, `A-F`) to its numeric
/// value `0..=15`, returning `None` for any non-hex byte.
pub(super) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::hex_value;

    #[test]
    fn decodes_ascii_digits_zero_through_nine() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'5'), Some(5));
        assert_eq!(hex_value(b'9'), Some(9));
    }

    #[test]
    fn decodes_lowercase_a_through_f() {
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'c'), Some(12));
        assert_eq!(hex_value(b'f'), Some(15));
    }

    #[test]
    fn decodes_uppercase_a_through_f() {
        assert_eq!(hex_value(b'A'), Some(10));
        assert_eq!(hex_value(b'C'), Some(12));
        assert_eq!(hex_value(b'F'), Some(15));
    }

    #[test]
    fn rejects_non_hex_bytes() {
        // Boundaries just outside each accepted range.
        assert_eq!(hex_value(b'/'), None); // one below b'0'
        assert_eq!(hex_value(b':'), None); // one above b'9'
        assert_eq!(hex_value(b'`'), None); // one below b'a'
        assert_eq!(hex_value(b'g'), None); // one above b'f'
        assert_eq!(hex_value(b'@'), None); // one below b'A'
        assert_eq!(hex_value(b'G'), None); // one above b'F'
        assert_eq!(hex_value(b' '), None);
        assert_eq!(hex_value(0x00), None);
        assert_eq!(hex_value(0xFF), None);
    }

    #[test]
    fn matches_std_hex_oracle_over_the_entire_byte_domain() {
        // COMPLETE-DOMAIN differential: for every one of the 256 possible bytes,
        // `hex_value` must agree with an INDEPENDENT std oracle. `byte as char` is
        // lossless for 0..=255 (each byte maps to its Latin-1 scalar), and
        // `char::to_digit(16)` accepts exactly `0-9`/`a-f`/`A-F` → 0..=15 and
        // rejects everything else (all of 0x80..=0xFF are non-ASCII, hence None) 
        // so this is `hex_value`'s exact contract computed a different way. It
        // subsumes the point examples above and locks the three ranges against any
        // future off-by-one drift (Law 6: truth via an independent oracle, over the
        // whole input space rather than six hand-picked boundaries).
        for byte in 0u8..=u8::MAX {
            let oracle = (byte as char).to_digit(16).map(|v| v as u8);
            assert_eq!(
                hex_value(byte),
                oracle,
                "hex_value(0x{byte:02X}) disagrees with the std hex oracle"
            );
        }
    }
}
