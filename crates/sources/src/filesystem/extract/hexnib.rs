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
}
