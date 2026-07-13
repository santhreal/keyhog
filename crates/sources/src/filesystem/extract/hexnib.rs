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
#[path = "../../../tests/unit/hexnib.rs"]
mod tests;
