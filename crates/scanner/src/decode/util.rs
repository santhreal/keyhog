//! Shared helpers used across the per-encoding decoders.

/// Pull `count` hex digits from `chars` and pack them MSB-first into a `u32`.
///
/// Returns `Err(())` if the iterator runs out before `count` characters or
/// any character isn't a valid hex digit (`0-9` / `a-f` / `A-F`).
///
/// Lives in this shared util module so the three decoders that need it
/// (`url`, `json`, `unicode_escape`) all call the same implementation —
/// the pre-2026-05-24 state had a byte-for-byte identical copy in each
/// of those three files (kimi-dedup audit row #1).
pub(super) fn take_hex_digits<I>(
    chars: &mut std::iter::Peekable<I>,
    count: usize,
) -> Result<u32, ()>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u32;
    for _ in 0..count {
        let ch = chars.next().ok_or(())?;
        value = (value << 4) | ch.to_digit(16).ok_or(())?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_hex_digits_basic() {
        let mut it = "deadbeef".chars().peekable();
        assert_eq!(take_hex_digits(&mut it, 8).unwrap(), 0xdeadbeef);
    }

    #[test]
    fn take_hex_digits_partial_consumption() {
        let mut it = "ff00".chars().peekable();
        assert_eq!(take_hex_digits(&mut it, 2).unwrap(), 0xff);
        assert_eq!(take_hex_digits(&mut it, 2).unwrap(), 0x00);
    }

    #[test]
    fn take_hex_digits_uppercase() {
        let mut it = "ABCD".chars().peekable();
        assert_eq!(take_hex_digits(&mut it, 4).unwrap(), 0xABCD);
    }

    #[test]
    fn take_hex_digits_rejects_non_hex() {
        let mut it = "ZZZZ".chars().peekable();
        assert!(take_hex_digits(&mut it, 4).is_err());
    }

    #[test]
    fn take_hex_digits_rejects_short_input() {
        let mut it = "ff".chars().peekable();
        assert!(take_hex_digits(&mut it, 4).is_err());
    }
}
