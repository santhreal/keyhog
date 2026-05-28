//! Shared helpers used across the per-encoding decoders.

/// Pull `count` hex digits from `chars` and pack them MSB-first into a `u32`.
///
/// Returns `Err(())` if the iterator runs out before `count` characters or
/// any character isn't a valid hex digit (`0-9` / `a-f` / `A-F`).
///
/// Lives in this shared util module so the three decoders that need it
/// (`url`, `json`, `unicode_escape`) all call the same implementation -
/// the pre-2026-05-24 state had a byte-for-byte identical copy in each
/// of those three files (kimi-dedup audit row #1).
pub fn take_hex_digits<I>(chars: &mut std::iter::Peekable<I>, count: usize) -> Result<u32, ()>
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
