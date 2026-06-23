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
///
/// `Err(())` is intentional: the only failure mode is "fewer than `count` hex
/// digits available", and every caller just falls back to the raw text, so a
/// richer error type would be ceremony with no consumer.
#[allow(clippy::result_unit_err)]
pub(crate) fn take_hex_digits<I>(
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

#[allow(clippy::result_unit_err)]
pub(crate) fn take_hex_digits_indexed<I>(chars: &mut I, count: usize) -> Result<u32, ()>
where
    I: Iterator<Item = (usize, char)>,
{
    let mut value = 0u32;
    for _ in 0..count {
        let digit = chars.next().ok_or(())?.1.to_digit(16).ok_or(())?;
        value = (value << 4) | digit;
    }
    Ok(value)
}

pub(super) fn lazy_decoded_prefix<'a>(
    decoded: &'a mut Option<String>,
    input: &str,
    prefix_end: usize,
) -> &'a mut String {
    decoded.get_or_insert_with(|| {
        let mut out = String::with_capacity(input.len());
        out.push_str(&input[..prefix_end]);
        out
    })
}

#[allow(clippy::result_unit_err)]
pub(crate) fn hex_val(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}
