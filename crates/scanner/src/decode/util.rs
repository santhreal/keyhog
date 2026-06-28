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

/// Combine a UTF-16 surrogate PAIR into its astral-plane scalar `char`.
///
/// `high` must be a high surrogate (`0xD800..=0xDBFF`) and `low` a low surrogate
/// (`0xDC00..=0xDFFF`); the caller validates those ranges. Returns `None` only
/// if the combined scalar is not a valid `char` (unreachable for in-range
/// surrogates, but checked rather than unwrapped).
///
/// Shared by the `json` and `unicode_escape` decoders so the surrogate bit-math
/// (the part most prone to silent drift) has exactly ONE definition. The
/// per-decoder code still reads `\u` + the low code unit itself, because the two
/// callers walk different iterators (`Chars` vs `CharIndices`).
pub(crate) fn surrogate_pair_to_char(high: u32, low: u32) -> Option<char> {
    let scalar = 0x10000 + (((high - 0xD800) << 10) | (low - 0xDC00));
    char::from_u32(scalar)
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
