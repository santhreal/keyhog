//! Shared helpers used across the per-encoding decoders.

/// Shortest candidate length worth an evasion-decode (reverse / Caesar shift).
/// Below this, reversed/shifted strings collide with ordinary text and produce
/// useless sub-chunks the scanner just has to dedup away. The single owner for
/// both [`crate::decode::caesar::MIN_CAESAR_LEN`] and `reverse::MIN_REVERSE_LEN`
/// (each a semantic alias of this value), so the two floors can never drift.
pub(crate) const MIN_EVASION_DECODE_LEN: usize = 16;

/// Pull `count` hex digits from `chars` and pack them MSB-first into a `u32`.
///
/// Returns `Err(())` if the iterator runs out before `count` characters or
/// any character isn't a valid hex digit (`0-9` / `a-f` / `A-F`).
///
/// The single MSB-first hex-packing loop. `json` calls it directly on a
/// `Chars` iterator; `unicode_escape` reaches it through
/// [`take_hex_digits_indexed`] (the `CharIndices` sibling that maps the item to
/// its `char`). `url` decodes byte-at-a-time via [`hex_val`] instead, so it does
/// not use this reader.
///
/// `Err(())` is intentional: the only failure mode is "fewer than `count` hex
/// digits available", and every caller just falls back to the raw text, so a
/// richer error type would be ceremony with no consumer.
#[allow(clippy::result_unit_err)]
pub(crate) fn take_hex_digits<I>(chars: &mut I, count: usize) -> Result<u32, ()>
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

/// `CharIndices` sibling of [`take_hex_digits`]: derives the packing from the
/// one loop by mapping each `(usize, char)` item to its `char`. No second copy
/// of the packing math.
#[allow(clippy::result_unit_err)]
pub(crate) fn take_hex_digits_indexed<I>(chars: &mut I, count: usize) -> Result<u32, ()>
where
    I: Iterator<Item = (usize, char)>,
{
    take_hex_digits(&mut chars.map(|(_, c)| c), count)
}

/// Resolve one already-read `\u`-escape code unit (`code`) into a `char`,
/// reading a following `\u` low-surrogate code unit from `chars` when `code` is
/// a high surrogate. A lone low surrogate is rejected. This is the ONE owner of
/// the UTF-16 surrogate-pair detection + second-unit read shared by the `json`
/// and `unicode_escape` decoders (both feed it a `char` iterator), so the range
/// checks — not just the [`surrogate_pair_to_char`] bit-math — have a single
/// definition and cannot drift.
#[allow(clippy::result_unit_err)]
pub(crate) fn resolve_escaped_codepoint<I>(code: u32, chars: &mut I) -> Result<char, ()>
where
    I: Iterator<Item = char>,
{
    if (0xD800..=0xDBFF).contains(&code) {
        // High surrogate: only half of an astral-plane scalar. It MUST be
        // followed by `\u` + a low surrogate, combined into the real char.
        match (chars.next(), chars.next()) {
            (Some('\\'), Some('u')) => {}
            _ => return Err(()),
        }
        let low = take_hex_digits(chars, 4)?;
        if !(0xDC00..=0xDFFF).contains(&low) {
            return Err(());
        }
        return surrogate_pair_to_char(code, low).ok_or(());
    }
    if (0xDC00..=0xDFFF).contains(&code) {
        // A lone low surrogate is never valid on its own.
        return Err(());
    }
    char::from_u32(code).ok_or(())
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
/// The bit-math half of [`resolve_escaped_codepoint`], which owns the full
/// surrogate-pair detection + second-unit read shared by the `json` and
/// `unicode_escape` decoders.
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
