//! RFC 4648 and Crockford Base32 byte-stream decoding routines.
//!
//! Provides bounded, zeroizing Base32 decoding for arbitrary binary payloads.
//! On decode error (invalid character, padding mismatch, or non-zero trailing
//! bits), intermediate allocated byte buffers are securely zeroized before
//! returning `Err(())`. On success, ownership of the decoded buffer is transferred
//! to the caller.
//!
//! These decoders provide standalone byte-stream recovery and do not participate
//! in the default automated scan pipeline. Unlike `keyhog_core::aws::aws_account_from_key_id`
//! (which is a specialized u48 bit-extractor for the 10-char account segment of an
//! AWS key ID), these routines perform full-payload RFC 4648 and Crockford decoding.
use super::limits::MAX_BASE32_INPUT_LEN;
use zeroize::Zeroize;

/// RFC 4648 Base32 lookup table mapping ASCII bytes to 5-bit values (0..=31).
/// Invalid bytes map to 0xFF.
pub const BASE32_DECODE_TABLE: [u8; 256] = build_base32_table();

/// Crockford Base32 lookup table mapping ASCII bytes to 5-bit values (0..=31).
/// Invalid bytes map to 0xFF.
pub const CROCKFORD_DECODE_TABLE: [u8; 256] = build_crockford_table();

const fn build_base32_table() -> [u8; 256] {
    let mut table = [0xFF; 256];
    let mut i = 0;
    while i < 26 {
        table[(b'A' + i) as usize] = i;
        table[(b'a' + i) as usize] = i;
        i += 1;
    }
    let mut j = 0;
    while j < 6 {
        table[(b'2' + j) as usize] = 26 + j;
        j += 1;
    }
    table
}

const fn build_crockford_table() -> [u8; 256] {
    let mut table = [0xFF; 256];
    // Digits 0-9
    let mut i = 0;
    while i < 10 {
        table[(b'0' + i) as usize] = i;
        i += 1;
    }
    // Letters A-H -> 10..17
    let mut c = 0;
    while c < 8 {
        table[(b'A' + c) as usize] = 10 + c;
        table[(b'a' + c) as usize] = 10 + c;
        c += 1;
    }
    // J-K -> 18..19
    table[b'J' as usize] = 18;
    table[b'j' as usize] = 18;
    table[b'K' as usize] = 19;
    table[b'k' as usize] = 19;
    // M-N -> 20..21
    table[b'M' as usize] = 20;
    table[b'm' as usize] = 20;
    table[b'N' as usize] = 21;
    table[b'n' as usize] = 21;
    // P-T -> 22..26
    let mut p = 0;
    while p < 5 {
        table[(b'P' + p) as usize] = 22 + p;
        table[(b'p' + p) as usize] = 22 + p;
        p += 1;
    }
    // V-Z -> 27..31
    let mut v = 0;
    while v < 5 {
        table[(b'V' + v) as usize] = 27 + v;
        table[(b'v' + v) as usize] = 27 + v;
        v += 1;
    }
    // Aliases:
    // O / o -> 0
    table[b'O' as usize] = 0;
    table[b'o' as usize] = 0;
    // I / i / L / l -> 1
    table[b'I' as usize] = 1;
    table[b'i' as usize] = 1;
    table[b'L' as usize] = 1;
    table[b'l' as usize] = 1;

    table
}

/// Decode an RFC 4648 standard base32 string, bounded to
/// `MAX_BASE32_INPUT_LEN` bytes for DoS safety. Returns `Err(())` on invalid
/// character, invalid padding, or over-length input.
#[allow(clippy::result_unit_err)]
pub fn base32_decode(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() > MAX_BASE32_INPUT_LEN {
        return Err(());
    }

    if input.is_empty() {
        return Ok(Vec::new());
    }

    let bytes = input.as_bytes();
    let (data, padding_len) = match bytes.iter().position(|&b| b == b'=') {
        Some(pos) => {
            if !input.len().is_multiple_of(8) {
                return Err(());
            }
            let pad_count = input.len() - pos;
            if !matches!(pad_count, 1 | 3 | 4 | 6) {
                return Err(());
            }
            if !bytes[pos..].iter().all(|&b| b == b'=') {
                return Err(());
            }
            (&bytes[..pos], pad_count)
        }
        None => (bytes, 0),
    };

    let rem_len = data.len() % 8;
    if !matches!(rem_len, 0 | 2 | 4 | 5 | 7) {
        return Err(());
    }

    if padding_len > 0 {
        let expected_rem = match padding_len {
            1 => 7,
            3 => 5,
            4 => 4,
            6 => 2,
            _ => return Err(()),
        };
        if rem_len != expected_rem {
            return Err(());
        }
    }

    decode_base32_slice(data, &BASE32_DECODE_TABLE)
}

/// Decode a byte-stream Crockford base32 string, bounded to `MAX_BASE32_INPUT_LEN` bytes
/// for DoS safety. Hyphens are ignored as separators, and character aliases (`O`/`o` -> 0,
/// `I`/`i`/`L`/`l` -> 1) are normalized.
///
/// Uses standard byte-aligned framing (5-byte blocks per 8 characters) with trailing-bit
/// zero checks on fractional blocks. Empty strings and hyphen-only separator strings decode
/// to an empty vector. Returns `Err(())` on invalid character, invalid length, or over-length input.
#[allow(clippy::result_unit_err)]
pub fn crockford_base32_decode(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() > MAX_BASE32_INPUT_LEN {
        return Err(());
    }

    if !input.as_bytes().contains(&b'-') {
        return decode_base32_slice(input.as_bytes(), &CROCKFORD_DECODE_TABLE);
    }

    if input.len() <= 256 {
        let mut buf = [0u8; 256];
        let mut len = 0usize;
        for &b in input.as_bytes() {
            if b != b'-' {
                buf[len] = b;
                len += 1;
            }
        }
        let res = decode_base32_slice(&buf[..len], &CROCKFORD_DECODE_TABLE);
        buf.zeroize();
        res
    } else {
        let mut cleaned = Vec::with_capacity(input.len());
        for &b in input.as_bytes() {
            if b != b'-' {
                cleaned.push(b);
            }
        }
        let res = decode_base32_slice(&cleaned, &CROCKFORD_DECODE_TABLE);
        cleaned.zeroize();
        res
    }
}

fn decode_base32_slice(data: &[u8], table: &[u8; 256]) -> Result<Vec<u8>, ()> {
    let rem_len = data.len() % 8;
    if !matches!(rem_len, 0 | 2 | 4 | 5 | 7) {
        return Err(());
    }

    let full_blocks = data.len() / 8;
    let tail_bytes = match rem_len {
        0 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        7 => 4,
        _ => return Err(()),
    };
    let total_len = full_blocks * 5 + tail_bytes;
    let mut out = Vec::with_capacity(total_len);

    for chunk in data.chunks_exact(8) {
        let v0 = table[chunk[0] as usize];
        let v1 = table[chunk[1] as usize];
        let v2 = table[chunk[2] as usize];
        let v3 = table[chunk[3] as usize];
        let v4 = table[chunk[4] as usize];
        let v5 = table[chunk[5] as usize];
        let v6 = table[chunk[6] as usize];
        let v7 = table[chunk[7] as usize];

        if (v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) & 0xE0 != 0 {
            out.zeroize();
            return Err(());
        }

        let combined = ((v0 as u64) << 35)
            | ((v1 as u64) << 30)
            | ((v2 as u64) << 25)
            | ((v3 as u64) << 20)
            | ((v4 as u64) << 15)
            | ((v5 as u64) << 10)
            | ((v6 as u64) << 5)
            | (v7 as u64);

        out.push((combined >> 32) as u8);
        out.push((combined >> 24) as u8);
        out.push((combined >> 16) as u8);
        out.push((combined >> 8) as u8);
        out.push(combined as u8);
    }

    let rem = data.chunks_exact(8).remainder();
    match rem.len() {
        0 => Ok(out),
        2 => {
            let v0 = table[rem[0] as usize];
            let v1 = table[rem[1] as usize];
            if (v0 | v1) & 0xE0 != 0 {
                out.zeroize();
                return Err(());
            }
            let combined = ((v0 as u16) << 5) | (v1 as u16);
            if combined & 0x03 != 0 {
                out.zeroize();
                return Err(());
            }
            out.push((combined >> 2) as u8);
            Ok(out)
        }
        4 => {
            let v0 = table[rem[0] as usize];
            let v1 = table[rem[1] as usize];
            let v2 = table[rem[2] as usize];
            let v3 = table[rem[3] as usize];
            if (v0 | v1 | v2 | v3) & 0xE0 != 0 {
                out.zeroize();
                return Err(());
            }
            let combined =
                ((v0 as u32) << 15) | ((v1 as u32) << 10) | ((v2 as u32) << 5) | (v3 as u32);
            if combined & 0x0F != 0 {
                out.zeroize();
                return Err(());
            }
            out.push((combined >> 12) as u8);
            out.push((combined >> 4) as u8);
            Ok(out)
        }
        5 => {
            let v0 = table[rem[0] as usize];
            let v1 = table[rem[1] as usize];
            let v2 = table[rem[2] as usize];
            let v3 = table[rem[3] as usize];
            let v4 = table[rem[4] as usize];
            if (v0 | v1 | v2 | v3 | v4) & 0xE0 != 0 {
                out.zeroize();
                return Err(());
            }
            let combined = ((v0 as u32) << 20)
                | ((v1 as u32) << 15)
                | ((v2 as u32) << 10)
                | ((v3 as u32) << 5)
                | (v4 as u32);
            if combined & 0x01 != 0 {
                out.zeroize();
                return Err(());
            }
            out.push((combined >> 17) as u8);
            out.push((combined >> 9) as u8);
            out.push((combined >> 1) as u8);
            Ok(out)
        }
        7 => {
            let v0 = table[rem[0] as usize];
            let v1 = table[rem[1] as usize];
            let v2 = table[rem[2] as usize];
            let v3 = table[rem[3] as usize];
            let v4 = table[rem[4] as usize];
            let v5 = table[rem[5] as usize];
            let v6 = table[rem[6] as usize];
            if (v0 | v1 | v2 | v3 | v4 | v5 | v6) & 0xE0 != 0 {
                out.zeroize();
                return Err(());
            }
            let combined = ((v0 as u64) << 30)
                | ((v1 as u64) << 25)
                | ((v2 as u64) << 20)
                | ((v3 as u64) << 15)
                | ((v4 as u64) << 10)
                | ((v5 as u64) << 5)
                | (v6 as u64);
            if combined & 0x07 != 0 {
                out.zeroize();
                return Err(());
            }
            out.push((combined >> 27) as u8);
            out.push((combined >> 19) as u8);
            out.push((combined >> 11) as u8);
            out.push((combined >> 3) as u8);
            Ok(out)
        }
        _ => {
            out.zeroize();
            Err(())
        }
    }
}
