//! CRC-32 (IEEE 802.3) hash primitive.
//!
//! Polynomial `0xEDB88320` — the reflected form of `0x04C11DB7`, the
//! one used by gzip, zip, Ethernet, PNG, rsync. Byte-at-a-time
//! table-driven. Reference implementation is a straight port of the
//! textbook slicing algorithm.

/// Canonical CRC-32 initial value.
pub const CRC32_INIT: u32 = 0xFFFF_FFFF;

/// Reflected IEEE 802.3 polynomial.
pub const CRC32_POLY: u32 = 0xEDB8_8320;

/// CPU reference: CRC-32 over a byte slice. Returns the post-complement
/// value (matches the gzip / zip convention).
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let table = build_table();
    let mut crc = CRC32_INIT;
    for &byte in bytes {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ CRC32_INIT
}

/// Build the 256-entry CRC-32 table at runtime. Deterministic; the
/// GPU-side op loads this buffer from the host.
#[must_use]
pub fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ CRC32_POLY
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors from RFC 3720 (iSCSI) + the Castagnoli paper.

    #[test]
    fn crc32_empty_is_zero() {
        // CRC-32("" ) = 0 after the final complement.
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_single_zero_byte() {
        // crc32([0x00]) = 0xD202_EF8D
        assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
    }

    #[test]
    fn crc32_nine_ones() {
        // crc32("123456789") = 0xCBF4_3926 — classic test vector.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_table_128_slot() {
        // First row after zero should be 1→polynomial-shift.
        let table = build_table();
        assert_eq!(table[0], 0);
        // Standard table[1] for 0xEDB88320.
        assert_eq!(table[1], 0x7707_3096);
    }
}
