//! unique_byte_count is the single distinct-byte-count primitive that replaced
//! three byte-identical `[false; 256]` presence loops: normalized_entropy's
//! log2(unique) denominator, confidence::penalties::char_diversity, and the ML
//! feature ml_scorer::ml_features::unique_byte_count. This pins the primitive's
//! values so the DEDUP cannot drift; char_diversity now divides this by the
//! byte length and normalized_entropy feeds it to log2, both by construction.

use keyhog_scanner::testing::confidence::unique_byte_count;

#[test]
fn unique_byte_count_counts_distinct_byte_values() {
    assert_eq!(unique_byte_count(b""), 0);
    assert_eq!(unique_byte_count(b"a"), 1);
    assert_eq!(unique_byte_count(b"aaaa"), 1);
    assert_eq!(unique_byte_count(b"abcd"), 4);
    assert_eq!(unique_byte_count(b"aabbccdd"), 4);
    assert_eq!(unique_byte_count(b"abcabcabc"), 3);
    // A 20-char AWS-style placeholder: 'A','K','I' + 'X' = 4 distinct.
    assert_eq!(unique_byte_count(b"AKIAXXXXXXXXXXXXXXXX"), 4);
    // Non-ASCII bytes are counted per-byte (UTF-8 of 'é' = 0xC3 0xA9 -> 2 bytes,
    // plus 'a' = 3 distinct byte values).
    assert_eq!(unique_byte_count("aé".as_bytes()), 3);
    // Every distinct byte value present -> 256; repeating it stays 256.
    let all_bytes: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    assert_eq!(unique_byte_count(&all_bytes), 256);
    let twice: Vec<u8> = all_bytes.iter().chain(all_bytes.iter()).copied().collect();
    assert_eq!(unique_byte_count(&twice), 256);
}
