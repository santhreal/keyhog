use keyhog_scanner::decode::base32::{
    base32_decode, crockford_base32_decode, BASE32_DECODE_TABLE, CROCKFORD_DECODE_TABLE,
};

#[test]
fn rfc4648_test_vectors() {
    assert_eq!(base32_decode("").unwrap(), b"");
    assert_eq!(base32_decode("MY======").unwrap(), b"f");
    assert_eq!(base32_decode("MZXQ====").unwrap(), b"fo");
    assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
    assert_eq!(base32_decode("MZXW6YQ=").unwrap(), b"foob");
    assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
    assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
}

#[test]
fn rfc4648_unpadded_vectors() {
    assert_eq!(base32_decode("MY").unwrap(), b"f");
    assert_eq!(base32_decode("MZXQ").unwrap(), b"fo");
    assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
    assert_eq!(base32_decode("MZXW6YQ").unwrap(), b"foob");
    assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
    assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
}

#[test]
fn rfc4648_case_insensitivity() {
    assert_eq!(base32_decode("my======").unwrap(), b"f");
    assert_eq!(base32_decode("mzxq====").unwrap(), b"fo");
    assert_eq!(base32_decode("mzxw6ytb").unwrap(), b"fooba");
}

#[test]
fn rfc4648_rejects_invalid_chars() {
    assert!(base32_decode("1890=====").is_err());
    assert!(base32_decode("MZXW6!TB").is_err());
    assert!(base32_decode("MZXW6@TB").is_err());
}

#[test]
fn rfc4648_rejects_invalid_padding() {
    // 2 or 5 padding '=' chars are invalid in RFC 4648
    assert!(base32_decode("MZXW6Y==").is_err());
    assert!(base32_decode("MZX=====").is_err());
    // Equals in middle
    assert!(base32_decode("MZ=W6YTB").is_err());
    // Extra char after padding
    assert!(base32_decode("MY=====A").is_err());
}

#[test]
fn rfc4648_rejects_invalid_lengths() {
    assert!(base32_decode("M").is_err());
    assert!(base32_decode("MZX").is_err());
    assert!(base32_decode("MZXW6Y").is_err());
}

#[test]
fn rfc4648_rejects_non_zero_padding_bits() {
    // 'Z' = 25 (0b11001), low 2 bits are 01 != 0
    assert!(base32_decode("MZ======").is_err());
}

#[test]
fn crockford_test_vectors() {
    assert_eq!(crockford_base32_decode("").unwrap(), b"");
    // "fooba" in Crockford Base32:
    // 'f' (0x66), 'o' (0x6F), 'o' (0x6F), 'b' (0x62), 'a' (0x61)
    // 5-bit chunks:
    // 12 (C), 25 (S), 23 (Q), 22 (P), 30 (Y), 24 (R), 19 (K), 1 (1)
    let dec = crockford_base32_decode("CSQPYRK1").unwrap();
    assert_eq!(dec, b"fooba");
    let dec2 = crockford_base32_decode("CSQPYRK1CSQPYRK1").unwrap();
    assert_eq!(dec2, b"foobafooba");
}

#[test]
fn crockford_aliases_and_case() {
    // 'O' and 'o' map to 0, 'I'/'i'/'L'/'l' map to 1
    let dec1 = crockford_base32_decode("10").unwrap();
    let dec2 = crockford_base32_decode("IO").unwrap();
    let dec3 = crockford_base32_decode("io").unwrap();
    let dec4 = crockford_base32_decode("LO").unwrap();
    let dec5 = crockford_base32_decode("lo").unwrap();
    assert_eq!(dec1, vec![8]);
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, dec3);
    assert_eq!(dec1, dec4);
    assert_eq!(dec1, dec5);

    let dec_zero1 = crockford_base32_decode("00").unwrap();
    let dec_zero2 = crockford_base32_decode("OO").unwrap();
    let dec_zero3 = crockford_base32_decode("oo").unwrap();
    assert_eq!(dec_zero1, vec![0]);
    assert_eq!(dec_zero1, dec_zero2);
    assert_eq!(dec_zero1, dec_zero3);
}

#[test]
fn crockford_hyphens_ignored() {
    assert_eq!(crockford_base32_decode("").unwrap(), b"");
    assert_eq!(crockford_base32_decode("-").unwrap(), b"");
    assert_eq!(crockford_base32_decode("---").unwrap(), b"");
    let dec1 = crockford_base32_decode("CSQPYRK1").unwrap();
    let dec2 = crockford_base32_decode("CSQP-YRK1").unwrap();
    let dec3 = crockford_base32_decode("CS-QP-YR-K1").unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, dec3);
}

#[test]
fn crockford_rejects_invalid_chars() {
    // 'U' / 'u' are excluded in Crockford Base32
    assert!(crockford_base32_decode("01ARZ3NDEKTSU4RRFFQ69G5FAV").is_err());
    assert!(crockford_base32_decode("01ARZ3NDEKTSu4RRFFQ69G5FAV").is_err());
    // Non-alphanumeric (except hyphen)
    assert!(crockford_base32_decode("01ARZ3NDEKTS*4RRFFQ69G5FAV").is_err());
}

#[test]
fn crockford_rejects_invalid_lengths() {
    assert!(crockford_base32_decode("C").is_err());
    assert!(crockford_base32_decode("CTQ").is_err());
    assert!(crockford_base32_decode("CTQPYS").is_err());
}

#[test]
fn crockford_rejects_non_zero_trailing_bits() {
    // 2 chars -> 10 bits: 8 data bits + 2 trailing bits.
    // '0' = 0, 'Z' = 31 (0b11111), low 2 bits are 11 != 0
    assert!(crockford_base32_decode("0Z").is_err());
}

#[test]
fn table_bounds_and_coverage() {
    for b in 0..=255u8 {
        let b32_val = BASE32_DECODE_TABLE[b as usize];
        if (b.is_ascii_alphabetic() && b.is_ascii_uppercase())
            || (b.is_ascii_alphabetic() && b.is_ascii_lowercase())
            || (b'2'..=b'7').contains(&b)
        {
            assert!(
                b32_val < 32,
                "valid base32 byte 0x{:02X} mapped to invalid",
                b
            );
        } else {
            assert_eq!(b32_val, 0xFF, "invalid byte 0x{:02X} not 0xFF", b);
        }

        let crock_val = CROCKFORD_DECODE_TABLE[b as usize];
        if b.is_ascii_digit()
            || matches!(b, b'A'..=b'H' | b'a'..=b'h' | b'J'..=b'K' | b'j'..=b'k' | b'M'..=b'N' | b'm'..=b'n' | b'P'..=b'T' | b'p'..=b't' | b'V'..=b'Z' | b'v'..=b'z' | b'O' | b'o' | b'I' | b'i' | b'L' | b'l')
        {
            assert!(
                crock_val < 32,
                "valid crockford byte 0x{:02X} mapped to invalid",
                b
            );
        } else {
            assert_eq!(
                crock_val, 0xFF,
                "invalid crockford byte 0x{:02X} not 0xFF",
                b
            );
        }
    }
}

#[test]
fn zeroization_on_invalid_mid_stream() {
    // Long valid prefix followed by invalid byte in the second block
    let bad_rfc = "MZXW6YTB00000000";
    assert!(base32_decode(bad_rfc).is_err());
    let bad_crock = "CSQPYRK1UUUUUUUU";
    assert!(crockford_base32_decode(bad_crock).is_err());
}
