use super::*;

#[test]
fn hex_decode_empty_and_valid_cases() {
    assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
    assert_eq!(hex_decode("48656C6C6F").unwrap(), b"Hello");
    assert_eq!(
        hex_decode("deadbeef").unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        hex_decode("de_ad_be_ef").unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn hex_decode_rejects_malformed_and_odd_sequences() {
    assert!(hex_decode("a").is_err());
    assert!(hex_decode("abc").is_err());
    assert!(hex_decode("12345").is_err());
    assert!(hex_decode("gg41").is_err());
    assert!(hex_decode("41gg").is_err());
    assert!(hex_decode("48é6").is_err());
    assert!(hex_decode("41_4").is_err());
    assert!(hex_decode("41_zz").is_err());
}

#[test]
fn hex_decode_fixed_validates_16_byte_hashes() {
    let md5_hex = "d41d8cd98f00b204e9800998ecf8427e";
    let decoded = validate_hex_hash_16(md5_hex).expect("valid 16-byte hash must decode");
    assert_eq!(
        decoded,
        [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e
        ]
    );

    let md5_with_underscores = "d4_1d_8c_d9_8f_00_b2_04_e9_80_09_98_ec_f8_42_7e";
    let decoded_underscores = validate_hex_hash_16(md5_with_underscores)
        .expect("underscore-separated 16-byte hash must decode");
    assert_eq!(decoded_underscores, decoded);

    // Rejections: wrong length or non-hex
    assert!(validate_hex_hash_16("d41d8cd98f00b204e9800998ecf8427").is_err());
    assert!(validate_hex_hash_16("d41d8cd98f00b204e9800998ecf8427ea").is_err());
    assert!(validate_hex_hash_16("d41d8cd98f00b204e9800998ecf842zz").is_err());
}

#[test]
fn hex_decode_fixed_validates_32_byte_hashes() {
    let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let decoded = validate_hex_hash_32(sha256_hex).expect("valid 32-byte hash must decode");
    assert_eq!(decoded.len(), 32);
    assert_eq!(decoded[0], 0xe3);
    assert_eq!(decoded[31], 0x55);

    let sha256_underscores =
        "e3b0c442_98fc1c14_9afbf4c8_996fb924_27ae41e4_649b934c_a495991b_7852b855";
    let decoded_underscores = validate_hex_hash_32(sha256_underscores)
        .expect("underscore-separated 32-byte hash must decode");
    assert_eq!(decoded_underscores, decoded);

    // Rejections: wrong length or non-hex
    assert!(validate_hex_hash_32(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
    )
    .is_err());
    assert!(validate_hex_hash_32(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855a"
    )
    .is_err());
    assert!(validate_hex_hash_32(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8zz"
    )
    .is_err());
}

#[test]
fn try_decode_hex_candidate_utf8_fast_path() {
    // Text hex decodes to valid UTF-8 string
    assert_eq!(
        try_decode_hex_candidate_to_utf8("48656c6c6f").as_deref(),
        Some("Hello")
    );
    assert_eq!(
        try_decode_hex_candidate_to_utf8("73_6b_2d_70_72_6f_6a").as_deref(),
        Some("sk-proj")
    );

    // Binary hashes (random cryptographic digests) fail UTF-8 check and return None
    // without allocating heap Strings.
    let md5_hex = "d41d8cd98f00b204e9800998ecf8427e";
    assert_eq!(try_decode_hex_candidate_to_utf8(md5_hex), None);

    let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(try_decode_hex_candidate_to_utf8(sha256_hex), None);

    // Malformed inputs return None
    assert_eq!(try_decode_hex_candidate_to_utf8("abc"), None);
    assert_eq!(try_decode_hex_candidate_to_utf8("zz41"), None);
}
