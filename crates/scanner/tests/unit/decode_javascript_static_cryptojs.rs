use super::evp_bytes_to_key_md5;

#[test]
fn evp_bytes_to_key_matches_openssl_vector() {
    let salt: [u8; 8] = hex::decode("0011223344556677")
        .expect("valid fixed salt")
        .try_into()
        .expect("eight-byte fixed salt");
    let (key, iv) = evp_bytes_to_key_md5(b"mySecretKey123", &salt);
    assert_eq!(
        key.as_slice(),
        hex::decode("e25410b8ef51f7047637c5e4dd5921ae15f98bf04076fa178e96fad9d45ec984")
            .expect("valid fixed key")
    );
    assert_eq!(
        iv.as_slice(),
        hex::decode("317406af052f963ee40fba3f9bed5d72").expect("valid fixed IV")
    );
}
