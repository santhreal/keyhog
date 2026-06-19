//! Caesar +1 ciphertext round-trips to AKIA-shaped plaintext.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_chunk;

#[test]
fn caesar_shift_surfaces_aws_access_key_plaintext() {
    let chunk = Chunk {
        data: "k = \"BLJBRS4EFGHIJKLM2345\";".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test".into(),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let expected = concat!("AK", "IAQR4DEFGHIJKL2345");
    assert!(
        decoded.iter().any(|c| c.data.contains(expected)),
        "Caesar decoder did not surface round-trip plaintext among {} variants",
        decoded.len()
    );
}
