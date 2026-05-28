//! Hex decoder recognizes underscore-separated firmware-style literals.

use keyhog_core::Chunk;
use keyhog_scanner::decode::{decode_chunk, hex_decode};

#[test]
fn underscored_hex_literal_decodes_to_bytes() {
    let body = "\"41_42_43_44_45_46_47_48_49_4a_4b_4c_4d_4e_4f_50\
                _51_52_53_54_55_56_57_58_59_5a_61_62_63_64_65_66\"";
    let chunk = Chunk {
        data: format!("token_hex = {body};").into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded.iter().any(|c| c.data.contains("ABCDEFGHIJKLMNOP")),
        "hex decoder must surface underscored literal; got {:?}",
        decoded.iter().map(|c| &c.data).collect::<Vec<_>>()
    );
    let cleaned: String = body
        .trim_matches('"')
        .chars()
        .filter(|c| *c != '_')
        .collect();
    let bytes = hex_decode(&cleaned).expect("cleaned hex decodes");
    assert_eq!(&bytes[..16], b"ABCDEFGHIJKLMNOP");
}
