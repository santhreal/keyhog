#![cfg(feature = "binary")]

use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn ghidra_literal_minimum_length_is_inclusive() {
    let literals = TestApi.extract_string_literals(r#"const char *s = "12345678";"#);

    assert_eq!(
        literals,
        vec!["12345678".to_string()],
        "8-byte Ghidra string literals meet the binary literal minimum and must be scanned"
    );
}

#[test]
fn ghidra_literal_decodes_hex_and_octal_escapes_before_scanning() {
    let literals =
        TestApi.extract_string_literals(r#"const char *s = "AKI\x41QYLPM\1165HFIQ\1227XYA";"#);

    assert_eq!(
        literals,
        vec!["AKIAQYLPMN5HFIQR7XYA".to_string()],
        "decompiler byte escapes must be normalized before detector matching"
    );
}
