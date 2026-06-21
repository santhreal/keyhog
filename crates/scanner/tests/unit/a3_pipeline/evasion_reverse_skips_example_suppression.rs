use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed_with_source;

#[test]
fn reverse_decoder_bypasses_example_gate() {
    assert!(!known_example_suppressed_with_source(
        "ELPMAXE_AKEY",
        None,
        CodeContext::Unknown,
        Some("decode/reverse"),
    ));
}
