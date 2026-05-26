use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_known_example_credential_with_source;

#[test]
fn reverse_decoder_bypasses_example_gate() {
    assert!(!should_suppress_known_example_credential_with_source(
        "ELPMAXE_AKEY",
        None,
        CodeContext::Unknown,
        Some("decode/reverse"),
    ));
}
