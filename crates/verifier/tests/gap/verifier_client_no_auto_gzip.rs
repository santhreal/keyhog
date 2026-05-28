//! KH-GAP-117: verifier engine client must disable auto gzip/brotli/deflate.

#[test]
fn verifier_client_no_auto_gzip() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/mod.rs"
    ))
    .expect("verify/mod.rs");
    let new_fn = src
        .split("pub fn new(")
        .nth(1)
        .expect("VerificationEngine::new must exist");
    let builder_section = new_fn
        .split("let client = builder.build()")
        .next()
        .expect("client build site");
    for needle in [".no_gzip()", ".no_brotli()", ".no_deflate()"] {
        assert!(
            builder_section.contains(needle),
            "VerificationEngine client builder must call {needle}"
        );
    }
}
