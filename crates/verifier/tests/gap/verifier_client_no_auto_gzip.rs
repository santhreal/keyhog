//! KH-GAP-117: verifier engine client must disable auto gzip/brotli/deflate.

#[test]
fn verifier_client_no_auto_gzip() {
    // The base engine client routes through the single-owner
    // `harden_verifier_client_builder` (lib.rs) for its decompression posture.
    // Verify the delegation, then that the owner disables the codecs.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/mod.rs"))
        .expect("verify/mod.rs");
    let new_fn = src
        .split("pub fn new(")
        .nth(1)
        .expect("VerificationEngine::new must exist");
    let builder_section = new_fn
        .split("let client = builder.build()")
        .next()
        .expect("client build site");
    assert!(
        builder_section.contains("harden_verifier_client_builder("),
        "VerificationEngine base client must apply the shared hardened posture"
    );

    let lib_src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("lib.rs");
    let harden = lib_src
        .split("fn harden_verifier_client_builder(")
        .nth(1)
        .expect("harden_verifier_client_builder must exist")
        .split("\nfn ")
        .next()
        .expect("harden fn body bounded");
    for needle in [".no_gzip()", ".no_brotli()", ".no_deflate()"] {
        assert!(
            harden.contains(needle),
            "harden_verifier_client_builder must call {needle}"
        );
    }
}
