//! Gate `checksum::stripe`: modularity file cap (500 LOC).

#[test]
fn checksum_stripe_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/stripe.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "checksum::stripe: {lines} lines exceeds 500-line cap - split module"
    );
}
