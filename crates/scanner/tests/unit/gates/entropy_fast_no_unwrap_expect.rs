//! Gate `entropy_fast`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn entropy_fast_no_unwrap_expect() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/fast.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let offenders = unwrap_expect_offenders(&src);
    assert!(
        offenders.is_empty(),
        "entropy_fast: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
