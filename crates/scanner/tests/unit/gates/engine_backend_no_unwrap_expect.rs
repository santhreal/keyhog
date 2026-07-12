//! Gate `engine::backend`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn engine_backend_no_unwrap_expect() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/backend.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let offenders = unwrap_expect_offenders(&src);
    assert!(
        offenders.is_empty(),
        "engine::backend: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
