//! Gate `engine::boundary`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_boundary_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/boundary.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "engine::boundary: move inline tests to crates/scanner/tests/"
    );
}
