//! Gate `benchmark`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn benchmark_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/benchmark.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "benchmark: move inline tests to crates/cli/tests/"
    );
}
