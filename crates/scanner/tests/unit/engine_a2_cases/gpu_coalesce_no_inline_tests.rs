#[test]
fn gpu_coalesce_no_inline_tests() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/gpu_coalesce.rs")).unwrap();
    assert!(!src.contains("#[cfg(test)]"));
}
