#[test]
fn gpu_forced_module_exists() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/gpu_forced.rs");
    assert!(std::path::Path::new(p).exists());
}
