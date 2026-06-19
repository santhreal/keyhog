#[test]
fn scan_gpu_monolith_removed() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/scan_gpu.rs");
    assert!(
        !std::path::Path::new(p).exists(),
        "scan_gpu.rs god file must be split"
    );
}
