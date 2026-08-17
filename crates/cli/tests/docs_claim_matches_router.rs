//! WHY THIS TEST EXISTS:
//! Row 10 / Product truth contract:
//! Documentation must describe the true behavior of the router:
//! the default scan path runs on SIMD / CPU, and GPU engages for large-chunk-dominant
//! batches above tier floors under proof-backed calibration or explicit backend opt-in.
//!
//! WHAT IT DOES NOT CATCH:
//! Dynamic hardware capabilities of unattached GPUs.

use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
}

#[test]
fn router_thresholds_keep_small_workloads_on_simd_or_cpu() {
    use keyhog_scanner::hw_probe::{gpu_could_engage, probe_hardware};

    // Synthesize a high-tier GPU capability profile
    let mut caps = probe_hardware().clone();
    caps.gpu_available = true;
    caps.gpu_is_software = false;

    // A standard tiny file / pre-commit hook payload (e.g., 64 KiB, 1000 patterns)
    // must NOT engage the GPU because dispatch latency exceeds SIMD scan time.
    let small_payload_bytes = 64 * 1024;
    let pattern_count = 926;

    let could_engage = gpu_could_engage(&caps, small_payload_bytes, pattern_count);
    assert!(
        !could_engage,
        "Small workloads (64 KiB) must route to SIMD/CPU, not GPU, matching documented routing behavior"
    );
}

#[test]
fn readme_and_cargo_description_truth_check() {
    let root = repo_root();
    let readme_path = root.join("README.md");
    let cargo_path = root.join("Cargo.toml");

    let readme = std::fs::read_to_string(&readme_path).expect("read README.md");
    let cargo = std::fs::read_to_string(&cargo_path).expect("read Cargo.toml");
    assert!(
        readme.contains("Calibration measures every eligible")
            && readme.contains("pure-Rust CPU, Hyperscan/SIMD, and GPU backend"),
        "README must state that calibration measures CPU, SIMD, and GPU backends"
    );

    assert!(
        cargo.contains("secret scanner"),
        "Cargo.toml must accurately describe keyhog"
    );
}
