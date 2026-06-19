//! Static fail-closed guard: the GPU region-presence fast path must not secretly run
//! the full CPU Hyperscan trigger net. Full CPU recall floor is explicit
//! parity/debug behavior.

use std::fs;
use std::path::PathBuf;

#[test]
fn gpu_region_cpu_floor_is_explicit_not_default() {
    let mk = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/gpu_region_dispatch.rs"),
    )
    .expect("gpu_region_dispatch.rs readable");

    assert!(
        mk.contains("self.tuning.gpu_recall_floor_enabled()")
            && !mk.contains("KEYHOG_GPU_RECALL_FLOOR")
            && !mk.contains("KEYHOG_GPU_PARITY"),
        "full CPU recall floor must be explicit scanner tuning, not ambient env"
    );

    assert!(
        mk.contains("if full_recall_floor") && mk.contains("gpu_recall_floor requested"),
        "region-presence dispatch must compute the CPU trigger net only for the explicit recall floor"
    );

    assert!(
        mk.contains("full_recall_floor={}") && !mk.contains("host_floor={}"),
        "--perf-trace output must expose whether the scan paid for the CPU trigger floor"
    );
}
