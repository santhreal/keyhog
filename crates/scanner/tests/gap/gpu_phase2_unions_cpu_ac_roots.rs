//! Static fail-closed guard: the GPU megakernel fast path must not secretly run
//! the full CPU Hyperscan trigger net. Full CPU recall floor is explicit
//! parity/debug behavior; host-only detectors still require CPU coverage.

use std::fs;
use std::path::PathBuf;

#[test]
fn megakernel_cpu_floor_is_explicit_not_default() {
    let mk = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/megakernel_dispatch.rs"),
    )
    .expect("megakernel_dispatch.rs readable");

    assert!(
        mk.contains("self.tuning.gpu_recall_floor_enabled()")
            && !mk.contains("KEYHOG_GPU_RECALL_FLOOR")
            && !mk.contains("KEYHOG_GPU_PARITY"),
        "full CPU recall floor must be explicit scanner tuning, not ambient env"
    );

    assert!(
        mk.contains("let host_floor = !catalog.host_detectors().is_empty();"),
        "host-only detectors must remain an explicit CPU coverage reason"
    );

    assert!(
        mk.contains("if full_recall_floor || host_floor")
            && mk.contains("None if host_floor")
            && mk.contains("None => None"),
        "megakernel must compute the CPU trigger net only for explicit floor or host coverage"
    );

    assert!(
        mk.contains("full_recall_floor={}") && mk.contains("host_floor={}"),
        "--perf-trace output must expose whether the scan paid for the CPU trigger floor"
    );
}
