//! Static fail-closed guard: the GPU megakernel path must UNION its DFA firings on
//! top of the full CPU Hyperscan prefilter (`compute_coalesced_triggers`, which
//! covers every `ac_map` pattern — host-only detectors included). That makes the
//! trigger set provably ⊇ the default coalesced scan, so GPU literal-set drift can
//! never drop a raw detector match the CPU path would fire. The old
//! `backend_pattern_hits.rs` union site was folded into `megakernel_dispatch.rs`;
//! this guard tracks the invariant at its new home (Law 10).

use std::fs;
use std::path::PathBuf;

#[test]
fn megakernel_unions_cpu_hyperscan_net_before_extraction() {
    let mk = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/megakernel_dispatch.rs"),
    )
    .expect("megakernel_dispatch.rs readable");

    // (1) The recall-safe base: the full CPU Hyperscan prefilter is computed first.
    assert!(
        mk.contains("self.compute_coalesced_triggers(chunks, scanner)"),
        "megakernel must seed the trigger set from the full CPU Hyperscan net so \
         host-only / un-lowerable detectors are never dropped"
    );

    // (2) The GPU firings are OR'd ON TOP of that net (union, not replace), so the
    //     result is a strict superset of the CPU-only trigger set.
    assert!(
        mk.contains("slot[f.detector / 64] |= 1u64 << (f.detector % 64);"),
        "megakernel must union DFA firings into the CPU net bitmap, never replace it"
    );

    // (3) The fail-closed intent must stay documented at the union site.
    assert!(
        mk.contains("can never drop a detector the CPU path fires"),
        "megakernel union must remain provably ⊇ the default coalesced scan"
    );
}
