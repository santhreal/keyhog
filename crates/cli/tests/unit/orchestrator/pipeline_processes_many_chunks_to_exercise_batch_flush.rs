//! Pipeline: batch flush preserves recall across >4096 chunks.

use super::support::{make_chunk, make_detector, make_orchestrator, StaticSource};
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{Chunk, Source};

#[test]
fn pipeline_processes_many_chunks_to_exercise_batch_flush() {
    const N: usize = 6000;
    let orch = make_orchestrator(vec![make_detector()]);
    let chunks: Vec<Chunk> = (0..N)
        .map(|i| {
            make_chunk(
                &format!("token = STATIC_SECRET_{:012}", 100_000_000 + i),
                &format!("file_{i}.rs"),
            )
        })
        .collect();
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks })];
    let findings = API
        .scan_orchestrator_scan_sources_for_test(&orch, sources, false, None)
        .expect("scan sources");
    // Every one of the N chunks contains exactly one planted STATIC_SECRET_ match, so a
    // correct batch flush across the >4096 boundary must surface exactly N findings. A loose
    // recall floor (e.g. 0.80) would silently tolerate ~1200 dropped chunks - the exact
    // flush regression this test exists to catch - so assert the exact count instead.
    let static_findings = findings
        .iter()
        .filter(|finding| finding.detector_id.as_ref() == "static-test")
        .count();
    assert_eq!(
        static_findings,
        N,
        "batch flush must not drop any static-test chunk; delta {} (total raw findings {})",
        N.abs_diff(static_findings),
        findings.len()
    );
}
