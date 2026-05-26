//! Pipeline: batch flush preserves recall across >4096 chunks.

use super::support::{make_chunk, make_detector, make_orchestrator, StaticSource};
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
    let findings = orch.scan_sources_for_test(sources, false, None);
    let recall = findings.len() as f64 / N as f64;
    assert!(recall >= 0.80, "recall {:.2}% below floor", recall * 100.0);
}
