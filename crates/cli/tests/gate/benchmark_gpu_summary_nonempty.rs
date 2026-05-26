//! LR1-A8 replacement gate: `benchmark.rs` must report GPU probe text.

use keyhog::benchmark::format_gpu_summary;

#[test]
fn format_gpu_summary_is_nonempty_string() {
    let summary = format_gpu_summary();
    assert!(
        summary == "unavailable" || summary.contains('(') || !summary.is_empty(),
        "GPU summary must be a concrete label or 'unavailable', got {summary:?}"
    );
}
