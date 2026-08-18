//! WHY: Closes the defect class where the markdown profile report omitted
//! blocked wait attribution, concurrency, and queue depths from the stage performance table (Row 108).
//! Without these columns, operators reading the text/markdown profile report cannot tell
//! whether a slow stage was blocked on I/O, starved by a queue, or executed with low worker concurrency.
//!
//! What this does NOT catch: Markdown visual font rendering differences in external PDF generators.

use keyhog_profile::{
    blocked, record_queue_depth_enqueue, span, CausalProfileV2, MacroStageId, MetricId,
    QueueDepthV2, QueueId, RunIdentity, RunState, Session, Stage, StageConcurrencyV2,
};
use std::time::Duration;

fn test_identity(name: &str) -> RunIdentity {
    RunIdentity::new("0.5.82", "detectors", "config", name, "test", "cpu-simd")
}

#[test]
fn row_108_markdown_report_renders_blocked_time_concurrency_and_queue_depth() {
    let session = Session::start(test_identity("row-108-markdown")).expect("start session");

    // 1. A non-wait stage (BackendDispatch)
    let s = span(Stage::BackendDispatch);
    std::thread::sleep(Duration::from_millis(1));
    drop(s);

    // 2. A wait stage (SourceQueueWait)
    record_queue_depth_enqueue(QueueId::ScannerWork);
    let wait_span = blocked(Stage::SourceQueueWait);
    std::thread::sleep(Duration::from_millis(5));
    drop(wait_span);

    let profile = session.finish(RunState::Completed);
    let mut causal = CausalProfileV2::from_v1(profile.clone());

    // Inject concurrency and queue depth to verify tabular rendering
    causal.stage_concurrency.push(StageConcurrencyV2 {
        version: 1,
        metric_id: MetricId::from(Stage::BackendDispatch),
        macro_stage_id: MacroStageId::Scan,
        calls: 1,
        elapsed_ns: 1_000_000,
        window_ns: 1_000_000,
        first_start_ns: 0,
        last_end_ns: 1_000_000,
        worker_count: 4,
        max_worker_elapsed_ns: 1_000_000,
        concurrency_milli: 3500, // 3.50x
        declared_serial_ns: 0,
        declared_serial_calls: 0,
        bytes: 1024,
    });

    causal.queue_depths.push(QueueDepthV2 {
        version: 1,
        queue: QueueId::ScannerWork,
        current: 2,
        high_water: 10,
        enqueues: 50,
        dequeues: 48,
    });

    let md = causal.render_markdown();

    // Verify all required table headers are present
    assert!(md.contains("| Stage | Calls | Elapsed (ms) | Self (ms) | Blocked (ms) | Concurrency | Queue Depth |"));
    assert!(md.contains("| :--- | ---: | ---: | ---: | ---: | ---: | :--- |"));

    // Find the row for source-queue-wait
    let source_wait_row = md
        .lines()
        .find(|line| line.contains("source-queue-wait"))
        .expect("source-queue-wait row present in markdown table");

    // For wait stage: blocked time and queue depth must be non-empty (not a dash)
    assert!(
        !source_wait_row.contains("| - | - | - |"),
        "wait stage should carry measured blocked time and queue depth: {source_wait_row}"
    );
    assert!(
        source_wait_row.contains("10/2"),
        "queue depth 10/2 should be rendered for source-queue-wait: {source_wait_row}"
    );

    // Find the row for backend-dispatch
    let backend_dispatch_row = md
        .lines()
        .find(|line| line.contains("backend-dispatch"))
        .expect("backend-dispatch row present in markdown table");

    // For non-wait stage: blocked time must be explicit dash, concurrency must be rendered
    assert!(
        backend_dispatch_row.contains("3.50x"),
        "concurrency 3.50x must be rendered: {backend_dispatch_row}"
    );
    // Non-wait stage should render explicit '-' for blocked time
    let parts: Vec<&str> = backend_dispatch_row.split('|').map(str::trim).collect();
    // parts[0] is empty, parts[1] is Stage, parts[2] is Calls, parts[3] is Elapsed, parts[4] is Self, parts[5] is Blocked, parts[6] is Concurrency, parts[7] is Queue Depth
    assert_eq!(parts[5], "-", "non-wait stage must render explicit dash for blocked time: {backend_dispatch_row}");
}

#[test]
fn row_108_every_stage_renders_tabular_columns() {
    let session = Session::start(test_identity("row-108-sweep")).expect("start session");
    for stage in Stage::ALL {
        let s = span(stage);
        drop(s);
    }
    let profile = session.finish(RunState::Completed);
    let md = profile.render_markdown();

    // Table headers and structural separator
    assert!(md.contains("| Stage | Calls | Elapsed (ms) | Self (ms) | Blocked (ms) | Concurrency | Queue Depth |"));

    // Every stage must appear as a row with valid markdown table columns
    for stage in Stage::ALL {
        let stage_name = stage.as_str();
        let row = md.lines().find(|l| l.contains(stage_name)).expect("stage row exists");
        let col_count = row.matches('|').count();
        // 7 columns -> 8 pipe symbols
        assert_eq!(
            col_count, 8,
            "stage {stage_name} row must have exact 7 columns (8 pipes), got {col_count}: {row}"
        );
    }
}

#[test]
fn row_108_observer_effect_overhead_is_recorded_and_proportional() {
    let session = Session::start(test_identity("row-108-observer")).expect("start session");

    // Stage with many calls (hot path)
    for _ in 0..100 {
        let s = span(Stage::HotPatterns);
        drop(s);
    }

    // Stage with few calls (coarse path)
    for _ in 0..2 {
        let s = span(Stage::SourceRead);
        drop(s);
    }

    let profile = session.finish(RunState::Completed);
    let causal = CausalProfileV2::from_v1(profile);

    let observer = causal.observer_effect.expect("observer effect must be present");
    assert!(observer.total_instrumentation_events >= 102);
    assert!(observer.estimated_overhead_ns > 0);
    assert_eq!(observer.estimated_ns_per_event, 35);

    // Hot stage should have higher total estimated overhead than coarse stage
    let hot = observer
        .stage_overhead
        .iter()
        .find(|s| s.stage == Stage::HotPatterns)
        .expect("hot stage overhead present");
    let coarse = observer
        .stage_overhead
        .iter()
        .find(|s| s.stage == Stage::SourceRead)
        .expect("coarse stage overhead present");

    assert_eq!(hot.calls, 100);
    assert_eq!(coarse.calls, 2);
    assert_eq!(hot.estimated_overhead_ns, 100 * 35);
    assert_eq!(coarse.estimated_overhead_ns, 2 * 35);
    assert!(hot.estimated_overhead_ns > coarse.estimated_overhead_ns);
}
