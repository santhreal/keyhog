//! WHY: Closes the defect class where profiler stage metrics and worker occupancy
//! double-count nested container spans instead of computing exclusive self-time (Row 104 and Row 109).
//! Without exclusive self-time, parent container spans (e.g. backend dispatch enclosing pattern matching)
//! inflate total stage elapsed time beyond 100% of wall clock and distort worker busy spread.
//!
//! What this does NOT catch: OS scheduler preemption delays or CPU frequency scaling occurring
//! within a single leaf span.

use keyhog_profile::{
    decision_timer, instrument_future, span, RunIdentity, RunState, Session, Stage,
};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

fn test_identity(name: &str) -> RunIdentity {
    RunIdentity::new("0.5.82", "detectors", "config", name, "test", "cpu-simd")
}

#[test]
fn row_104_worker_occupancy_uses_exclusive_self_time_without_nested_inflation() {
    let session = Session::start(test_identity("row-104-occupancy")).expect("start session");
    let runtime = session.runtime();

    let start = Instant::now();

    // Open an outer span (parent container)
    let outer = span(Stage::BackendDispatch);
    std::thread::sleep(Duration::from_millis(5));

    // Open an inner span (child stage)
    let inner = span(Stage::HotPatterns);
    std::thread::sleep(Duration::from_millis(10));
    drop(inner);

    std::thread::sleep(Duration::from_millis(5));
    drop(outer);

    let wall_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);

    let occupancy = runtime.take_session_worker_occupancy();
    assert!(occupancy.worker_count >= 1);
    assert_eq!(occupancy.active_worker_count, 1);

    // Busiest busy_ns must be close to total wall time (~20ms), NOT outer + inner (~30ms)
    // Busy time is bounded by top-level span elapsed time
    let total_busy_ns = occupancy.busy_ns;
    assert!(
        total_busy_ns >= 18_000_000,
        "total busy_ns should be at least ~18ms, got {total_busy_ns}"
    );

    // Invariant: total busy across workers cannot exceed wall * worker_count
    let max_allowed = wall_ns.saturating_mul(occupancy.worker_count.max(1));
    assert!(
        total_busy_ns <= max_allowed,
        "total busy ({total_busy_ns}) exceeds wall * worker_count ({max_allowed})"
    );

    // If nested double counting occurred, total_busy_ns would be >= 30ms.
    assert!(
        total_busy_ns < 28_000_000,
        "total busy_ns inflated by double counting: got {total_busy_ns} ns"
    );

    let _ = session.finish(RunState::Completed);
}

#[test]
fn row_109_every_stage_carries_exclusive_self_time_attributed_ns() {
    let session = Session::start(test_identity("row-109-attributed")).expect("start session");

    // Outer stage: BackendDispatch (~20ms total, ~10ms exclusive)
    let outer = span(Stage::BackendDispatch);
    std::thread::sleep(Duration::from_millis(5));

    // Child stage: ConfirmedPatterns (~10ms total and exclusive)
    let inner = span(Stage::ConfirmedPatterns);
    std::thread::sleep(Duration::from_millis(10));
    drop(inner);

    std::thread::sleep(Duration::from_millis(5));
    drop(outer);

    let profile = session.finish(RunState::Completed);
    let parent_stage = profile
        .stages
        .iter()
        .find(|s| s.stage == Stage::BackendDispatch)
        .expect("parent stage BackendDispatch present");
    let child_stage = profile
        .stages
        .iter()
        .find(|s| s.stage == Stage::ConfirmedPatterns)
        .expect("child stage ConfirmedPatterns present");

    // Parent elapsed should be ~20ms
    assert!(
        parent_stage.elapsed_ns >= 18_000_000,
        "parent elapsed_ns should be >= 18ms, got {}",
        parent_stage.elapsed_ns
    );
    // Parent attributed (self-time) should be ~10ms (20ms - 10ms child)
    assert!(
        parent_stage.attributed_ns >= 8_000_000 && parent_stage.attributed_ns < 16_000_000,
        "parent attributed_ns should be ~10ms, got {}",
        parent_stage.attributed_ns
    );

    // Child elapsed should be ~10ms
    assert!(
        child_stage.elapsed_ns >= 9_000_000,
        "child elapsed_ns should be >= 9ms, got {}",
        child_stage.elapsed_ns
    );
    // Child attributed should be ~10ms (no children)
    assert!(
        child_stage.attributed_ns >= 9_000_000,
        "child attributed_ns should be >= 9ms, got {}",
        child_stage.attributed_ns
    );

    // Total attributed time (parent self-time + child self-time) should equal total elapsed time of parent
    let sum_attributed = parent_stage.attributed_ns + child_stage.attributed_ns;
    let diff = parent_stage.elapsed_ns.abs_diff(sum_attributed);
    assert!(
        diff < 2_000_000,
        "sum of attributed times ({sum_attributed}) should match parent elapsed ({}), diff={diff}",
        parent_stage.elapsed_ns
    );

    // Both ranking by elapsed_ns and ranking by attributed_ns (self-time) are derivable:
    let mut by_elapsed = profile.stages.clone();
    by_elapsed.sort_by_key(|s| std::cmp::Reverse(s.elapsed_ns));

    let mut by_self_time = profile.stages.clone();
    by_self_time.sort_by_key(|s| std::cmp::Reverse(s.attributed_ns));

    assert_eq!(by_elapsed[0].stage, Stage::BackendDispatch);
    assert!(by_self_time[0].attributed_ns > 0);
    assert!(by_self_time[1].attributed_ns > 0);
}

#[test]
fn row_104_109_dynamic_stage_sweep_preserves_self_time_invariant() {
    // Derive the variant space at runtime across all Stage variants
    let all_stages = Stage::ALL;

    let session = Session::start(test_identity("row-104-109-sweep")).expect("start session");

    for stage in all_stages {
        let s = span(stage);
        std::thread::sleep(Duration::from_micros(10));
        drop(s);
    }

    let profile = session.finish(RunState::Completed);
    assert_eq!(profile.stages.len(), all_stages.len());

    for m in profile.stages {
        assert_eq!(m.calls, 1);
        assert!(
            m.elapsed_ns > 0,
            "stage {:?} must have non-zero elapsed_ns",
            m.stage
        );
        assert!(
            m.attributed_ns > 0,
            "stage {:?} must have non-zero attributed_ns for leaf execution",
            m.stage
        );
        assert!(
            m.attributed_ns <= m.elapsed_ns,
            "stage {:?} attributed_ns ({}) must not exceed elapsed_ns ({})",
            m.stage,
            m.attributed_ns,
            m.elapsed_ns
        );
    }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

#[test]
fn row_104_async_and_decision_timer_occupancy_bounded_without_double_counting() {
    let session = Session::start(test_identity("row-104-async-occupancy")).expect("start session");
    let runtime = session.runtime();

    let start = Instant::now();

    // Wrap synchronous span and decision timer inside instrumented future
    let future = instrument_future(Stage::BackendDispatch, async {
        let s = span(Stage::HotPatterns);
        std::thread::sleep(Duration::from_millis(5));
        let dt = decision_timer(Stage::BackendSelect);
        std::thread::sleep(Duration::from_millis(5));
        dt.finish();
        drop(s);
    });
    block_on(future);

    let wall_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let occupancy = runtime.take_session_worker_occupancy();
    assert!(occupancy.worker_count >= 1);

    let total_busy_ns = occupancy.busy_ns;
    let max_allowed = wall_ns.saturating_mul(occupancy.worker_count.max(1));
    assert!(
        total_busy_ns <= max_allowed,
        "total busy ns ({total_busy_ns}) must not exceed wall * worker_count ({max_allowed})"
    );

    let _ = session.finish(RunState::Completed);
}
