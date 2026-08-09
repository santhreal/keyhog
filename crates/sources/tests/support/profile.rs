//! Shared profiling harness for the source-instrumentation suites.
//!
//! Drives a real `keyhog_profile::Session` around one source collection and
//! exposes exact stage call counts, input totals, derived bytes, and typed
//! annotations for assertions. A session enters its runtime on the calling
//! thread; adapters that fan out to worker threads propagate that runtime
//! themselves, so the drained values cover the whole adapter path.

use keyhog_profile::{AnnotationId, RunIdentity, RunProfile, RunState, Session, Stage};

/// Serialize profiled runs inside one test binary: skip counters and reader
/// pools are process-global, so concurrent profiled scans would interleave.
static PROFILE_RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn profile_run_guard() -> std::sync::MutexGuard<'static, ()> {
    PROFILE_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Run `operation` inside an active profiling session and return the finished
/// profile plus the operation's output.
pub fn run_with_profile<T>(operation: impl FnOnce() -> T) -> (RunProfile, T) {
    let _guard = profile_run_guard();
    let identity = RunIdentity::new(
        "sources-profile-test",
        "detector-digest",
        "config-digest",
        "sources",
        "synthetic",
        "auto",
    );
    let mut session = Session::start(identity).expect("start profile session");
    session.transition(RunState::Scanning);
    let output = operation();
    let profile = session.finish(RunState::Completed);
    (profile, output)
}

/// Exact recorded call count for one stage.
pub fn stage_calls(profile: &RunProfile, stage: Stage) -> u64 {
    profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == stage)
        .map_or(0, |measurement| measurement.calls)
}

/// Run `operation` inside an active profiling session and drain the typed
/// annotations recorded for `annotation` before the session finishes.
pub fn run_with_profile_annotations<T>(
    annotation: AnnotationId,
    operation: impl FnOnce() -> T,
) -> (RunProfile, Vec<u64>, T) {
    let _guard = profile_run_guard();
    let identity = RunIdentity::new(
        "sources-profile-test",
        "detector-digest",
        "config-digest",
        "sources",
        "synthetic",
        "auto",
    );
    let mut session = Session::start(identity).expect("start profile session");
    session.transition(RunState::Scanning);
    let runtime = session.runtime();
    let output = operation();
    let (_events, annotations, loss) = runtime.take_session_typed_events();
    assert_eq!(
        loss.annotations, 0,
        "annotation storage must not drop records"
    );
    let values = annotations
        .into_iter()
        .filter(|record| record.annotation_id == annotation)
        .map(|record| record.value)
        .collect();
    let profile = session.finish(RunState::Completed);
    (profile, values, output)
}
