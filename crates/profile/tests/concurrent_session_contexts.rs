use keyhog_profile::{
    add_input_bytes, current_runtime, span, MetricId, RunIdentity, RunState, Runtime, Session,
    Stage,
};
use std::collections::HashSet;

fn identity(name: &str) -> RunIdentity {
    RunIdentity::new("0.5.49", "detectors", "config", name, "test", "cpu-simd")
}

/// Concurrent runtime construction must allocate a distinct process-local context identity.
#[test]
fn concurrent_runtime_context_ids_are_unique() {
    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                (0..32)
                    .map(|_| Runtime::new().context_id())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let ids: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().expect("runtime creator completes"))
        .collect();
    let unique: HashSet<_> = ids.iter().copied().collect();
    assert_eq!(ids.len(), 256);
    assert_eq!(unique.len(), ids.len());
    assert!(ids.iter().all(|context_id| *context_id != 0));
}

/// Runtime clones must preserve ownership identity instead of allocating a second context.
#[test]
fn cloned_runtime_retains_its_context_identity() {
    let runtime = Runtime::new();
    let cloned = runtime.clone();
    assert_eq!(runtime.context_id(), cloned.context_id());
    assert_ne!(runtime.context_id(), Runtime::new().context_id());
}

/// A nested session must capture only its own work and restore the outer session after finishing.
#[test]
fn nested_sessions_isolate_metrics_and_restore_outer_context() {
    let outer = Session::start(identity("outer")).expect("start outer session");
    let outer_context_id = outer.runtime().context_id();
    add_input_bytes(11);
    drop(span(Stage::SourceRead));

    let inner = Session::start(identity("inner")).expect("start inner session");
    let inner_context_id = inner.runtime().context_id();
    assert_ne!(outer_context_id, inner_context_id);
    assert_eq!(
        current_runtime()
            .expect("inner context is current")
            .context_id(),
        inner_context_id
    );
    add_input_bytes(22);
    drop(span(Stage::Reporting));
    let inner_profile = inner.finish(RunState::Completed);

    assert_eq!(
        current_runtime()
            .expect("outer context is restored")
            .context_id(),
        outer_context_id
    );
    add_input_bytes(7);
    drop(span(Stage::SourceRead));
    let outer_profile = outer.finish(RunState::Completed);

    assert_eq!(inner_profile.input_bytes, 22);
    assert_eq!(inner_profile.stages.len(), 1);
    assert_eq!(inner_profile.stages[0].stage, Stage::Reporting);
    assert_eq!(inner_profile.stages[0].calls, 1);
    assert_eq!(outer_profile.input_bytes, 18);
    assert_eq!(outer_profile.stages.len(), 1);
    assert_eq!(outer_profile.stages[0].stage, Stage::SourceRead);
    assert_eq!(outer_profile.stages[0].calls, 2);
    assert!(current_runtime().is_none());
}

/// Finishing a non-current session must remove only its own context and leave the current peer live.
#[test]
fn out_of_order_session_finish_preserves_current_peer() {
    let outer = Session::start(identity("finish-first")).expect("start first session");
    let outer_id = outer.runtime().context_id();
    drop(span(Stage::SourceRead));
    let inner = Session::start(identity("finish-second")).expect("start second session");
    let inner_id = inner.runtime().context_id();

    let outer_profile = outer.finish(RunState::Completed);
    assert_eq!(
        current_runtime()
            .expect("inner remains current")
            .context_id(),
        inner_id
    );
    drop(span(Stage::Reporting));
    let inner_profile = inner.finish(RunState::Completed);

    assert_ne!(outer_id, inner_id);
    assert_eq!(outer_profile.stages.len(), 1);
    assert_eq!(outer_profile.stages[0].stage, Stage::SourceRead);
    assert_eq!(inner_profile.stages.len(), 1);
    assert_eq!(inner_profile.stages[0].stage, Stage::Reporting);
    assert!(current_runtime().is_none());
}

/// Non-LIFO context-guard drops must not pop a different runtime from the thread-local stack.
#[test]
fn non_lifo_guard_drop_removes_only_matching_runtime() {
    let first = Runtime::new();
    let second = Runtime::new();
    let first_guard = first.enter();
    let second_guard = second.enter();
    drop(span(Stage::Reporting));
    drop(first_guard);
    assert_eq!(
        current_runtime()
            .expect("second context remains")
            .context_id(),
        second.context_id()
    );
    drop(span(Stage::Reporting));
    drop(second_guard);
    assert!(current_runtime().is_none());

    assert!(first.take_session_latency_distributions().is_empty());
    let second_distributions = second.take_session_latency_distributions();
    assert_eq!(second_distributions.len(), 1);
    assert_eq!(second_distributions[0].metric_id, MetricId::Reporting);
    assert_eq!(second_distributions[0].call_count, 2);
}

/// Simultaneous sessions must keep both run IDs and runtime context IDs unique while work overlaps.
#[test]
fn overlapping_sessions_have_unique_run_and_context_identities() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let session = Session::start(identity(&format!("worker-{worker}")))
                    .expect("start concurrent session");
                let context_id = session.runtime().context_id();
                barrier.wait();
                drop(span(Stage::BackendDispatch));
                let profile = session.finish(RunState::Completed);
                (context_id, profile)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("concurrent session completes"))
        .collect();
    let context_ids: HashSet<_> = results.iter().map(|(id, _)| *id).collect();
    let run_ids: HashSet<_> = results
        .iter()
        .map(|(_, profile)| profile.identity.run_id.as_str())
        .collect();
    assert_eq!(context_ids.len(), 8);
    assert_eq!(run_ids.len(), 8);
    assert!(results.iter().all(|(_, profile)| {
        profile.stages.len() == 1
            && profile.stages[0].stage == Stage::BackendDispatch
            && profile.stages[0].calls == 1
    }));
}
