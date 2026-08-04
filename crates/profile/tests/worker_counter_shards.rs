use keyhog_profile::{
    add_counter, add_input_units, span, CounterId, MetricId, RunIdentity, RunState, Session, Stage,
};

fn session(name: &str) -> Session {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        name,
        "test",
        "cpu-simd",
    ))
    .expect("start profile")
}

/// Repeated and nested context entry on one thread must reuse one shard instead of growing storage per call.
#[test]
fn one_thread_reuses_one_counter_shard_across_nested_scopes() {
    let session = session("single-shard");
    let runtime = session.runtime();
    assert_eq!(runtime.worker_shard_count(), 1);
    for _ in 0..100 {
        runtime.scope(|| {
            runtime.scope(|| {
                drop(span(Stage::Preprocess));
                add_counter(CounterId::InputUnits, 1);
            });
        });
    }
    assert_eq!(runtime.worker_shard_count(), 1);
    let metrics = runtime.take_session_typed_metrics();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].metric_id, MetricId::InputUnits);
    assert_eq!(metrics[0].value, 100);
    let profile = session.finish(RunState::Completed);
    let preprocess = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::Preprocess)
        .expect("preprocess aggregate");
    assert_eq!(preprocess.calls, 100);
}

/// Every active worker must receive one isolated shard and cold-path merging must lose no calls or units.
#[test]
fn concurrent_workers_register_distinct_shards_and_merge_exactly() {
    let session = session("concurrent-shards");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..1_000 {
                        drop(span(Stage::BackendDispatch));
                        add_input_units(1);
                    }
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }
    assert_eq!(
        runtime.worker_shard_count(),
        17,
        "the session-owning thread plus sixteen workers each own one shard"
    );
    let distributions = runtime.take_session_latency_distributions();
    assert_eq!(distributions.len(), 1);
    assert_eq!(distributions[0].metric_id, MetricId::BackendDispatch);
    assert_eq!(distributions[0].call_count, 16_000);
    let metrics = runtime.take_session_typed_metrics();
    let units = metrics
        .iter()
        .find(|metric| metric.metric_id == MetricId::InputUnits)
        .expect("input unit counter");
    assert_eq!(units.value, 16_000);
    let profile = session.finish(RunState::Completed);
    assert_eq!(profile.input_units, 16_000);
    let backend = profile
        .stages
        .iter()
        .find(|measurement| measurement.stage == Stage::BackendDispatch)
        .expect("backend aggregate");
    assert_eq!(backend.calls, 16_000);
}

/// Re-entering a worker context after dropping its guard must retain the same thread-local shard assignment.
#[test]
fn worker_reentry_does_not_register_duplicate_shards() {
    let session = session("worker-reentry");
    let runtime = session.runtime();
    let worker_runtime = runtime.clone();
    std::thread::spawn(move || {
        for _ in 0..100 {
            worker_runtime.scope(|| drop(span(Stage::Decode)));
        }
        assert_eq!(worker_runtime.worker_shard_count(), 2);
    })
    .join()
    .expect("worker completes");
    assert_eq!(runtime.worker_shard_count(), 2);
    let profile = session.finish(RunState::Completed);
    assert_eq!(profile.stages[0].calls, 100);
}

/// Sequential sessions on one thread must not reuse stale shards from a completed runtime.
#[test]
fn sequential_sessions_keep_worker_shards_isolated() {
    for name in ["first", "second"] {
        let session = session(name);
        let runtime = session.runtime();
        drop(span(Stage::SourceRead));
        assert_eq!(runtime.worker_shard_count(), 1);
        let profile = session.finish(RunState::Completed);
        assert_eq!(profile.stages.len(), 1);
        assert_eq!(profile.stages[0].stage, Stage::SourceRead);
        assert_eq!(profile.stages[0].calls, 1);
    }
}
