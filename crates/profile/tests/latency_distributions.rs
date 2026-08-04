use keyhog_profile::{span, MetricId, RunIdentity, RunState, Session, Stage, MAX_RECORDED_SPANS};
use std::time::Duration;

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

/// Every completed call must land in exactly one contiguous logarithmic bucket.
#[test]
fn completed_calls_form_exact_non_overlapping_distribution() {
    let session = session("distribution");
    let runtime = session.runtime();
    for delay_ms in [0, 1, 2] {
        let guard = span(Stage::SourceRead);
        std::thread::sleep(Duration::from_millis(delay_ms));
        drop(guard);
    }
    let spans = runtime.take_session_span_records().0;
    let distributions = runtime.take_session_latency_distributions();
    assert_eq!(distributions.len(), 1);
    let distribution = &distributions[0];
    assert_eq!(distribution.metric_id, MetricId::SourceRead);
    assert_eq!(distribution.call_count, 3);
    let exact_minimum = spans
        .iter()
        .map(|record| record.inclusive_ns)
        .min()
        .expect("recorded minimum");
    let exact_maximum = spans
        .iter()
        .map(|record| record.inclusive_ns)
        .max()
        .expect("recorded maximum");
    assert_eq!(distribution.minimum_ns, exact_minimum);
    assert_eq!(distribution.maximum_ns, exact_maximum);
    assert!(
        distribution.minimum_ns <= distribution.p50_ns
            && distribution.p50_ns <= distribution.p90_ns
            && distribution.p90_ns <= distribution.p95_ns
            && distribution.p95_ns <= distribution.p99_ns
            && distribution.p99_ns <= distribution.maximum_ns
    );
    assert_eq!(
        distribution
            .buckets
            .iter()
            .map(|bucket| bucket.count)
            .sum::<u64>(),
        3
    );
    assert!(distribution
        .buckets
        .windows(2)
        .all(|pair| pair[0].upper_bound_ns < pair[1].lower_bound_ns));
    for span in spans {
        assert!(distribution.buckets.iter().any(|bucket| {
            bucket.lower_bound_ns <= span.inclusive_ns
                && span.inclusive_ns <= bucket.upper_bound_ns
                && bucket.count > 0
        }));
    }
    let _ = session.finish(RunState::Completed);
}

/// A single call's minimum, maximum, and every nearest-rank percentile must be exact.
#[test]
fn single_call_summary_is_exact_at_every_percentile() {
    let session = session("single-call");
    let runtime = session.runtime();
    drop(span(Stage::Reporting));
    let recorded_ns = runtime.take_session_span_records().0[0].inclusive_ns;
    let distributions = runtime.take_session_latency_distributions();
    let distribution = &distributions[0];
    assert_eq!(distribution.minimum_ns, recorded_ns);
    assert_eq!(distribution.maximum_ns, recorded_ns);
    assert_eq!(distribution.p50_ns, recorded_ns);
    assert_eq!(distribution.p90_ns, recorded_ns);
    assert_eq!(distribution.p95_ns, recorded_ns);
    assert_eq!(distribution.p99_ns, recorded_ns);
    let _ = session.finish(RunState::Completed);
}

/// Distinct micro-functions must retain separate call counts and latency ranges.
#[test]
fn distributions_are_isolated_by_stable_micro_function_id() {
    let session = session("stage-isolation");
    let runtime = session.runtime();
    drop(span(Stage::Preprocess));
    drop(span(Stage::Decode));
    drop(span(Stage::Decode));

    let distributions = runtime.take_session_latency_distributions();
    assert_eq!(distributions.len(), 2);
    assert_eq!(distributions[0].metric_id, MetricId::Preprocess);
    assert_eq!(distributions[0].call_count, 1);
    assert_eq!(distributions[1].metric_id, MetricId::Decode);
    assert_eq!(distributions[1].call_count, 2);
    let _ = session.finish(RunState::Completed);
}

/// Distribution counters must outlive bounded detail-event capacity and account for every call.
#[test]
fn distribution_counts_all_calls_when_detailed_events_overflow() {
    let session = session("event-overflow");
    let runtime = session.runtime();
    for _ in 0..=MAX_RECORDED_SPANS {
        drop(span(Stage::GenericDetection));
    }
    let (events, dropped) = runtime.take_session_span_records();
    let distributions = runtime.take_session_latency_distributions();
    assert_eq!(events.len(), MAX_RECORDED_SPANS);
    assert_eq!(dropped, 1);
    assert_eq!(distributions.len(), 1);
    assert_eq!(distributions[0].call_count, MAX_RECORDED_SPANS as u64 + 1);
    assert_eq!(
        distributions[0]
            .buckets
            .iter()
            .map(|bucket| bucket.count)
            .sum::<u64>(),
        MAX_RECORDED_SPANS as u64 + 1
    );
    let _ = session.finish(RunState::Completed);
}

/// Concurrent workers must merge relaxed atomic buckets without losing or duplicating calls.
#[test]
fn concurrent_workers_merge_exact_distribution_counts() {
    let session = session("concurrent-distribution");
    let runtime = session.runtime();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let runtime = runtime.clone();
            std::thread::spawn(move || {
                runtime.scope(|| {
                    for _ in 0..100 {
                        drop(span(Stage::BackendDispatch));
                    }
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker completes");
    }

    let distributions = runtime.take_session_latency_distributions();
    assert_eq!(distributions.len(), 1);
    assert_eq!(distributions[0].metric_id, MetricId::BackendDispatch);
    assert_eq!(distributions[0].call_count, 800);
    assert_eq!(
        distributions[0]
            .buckets
            .iter()
            .map(|bucket| bucket.count)
            .sum::<u64>(),
        800
    );
    let _ = session.finish(RunState::Completed);
}

/// Draining must be destructive so a later analysis pass cannot duplicate prior calls.
#[test]
fn distribution_drain_clears_every_bucket() {
    let session = session("drain");
    let runtime = session.runtime();
    drop(span(Stage::Suppression));
    assert_eq!(runtime.take_session_latency_distributions().len(), 1);
    assert!(runtime.take_session_latency_distributions().is_empty());
    drop(span(Stage::Suppression));
    let second = runtime.take_session_latency_distributions();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].call_count, 1);
    let _ = session.finish(RunState::Completed);
}
