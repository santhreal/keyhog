use keyhog_profile::{enabled, reset, set_enabled, span, MetricId, Runtime, Stage};
use std::hint::black_box;
use std::time::Instant;

const ITERATIONS: u64 = 20_000;
const ROUNDS: usize = 9;

// Absolute budgets leave headroom for shared CI hosts while still catching an
// extra clock read, allocation, lock, or unbounded lookup on the hot paths.
const DISABLED_SPAN_BUDGET_NS: f64 = 10.0;
const ENABLED_CHECK_BUDGET_NS: f64 = 5.0;
const AGGREGATE_SPAN_BUDGET_NS: f64 = 250.0;
const CAUSAL_SPAN_BUDGET_NS: f64 = 1_000.0;

fn measure(operation: &mut impl FnMut()) -> f64 {
    for _ in 0..ITERATIONS {
        operation();
    }
    let mut samples = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            operation();
        }
        samples.push(started.elapsed().as_secs_f64() * 1_000_000_000.0 / ITERATIONS as f64);
    }
    samples.sort_by(f64::total_cmp);
    samples[ROUNDS / 2]
}

fn measure_causal_span() -> f64 {
    let mut samples = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let runtime = Runtime::new();
        let guard = runtime.enter();
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            drop(black_box(span(Stage::Preprocess)));
        }
        samples.push(started.elapsed().as_secs_f64() * 1_000_000_000.0 / ITERATIONS as f64);
        drop(guard);
        let (records, dropped) = runtime.take_session_span_records();
        assert_eq!(records.len(), ITERATIONS as usize);
        assert_eq!(dropped, 0);
        let distributions = runtime.take_session_latency_distributions();
        let preprocess = distributions
            .iter()
            .find(|distribution| distribution.metric_id == MetricId::Preprocess)
            .expect("causal benchmark emits preprocess distribution");
        assert_eq!(preprocess.call_count, ITERATIONS);
    }
    samples.sort_by(f64::total_cmp);
    samples[ROUNDS / 2]
}

fn enforce(label: &str, observed_ns: f64, budget_ns: f64) {
    println!("{label}: median={observed_ns:.3} ns/call budget={budget_ns:.3} ns/call");
    assert!(
        observed_ns <= budget_ns,
        "{label} profiler overhead {observed_ns:.3} ns/call exceeds {budget_ns:.3} ns/call budget"
    );
}

fn main() {
    set_enabled(false);
    let disabled = measure(&mut || drop(black_box(span(Stage::Preprocess))));

    set_enabled(true);
    let check = measure(&mut || {
        black_box(enabled());
    });
    let aggregate = measure(&mut || drop(black_box(span(Stage::Preprocess))));
    set_enabled(false);
    reset();

    let causal = measure_causal_span();

    enforce("disabled-span", disabled, DISABLED_SPAN_BUDGET_NS);
    enforce("enabled-check", check, ENABLED_CHECK_BUDGET_NS);
    enforce("aggregate-span", aggregate, AGGREGATE_SPAN_BUDGET_NS);
    enforce("causal-span", causal, CAUSAL_SPAN_BUDGET_NS);
}
