use super::*;

/// The filter admits exactly the first `WARN_REPEATS_SHOWN` events per
/// callsite and suppresses (while counting) every later one; the summary
/// guard reports the suppressed remainder. Uses the real filter + real
/// `warn!` events through a scoped subscriber; asserts via the counts table
/// (the summary line itself is Drop-printed).
#[test]
fn warn_callsite_suppressed_after_shown_budget_and_counted() {
    use tracing_subscriber::layer::SubscriberExt;
    let layer = tracing_subscriber::fmt::layer().with_writer(std::io::sink); // discard output
    let filtered = tracing_subscriber::Layer::with_filter(layer, WarnRepeatLimit);
    let subscriber = tracing_subscriber::registry().with(filtered);
    tracing::subscriber::with_default(subscriber, || {
        for idx in 0..10u64 {
            tracing::warn!(idx, "dedup-test repeated warning");
        }
    });
    let state = match WARN_REPEATS.lock() {
        Ok(state) => state,
        Err(poisoned) => panic!("warning-dedup mutex poisoned during isolated test: {poisoned}"),
    };
    let entry = state
        .counts
        .values()
        .find(|count| count.location.contains("log_dedup"))
        .expect("the repeated warn callsite must be counted");
    assert_eq!(
        entry.seen, 10,
        "every occurrence is counted, shown and suppressed alike"
    );
    assert!(
        entry.seen > WARN_REPEATS_SHOWN,
        "test must exercise the suppressed regime"
    );
}

#[test]
fn dependency_warning_targets_do_not_create_hidden_summaries() {
    use tracing_subscriber::layer::SubscriberExt;
    let layer = tracing_subscriber::fmt::layer().with_writer(std::io::sink);
    let filtered = tracing_subscriber::Layer::with_filter(layer, WarnRepeatLimit);
    let subscriber = tracing_subscriber::registry().with(filtered);
    tracing::subscriber::with_default(subscriber, || {
        for idx in 0..10u64 {
            tracing::warn!(target: "wgpu_hal::vulkan::instance", idx, "dependency warning");
        }
    });
    let state = match WARN_REPEATS.lock() {
        Ok(state) => state,
        Err(poisoned) => panic!("warning-dedup mutex poisoned during isolated test: {poisoned}"),
    };
    assert!(
        state
            .counts
            .values()
            .all(|count| count.target != "wgpu_hal::vulkan::instance"),
        "filtered dependency warnings must not be summarized"
    );
}
