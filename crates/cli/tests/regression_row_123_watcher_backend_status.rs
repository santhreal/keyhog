//! WHY: Closes the defect class where filesystem watcher backend selection was chosen at
//! runtime and never reported, leaving operators unable to tell whether the guard is running
//! natively (inotify/fsevent/kqueue/read-directory-changes), polling at an interval, or unmonitored (Row 123).
//!
//! What this does NOT catch: OS kernel dropping inotify/FSEvent events due to global memory pressure.

use keyhog::daemon::guard_watcher::{GuardWatcher, GuardWatcherBackendKind};
use keyhog_sources::guard::GuardReconciliationConfig;
use notify::Watcher;
use std::time::Duration;

#[test]
fn row_123_all_watcher_kinds_classified_with_declared_latency_bounds() {
    let notify_kinds = [
        notify::WatcherKind::Inotify,
        notify::WatcherKind::Fsevent,
        notify::WatcherKind::Kqueue,
        notify::WatcherKind::ReadDirectoryChangesWatcher,
        notify::WatcherKind::PollWatcher,
        notify::WatcherKind::NullWatcher,
    ];

    for notify_kind in notify_kinds {
        let classified = GuardWatcherBackendKind::from_notify_kind(notify_kind);
        assert!(
            !classified.label().is_empty(),
            "classified label must not be empty for {notify_kind:?}"
        );
        assert!(
            !classified.latency_tier().is_empty(),
            "classified latency tier must not be empty for {notify_kind:?}"
        );
        let _bound = classified.expected_latency_bound_ms();
    }

    for kind in GuardWatcherBackendKind::all_kinds() {
        assert!(!kind.label().is_empty());
        assert!(!kind.latency_tier().is_empty());
        match kind {
            GuardWatcherBackendKind::Inotify => {
                assert!(kind.is_native());
                assert_eq!(kind.label(), "inotify");
                assert_eq!(kind.latency_tier(), "sub-millisecond");
                assert_eq!(kind.expected_latency_bound_ms(), 50);
            }
            GuardWatcherBackendKind::Fsevent => {
                assert!(kind.is_native());
                assert_eq!(kind.label(), "fsevent");
                assert_eq!(kind.latency_tier(), "event-driven");
                assert_eq!(kind.expected_latency_bound_ms(), 250);
            }
            GuardWatcherBackendKind::Kqueue => {
                assert!(kind.is_native());
                assert_eq!(kind.label(), "kqueue");
                assert_eq!(kind.latency_tier(), "sub-millisecond");
                assert_eq!(kind.expected_latency_bound_ms(), 50);
            }
            GuardWatcherBackendKind::ReadDirectoryChangesWatcher => {
                assert!(kind.is_native());
                assert_eq!(kind.label(), "read-directory-changes");
                assert_eq!(kind.latency_tier(), "event-driven");
                assert_eq!(kind.expected_latency_bound_ms(), 250);
            }
            GuardWatcherBackendKind::PollWatcher => {
                assert!(!kind.is_native());
                assert_eq!(kind.label(), "poll");
                assert_eq!(kind.latency_tier(), "polling");
                assert_eq!(kind.expected_latency_bound_ms(), 30_000);
            }
            GuardWatcherBackendKind::NullWatcher => {
                assert!(!kind.is_native());
                assert_eq!(kind.label(), "null");
                assert_eq!(kind.latency_tier(), "unmonitored");
                assert_eq!(kind.expected_latency_bound_ms(), 0);
            }
            GuardWatcherBackendKind::Disabled => {
                assert!(!kind.is_native());
                assert_eq!(kind.label(), "disabled");
                assert_eq!(kind.latency_tier(), "unmonitored");
                assert_eq!(kind.expected_latency_bound_ms(), 0);
            }
            GuardWatcherBackendKind::CustomTest => {
                assert!(!kind.is_native());
                assert_eq!(kind.label(), "channel-test");
                assert_eq!(kind.latency_tier(), "in-memory");
                assert_eq!(kind.expected_latency_bound_ms(), 10);
            }
        }
    }
}

#[test]
fn row_123_recommended_watcher_reports_native_or_platform_fallback() {
    let config = GuardReconciliationConfig::default();
    let watcher = GuardWatcher::new(config).expect("create recommended watcher");
    let expected_notify_kind = notify::RecommendedWatcher::kind();
    let expected_backend = GuardWatcherBackendKind::from_notify_kind(expected_notify_kind);

    assert_eq!(watcher.backend_kind(), expected_backend);
    assert_eq!(watcher.backend_label(), expected_backend.label());
    assert_eq!(watcher.latency_tier(), expected_backend.latency_tier());
    if expected_backend == GuardWatcherBackendKind::PollWatcher {
        assert!(watcher.poll_interval_ms().is_some());
    } else {
        assert_eq!(watcher.poll_interval_ms(), None);
    }
}

#[test]
fn row_123_forced_polling_watcher_reports_interval_and_polling_tier() {
    let config = GuardReconciliationConfig::default();
    let interval = Duration::from_millis(750);
    let watcher = GuardWatcher::new_polling(config, interval).expect("create polling watcher");

    assert_eq!(watcher.backend_kind(), GuardWatcherBackendKind::PollWatcher);
    assert_eq!(watcher.backend_label(), "poll");
    assert_eq!(watcher.latency_tier(), "polling");
    assert_eq!(watcher.poll_interval_ms(), Some(750));
}

#[test]
fn row_123_null_watcher_reports_null_unmonitored() {
    let config = GuardReconciliationConfig::default();
    let watcher = GuardWatcher::new_null(config).expect("create null watcher");

    assert_eq!(watcher.backend_kind(), GuardWatcherBackendKind::NullWatcher);
    assert_eq!(watcher.backend_label(), "null");
    assert_eq!(watcher.latency_tier(), "unmonitored");
    assert_eq!(watcher.poll_interval_ms(), None);
}

#[test]
fn row_123_disabled_watcher_reports_disabled_unmonitored() {
    let watcher = GuardWatcher::new_disabled();

    assert_eq!(watcher.backend_kind(), GuardWatcherBackendKind::Disabled);
    assert_eq!(watcher.backend_label(), "disabled");
    assert_eq!(watcher.latency_tier(), "unmonitored");
    assert_eq!(watcher.poll_interval_ms(), None);
}

#[test]
fn row_123_custom_channel_watcher_reports_in_memory_simulation() {
    let config = GuardReconciliationConfig::default();
    let (watcher, _tx) = GuardWatcher::new_with_channel(config);

    assert_eq!(watcher.backend_kind(), GuardWatcherBackendKind::CustomTest);
    assert_eq!(watcher.backend_label(), "channel-test");
    assert_eq!(watcher.latency_tier(), "in-memory");
    assert_eq!(watcher.poll_interval_ms(), None);
}
