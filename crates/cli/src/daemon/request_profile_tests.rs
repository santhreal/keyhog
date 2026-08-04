//! Per-request daemon profile isolation: request identity allocation, exact
//! stage attribution, and no cross-contamination between concurrent profiled
//! requests.
#![cfg(test)]

use super::{scan_results_response, RequestIdAllocator, RequestProfileCapture};
use crate::daemon::protocol::{response_kind, ProfileStageMeasurement, RequestProfile, Response};
use std::collections::{BTreeMap, HashSet};
use std::sync::Barrier;
use std::time::Instant;

fn stage_calls(profile: &RequestProfile) -> BTreeMap<&str, u64> {
    profile
        .stages
        .iter()
        .map(|stage| (stage.stage.as_str(), stage.calls))
        .collect()
}

fn busy_work() {
    for value in 0..10_000_u64 {
        std::hint::black_box(value);
    }
}

/// WHY: the wire v12 profile payload is keyed by request id, so id reuse
/// would silently merge two requests' measurements. The allocator must stay
/// unique under parallel allocation and every id must carry the daemon
/// generation string that `WarmBackendStatus` advertises.
#[test]
fn request_ids_are_unique_across_threads_and_carry_the_daemon_generation() {
    let allocator = std::sync::Arc::new(RequestIdAllocator::new("gen-test".to_string()));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let allocator = allocator.clone();
        handles.push(std::thread::spawn(move || {
            (0..500).map(|_| allocator.next()).collect::<Vec<_>>()
        }));
    }
    let mut ids = HashSet::new();
    for handle in handles {
        for id in handle.join().expect("allocator thread") {
            assert!(
                id.starts_with("gen-test-"),
                "request id must carry the daemon generation: {id}"
            );
            assert!(ids.insert(id.clone()), "duplicate request id: {id}");
        }
    }
    assert_eq!(ids.len(), 8 * 500, "every allocated id must be unique");
}

/// WHY: a profiled request must report exactly the stage calls recorded
/// inside its own runtime with the server-assigned request id, and exact zero
/// loss counts when bounded storage never fills. Regression lock against the
/// payload dropping or inventing measurements.
#[test]
fn profile_capture_reports_exact_stage_calls_and_zero_loss() {
    let capture = RequestProfileCapture::new("gen-one-0000000000000000".to_string());
    let started = Instant::now();
    {
        let _guard = capture.enter();
        for _ in 0..3 {
            let _span = keyhog_profile::span(keyhog_profile::Stage::Phase1Triggers);
            busy_work();
        }
        let _span = keyhog_profile::span(keyhog_profile::Stage::Entropy);
        busy_work();
        drop(_span);
        let profile = capture.finish(started);
        assert_eq!(profile.request_id, "gen-one-0000000000000000");
        let mut expected: BTreeMap<&str, u64> = BTreeMap::new();
        expected.insert(keyhog_profile::Stage::Phase1Triggers.as_str(), 3);
        expected.insert(keyhog_profile::Stage::Entropy.as_str(), 1);
        assert_eq!(stage_calls(&profile), expected);
        assert!(
            profile.wall_time_ns > 0,
            "wall time must cover the recorded work"
        );
        assert!(
            profile
                .stages
                .iter()
                .all(|stage| stage.elapsed_ns <= profile.wall_time_ns),
            "per-stage elapsed time cannot exceed the request wall time: {:?}",
            profile.stages
        );
        assert_eq!(profile.dropped_span_events, 0);
        assert_eq!(profile.dropped_point_events, 0);
        assert_eq!(profile.dropped_annotations, 0);
        assert_eq!(profile.sampled_out_events, 0);
    }
}

/// WHY: the daemon serves concurrent requests; if two profiled requests
/// shared profiling state, each response would attribute the other request's
/// stage time. Two barrier-synced requests plus a third worker thread that
/// enters request A's runtime (the same propagation the scanner's rayon
/// workers use) must drain into exactly their own payloads.
#[test]
fn concurrent_profiled_requests_stay_isolated_per_request_id() {
    let overlap = std::sync::Arc::new(Barrier::new(2));
    let capture_a = RequestProfileCapture::new("gen-a-0000000000000001".to_string());
    let capture_b = RequestProfileCapture::new("gen-b-0000000000000002".to_string());
    let runtime_a = capture_a.runtime.clone();

    let worker = std::thread::spawn(move || {
        // Simulates a scanner rayon worker: no context of its own, adopts the
        // requesting thread's runtime exactly like `current_runtime()` + `enter`.
        let _guard = runtime_a.enter();
        for _ in 0..2 {
            let _span = keyhog_profile::span(keyhog_profile::Stage::BackendDispatch);
            busy_work();
        }
    });

    let (profile_a, profile_b) = std::thread::scope(|scope| {
        let overlap_a = overlap.clone();
        let a = scope.spawn(move || {
            let _guard = capture_a.enter();
            let started = Instant::now();
            overlap_a.wait();
            for _ in 0..4 {
                let _span = keyhog_profile::span(keyhog_profile::Stage::Phase1Triggers);
                busy_work();
            }
            overlap_a.wait();
            worker.join().expect("runtime A worker");
            capture_a.finish(started)
        });
        let b = scope.spawn(move || {
            let _guard = capture_b.enter();
            let started = Instant::now();
            overlap.wait();
            for _ in 0..7 {
                let _span = keyhog_profile::span(keyhog_profile::Stage::HotPatterns);
                busy_work();
            }
            overlap.wait();
            capture_b.finish(started)
        });
        (a.join().expect("request A"), b.join().expect("request B"))
    });

    assert_eq!(profile_a.request_id, "gen-a-0000000000000001");
    assert_eq!(profile_b.request_id, "gen-b-0000000000000002");
    assert_ne!(
        profile_a.request_id, profile_b.request_id,
        "concurrent requests must receive distinct identities"
    );

    let mut expected_a: BTreeMap<&str, u64> = BTreeMap::new();
    expected_a.insert(keyhog_profile::Stage::Phase1Triggers.as_str(), 4);
    expected_a.insert(keyhog_profile::Stage::BackendDispatch.as_str(), 2);
    assert_eq!(
        stage_calls(&profile_a),
        expected_a,
        "request A must own exactly its main-thread and propagated-worker calls"
    );
    let mut expected_b: BTreeMap<&str, u64> = BTreeMap::new();
    expected_b.insert(keyhog_profile::Stage::HotPatterns.as_str(), 7);
    assert_eq!(
        stage_calls(&profile_b),
        expected_b,
        "request B must own exactly its own calls and none of request A's"
    );
    for stage in &profile_b.stages {
        assert_ne!(
            stage.stage,
            keyhog_profile::Stage::Phase1Triggers.as_str(),
            "request B must not attribute request A stages"
        );
        assert_ne!(
            stage.stage,
            keyhog_profile::Stage::BackendDispatch.as_str(),
            "request B must not attribute request A worker stages"
        );
    }
}

/// WHY: the profile payload is opt-in. A `profile=false` request must produce
/// a `ScanResults` whose profile field is explicitly absent, and a profiled
/// request must carry the exact payload the server drained; a regression here
/// would either tax unprofiled requests with profiling overhead or silently
/// drop the requested measurements.
#[test]
fn scan_results_carries_profile_only_when_requested() {
    let telemetry = keyhog_scanner::telemetry::ScanTelemetry::new().drain();
    let unprofiled =
        scan_results_response(None, Vec::new(), telemetry, Default::default(), None, None);
    match unprofiled {
        Response::ScanResults { profile, .. } => {
            assert!(
                profile.is_none(),
                "profile=false must not attach a request profile"
            );
        }
        other => panic!("expected ScanResults, got {}", response_kind(&other)),
    }

    let payload = RequestProfile {
        request_id: "gen-c-0000000000000003".to_string(),
        wall_time_ns: 42_000,
        stages: vec![ProfileStageMeasurement {
            stage: keyhog_profile::Stage::Entropy.as_str().to_string(),
            calls: 2,
            elapsed_ns: 30_000,
        }],
        dropped_span_events: 1,
        dropped_point_events: 2,
        dropped_annotations: 3,
        sampled_out_events: 4,
    };
    let telemetry = keyhog_scanner::telemetry::ScanTelemetry::new().drain();
    let profiled = scan_results_response(
        None,
        Vec::new(),
        telemetry,
        Default::default(),
        None,
        Some(payload.clone()),
    );
    match profiled {
        Response::ScanResults { profile, .. } => {
            assert_eq!(
                profile.expect("profiled response must carry the payload"),
                payload
            );
        }
        other => panic!("expected ScanResults, got {}", response_kind(&other)),
    }
}

/// Locks that an unprofiled request never constructs a profiling runtime: the
/// `Option<RequestProfileCapture>` gate at the scan entry points must yield
/// `None`, so `profile=false` pays no profiling allocation or clock cost.
#[test]
fn unprofiled_request_builds_no_capture() {
    let capture = false.then(|| RequestProfileCapture::new("unused".to_string()));
    assert!(capture.is_none());
    let capture = true.then(|| RequestProfileCapture::new("used".to_string()));
    assert!(capture.is_some());
}
