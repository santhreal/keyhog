use keyhog_profile::{
    record_batch_route, BatchRouteV2, Evidence, EvidenceGap, RouteIdentityV2, RunIdentity,
    RunState, Session, MAX_BATCH_ROUTES,
};

fn batch(
    sequence: u64,
    requested: &str,
    selected: &str,
    completed: &str,
    recovered_from: Option<&str>,
) -> BatchRouteV2 {
    BatchRouteV2 {
        version: 1,
        batch_sequence: sequence,
        workload_key_digest: format!("workload-{sequence}"),
        requested_backend: requested.to_owned(),
        selected_backend: selected.to_owned(),
        completed_backend: completed.to_owned(),
        recovered_from_backend: recovered_from.map_or_else(
            || Evidence::unavailable(EvidenceGap::Unavailable),
            |backend| Evidence::recorded(backend.to_owned()),
        ),
    }
}

/// A completed recovery must retain both the failed selected route and the backend that produced the findings.
#[test]
fn recovered_batch_preserves_requested_selected_completed_and_failed_routes() {
    let route = RouteIdentityV2::from_recorded_batches(
        "auto".to_owned(),
        vec![batch(0, "auto", "gpu-cuda", "simd", Some("gpu-cuda"))],
    );

    assert_eq!(route.request_mode, "autoroute");
    assert_eq!(route.requested_backend, "auto");
    assert_eq!(
        route.selected_backend,
        Evidence::recorded("gpu-cuda".to_owned())
    );
    assert_eq!(
        route.completed_backend,
        Evidence::recorded("simd".to_owned())
    );
    assert_eq!(
        route.batches[0].recovered_from_backend,
        Evidence::recorded("gpu-cuda".to_owned())
    );
}

/// Per-batch evidence must remain exact when autoroute selects more than one backend in a run.
#[test]
fn mixed_routes_are_aggregated_without_erasing_exact_batch_evidence() {
    let route = RouteIdentityV2::from_recorded_batches(
        "auto".to_owned(),
        vec![
            batch(0, "auto", "simd", "simd", None),
            batch(1, "auto", "gpu-wgpu", "gpu-wgpu", None),
        ],
    );

    assert_eq!(
        route.selected_backend,
        Evidence::recorded("mixed".to_owned())
    );
    assert_eq!(
        route.completed_backend,
        Evidence::recorded("mixed".to_owned())
    );
    assert_eq!(route.batches[0].selected_backend, "simd");
    assert_eq!(route.batches[1].selected_backend, "gpu-wgpu");
}

/// An enabled session must assign unique monotonic sequence identities even when callers do not supply them.
#[test]
fn runtime_assigns_monotonic_batch_sequences_and_drains_once() {
    let identity = RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        "filesystem",
        "runtime-batches",
        "auto",
    );
    let session = Session::start(identity).expect("start route identity profile");

    record_batch_route("workload-b", "auto", "simd", "simd", None);
    record_batch_route("workload-a", "auto", "gpu-cuda", "simd", Some("gpu-cuda"));

    let runtime = session.runtime();
    let records = runtime.take_session_batch_routes();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].batch_sequence, 0);
    assert_eq!(records[0].workload_key_digest, "workload-b");
    assert_eq!(records[1].batch_sequence, 1);
    assert_eq!(records[1].completed_backend, "simd");
    assert!(runtime.take_session_batch_routes().is_empty());

    let _profile = session.finish(RunState::Completed);
}

/// A run that completes no backend batch must state that route evidence is unavailable rather than inventing a default.
#[test]
fn empty_route_set_keeps_selected_and_completed_evidence_unavailable() {
    let route = RouteIdentityV2::from_recorded_batches("cpu".to_owned(), Vec::new());

    assert_eq!(route.request_mode, "explicit");
    assert!(matches!(
        route.selected_backend,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
    assert!(matches!(
        route.completed_backend,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    ));
}

#[test]
fn batch_route_cap_counts_drops_instead_of_growing_unbounded() {
    let session = Session::start(RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        "batch-route-cap",
        "test",
        "auto",
    ))
    .expect("start");
    let runtime = session.runtime();

    for i in 0..(MAX_BATCH_ROUTES + 3) {
        record_batch_route(&format!("workload-{i}"), "auto", "simd", "simd", None);
    }

    let routes = runtime.take_session_batch_routes();
    let dropped = runtime.take_session_dropped_batch_routes();
    assert_eq!(routes.len(), MAX_BATCH_ROUTES);
    assert_eq!(dropped, 3);

    let identity =
        RouteIdentityV2::from_recorded_batches_with_drops("auto".into(), routes, dropped);
    assert_eq!(identity.dropped_batches, 3);
    assert_eq!(identity.batches.len(), MAX_BATCH_ROUTES);
}
