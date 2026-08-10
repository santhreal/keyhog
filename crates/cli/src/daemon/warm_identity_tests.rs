use super::protocol::{Response, WarmBackendIdentity, WarmBackendStatus};
use super::server::warm_route_error;
use super::warm_identity::{evaluate_status, validate_for_client};

fn identity() -> WarmBackendIdentity {
    WarmBackendIdentity {
        engine: "engine-a".into(),
        gpu_artifact: Some("gpu-a".into()),
        binary_sha256: "binary-a".into(),
        detector_rules_digest: "detectors-a".into(),
        config_digest: "config-a".into(),
    }
}

fn ready_status(generation: &str) -> WarmBackendStatus {
    let identity = identity();
    evaluate_status(
        generation.into(),
        identity.clone(),
        Ok(identity),
        vec!["gpu-wgpu".into()],
        vec!["gpu-wgpu".into()],
    )
}

/// Regression: an exact engine/binary/detector/config match accepts a daemon
/// whose server-side GPU artifact and required backend are both ready.
#[test]
fn matching_ready_identity_satisfies_client_and_server() {
    let status = ready_status("gen-a");
    let mut expected = identity();
    expected.gpu_artifact = None;
    assert!(status.ready);
    assert!(validate_for_client(&status, &expected).is_empty());
    assert!(warm_route_error(&status).is_none());
}

/// Regression: an old in-memory engine cannot claim readiness to a client
/// running a different autoroute engine feature identity.
#[test]
fn stale_engine_is_rejected_with_exact_identity_pair() {
    let status = ready_status("gen-a");
    let mut expected = identity();
    expected.engine = "engine-b".into();
    expected.gpu_artifact = None;
    assert_eq!(
        validate_for_client(&status, &expected),
        vec!["engine daemon=engine-a, client=engine-b"]
    );
}

/// Regression: replacing the acquired GPU artifact after warmup invalidates
/// readiness instead of replaying evidence for the old accelerator peer.
#[test]
fn replaced_gpu_artifact_invalidates_server_readiness() {
    let startup = identity();
    let mut current = startup.clone();
    current.gpu_artifact = Some("gpu-b".into());
    let status = evaluate_status(
        "gen-a".into(),
        startup,
        Ok(current),
        vec!["gpu-wgpu".into()],
        vec!["gpu-wgpu".into()],
    );
    assert!(!status.ready);
    assert_eq!(
        status.reason.as_deref(),
        Some("warm backend identity drift: GPU artifact expected=Some(\"gpu-a\") current=Some(\"gpu-b\")")
    );
    assert_eq!(
        status.repair_command.as_deref(),
        Some("keyhog daemon stop && keyhog daemon start")
    );
}

/// Regression: replacing the executable at the same package/Git version is
/// detected by the exact autoroute SHA-256 artifact identity.
#[test]
fn replaced_binary_artifact_is_rejected() {
    let status = ready_status("gen-a");
    let mut expected = identity();
    expected.binary_sha256 = "binary-b".into();
    expected.gpu_artifact = None;
    assert_eq!(
        validate_for_client(&status, &expected),
        vec!["binary artifact daemon=binary-a, client=binary-b"]
    );
}

/// Regression: detector and resolved-config drift are both surfaced, in stable
/// field order, so operators know whether to restart or recalibrate policy.
#[test]
fn detector_and_config_drift_are_both_actionable() {
    let status = ready_status("gen-a");
    let mut expected = identity();
    expected.detector_rules_digest = "detectors-b".into();
    expected.config_digest = "config-b".into();
    expected.gpu_artifact = None;
    assert_eq!(
        validate_for_client(&status, &expected),
        vec![
            "detector rules daemon=detectors-a, client=detectors-b",
            "resolved config daemon=config-a, client=config-b",
        ]
    );
}

/// Regression: publishing an identity before every selected backend retains an
/// initialized execution handle cannot accidentally satisfy warm readiness.
#[test]
fn partial_initialization_fails_closed_with_missing_backend() {
    let startup = identity();
    let status = evaluate_status(
        "gen-a".into(),
        startup.clone(),
        Ok(startup),
        vec!["gpu-wgpu".into(), "simd".into()],
        vec!["simd".into()],
    );
    assert_eq!(
        status,
        WarmBackendStatus {
            ready: false,
            daemon_generation: "gen-a".into(),
            identity: identity(),
            required_backends: vec!["gpu-wgpu".into(), "simd".into()],
            initialized_backends: vec!["simd".into()],
            reason: Some(
                "warm backend initialization incomplete: missing [gpu-wgpu] from required [gpu-wgpu,simd]"
                    .into(),
            ),
            repair_command: Some("keyhog daemon stop && keyhog daemon start".into()),
        }
    );
    assert_eq!(
        serde_json::to_string(&status).expect("serialize incomplete warm status"),
        "{\"ready\":false,\"daemon_generation\":\"gen-a\",\"identity\":{\"engine\":\"engine-a\",\"gpu_artifact\":\"gpu-a\",\"binary_sha256\":\"binary-a\",\"detector_rules_digest\":\"detectors-a\",\"config_digest\":\"config-a\"},\"required_backends\":[\"gpu-wgpu\",\"simd\"],\"initialized_backends\":[\"simd\"],\"reason\":\"warm backend initialization incomplete: missing [gpu-wgpu] from required [gpu-wgpu,simd]\",\"repair_command\":\"keyhog daemon stop && keyhog daemon start\"}"
    );
    match warm_route_error(&status) {
        Some(Response::Error { message }) => assert_eq!(
            message,
            "daemon warm route is not ready: warm backend initialization incomplete: missing [gpu-wgpu] from required [gpu-wgpu,simd]. Repair with `keyhog daemon stop && keyhog daemon start`."
        ),
        other => panic!("partial initialization must return an exact route denial, got {other:?}"),
    }
}

/// Regression: a restarted daemon publishes a new generation even when every
/// autoroute identity remains identical, preventing a cached readiness lease
/// from being mistaken for the new process.
#[test]
fn daemon_restart_changes_generation_without_changing_identity() {
    let before = ready_status("gen-before");
    let after = ready_status("gen-after");
    assert!(before.ready && after.ready);
    assert_eq!(before.identity, after.identity);
    assert_ne!(before.daemon_generation, after.daemon_generation);
}

/// Regression: the v7 status JSON is exact and includes every identity,
/// initialization list, and nullable actionable-status field.
#[test]
fn exact_ready_status_json_is_stable() {
    let response = Response::Health {
        uptime_secs: 12,
        scans_served: 3,
        active_scans: 1,
        detector_count: 923,
        backend_recoveries: 0,
        last_backend_fault: None,
        guard_roots_registered: 0,
        guard_roots_current: 0,
        guard_roots_blocked: 0,
        guard_roots_degraded: 0,
        guard_active_transactions: 0,
        warm_backend: ready_status("gen-a"),
    };
    let json = serde_json::to_string(&response).expect("serialize warm health status");
    assert_eq!(
        json,
        "{\"kind\":\"health\",\"uptime_secs\":12,\"scans_served\":3,\"active_scans\":1,\"detector_count\":923,\"backend_recoveries\":0,\"last_backend_fault\":null,\"guard_roots_registered\":0,\"guard_roots_current\":0,\"guard_roots_blocked\":0,\"guard_roots_degraded\":0,\"guard_active_transactions\":0,\"warm_backend\":{\"ready\":true,\"daemon_generation\":\"gen-a\",\"identity\":{\"engine\":\"engine-a\",\"gpu_artifact\":\"gpu-a\",\"binary_sha256\":\"binary-a\",\"detector_rules_digest\":\"detectors-a\",\"config_digest\":\"config-a\"},\"required_backends\":[\"gpu-wgpu\"],\"initialized_backends\":[\"gpu-wgpu\"],\"reason\":null,\"repair_command\":null}}"
    );
}
