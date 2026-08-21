use super::*;

/// WHY: the three watcher fields are `#[serde(default)]` so a status frame
/// from a daemon built before them still parses. The payload below carries
/// every field the wire format REQUIRES and omits exactly those three; a
/// later field added without a default turns this red, which is the
/// decision point for whether the wire version has to move.
#[test]
fn test_row_123_guard_status_result_backward_compatibility() {
    let legacy_json = serde_json::json!({
        "kind": "guard_status_result",
        "root": "/srv/repo",
        "mode": "repo",
        "state": "guarded",
        "filesystem_type": "ext4",
        "filesystem_authoritative": true,
        "filesystem_unauthoritative_reason": serde_json::Value::Null,
        "scrub_interval_secs": 900u64,
        "terminal_sequence": 12u64,
        "accepted_event_sequence": 12u64,
        "completed_event_sequence": 12u64,
        "pending_events": 0u64,
        "files_scanned": 41u64,
        "bytes_scanned": 8192u64,
        "attestation_hits": 40u64,
        "attestation_misses": 1u64,
        "findings_count": 0u64,
        "coverage_gaps": 0u64,
        "initial_reconciliation_time": 1700000000u64,
        "last_reconciliation_time": 1700000010u64,
        "scanner_residency": "resident",
        "backend_route_label": "simd",
        "build_identity_short": "abc12345",
        "detector_digest_short": "1234567890ab",
        "suppression_digest_short": "1234567890ab",
        "config_digest_short": "1234567890ab",
        "autoroute_evidence_status": "present",
        "store_schema_version": 1u32,
        "store_path": "/var/lib/keyhog/guard.db",
        "repair_command": "keyhog guard reconcile /srv/repo"
    });

    let parsed: Result<Response, _> = serde_json::from_value(legacy_json);
    assert!(
        parsed.is_ok(),
        "legacy payload without watcher fields must parse: {parsed:?}"
    );
    match parsed {
        Ok(Response::GuardStatusResult {
            watcher_backend,
            watcher_latency_tier,
            watcher_poll_interval_ms,
            ..
        }) => {
            assert_eq!(watcher_backend, "");
            assert_eq!(watcher_latency_tier, "");
            assert_eq!(watcher_poll_interval_ms, None);
        }
        _ => panic!("expected GuardStatusResult response"),
    }
}
