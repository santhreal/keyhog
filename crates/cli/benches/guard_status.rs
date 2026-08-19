use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
#[cfg(unix)]
use keyhog::testing::daemon::fs_probe::probe_filesystem_authority;
#[cfg(unix)]
use keyhog::testing::daemon::guard_runtime::GuardRuntime;
#[cfg(unix)]
use keyhog::testing::daemon::protocol::{Request, Response};
use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GuardPolicyIdentity, GuardRootMode, GuardRootState,
    GuardTransition,
};
use std::hint::black_box;
use tempfile::tempdir;

fn sample_fs_identity(dev: u64, ino: u64) -> FilesystemIdentity {
    FilesystemIdentity {
        device: dev,
        inode: ino,
    }
}

/// WHY: Measures protocol frame serialization and deserialization latency for
/// guard status and control frames between the CLI client and guard daemon.
#[cfg(unix)]
fn bench_guard_protocol_framing(c: &mut Criterion) {
    use keyhog::testing::daemon::protocol::response_kind;

    let mut group = c.benchmark_group("guard_protocol_framing");

    let status_req = Request::GuardStatus {
        root: "/var/repos/service-backend".to_string(),
    };
    let status_resp = Response::GuardStatusResult {
        root: "/var/repos/service-backend".to_string(),
        mode: "repo".to_string(),
        state: "current".to_string(),
        filesystem_type: "ext4".to_string(),
        filesystem_authoritative: true,
        filesystem_unauthoritative_reason: None,
        scrub_interval_secs: 60,
        terminal_sequence: 42,
        accepted_event_sequence: 42,
        completed_event_sequence: 42,
        pending_events: 0,
        files_scanned: 1542,
        bytes_scanned: 1048576,
        attestation_hits: 1500,
        attestation_misses: 42,
        findings_count: 0,
        coverage_gaps: 0,
        initial_reconciliation_time: Some(1787140800),
        last_reconciliation_time: Some(1787140800),
        scanner_residency: "resident".to_string(),
        watcher_backend: "inotify".to_string(),
        watcher_latency_tier: "instant".to_string(),
        watcher_poll_interval_ms: None,
        backend_route_label: "cpu".to_string(),
        build_identity_short: "abc123456789".to_string(),
        detector_digest_short: "def123456789".to_string(),
        suppression_digest_short: String::new(),
        config_digest_short: "789123456789".to_string(),
        autoroute_evidence_status: "valid".to_string(),
        store_schema_version: 1,
        store_path: "/var/repos/.keyhog-guard.db".to_string(),
        repair_command: "keyhog guard reconcile /var/repos/service-backend".to_string(),
        recent_transitions: Vec::new(),
    };

    group.bench_function("serialize_request_guard_status", |b| {
        b.iter(|| {
            let json = serde_json::to_vec(black_box(&status_req)).expect("serialize");
            let _ = black_box(json);
        });
    });

    group.bench_function("deserialize_request_guard_status", |b| {
        let json = serde_json::to_vec(&status_req).expect("serialize");
        b.iter(|| {
            let req: Request = serde_json::from_slice(black_box(&json)).expect("deserialize");
            let _ = black_box(req);
        });
    });

    group.bench_function("serialize_response_guard_status", |b| {
        b.iter(|| {
            let json = serde_json::to_vec(black_box(&status_resp)).expect("serialize");
            let _ = black_box(json);
        });
    });

    group.bench_function("deserialize_response_guard_status", |b| {
        let json = serde_json::to_vec(&status_resp).expect("serialize");
        b.iter(|| {
            let resp: Response = serde_json::from_slice(black_box(&json)).expect("deserialize");
            let _ = black_box(resp);
        });
    });

    group.bench_function("response_kind_classification", |b| {
        b.iter(|| {
            let kind = response_kind(black_box(&status_resp));
            let _ = black_box(kind);
        });
    });

    group.finish();
}

/// WHY: Measures in-memory `GuardRuntime` lookup and status record synthesis
/// latency as the number of registered guard roots scales.
#[cfg(unix)]
fn bench_guard_runtime_status_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("guard_runtime_status_lookup");

    for &num_roots in &[1, 10, 50, 200] {
        let rt = GuardRuntime::new();
        for i in 0..num_roots {
            let root_path = format!("/srv/repos/repo_{i:04}").into_bytes();
            rt.add_root(
                root_path.clone(),
                sample_fs_identity(1, i as u64 + 1),
                FilesystemAuthority::authoritative("ext4"),
                GuardRootMode::Repo,
            )
            .expect("add root");
            rt.transition_root(&root_path, &GuardTransition::ReconciliationStarted)
                .expect("start");
            rt.transition_root(&root_path, &GuardTransition::ReconciliationClean)
                .expect("clean");
        }

        let target_root = format!("/srv/repos/repo_{:04}", num_roots / 2).into_bytes();

        group.bench_with_input(
            BenchmarkId::new("root_record_lookup", num_roots),
            &target_root,
            |b, root| {
                b.iter(|| {
                    let record = rt.root_record(black_box(root)).expect("record");
                    let _ = black_box(record);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("list_roots", num_roots),
            &num_roots,
            |b, _| {
                b.iter(|| {
                    let list = rt.list_roots();
                    let _ = black_box(list);
                });
            },
        );
    }

    group.finish();
}

/// WHY: Measures guard state machine transition throughput and validity checks
/// across root lifecycle events.
fn bench_guard_state_transitions(c: &mut Criterion) {
    let mut group = c.benchmark_group("guard_state_transitions");

    group.bench_function("valid_transition_cycle", |b| {
        b.iter(|| {
            let mut state = GuardRootState::Stopped;
            state = state
                .transition(&GuardTransition::ReconciliationStarted)
                .expect("reconcile start");
            state = state
                .transition(&GuardTransition::ReconciliationClean)
                .expect("reconcile clean");
            state = state
                .transition(&GuardTransition::EventAccepted)
                .expect("event accepted");
            state = state
                .transition(&GuardTransition::EventsClean)
                .expect("events clean");
            state = state.transition(&GuardTransition::Stopped).expect("stop");
            let _ = black_box(state);
        });
    });

    group.bench_function("policy_identity_digest_calculation", |b| {
        let policy = GuardPolicyIdentity {
            build_identity: "git:0.5.80".to_string(),
            detector_digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            suppression_digest: String::new(),
            keyhogignore_digest: String::new(),
            config_digest: "f4b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            decode_policy_version: 1,
            source_policy_digest: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            guard_schema_version: 1,
            report_semantics_version: 1,
        };

        b.iter(|| {
            let digest = policy.short_digest().expect("short digest");
            let _ = black_box(digest);
        });
    });

    group.finish();
}

/// WHY: Measures filesystem authority probing latency on directory roots.
#[cfg(unix)]
fn bench_filesystem_authority_probing(c: &mut Criterion) {
    let mut group = c.benchmark_group("filesystem_authority_probing");
    let dir = tempdir().expect("tempdir");

    group.bench_function("probe_local_tempdir_authority", |b| {
        b.iter(|| {
            let auth = probe_filesystem_authority(black_box(dir.path()));
            let _ = black_box(auth);
        });
    });

    group.finish();
}

#[cfg(unix)]
criterion_group!(
    benches,
    bench_guard_protocol_framing,
    bench_guard_runtime_status_lookup,
    bench_guard_state_transitions,
    bench_filesystem_authority_probing,
);

#[cfg(not(unix))]
criterion_group!(benches, bench_guard_state_transitions);

criterion_main!(benches);
