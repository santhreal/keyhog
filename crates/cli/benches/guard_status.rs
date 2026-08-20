use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
#[cfg(unix)]
use keyhog::testing::daemon::protocol::{
    deserialize_status_request, deserialize_status_response, response_kind_classification,
    sample_guard_status_result_frame, serialize_status_request, serialize_status_response,
};
#[cfg(unix)]
use keyhog::testing::daemon::GuardRuntime;
#[cfg(unix)]
use keyhog_core::guard_state::{FilesystemIdentity, GuardRootMode};
use keyhog_core::guard_state::{GuardPolicyIdentity, GuardRootState, GuardTransition};
use std::hint::black_box;

#[cfg(unix)]
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
    let mut group = c.benchmark_group("guard_protocol_framing");
    let status_root = "/var/repos/service-backend";
    let status_resp_frame = sample_guard_status_result_frame(status_root);

    group.bench_function("serialize_request_guard_status", |b| {
        b.iter(|| {
            let json = serialize_status_request(black_box(status_root));
            let _ = black_box(json);
        });
    });

    group.bench_function("deserialize_request_guard_status", |b| {
        let json = serialize_status_request(status_root);
        b.iter(|| {
            let req = deserialize_status_request(black_box(&json)).expect("deserialize");
            let _ = black_box(req);
        });
    });

    group.bench_function("serialize_response_guard_status", |b| {
        b.iter(|| {
            let json = serialize_status_response(black_box(&status_resp_frame));
            let _ = black_box(json);
        });
    });

    group.bench_function("deserialize_response_guard_status", |b| {
        let json = serialize_status_response(&status_resp_frame);
        b.iter(|| {
            let resp = deserialize_status_response(black_box(&json)).expect("deserialize");
            let _ = black_box(resp);
        });
    });

    group.bench_function("response_kind_classification", |b| {
        b.iter(|| {
            let kind = response_kind_classification(black_box(&status_resp_frame));
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
                .expect("fs event");
            state = state
                .transition(&GuardTransition::EventsClean)
                .expect("reconcile clean");
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

#[cfg(unix)]
criterion_group!(
    benches,
    bench_guard_protocol_framing,
    bench_guard_runtime_status_lookup,
    bench_guard_state_transitions,
);

#[cfg(not(unix))]
criterion_group!(benches, bench_guard_state_transitions);

criterion_main!(benches);
