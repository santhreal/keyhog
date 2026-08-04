use keyhog_profile::{
    add_backend_dispatched_bytes, add_derived_decoder_bytes, add_input_bytes, add_input_units,
    Evidence, EvidenceGap, RunIdentity, RunState, Session, WorkloadIdentityInput,
    WorkloadIdentityV2,
};

fn capture(bytes: u64, units: u64) -> WorkloadIdentityV2 {
    WorkloadIdentityV2::capture(WorkloadIdentityInput {
        class: "filesystem",
        raw_source_bytes: bytes,
        source_units: units,
        container_bytes: None,
        expanded_payload_bytes: None,
        derived_decoder_bytes: Some(0),
        backend_dispatched_bytes: Some(bytes),
    })
}

fn recorded_text(evidence: &Evidence<String>) -> &str {
    match evidence {
        Evidence::Recorded { value } => value,
        Evidence::Unavailable { reason } => panic!("expected recorded text, got {reason:?}"),
    }
}

/// Exact byte boundaries must map to stable size classes so repeated profiles remain comparable.
#[test]
fn workload_size_buckets_cover_every_boundary_without_gaps() {
    for (bytes, expected) in [
        (0, "empty"),
        (1, "tiny"),
        (4_096, "tiny"),
        (4_097, "small"),
        (1_048_576, "small"),
        (1_048_577, "medium"),
        (67_108_864, "medium"),
        (67_108_865, "large"),
        (1_073_741_824, "large"),
        (1_073_741_825, "huge"),
    ] {
        assert_eq!(recorded_text(&capture(bytes, 1).size_bucket), expected);
    }
}

/// Exact source-unit boundaries must map to stable fanout classes used by benchmark pairing.
#[test]
fn workload_fanout_buckets_cover_every_boundary_without_gaps() {
    for (units, expected) in [
        (0, "empty"),
        (1, "single"),
        (2, "low"),
        (16, "low"),
        (17, "medium"),
        (1_024, "medium"),
        (1_025, "high"),
    ] {
        assert_eq!(recorded_text(&capture(1, units).fanout_bucket), expected);
    }
}

/// Uninstrumented expansion domains must remain unavailable while measured zeroes stay recorded.
#[test]
fn workload_identity_distinguishes_unavailable_domains_from_measured_zeroes() {
    let identity = capture(0, 0);

    assert_eq!(
        identity.container_bytes,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    );
    assert_eq!(identity.derived_decoder_bytes, Evidence::recorded(0));
    assert_eq!(identity.backend_dispatched_bytes, Evidence::recorded(0));
}

/// A profile session must aggregate decode and completed backend bytes independently from raw input.
#[test]
fn session_records_exact_workload_byte_domains() {
    let identity = RunIdentity::new(
        "0.5.50",
        "detectors",
        "config",
        "filesystem",
        "filesystem",
        "cpu",
    );
    let session = Session::start(identity).expect("start workload profile");
    add_input_bytes(100);
    add_input_units(2);
    add_derived_decoder_bytes(33);
    add_derived_decoder_bytes(7);
    add_backend_dispatched_bytes(100);
    let profile = session.finish(RunState::Completed);

    assert_eq!(profile.input_bytes, 100);
    assert_eq!(profile.input_units, 2);
    assert_eq!(profile.workload.container_bytes, None);
    assert_eq!(profile.workload.expanded_payload_bytes, None);
    assert_eq!(profile.workload.derived_decoder_bytes, Some(40));
    assert_eq!(profile.workload.backend_dispatched_bytes, Some(100));
}
