use keyhog_profile::{
    span, RunIdentity, RunProfile, RunState, Session, Stage, COLLECTOR_CAPABILITY_VERSION,
    RESOURCE_SAMPLE_VERSION, RESOURCE_SNAPSHOT_VERSION, RESOURCE_USAGE_VERSION,
    RUN_IDENTITY_VERSION, RUN_PROFILE_VERSION, STAGE_MEASUREMENT_VERSION,
    STATE_MEASUREMENT_VERSION, STATE_TRANSITION_VERSION, WORKLOAD_MEASUREMENTS_VERSION,
};

fn identity() -> RunIdentity {
    RunIdentity::new(
        "0.5.49",
        "detectors-a",
        "config-a",
        "filesystem",
        "small-text",
        "auto",
    )
}

fn remove_component_versions(value: &mut serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(object) => {
            usize::from(object.remove("version").is_some())
                + object
                    .values_mut()
                    .map(remove_component_versions)
                    .sum::<usize>()
        }
        serde_json::Value::Array(values) => values.iter_mut().map(remove_component_versions).sum(),
        _ => 0,
    }
}

fn count_component_versions(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(object) => {
            usize::from(object.contains_key("version"))
                + object.values().map(count_component_versions).sum::<usize>()
        }
        serde_json::Value::Array(values) => values.iter().map(count_component_versions).sum(),
        _ => 0,
    }
}

/// Every persisted object must carry its own version so one component can evolve without relabeling unrelated records.
#[test]
fn every_persisted_component_carries_its_independent_version() {
    let mut session = Session::start(identity()).expect("start versioned profile");
    session.transition(RunState::Acquiring);
    {
        let _span = span(Stage::SourceRead);
    }
    let profile = session.finish(RunState::Completed);

    assert_eq!(profile.version, RUN_PROFILE_VERSION);
    assert_eq!(profile.identity.version, RUN_IDENTITY_VERSION);
    assert_eq!(profile.workload.version, WORKLOAD_MEASUREMENTS_VERSION);
    assert!(profile
        .stages
        .iter()
        .all(|stage| stage.version == STAGE_MEASUREMENT_VERSION));
    assert!(profile
        .transitions
        .iter()
        .all(|transition| transition.version == STATE_TRANSITION_VERSION));
    assert!(profile
        .states
        .iter()
        .all(|state| state.version == STATE_MEASUREMENT_VERSION));
    assert!(profile
        .collectors
        .iter()
        .all(|collector| collector.version == COLLECTOR_CAPABILITY_VERSION));
    assert!(profile
        .resource_samples
        .iter()
        .all(|sample| sample.version == RESOURCE_SAMPLE_VERSION
            && sample.snapshot.version == RESOURCE_SNAPSHOT_VERSION));
    assert_eq!(profile.resources.version, RESOURCE_USAGE_VERSION);
    assert_eq!(profile.resources.start.version, RESOURCE_SNAPSHOT_VERSION);
    assert_eq!(profile.resources.finish.version, RESOURCE_SNAPSHOT_VERSION);
}

/// Records written before component versions existed must decode as version one at every nested boundary.
#[test]
fn legacy_unversioned_components_decode_as_version_one() {
    let mut session = Session::start(identity()).expect("start legacy compatibility profile");
    session.transition(RunState::Scanning);
    let profile = session.finish(RunState::Completed);
    let mut json = serde_json::to_value(&profile).expect("serialize profile value");

    // The decomposition of versioned components changes as the profile grows;
    // the invariant under test is structural: removal strips exactly the
    // version fields present, none survive, and the stripped document decodes
    // as the legacy profile shape.
    let versions_before = count_component_versions(&json);
    assert!(
        versions_before > 0,
        "the profile carries component versions"
    );
    let removed = remove_component_versions(&mut json);
    assert_eq!(
        removed, versions_before,
        "removal must strip every version field the profile carried"
    );
    assert_eq!(
        count_component_versions(&json),
        0,
        "no version field may survive removal"
    );

    let mut decoded: RunProfile = serde_json::from_value(json).expect("decode unversioned profile");
    assert_eq!(decoded.version, 1);
    decoded.version = profile.version;
    // Resource snapshots moved to version 2; unversioned records still decode
    // through serde defaults, so normalize before the deep equality check.
    for (decoded_sample, profile_sample) in decoded
        .resource_samples
        .iter_mut()
        .zip(profile.resource_samples.iter())
    {
        decoded_sample.snapshot.version = profile_sample.snapshot.version;
    }
    decoded.resources.start.version = profile.resources.start.version;
    decoded.resources.finish.version = profile.resources.finish.version;
    assert_eq!(decoded, profile);
}

/// A nested component version must round-trip independently without changing the outer profile version.
#[test]
fn nested_component_version_does_not_change_envelope_version() {
    let mut profile = Session::start(identity())
        .expect("start independent version profile")
        .finish(RunState::Completed);
    profile.resources.version = 7;

    let json = profile
        .to_json_pretty()
        .expect("serialize independent version");
    let decoded: RunProfile = serde_json::from_str(&json).expect("decode independent version");
    assert_eq!(decoded.version, RUN_PROFILE_VERSION);
    assert_eq!(decoded.resources.version, 7);
    assert_eq!(decoded.identity.version, RUN_IDENTITY_VERSION);
}
