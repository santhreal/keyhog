use keyhog_scanner::testing::{
    detector_plan_fixture_for_test, reset_detector_plan_ownership_telemetry_for_test,
    stream_detector_plan_for_test,
};

fn fixture() -> (Vec<u8>, [u8; 32]) {
    detector_plan_fixture_for_test(&["a-plan", "b-plan"]).expect("compile detector plan")
}

fn replace_once(bytes: &mut [u8], old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len());
    let offset = bytes
        .windows(old.len())
        .position(|window| window == old)
        .expect("fixture contains field");
    bytes[offset..offset + old.len()].copy_from_slice(new);
}

/// WHY: detector-plan hydration must preserve canonical detector order while
/// retaining at most one deserialized wire row at a time, and bind every row to
/// the exact DetectorIr digest that produced it.
#[test]
fn detector_plan_round_trip_streams_one_canonical_row_at_a_time() {
    let (section, digest) = fixture();
    reset_detector_plan_ownership_telemetry_for_test();
    let snapshot = stream_detector_plan_for_test(&section, digest).expect("decode");

    assert_eq!(snapshot.detector_ir_digest, digest);
    assert_eq!(snapshot.detector_count, 2);
    assert_eq!(snapshot.ids, ["a-plan", "b-plan"]);
    assert_eq!(snapshot.live_wire_rows, 0);
    assert_eq!(snapshot.peak_live_wire_rows, 1);

    let mut wrong_digest = digest;
    wrong_digest[0] ^= 0xff;
    assert!(stream_detector_plan_for_test(&section, wrong_digest)
        .expect_err("DetectorIr digest drift must fail")
        .contains("another DetectorIr digest"));
}

/// WHY: every framing, identity, payload-integrity, truncation, and exact-length
/// boundary must fail closed so a corrupted installed plan cannot hydrate into
/// a different detector execution contract.
#[test]
fn detector_plan_rejects_stale_semantic_schema_framing_identity_and_trailing_corruption() {
    let (section, digest) = fixture();

    let mut version = section.clone();
    version[8..10].copy_from_slice(&2u16.to_le_bytes());
    assert!(stream_detector_plan_for_test(&version, digest)
        .expect_err("legacy detector-plan version must fail closed")
        .contains("version 2"));

    let mut count = section.clone();
    count[140..144].copy_from_slice(&9u32.to_le_bytes());
    assert!(stream_detector_plan_for_test(&count, digest)
        .expect_err("count drift must fail")
        .contains("truncated"));

    let mut order = section.clone();
    replace_once(&mut order, b"\"id\":\"a-plan\"", b"\"id\":\"z-plan\"");
    assert!(stream_detector_plan_for_test(&order, digest)
        .expect_err("order drift must fail")
        .contains("noncanonical"));

    let mut compiled_digest = section.clone();
    compiled_digest[44] ^= 0xff;
    assert!(stream_detector_plan_for_test(&compiled_digest, digest)
        .expect_err("compiled digest corruption must fail")
        .contains("payload digest"));

    let truncated = &section[..section.len() - 1];
    assert!(stream_detector_plan_for_test(truncated, digest)
        .expect_err("truncation must fail")
        .contains("truncated"));

    let mut trailing = section;
    trailing.push(0);
    assert!(stream_detector_plan_for_test(&trailing, digest)
        .expect_err("trailing bytes must fail")
        .contains("trailing"));
}
