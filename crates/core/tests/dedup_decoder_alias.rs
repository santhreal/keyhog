use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

fn raw_match(source: &str, line: usize, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: "devcycle-api-credentials".into(),
        detector_name: "DevCycle API Credentials".into(),
        service: "devcycle".into(),
        severity: Severity::High,
        credential: "DVC_CTRL_REG3_SW_PROG".into(),
        credential_hash: [0; 32].into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: source.into(),
            file_path: Some("drivers/i2c/busses/i2c-tegra.c".into()),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.5),
    }
}

#[test]
fn dedup_prefers_original_location_over_nearby_decoder_alias() {
    let decoded = raw_match("filesystem/json", 613, 18999);
    let original = raw_match("filesystem", 612, 19000);

    let deduped = dedup_matches(vec![decoded, original], &DedupScope::Credential);

    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].primary_location.source.as_ref(), "filesystem");
    assert_eq!(deduped[0].primary_location.line, Some(612));
    assert_eq!(deduped[0].primary_location.offset, 19000);
    assert!(deduped[0].additional_locations.is_empty());
}

#[test]
fn dedup_keeps_nearby_decoder_match_when_known_lines_are_far_apart() {
    let decoded = raw_match("filesystem/json", 615, 19008);
    let original = raw_match("filesystem", 612, 19000);

    let deduped = dedup_matches(vec![decoded, original], &DedupScope::Credential);

    assert_eq!(
        deduped.len(),
        1,
        "same detector/credential still forms one reported finding"
    );
    assert_eq!(
        deduped[0].additional_locations.len(),
        1,
        "known line distance above one must not be collapsed as a decoder alias"
    );
    assert_eq!(deduped[0].additional_locations[0].line, Some(615));
}
