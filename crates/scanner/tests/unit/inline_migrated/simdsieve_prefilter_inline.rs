//! Migrated from src/simdsieve_prefilter.rs

use keyhog_scanner::testing::{
    HOT_PATTERN_DETECTOR_IDS, HOT_PATTERN_DISPLAY_NAMES, HOT_PATTERN_NAMES,
};

#[test]
fn detector_id_array_matches_names() {
    assert_eq!(HOT_PATTERN_NAMES.len(), HOT_PATTERN_DETECTOR_IDS.len());
    for (name, id) in HOT_PATTERN_NAMES.iter().zip(HOT_PATTERN_DETECTOR_IDS) {
        assert_eq!(format!("hot-{name}"), *id);
    }
}

#[test]
fn display_name_array_matches_names() {
    assert_eq!(HOT_PATTERN_NAMES.len(), HOT_PATTERN_DISPLAY_NAMES.len());
    for (name, display) in HOT_PATTERN_NAMES.iter().zip(HOT_PATTERN_DISPLAY_NAMES) {
        assert_eq!(format!("Hot Pattern: {name}"), *display);
    }
}
