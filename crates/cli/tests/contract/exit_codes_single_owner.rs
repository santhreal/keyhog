//! Contract: exit-code numbers have one owner and scan-reachable outcomes do
//! not collide.

use keyhog::exit_codes::{
    DEFINITIONS, EXIT_REQUIRE_GPU_UNMET, EXIT_SOURCE_FAILED, EXIT_USER_ERROR, HELP,
};
use std::collections::BTreeMap;

#[test]
fn scan_reachable_exit_codes_are_unique() {
    let mut seen = BTreeMap::new();
    for definition in DEFINITIONS.iter().filter(|d| d.scan_reachable) {
        if let Some(previous) = seen.insert(definition.code, definition.label) {
            panic!(
                "scan-reachable exit code {} is reused by both {:?} and {:?}",
                definition.code, previous, definition.label
            );
        }
    }
}

#[test]
fn user_gpu_and_source_failures_have_distinct_codes() {
    assert_ne!(EXIT_USER_ERROR, EXIT_REQUIRE_GPU_UNMET);
    assert_ne!(EXIT_USER_ERROR, EXIT_SOURCE_FAILED);
    assert_ne!(EXIT_REQUIRE_GPU_UNMET, EXIT_SOURCE_FAILED);
}

#[test]
fn help_text_names_every_owned_exit_code() {
    for definition in DEFINITIONS {
        assert!(
            HELP.contains(&definition.code.to_string()),
            "exit help omits owned code {} ({})",
            definition.code,
            definition.label
        );
    }
}
