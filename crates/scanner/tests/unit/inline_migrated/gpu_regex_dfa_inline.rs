//! Migrated from src/engine/gpu_regex_dfa.rs
use keyhog_scanner::testing::extract_literal_core;

#[test]
fn extract_literal_core_simple() {
    assert_eq!(extract_literal_core("AKIA"), b"AKIA");
}

#[test]
fn extract_literal_core_with_class() {
    assert_eq!(extract_literal_core("AKIA[A-Z]{16}"), b"AKIA");
}

#[test]
fn extract_literal_core_pure_regex() {
    assert!(extract_literal_core("[a-z]+").is_empty());
}

#[test]
fn extract_literal_core_escaped() {
    assert_eq!(extract_literal_core(r"foo\.bar"), b"foo.bar");
}

#[test]
fn extract_literal_core_shorthand_stops() {
    assert_eq!(extract_literal_core(r"key\d+"), b"key");
}
