//! Gate `ml_scorer`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn ml_scorer_no_unwrap_expect() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ml_scorer.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let offenders = unwrap_expect_offenders(&src);
    assert!(
        offenders.is_empty(),
        "ml_scorer: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
