//! Gate `segment_attribution`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn engine_segment_attribution_no_unwrap_expect() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/segment_attribution.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let offenders = unwrap_expect_offenders(&src);
    assert!(
        offenders.is_empty(),
        "segment_attribution: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
