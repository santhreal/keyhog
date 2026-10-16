//! Gate `entropy::scanner`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn entropy_scanner_no_unwrap_expect() {
    for rel in ["/src/entropy/scanner.rs", "/src/entropy/scanner_policy.rs"] {
        let path = format!("{}{rel}", env!("CARGO_MANIFEST_DIR"));
        let src = std::fs::read_to_string(&path).expect("source readable");
        let offenders = unwrap_expect_offenders(&src);
        assert!(
            offenders.is_empty(),
            "entropy::scanner ({rel}): unwrap/expect in production source at {:?}",
            offenders.iter().take(5).collect::<Vec<_>>()
        );
    }
}
