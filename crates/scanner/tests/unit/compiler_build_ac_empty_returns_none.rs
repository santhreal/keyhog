//! Empty literal list yields None AC automaton.

use keyhog_scanner::compiler::build_ac_pattern_set;

#[test]
fn compiler_build_ac_empty_returns_none() {
    assert!(
        build_ac_pattern_set(&[]).unwrap().is_none(),
        "empty literal list must not build AC"
    );
}
