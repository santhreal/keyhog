//! Bracket metacharacters escaped in prefix are literal.

use keyhog_scanner::compiler::is_escaped_literal;

#[test]
fn compiler_is_escaped_literal_bracket() {
    assert!(is_escaped_literal('['));
    assert!(is_escaped_literal(']'));
    assert!(!is_escaped_literal('a'));
}
