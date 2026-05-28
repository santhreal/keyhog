//! R5-T property: parse_verify_rate accepts 10000 rps cap boundary.

use keyhog::value_parsers::parse_verify_rate;

#[test]
fn r5t_parse_verify_rate_accepts_ten_thousand_boundary() {
    let parsed = parse_verify_rate("10000").expect("cap boundary must parse");
    assert!((parsed - 10000.0).abs() < f64::EPSILON);
}
