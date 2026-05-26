//! x/X-dominated strings ≥16 chars are placeholder masks.

use keyhog_scanner::context::is_known_example_credential;

#[test]
fn context_example_x_dominated_mask() {
    let mask = "xxxxxxxxxxxxxxxx";
    assert!(
        is_known_example_credential(mask),
        "all-x mask of length 16 must be example credential"
    );
    assert!(
        !is_known_example_credential(concat!("xox", "b-1234567890-abcd")),
        "Slack token shape must not match x-dominated heuristic"
    );
}
