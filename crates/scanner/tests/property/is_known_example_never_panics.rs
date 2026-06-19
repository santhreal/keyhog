//! is_known_example_credential must never panic on arbitrary strings.

use keyhog_scanner::testing::context::is_known_example_credential;
use proptest::prelude::*;

#[test]
fn is_known_example_never_panics() {
    proptest!(|(s: String)| {
        let _ = is_known_example_credential(&s);
    });
}
