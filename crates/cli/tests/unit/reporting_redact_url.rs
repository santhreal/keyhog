//! `redact_url_target`, relocated out of `crate::reporting` (the
//! `reporting_no_inline_tests` gate forbids inline `#[cfg(test)]`). Reached
//! through the `crate::testing` facade.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn url_targets_hide_queries_and_fragments() {
    assert_eq!(
        API.redact_url_target("https://example.com/app.js?token=secret#frag"),
        "https://example.com/app.js?<redacted>"
    );
    assert_eq!(
        API.redact_url_target("https://example.com/app.js#frag"),
        "https://example.com/app.js"
    );
}
