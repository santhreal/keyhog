//! LR1-A8 replacement gate: `oob/client.rs` protocol enum distinctness.

use keyhog_verifier::oob::InteractionProtocol;

#[test]
fn oob_protocol_http_and_dns_are_distinct() {
    assert_ne!(InteractionProtocol::Http, InteractionProtocol::Dns);
}
