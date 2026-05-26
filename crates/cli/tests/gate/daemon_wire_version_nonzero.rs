//! LR1-A8 replacement gate: `daemon/protocol.rs` wire version contract.

use keyhog::daemon::protocol::WIRE_VERSION;

#[test]
fn wire_version_is_positive_protocol_number() {
    assert!(
        WIRE_VERSION >= 1,
        "daemon wire protocol version must be >= 1, got {WIRE_VERSION}"
    );
}
