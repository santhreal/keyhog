//! Contract gate: orchestrator defines EXIT_LIVE_CREDENTIALS = 10.

use keyhog::exit_codes::EXIT_LIVE_CREDENTIALS;

#[test]
fn orchestrator_defines_live_exit_ten() {
    assert_eq!(EXIT_LIVE_CREDENTIALS, 10);
}
