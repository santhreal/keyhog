//! Contract gate: orchestrator defines EXIT_SCANNER_PANIC = 11.

use keyhog::exit_codes::EXIT_SCANNER_PANIC;

#[test]
fn orchestrator_defines_scanner_panic_exit_eleven() {
    assert_eq!(EXIT_SCANNER_PANIC, 11);
}
