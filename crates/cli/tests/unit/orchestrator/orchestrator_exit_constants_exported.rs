use keyhog::orchestrator::{EXIT_LIVE_CREDENTIALS, EXIT_SCANNER_PANIC};

#[test]
fn orchestrator_exit_constants_exported() {
    assert_eq!(EXIT_LIVE_CREDENTIALS, 10);
    assert_eq!(EXIT_SCANNER_PANIC, 11);
}
