use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator_config::build_scanner_config;

#[test]
fn build_scanner_config_fast_mode() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--fast"]).unwrap();
    let cfg = build_scanner_config(&args);
    assert!(!cfg.entropy_enabled, "--fast must disable entropy");
    assert!(!cfg.ml_enabled, "--fast must disable ML");
    assert_eq!(
        cfg.max_decode_depth, 0,
        "--fast must disable decode-through"
    );
}
