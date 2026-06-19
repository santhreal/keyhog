use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn build_scanner_config_respects_explicit_diagnostics() {
    let default_args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let default_cfg = API.build_scanner_config(&default_args);
    assert!(!default_cfg.profile);
    assert!(!default_cfg.perf_trace);

    let args = ScanArgs::try_parse_from(["scan", ".", "--profile", "--perf-trace"]).unwrap();
    let cfg = API.build_scanner_config(&args);

    assert!(
        cfg.profile,
        "--profile must reach ScannerConfig instead of an ambient env read"
    );
    assert!(
        cfg.perf_trace,
        "--perf-trace must reach ScannerConfig instead of an ambient env read"
    );
}
