use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn build_scanner_config_no_suppress_disables_test_path_penalty() {
    let default_args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let default_cfg = API.build_scanner_config(&default_args);
    assert!(
        default_cfg.penalize_test_paths,
        "default scans should keep the test/example path confidence penalty"
    );

    let optout_args =
        ScanArgs::try_parse_from(["scan", ".", "--no-suppress-test-fixtures"]).unwrap();
    let optout_cfg = API.build_scanner_config(&optout_args);
    assert!(
        !optout_cfg.penalize_test_paths,
        "--no-suppress-test-fixtures must disable the test/example path confidence penalty as well as value suppressions"
    );
}
