//! LR1-A8 replacement gate: `reporting.rs` empty findings on stdout format.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn report_findings_empty_list_text_format_ok() {
    let guard = API.scan_runtime_guard_for_test();
    let args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let result = API.report_findings(&[], &args, &guard);
    assert!(
        result.is_ok(),
        "empty findings with default text output must succeed: {:?}",
        result.err()
    );
}
