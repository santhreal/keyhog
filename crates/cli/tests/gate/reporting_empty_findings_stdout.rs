//! LR1-A8 replacement gate: `reporting.rs` empty findings on stdout format.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::reporting::report_findings;

#[test]
fn report_findings_empty_list_text_format_ok() {
    let args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let result = report_findings(&[], &args);
    assert!(
        result.is_ok(),
        "empty findings with default text output must succeed: {:?}",
        result.err()
    );
}
