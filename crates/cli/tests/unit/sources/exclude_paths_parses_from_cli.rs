use clap::Parser;
use keyhog::args::ScanArgs;

#[test]
fn exclude_paths_parses_from_cli() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--exclude-paths", "a.txt"]).unwrap();
    let got: Vec<&str> = args
        .exclude_paths
        .as_ref()
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();
    assert_eq!(got, vec!["a.txt"]);
}
