use clap::Parser;
use keyhog::args::ScanArgs;

#[test]
fn exclude_paths_parses_from_cli() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--exclude-paths", "a.txt"]).unwrap();
    assert_eq!(
        args.exclude_paths.as_ref().map(|v| v.as_slice()),
        Some(&["a.txt"[..]])
    );
}
