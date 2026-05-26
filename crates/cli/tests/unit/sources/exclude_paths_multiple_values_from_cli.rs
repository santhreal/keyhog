use clap::Parser;
use keyhog::args::ScanArgs;

#[test]
fn exclude_paths_multiple_values_from_cli() {
    let args = ScanArgs::try_parse_from([
        "scan", ".", "--exclude-paths", "a.txt", "--exclude-paths", "b.txt",
    ]).unwrap();
    assert_eq!(args.exclude_paths.as_ref().unwrap().len(), 2);
}
