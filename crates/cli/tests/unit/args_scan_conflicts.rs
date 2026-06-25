use clap::error::ErrorKind;
use clap::Parser;
use keyhog::args::ScanArgs;

fn assert_conflict(args: &[&str]) {
    let error = match ScanArgs::try_parse_from(args) {
        Ok(_) => panic!("args must conflict: {args:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        ErrorKind::ArgumentConflict,
        "expected argument conflict for {args:?}, got {error}"
    );
}

#[test]
fn fast_conflicts_with_entropy_only_knobs() {
    for extra in [
        ["--entropy-threshold", "5.0"].as_slice(),
        ["--entropy-source-files"].as_slice(),
        ["--no-entropy-ml-scoring"].as_slice(),
        ["--no-keyword-low-entropy"].as_slice(),
        ["--min-secret-len", "24"].as_slice(),
    ] {
        let mut args = vec!["scan", ".", "--fast"];
        args.extend(extra);
        assert_conflict(&args);
    }
}

#[test]
fn precision_conflicts_with_entropy_only_knobs() {
    for extra in [
        ["--entropy-threshold", "5.0"].as_slice(),
        ["--entropy-source-files"].as_slice(),
        ["--no-entropy-ml-scoring"].as_slice(),
        ["--no-keyword-low-entropy"].as_slice(),
        ["--min-secret-len", "24"].as_slice(),
    ] {
        let mut args = vec!["scan", ".", "--precision"];
        args.extend(extra);
        assert_conflict(&args);
    }
}
