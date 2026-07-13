//! Regression: `.keyhog.toml` documented `incremental` / `incremental_cache`,
//! but the config parser did not wire either field into `ScanArgs`.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use std::path::PathBuf;
use tempfile::TempDir;

fn args_for_config(contents: &str, extra_args: &[&str]) -> ScanArgs {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join(".keyhog.toml"), contents).expect("write config");
    let scan_path = dir.path().to_string_lossy().to_string();
    let mut argv = vec!["scan".to_string(), "--path".to_string(), scan_path];
    argv.extend(extra_args.iter().copied().map(String::from));
    let mut args = ScanArgs::try_parse_from(argv).expect("parse scan args");
    API.apply_config_file_quiet(&mut args);
    args
}

#[test]
fn scan_table_incremental_cache_config_reaches_scan_args() {
    let args = args_for_config(
        r#"
        [scan]
        incremental = true
        incremental_cache = "/tmp/keyhog-scan-table-merkle.idx"
        "#,
        &[],
    );

    assert!(
        args.incremental,
        "[scan].incremental=true must reach ScanArgs"
    );
    assert_eq!(
        args.incremental_cache,
        Some(PathBuf::from("/tmp/keyhog-scan-table-merkle.idx")),
        "[scan].incremental_cache must reach ScanArgs"
    );
}

#[test]
fn cli_incremental_cache_wins_over_config_cache() {
    let args = args_for_config(
        r#"
        [scan]
        incremental = true
        incremental_cache = "/tmp/keyhog-config-merkle.idx"
        "#,
        &[
            "--incremental",
            "--incremental-cache",
            "/tmp/keyhog-cli-merkle.idx",
        ],
    );

    assert!(args.incremental);
    assert_eq!(
        args.incremental_cache,
        Some(PathBuf::from("/tmp/keyhog-cli-merkle.idx")),
        "explicit CLI cache path must override .keyhog.toml"
    );
}
