use clap::Parser;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog::args::{Cli, ScanArgs};
use keyhog::testing::{CliTestApi, API};
use std::hint::black_box;
use tempfile::tempdir;

/// WHY: Product-level CLI startup latency directly impacts developer interactive
/// invocation time for fast check commands, `--version`, `--help`, and pre-commit
/// invocations. Measures clap argument parsing and sub-command routing across
/// common CLI vectors.
fn bench_cli_arg_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("cli_startup_arg_parsing");

    let vectors: &[(&str, &[&str])] = &[
        ("version", &["keyhog", "--version"]),
        ("help", &["keyhog", "--help"]),
        ("scan_dot", &["keyhog", "scan", "."]),
        (
            "scan_hook_canonical",
            &[
                "keyhog",
                "scan",
                "--fast",
                "--git-staged",
                "--backend",
                "cpu",
            ],
        ),
        (
            "scan_flags_matrix",
            &[
                "keyhog",
                "scan",
                ".",
                "--format",
                "json",
                "--severity",
                "high",
                "--threads",
                "4",
                "--no-config",
            ],
        ),
        ("guard_status", &["keyhog", "guard", "status", "."]),
        ("guard_list", &["keyhog", "guard", "list"]),
        ("hook_install", &["keyhog", "hook", "install"]),
        ("daemon_status", &["keyhog", "daemon", "status"]),
        ("doctor", &["keyhog", "doctor"]),
        ("explain_detector", &["keyhog", "explain", "aws-access-key"]),
    ];

    for (name, argv) in vectors {
        group.bench_with_input(BenchmarkId::from_parameter(*name), argv, |b, args| {
            b.iter(|| {
                let parsed = Cli::try_parse_from(black_box(*args));
                let _ = black_box(parsed);
            });
        });
    }
    group.finish();
}

/// WHY: Measures file discovery, deserialization, and schema validation of `.keyhog.toml`
/// configuration files during startup.
fn bench_cli_config_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("cli_startup_config_resolution");

    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    let sample_config = r#"
[scan]
format = "json"
threads = 8
min_confidence = 0.8
min_secret_len = 16

[tuning]
fallback_hs = true
hs_prefilter_max_len = 64

[guard]
hot_index_memory = "64MiB"
coalesce_window = "100ms"
"#;
    std::fs::write(&config_path, sample_config).expect("write sample config");

    group.bench_function("parse_config_file_from_str", |b| {
        b.iter(|| {
            let res = API.parse_config_file_from_str(black_box(sample_config));
            let _ = black_box(res);
        });
    });

    group.bench_function("find_config_file_in_tree", |b| {
        let scan_root = dir.path().join("src").join("nested");
        std::fs::create_dir_all(&scan_root).expect("create nested");
        b.iter(|| {
            let found = API.find_config_file(Some(black_box(&scan_root)));
            let _ = black_box(found);
        });
    });

    group.bench_function("apply_config_file_quiet", |b| {
        b.iter(|| {
            let mut args = ScanArgs::try_parse_from(["scan"]).expect("parse scan args");
            args.path = Some(dir.path().to_path_buf());
            API.apply_config_file_quiet(&mut args);
            black_box(args);
        });
    });

    group.finish();
}

/// WHY: Measures terminal output palette initialization and startup banner generation
/// to ensure banner formatting stays sub-microsecond and non-allocating.
fn bench_cli_banner_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("cli_startup_banner");

    group.bench_function("write_banner_colored", |b| {
        b.iter(|| {
            let out = API.write_banner(true, black_box(150));
            let _ = black_box(out);
        });
    });

    group.bench_function("write_banner_plain", |b| {
        b.iter(|| {
            let out = API.write_banner(false, black_box(150));
            let _ = black_box(out);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cli_arg_parsing,
    bench_cli_config_resolution,
    bench_cli_banner_formatting,
);
criterion_main!(benches);
