use clap::Parser;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog::args::{Cli, Command, ScanArgs};
use keyhog::testing::hook::{find_hooks_dir_for_repo, install_at_repo, CANONICAL_SCAN_ARGS};
use keyhog::testing::{CliTestApi, API};
use keyhog_sources::StagedManifest;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command as SysCommand;
use tempfile::TempDir;

/// Initialize a test Git repository at `dir` with standard user identity.
fn init_git_repo(dir: &Path) {
    let out = SysCommand::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init must succeed");
    let email = SysCommand::new("git")
        .args(["config", "user.email", "bench@test.local"])
        .current_dir(dir)
        .output()
        .expect("git config user.email");
    assert!(email.status.success(), "git config user.email must succeed");
    let name = SysCommand::new("git")
        .args(["config", "user.name", "Bench Runner"])
        .current_dir(dir)
        .output()
        .expect("git config user.name");
    assert!(name.status.success(), "git config user.name must succeed");
}

/// Create and stage `count` synthetic files into the Git index.
fn create_and_stage_files(repo: &Path, count: usize) {
    for i in 0..count {
        let rel_path = format!("src/pkg_{:03}/module_{:05}.rs", i / 100, i);
        let full_path = repo.join(&rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(
            &full_path,
            format!("pub fn process_event_{i}() -> usize {{ {i} * 42 }}\n"),
        )
        .expect("write synthetic file");
    }
    let add_out = SysCommand::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add");
    assert!(add_out.status.success(), "git add must succeed");
}

/// Managed Git fixture containing staged files and initialized hooks directory.
struct HookBenchFixture {
    _dir: TempDir,
    repo_path: PathBuf,
    count: usize,
}

impl HookBenchFixture {
    fn new(count: usize) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let repo_path = dir.path().to_path_buf();
        init_git_repo(&repo_path);
        create_and_stage_files(&repo_path, count);
        Self {
            _dir: dir,
            repo_path,
            count,
        }
    }
}

/// WHY: Pre-commit hooks run `keyhog CANONICAL_SCAN_ARGS` on every commit.
/// Measures parsing and validating the canonical hook commandline tokens.
fn bench_hook_canonical_args_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_canonical_args_resolution");

    let raw_tokens: Vec<&str> = std::iter::once("keyhog")
        .chain(CANONICAL_SCAN_ARGS.split_whitespace())
        .collect();

    group.bench_function("parse_canonical_scan_args", |b| {
        b.iter(|| {
            let parsed = Cli::try_parse_from(black_box(&raw_tokens)).expect("parse canonical args");
            if let Some(Command::Scan(scan_args)) = parsed.command {
                black_box(scan_args);
            } else {
                panic!("expected Scan command");
            }
        });
    });

    group.finish();
}

/// WHY: Measures hook file discovery, installation, and idempotent update check
/// execution times across repository lifecycles.
fn bench_hook_install_lifecycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_install_lifecycle");

    let dir = TempDir::new().expect("tempdir");
    let repo_path = dir.path().to_path_buf();
    init_git_repo(&repo_path);

    group.bench_function("find_hooks_dir_for_repo", |b| {
        b.iter(|| {
            let hooks_dir = find_hooks_dir_for_repo(black_box(&repo_path)).expect("find hooks dir");
            black_box(hooks_dir);
        });
    });

    group.bench_function("install_at_repo_fresh_or_update", |b| {
        b.iter(|| {
            let res = install_at_repo(black_box(&repo_path), false).expect("install at repo");
            black_box(res);
        });
    });

    group.finish();
}

/// WHY: The core pre-commit execution path acquires the staged Git manifest
/// and checks staged blobs for secrets. Measures staged manifest acquisition
/// and source resolution latency across staged repository sizes.
fn bench_hook_staged_acquisition_and_sources(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_staged_acquisition_and_sources");

    let fixture_10 = HookBenchFixture::new(10);
    let fixture_100 = HookBenchFixture::new(100);
    let fixture_500 = HookBenchFixture::new(500);

    for fixture in &[&fixture_10, &fixture_100, &fixture_500] {
        group.bench_with_input(
            BenchmarkId::new("staged_manifest_acquire", fixture.count),
            &fixture.repo_path,
            |b, repo_path| {
                b.iter(|| {
                    let manifest = StagedManifest::acquire(black_box(repo_path))
                        .expect("acquire staged manifest");
                    black_box(manifest);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("build_staged_sources", fixture.count),
            &fixture.repo_path,
            |b, repo_path| {
                let args = ScanArgs::try_parse_from([
                    "scan",
                    "--path",
                    repo_path.to_str().unwrap(),
                    "--git-staged",
                    "--fast",
                    "--backend",
                    "cpu",
                ])
                .expect("parse scan args");

                b.iter(|| {
                    let sources = API
                        .build_sources(black_box(&args), Vec::new(), None)
                        .expect("build sources");
                    black_box(sources);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hook_canonical_args_resolution,
    bench_hook_install_lifecycle,
    bench_hook_staged_acquisition_and_sources,
);
criterion_main!(benches);
