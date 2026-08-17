use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyhog_sources::{parse_git_index_sizes, verify_staged_fingerprint, StagedManifest};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Initialize a test Git repository at `dir` with standard user identity.
fn init_git_repo(dir: &Path) {
    let out = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init must succeed");
    let _ = Command::new("git")
        .args(["config", "user.email", "bench@test.local"])
        .current_dir(dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Bench Runner"])
        .current_dir(dir)
        .output();
}

/// Create and stage `count` synthetic files into the Git index.
fn create_and_stage_files(repo: &Path, count: usize) {
    for i in 0..count {
        let rel_path = format!("src/pkg_{:03}/module_{:05}.rs", i / 250, i);
        let full_path = repo.join(&rel_path);
        if let Some(parent) = full_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(
            &full_path,
            format!("pub fn compute_{i}() -> usize {{ {i} * 3 }}\n"),
        )
        .expect("write synthetic file");
    }
    let add_out = Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add");
    assert!(add_out.status.success(), "git add must succeed");
}

/// Managed Git fixture containing staged files and cached index state.
struct StagedFixture {
    _dir: TempDir,
    repo_path: PathBuf,
    index_path: PathBuf,
    fingerprint: String,
    count: usize,
}

impl StagedFixture {
    fn new(count: usize) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let repo_path = dir.path().to_path_buf();
        init_git_repo(&repo_path);
        create_and_stage_files(&repo_path, count);
        let index_path = repo_path.join(".git").join("index");
        assert!(index_path.exists(), "git index must exist on disk");

        // Acquire initial manifest to compute expected fingerprint and populate
        // the process-local index fingerprint cache for fast verification.
        let manifest = StagedManifest::acquire(&repo_path).expect("acquire staged manifest");
        let fingerprint = manifest.index_fingerprint;

        let sizes = parse_git_index_sizes(&index_path);
        assert_eq!(
            sizes.len(),
            count,
            "parsed index size map must hold all staged entries"
        );

        let verified = verify_staged_fingerprint(&repo_path, &fingerprint);
        assert!(verified, "initial fingerprint verification must match");

        Self {
            _dir: dir,
            repo_path,
            index_path,
            fingerprint,
            count,
        }
    }
}

/// WHY: `parse_git_index_sizes` parses binary Git DIRC index files directly,
/// extracting object IDs and file lengths in a single sequential sweep. This
/// avoids thousands of individual loose-object file opens and zlib decompressions
/// during staged manifest acquisition in pre-commit hooks.
fn bench_parse_git_index_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_git_index_sizes");
    let fixture_1k = StagedFixture::new(1000);
    let fixture_5k = StagedFixture::new(5000);

    for fixture in &[&fixture_1k, &fixture_5k] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_entries", fixture.count)),
            &fixture.index_path,
            |bencher, index_path| {
                bencher.iter(|| {
                    let map = parse_git_index_sizes(black_box(index_path));
                    black_box(map);
                });
            },
        );
    }
    group.finish();
}

/// WHY: `verify_staged_fingerprint` validates that staged repository state has
/// not been concurrently mutated between `GuardCommitBegin` and `GuardCommitFinish`.
/// In the fast cached path (mtime and trailing 20-byte checksum match), this
/// completes in microseconds without spawning Git subprocesses or re-reading trees.
fn bench_verify_staged_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_staged_fingerprint");
    let fixture_1k = StagedFixture::new(1000);
    let fixture_5k = StagedFixture::new(5000);

    for fixture in &[&fixture_1k, &fixture_5k] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_entries", fixture.count)),
            fixture,
            |bencher, fix| {
                bencher.iter(|| {
                    let matched = verify_staged_fingerprint(
                        black_box(&fix.repo_path),
                        black_box(&fix.fingerprint),
                    );
                    black_box(matched);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_parse_git_index_sizes,
    bench_verify_staged_fingerprint
);
criterion_main!(benches);
