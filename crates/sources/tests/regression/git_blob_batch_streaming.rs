use keyhog_core::Source;
use keyhog_sources::testing::TestApi;
use keyhog_sources::GitSource;
use std::process::Command;

fn git(root: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "KeyHog Test")
        .env("GIT_AUTHOR_EMAIL", "keyhog-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "KeyHog Test")
        .env("GIT_COMMITTER_EMAIL", "keyhog-test@example.invalid")
        .output()
        .expect("run git fixture command");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// WHY: A commit can contain more blobs than one decode batch. The source must
/// yield each bounded batch before decoding the next one instead of retaining
/// every decoded payload in the commit until the first iterator item is read.
#[test]
fn git_blob_source_retains_at_most_one_decoded_batch() {
    let repo = tempfile::tempdir().expect("create git fixture");
    git(repo.path(), &["init", "--quiet"]);
    for index in 0..=4096 {
        std::fs::write(
            repo.path().join(format!("blob-{index:04}.txt")),
            format!("ordinary fixture row {index}\n"),
        )
        .expect("write unique git blob");
    }
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "--quiet", "-m", "fixture"]);

    TestApi.reset_max_buffered_git_blob_chunks();
    let rows = GitSource::new(repo.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>();
    let errors = rows.iter().filter(|row| row.is_err()).count();
    let chunks = rows.len() - errors;

    assert_eq!(errors, 0, "complete fixture history must scan without gaps");
    assert_eq!(chunks, 4097, "every committed blob must be emitted exactly once");
    let peak = TestApi.max_buffered_git_blob_chunks();
    assert!(
        peak <= 4096,
        "decoded Git blob retention crossed the one-batch bound: {peak}"
    );
    assert!(
        peak < chunks,
        "the iterator buffered the whole commit instead of streaming batches"
    );
}
