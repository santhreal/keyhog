//! Git commits with malformed author metadata must not scan with synthetic author truth.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_author_metadata_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let (_temp, repo) = crate::support::git::init_repo();
    std::fs::write(
        repo.join("live.env"),
        "KEY=ghp_corruptAuthorMetadata0000001\n",
    )
    .expect("write fixture");
    let add = Command::new("git")
        .args(["add", "live.env"])
        .current_dir(&repo)
        .output()
        .expect("git add");
    assert!(add.status.success(), "git add failed: {add:?}");
    let tree = Command::new("git")
        .args(["write-tree"])
        .current_dir(&repo)
        .output()
        .expect("git write-tree");
    assert!(tree.status.success(), "git write-tree failed: {tree:?}");
    let tree_id = String::from_utf8(tree.stdout).expect("tree id utf8");
    let commit_body = format!(
        "tree {}\ncommitter Bad <bad@example.com> 0 +0000\n\nmissing author\n",
        tree_id.trim()
    );
    let mut hash_object = Command::new("git")
        .args([
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ])
        .current_dir(&repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("git hash-object");
    hash_object
        .stdin
        .as_mut()
        .expect("hash-object stdin")
        .write_all(commit_body.as_bytes())
        .expect("write malformed commit");
    let hash_output = hash_object.wait_with_output().expect("hash-object output");
    assert!(
        hash_output.status.success(),
        "git hash-object failed: {hash_output:?}"
    );
    let commit_id = String::from_utf8(hash_output.stdout).expect("commit id utf8");
    let update = Command::new("git")
        .args(["update-ref", "refs/heads/main", commit_id.trim()])
        .current_dir(&repo)
        .output()
        .expect("git update-ref");
    assert!(update.status.success(), "git update-ref failed: {update:?}");

    let err = GitSource::new(repo)
        .chunks()
        .next()
        .expect("malformed author metadata must surface an error")
        .expect_err("malformed author metadata must not yield chunks with unknown author");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to read git commit author metadata"),
        "malformed author metadata must be operator-visible; got {msg}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_author_metadata_rejected() {}
