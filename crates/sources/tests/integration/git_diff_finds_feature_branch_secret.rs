//! GitDiffSource must diff base..head and surface added secrets.

#[cfg(feature = "git")]
#[test]
fn git_diff_finds_feature_branch_secret() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;
    use std::process::Command;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo,
        "base.txt",
        "stable=1
",
        "base",
    );
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo)
        .output()
        .expect("branch");
    crate::support::git::commit(
        &repo,
        "new.env",
        "SLACK=xoxb-integrationDiffBranch00000001
",
        "feature",
    );

    let bodies: Vec<String> = GitDiffSource::new(repo, "main")
        .with_head_ref("feature")
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains(concat!("xox", "b-integrationDiffBranch"))),
        "diff must include added file content; got {bodies:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_diff_integration_requires_git() {
    assert!(!cfg!(feature = "git"));
}
