//! #138 cross-source lock (git-history half): a MULTI-LINE private key committed
//! to a repository's history must surface as a contiguous, detectable block in a
//! single `git-history` chunk.
//!
//! `GitHistorySource` reconstructs the ADDED lines of each commit's patch. A PEM
//! /`.ppk` key spans many added lines; if that reconstruction split the block
//! across chunks (or dropped interior lines) the `private-key` /
//! `putty-private-key` detectors, whose match must span `-----BEGIN`…`-----END`
//! (or header…`Private-MAC`), would never fire, and a key leaked in an old
//! commit and "removed" in a later one would be invisible. These tests assert the
//! whole block lands in ONE history chunk, contiguous, with its commit metadata.
//!
//! The archive half lives in `regression_private_key_blocks_in_archives`.

#![cfg(unix)]

mod support;

#[cfg(feature = "git")]
mod git_history {
    use super::support::git::{commit, init_repo};
    use super::support::split_chunk_results;
    use keyhog_core::{Chunk, Source};
    use keyhog_sources::GitHistorySource;

    const PEM_INTERIOR_SENTINEL: &str = "KEYHOGgitHISTORYpemBODYsentinel0123456789abcDEF";
    const PEM_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3UzRe60Sgbw7Szrwkw4I97rbfs7+bvtt8ZAs9uO+Qz502eyS
m1Nr2kJ8oP1q6Yc3v9wXr4tH5sN0bQ2dE7fG8hI9jK0lM1nO2pP3qR4sT5uV6wX
KEYHOGgitHISTORYpemBODYsentinel0123456789abcDEFghijklmnopqrstuvw
7yZ8aB9cD0eF1gH2iJ3kL4mN5oP6qR7sT8uV9wX0yZ1aB2cD3eF4gH5iJ6kL7mN8
-----END RSA PRIVATE KEY-----
";

    const PPK_MAC: &str = "8a1b2c3d4e5f60718293a4b5c6d7e8f901234567";
    const PPK_KEY: &str = "PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: deploy-key-prod
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIGZ3aWxsbm90bWF0Y2hhbnl0aGluZ3JlYWxhdGE
xyZ0123456789abcdefABCDEFghijklmnopqrstuvWXYZ+/aSecondPublicLine
Private-Lines: 1
AAAAIHByaXZhdGVibG9iZ29lc2hlcmVrZXlob2dwcGtzZWNyZXRtYXRlcmlhbDAx
Private-MAC: 8a1b2c3d4e5f60718293a4b5c6d7e8f901234567
";

    /// Collect the owned history chunks for a repo (max 10 commits).
    fn history_chunks(repo: &std::path::Path) -> Vec<Chunk> {
        let source = GitHistorySource::new(repo.to_path_buf()).with_max_commits(10);
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, errors) = split_chunk_results(&rows);
        assert!(
            errors.is_empty(),
            "fixture repo must not emit SourceError rows: {errors:?}"
        );
        chunk_refs.into_iter().cloned().collect()
    }

    /// The single git-history chunk that contains `needle`.
    fn chunk_with<'a>(chunks: &'a [Chunk], needle: &str) -> Option<&'a Chunk> {
        chunks
            .iter()
            .find(|c| c.metadata.source_type.as_ref() == "git-history" && c.data.contains(needle))
    }

    #[test]
    fn pem_committed_to_history_surfaces_in_one_contiguous_chunk() {
        let (_g, repo) = init_repo();
        commit(&repo, "deploy/id_rsa.pem", PEM_KEY, "add deploy key");
        let chunks = history_chunks(&repo);
        let chunk = chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----")
            .expect("a git-history chunk must carry the committed PEM");
        // begin + interior + end all in the SAME chunk => detectable as one block.
        assert!(
            chunk.data.contains(PEM_INTERIOR_SENTINEL),
            "interior key line present in the block"
        );
        assert!(
            chunk.data.contains("-----END RSA PRIVATE KEY-----"),
            "end marker present in the block"
        );
    }

    #[test]
    fn pem_history_block_is_byte_intact() {
        let (_g, repo) = init_repo();
        commit(&repo, "id_rsa.pem", PEM_KEY, "add key");
        let chunks = history_chunks(&repo);
        let text: String = chunks
            .iter()
            .map(|c| c.data.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains(PEM_KEY.trim_end()),
            "the multi-line PEM block (newlines preserved) must survive history reconstruction"
        );
    }

    #[test]
    fn pem_history_block_preserves_interior_newlines() {
        let (_g, repo) = init_repo();
        commit(&repo, "id_rsa.pem", PEM_KEY, "add key");
        let chunks = history_chunks(&repo);
        let chunk = chunk_with(&chunks, PEM_INTERIOR_SENTINEL).expect("pem chunk");
        let begin = chunk.data.find("-----BEGIN RSA PRIVATE KEY-----").unwrap();
        let end = chunk.data.find("-----END RSA PRIVATE KEY-----").unwrap();
        assert!(begin < end, "BEGIN precedes END in the chunk");
        assert!(
            chunk.data[begin..end].matches('\n').count() >= 4,
            "the reconstructed block keeps its interior line breaks"
        );
    }

    #[test]
    fn pem_history_chunk_carries_commit_metadata() {
        let (_g, repo) = init_repo();
        commit(&repo, "secrets/id_rsa.pem", PEM_KEY, "leak key");
        let chunks = history_chunks(&repo);
        let chunk = chunk_with(&chunks, PEM_INTERIOR_SENTINEL).expect("pem chunk");
        let commit_id = chunk.metadata.commit.as_deref().expect("commit id present");
        assert_eq!(commit_id.len(), 40, "full SHA-1 commit id");
        assert!(
            commit_id.chars().all(|c| c.is_ascii_hexdigit()),
            "commit id is hex"
        );
        assert!(chunk.metadata.date.is_some(), "commit date present");
        assert!(
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|p| p.ends_with("id_rsa.pem")),
            "history chunk carries the file path; got {:?}",
            chunk.metadata.path
        );
    }

    #[test]
    fn pem_added_in_a_later_commit_surfaces() {
        let (_g, repo) = init_repo();
        commit(&repo, "app.conf", "name=app\n", "init");
        commit(&repo, "id_rsa.pem", PEM_KEY, "add key later");
        let chunks = history_chunks(&repo);
        assert!(
            chunk_with(&chunks, PEM_INTERIOR_SENTINEL).is_some(),
            "a key added in a non-initial commit must still surface"
        );
    }

    #[test]
    fn pem_committed_then_deleted_is_still_in_history() {
        // The classic "we removed the secret" case: the key is gone from HEAD but
        // remains in the patch history and must still be found.
        let (_g, repo) = init_repo();
        commit(&repo, "id_rsa.pem", PEM_KEY, "add key");
        commit(
            &repo,
            "id_rsa.pem",
            "# rotated, key removed\n",
            "remove key",
        );
        let chunks = history_chunks(&repo);
        assert!(
            chunk_with(&chunks, PEM_INTERIOR_SENTINEL).is_some(),
            "a key removed from HEAD but present in history must surface"
        );
    }

    #[test]
    fn pem_embedded_among_other_added_lines_stays_contiguous() {
        let body = format!("# config start\nhost = db.example.com\n{PEM_KEY}\nport = 5432\n");
        let (_g, repo) = init_repo();
        commit(&repo, "config_with_key.txt", &body, "add config + key");
        let chunks = history_chunks(&repo);
        let chunk = chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").expect("chunk");
        assert!(chunk.data.contains(PEM_INTERIOR_SENTINEL));
        assert!(chunk.data.contains("-----END RSA PRIVATE KEY-----"));
    }

    #[test]
    fn ppk_committed_to_history_surfaces() {
        let (_g, repo) = init_repo();
        commit(&repo, "deploy.ppk", PPK_KEY, "add ppk");
        let chunks = history_chunks(&repo);
        let chunk = chunk_with(&chunks, "PuTTY-User-Key-File-2:").expect("ppk chunk");
        assert!(
            chunk.data.contains("Private-Lines:"),
            "Private-Lines body marker present"
        );
        assert!(
            chunk.data.contains(&format!("Private-MAC: {PPK_MAC}")),
            "trailing MAC present"
        );
    }

    #[test]
    fn two_keys_across_commits_both_surface() {
        let second = PEM_KEY.replace(
            PEM_INTERIOR_SENTINEL,
            "SECONDgitKEYsentinel987654321ZYXwvut",
        );
        let (_g, repo) = init_repo();
        commit(&repo, "a.pem", PEM_KEY, "first key");
        commit(&repo, "b.pem", &second, "second key");
        let chunks = history_chunks(&repo);
        assert!(
            chunk_with(&chunks, PEM_INTERIOR_SENTINEL).is_some(),
            "first key surfaces"
        );
        assert!(
            chunk_with(&chunks, "SECONDgitKEYsentinel987654321ZYXwvut").is_some(),
            "second key surfaces"
        );
    }

    #[test]
    fn benign_history_has_no_private_key_marker() {
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "README.md",
            "# project\nnothing secret here\n",
            "init",
        );
        commit(
            &repo,
            "main.rs",
            "fn main() { println!(\"hi\"); }\n",
            "code",
        );
        let chunks = history_chunks(&repo);
        assert!(
            chunk_with(&chunks, "-----BEGIN RSA PRIVATE KEY-----").is_none(),
            "a key-free history must not fabricate a private-key marker"
        );
    }

    #[test]
    fn max_commits_bounds_history_scan() {
        let (_g, repo) = init_repo();
        commit(&repo, "id_rsa.pem", PEM_KEY, "add key (oldest)");
        for n in 0..3 {
            commit(
                &repo,
                "app.conf",
                &format!("rev={n}\n"),
                &format!("change {n}"),
            );
        }
        // Only the most recent commit is scanned, so the older key commit is excluded.
        let source = GitHistorySource::new(repo.clone()).with_max_commits(1);
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, _e) = split_chunk_results(&rows);
        let chunks: Vec<Chunk> = chunk_refs.into_iter().cloned().collect();
        assert!(
            chunk_with(&chunks, PEM_INTERIOR_SENTINEL).is_none(),
            "with_max_commits(1) must not reach the older key-bearing commit"
        );
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_history_private_key_lock_requires_git_feature() {
    assert!(
        !cfg!(feature = "git"),
        "this lock only runs with the git feature"
    );
}
