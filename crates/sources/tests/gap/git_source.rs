//! Gap-closure integration tests for the `git_source` coverage area
//! (`crates/sources/src/git/source.rs`, the `GitSource` blob scanner).
//!
//! Every expected value below is derived from reading the real implementation:
//!
//! * `decode_git_blob` (source.rs:316) — empty -> `Some("")`, valid UTF-8 ->
//!   owned copy, non-UTF-8 non-binary -> lossy decode, true binary -> `None`.
//! * `looks_binary_blob` (source.rs:339) — magic headers, early NUL, UTF-16 BOM
//!   / alternating-NUL exemption, and the `suspicious * 20 > total` (>5%) C0
//!   density rule.
//! * `stream_git_blobs` (source.rs:97) — `git log --reflog --all`, explicit
//!   refs/stash coverage, unreachable commit enumeration, gix tree walk,
//!   path-aware blob dedup / `seen_commits` dedup, the filesystem-owned
//!   default-exclude path classifier,
//!   the `header.size() > MAX_GIT_BLOB_BYTES` (10 MiB, strict `>`) bound,
//!   `source_type = git/head` vs `git/history`, `commit`/`author`/`size_bytes`
//!   attribution, and `date: None`.
//!
//! The tests are self-contained: they shell out to the real `git` binary to
//! build fixtures (mirroring `regression_git_blob_non_utf8_still_scanned.rs`)
//! so they do not depend on the `support` module, which is not wired into the
//! `gaps` aggregator.

#![cfg(feature = "git")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::{FilesystemSource, GitSource};

// ----------------------------------------------------------------------------
// fixture helpers
// ----------------------------------------------------------------------------

/// Run a git command in `repo`, asserting success.
fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `git init` a fresh repo on branch `main` with a deterministic identity.
fn init_repo() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().to_path_buf();
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.email", "gap@test.example"]);
    git(&repo, &["config", "user.name", "Gap Author"]);
    // Make commit timestamps deterministic so author/commit attribution is
    // stable across machines.
    (temp, repo)
}

/// Write `content` to `repo/relpath` (creating parent dirs), `git add` it, and
/// commit with `message` and a fixed author. Returns the full commit hash.
fn commit_file(repo: &Path, relpath: &str, content: &[u8], message: &str) -> String {
    let path = repo.join(relpath);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir parent");
    }
    std::fs::write(&path, content).expect("write fixture");
    git(repo, &["add", relpath]);
    commit_only(repo, message)
}

/// Commit whatever is staged and return the resulting full commit hash.
fn commit_only(repo: &Path, message: &str) -> String {
    let output = Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(repo)
        .output()
        .expect("git commit spawn");
    assert!(
        output.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rev = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("rev-parse spawn");
    assert!(rev.status.success(), "rev-parse failed");
    String::from_utf8_lossy(&rev.stdout).trim().to_string()
}

/// Drain `GitSource` over `repo` into a Vec of successful chunks (panicking on
/// any error, so a regression that turns a chunk into an error is loud).
fn collect_chunks(repo: &Path, max_commits: usize) -> Vec<Chunk> {
    GitSource::new(repo.to_path_buf())
        .with_max_commits(max_commits)
        .chunks()
        .map(|r| r.expect("git chunk should not error"))
        .collect()
}

/// Find the chunk whose `path` ends with `suffix`.
fn chunk_for<'a>(chunks: &'a [Chunk], suffix: &str) -> Option<&'a Chunk> {
    chunks.iter().find(|c| {
        c.metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with(suffix))
    })
}

fn normalize_chunk_path(repo: &Path, path: &str) -> String {
    let raw = PathBuf::from(path);
    let relative = if raw.is_absolute() {
        raw.strip_prefix(repo)
            .unwrap_or_else(|_| panic!("chunk path {raw:?} is outside repo {repo:?}"))
            .to_path_buf()
    } else {
        raw
    };
    relative.to_string_lossy().replace('\\', "/")
}

fn filesystem_text_map(repo: &Path) -> BTreeMap<String, String> {
    FilesystemSource::new(repo.to_path_buf())
        .chunks()
        .map(|result| result.expect("filesystem source must not error"))
        .filter(|chunk| chunk.metadata.source_type == "filesystem")
        .map(|chunk| {
            let path = chunk
                .metadata
                .path
                .as_deref()
                .map(|path| normalize_chunk_path(repo, path))
                .expect("filesystem chunk path");
            (path, chunk.data.to_string())
        })
        .collect()
}

fn git_head_text_map(repo: &Path) -> BTreeMap<String, String> {
    GitSource::new(repo.to_path_buf())
        .with_max_commits(1)
        .chunks()
        .map(|result| result.expect("git source must not error"))
        .filter(|chunk| chunk.metadata.source_type == "git/head")
        .map(|chunk| {
            let path = chunk.metadata.path.clone().expect("git head chunk path");
            (path.replace('\\', "/"), chunk.data.to_string())
        })
        .collect()
}

// ----------------------------------------------------------------------------
// non-UTF-8 blob still scanned (decode_git_blob lossy contract)
// ----------------------------------------------------------------------------

#[test]
fn non_utf8_blob_is_scanned_lossily_not_dropped() {
    // 0x92 (CP-1252 smart quote) is not valid UTF-8 and is NOT binary, so
    // decode_git_blob must take the from_utf8_lossy branch and keep the blob.
    let (_t, repo) = init_repo();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"# don\x92t drop me\n");
    bytes.extend_from_slice(b"AWS=AKIAIOSFODNN7EXAMPLE\n");
    assert!(
        std::str::from_utf8(&bytes).is_err(),
        "fixture must be non-UTF-8"
    );
    commit_file(&repo, "cfg.ini", &bytes, "non-utf8 config");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "cfg.ini").expect("cfg.ini chunk present");
    assert!(
        c.data.contains("AKIAIOSFODNN7EXAMPLE"),
        "credential beside a stray high byte must survive lossy decode; got {:?}",
        c.data.to_string()
    );
    assert!(
        c.data.contains("drop me"),
        "surrounding text must be preserved; got {:?}",
        c.data.to_string()
    );
    // The lone 0x92 byte must have been replaced by U+FFFD (lossy), not kept.
    assert!(
        c.data.contains('\u{FFFD}'),
        "the invalid byte must become the replacement char; got {:?}",
        c.data.to_string()
    );
}

#[test]
fn latin1_high_bytes_decoded_lossily() {
    // A run of Latin-1 accented bytes (0xE9 = é in CP-1252) is not valid UTF-8
    // and well under the 5% C0-control threshold, so it decodes lossily.
    let (_t, repo) = init_repo();
    let mut bytes = Vec::new();
    bytes.extend_from_slice("caf".as_bytes());
    bytes.push(0xE9); // lone 0xE9, invalid as standalone UTF-8
    bytes.extend_from_slice(b" TOKEN=ghp_latin1Survives0000000000001\n");
    assert!(std::str::from_utf8(&bytes).is_err());
    commit_file(&repo, "notes.txt", &bytes, "latin1");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "notes.txt").expect("notes.txt present");
    assert!(c.data.contains("ghp_latin1Survives0000000000001"));
}

#[test]
fn empty_blob_emits_empty_chunk_with_zero_size() {
    // decode_git_blob returns Some(String::new()) for empty data, and the
    // stream does NOT filter empty chunks (unlike git-diff/git-history which
    // trim). So a tracked empty file produces a chunk with empty data and
    // size_bytes == Some(0).
    let (_t, repo) = init_repo();
    commit_file(&repo, "empty.txt", b"", "empty file");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "empty.txt").expect("empty.txt chunk emitted");
    assert_eq!(c.data.len(), 0, "empty blob -> empty data");
    assert_eq!(c.data.to_string(), "");
    assert_eq!(
        c.metadata.size_bytes,
        Some(0),
        "header.size() of an empty blob is 0"
    );
}

#[test]
fn pure_binary_blob_is_skipped_not_emitted() {
    // An ELF magic header makes looks_binary_blob return true, so
    // decode_git_blob returns None and the blob produces NO chunk.
    let (_t, repo) = init_repo();
    let mut elf = Vec::new();
    elf.extend_from_slice(b"\x7fELF");
    elf.extend_from_slice(&[0u8; 64]);
    elf.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE"); // would-be secret, but binary
    commit_file(&repo, "a.out", &elf, "binary");
    // Add a sibling text file in the same commit so the source still emits
    // something and we can prove only the binary was dropped.
    commit_file(
        &repo,
        "real.env",
        b"KEY=ghp_realFileSurvives000000000001\n",
        "text",
    );

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "a.out").is_none(),
        "binary blob (ELF magic) must be skipped entirely"
    );
    assert!(
        chunk_for(&chunks, "real.env").is_some(),
        "sibling text file must still be scanned"
    );
}

#[test]
fn png_magic_blob_is_skipped() {
    let (_t, repo) = init_repo();
    let mut png = Vec::new();
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    png.extend_from_slice(b"some_pixels_that_look_like AKIAIOSFODNN7EXAMPLE");
    commit_file(&repo, "img.png", &png, "png");
    commit_file(&repo, "keep.txt", b"x=1\n", "keep");

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "img.png").is_none(),
        "PNG magic -> skipped"
    );
    assert!(chunk_for(&chunks, "keep.txt").is_some());
}

#[test]
fn early_nul_byte_marks_blob_binary_and_skips() {
    // A NUL within the first 1024 bytes that is not the UTF-16 alternating
    // pattern forces the binary verdict. Put NUL at offset 3 (data[0],data[1]
    // both nonzero -> not UTF-16) so looks_binary_blob returns true.
    let (_t, repo) = init_repo();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"abc");
    bytes.push(0x00);
    bytes.extend_from_slice(b"SECRET=AKIAIOSFODNN7EXAMPLE\n");
    commit_file(&repo, "blob.dat", &bytes, "early nul");
    commit_file(&repo, "ok.txt", b"y=2\n", "ok");

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "blob.dat").is_none(),
        "early NUL (non-UTF16) -> binary -> skipped"
    );
    assert!(chunk_for(&chunks, "ok.txt").is_some());
}

#[test]
fn high_c0_control_density_marks_binary() {
    // Build a blob that is valid-UTF-8 invalid? No: must be NON-UTF8 to reach
    // the density branch (UTF-8 valid takes the fast path and is always kept).
    // Use 0xFF (never valid UTF-8) plus >5% C0 control bytes (0x01) to trip
    // `suspicious * 20 > total`. 0xFF avoids the UTF-8 fast path; 0x01 bytes
    // are the suspicious controls. No NUL, no magic header.
    let (_t, repo) = init_repo();
    let mut bytes = vec![0xFFu8]; // invalidates UTF-8, not a control, not magic
                                  // 10 control bytes among ~100 total => 10*20=200 > 100 => binary.
    for _ in 0..10 {
        bytes.push(0x01);
    }
    bytes.extend_from_slice(&[b'a'; 80]);
    bytes.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
    // sanity: not valid utf-8, no leading magic, no NUL
    assert!(std::str::from_utf8(&bytes).is_err());
    assert!(!bytes.contains(&0u8));
    commit_file(&repo, "dense.bin", &bytes, "dense controls");
    commit_file(&repo, "plain.txt", b"z=3\n", "plain");

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "dense.bin").is_none(),
        ">5% C0-control density -> binary -> skipped"
    );
    assert!(chunk_for(&chunks, "plain.txt").is_some());
}

#[test]
fn low_c0_control_density_below_threshold_is_kept() {
    // Boundary twin of the previous test: keep control density at exactly the
    // non-binary side. With 1 control byte among >=20 total, 1*20=20 is NOT
    // > total (>=20), so it does NOT trip. Use 0xFF to dodge the UTF-8 fast
    // path and force the density branch to actually run.
    let (_t, repo) = init_repo();
    let mut bytes = vec![0xFFu8]; // 1 byte, not control (0xFF >= 0x20)
    bytes.push(0x01); // 1 suspicious control byte
    bytes.extend_from_slice(b"PLENTY_OF_NORMAL_TEXT_AKIAIOSFODNN7EXAMPLE_xxxxx"); // padding
    let total = bytes.len() as u64;
    assert!(20 <= total, "need total>=20 so 1*20 !> total");
    assert!(std::str::from_utf8(&bytes).is_err());
    commit_file(&repo, "sparse.txt", &bytes, "sparse control");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "sparse.txt").expect("sparse.txt kept");
    assert!(
        c.data.contains("AKIAIOSFODNN7EXAMPLE"),
        "below-threshold control density must be scanned lossily; got {:?}",
        c.data.to_string()
    );
}

#[test]
fn valid_utf8_blob_kept_byte_for_byte() {
    // Valid UTF-8 (including multibyte) goes through the fast path and is
    // copied verbatim — no replacement chars.
    let (_t, repo) = init_repo();
    let content = "user=café\nGITHUB=ghp_validUtf8Multibyte000000000001\n";
    commit_file(&repo, "u.txt", content.as_bytes(), "utf8");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "u.txt").expect("u.txt present");
    assert_eq!(c.data.to_string(), content, "valid UTF-8 must be verbatim");
    assert!(
        !c.data.contains('\u{FFFD}'),
        "no lossy replacement for valid UTF-8"
    );
}

// ----------------------------------------------------------------------------
// blob/commit attribution (source_type, commit, author, size_bytes, date)
// ----------------------------------------------------------------------------

#[test]
fn head_blob_is_labelled_git_head() {
    // A single commit on main: HEAD points at it, so its blob OID is in the
    // HEAD blob set -> source_type "git/head".
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "live.env",
        b"K=ghp_liveInHead00000000000000000001\n",
        "live",
    );

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "live.env").expect("live.env present");
    assert_eq!(
        c.metadata.source_type, "git/head",
        "blob reachable from HEAD tree is labelled git/head"
    );
}

#[test]
fn removed_blob_is_labelled_git_history() {
    // Commit a secret, then in a later commit replace the file content so the
    // old blob OID is no longer in HEAD's tree. The old blob is reachable via
    // `git log --all` but NOT in the HEAD blob set -> "git/history".
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "rot.env",
        b"OLD=ghp_removedFromHead0000000000001\n",
        "add secret",
    );
    commit_file(&repo, "rot.env", b"OLD=redacted\n", "scrub secret");

    let chunks = collect_chunks(&repo, 5);
    // The historical blob carries the removed secret and must be git/history.
    let hist = chunks
        .iter()
        .find(|c| c.data.contains("ghp_removedFromHead0000000000001"))
        .expect("historical secret blob must still be surfaced");
    assert_eq!(
        hist.metadata.source_type, "git/history",
        "a blob no longer in HEAD must be labelled git/history"
    );
    // The current (scrubbed) blob is in HEAD.
    let live = chunks
        .iter()
        .find(|c| c.data.contains("redacted"))
        .expect("current blob present");
    assert_eq!(live.metadata.source_type, "git/head");
}

#[test]
fn commit_hash_attribution_is_full_40_hex() {
    let (_t, repo) = init_repo();
    let hash = commit_file(&repo, "c.txt", b"v=1\n", "attrib");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "c.txt").expect("c.txt present");
    let got = c.metadata.commit.as_deref().expect("commit set");
    assert_eq!(got, hash, "chunk commit must equal the actual HEAD hash");
    assert_eq!(got.len(), 40, "git log %H is a full 40-char SHA-1");
    assert!(got.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn author_attribution_matches_commit_author_name() {
    // git log --format="%H %an": author is the %an (author name) we configured.
    let (_t, repo) = init_repo();
    commit_file(&repo, "a.txt", b"v=1\n", "author");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "a.txt").expect("a.txt present");
    assert_eq!(
        c.metadata.author.as_deref(),
        Some("Gap Author"),
        "author must be %an from git log"
    );
}

#[test]
fn author_with_internal_space_is_preserved_by_splitn() {
    // The stream parses each log line with splitn(2, ' '): hash, then the
    // ENTIRE remainder as author. A multi-word author name must survive intact.
    let (_t, repo) = init_repo();
    git(&repo, &["config", "user.name", "Ada B. Lovelace"]);
    commit_file(&repo, "ada.txt", b"v=1\n", "multi-word author");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "ada.txt").expect("ada.txt present");
    assert_eq!(
        c.metadata.author.as_deref(),
        Some("Ada B. Lovelace"),
        "splitn(2,' ') keeps the full author name including spaces"
    );
}

#[test]
fn size_bytes_equals_raw_blob_byte_length() {
    // size_bytes = header.size() = raw (decompressed) blob byte length, which
    // is the on-disk content length, independent of UTF-8 decoding.
    let (_t, repo) = init_repo();
    let content = b"FOO=barbaz\n"; // 11 bytes
    commit_file(&repo, "s.txt", content, "size");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "s.txt").expect("s.txt present");
    assert_eq!(
        c.metadata.size_bytes,
        Some(content.len() as u64),
        "size_bytes must be the raw blob byte length (11)"
    );
}

#[test]
fn size_bytes_counts_bytes_not_chars_for_non_utf8() {
    // For a non-UTF-8 blob, size_bytes is the raw byte count (header.size()),
    // NOT the char count of the lossy-decoded string (which differs once 0x92
    // becomes a 3-byte U+FFFD).
    let (_t, repo) = init_repo();
    let mut bytes = b"abc".to_vec();
    bytes.push(0x92); // 1 raw byte
    bytes.push(b'\n');
    let raw_len = bytes.len() as u64; // 5
    commit_file(&repo, "nb.txt", &bytes, "bytes");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "nb.txt").expect("nb.txt present");
    assert_eq!(
        c.metadata.size_bytes,
        Some(raw_len),
        "size_bytes is the raw byte count (5), not lossy-decoded char/byte count"
    );
    // The lossy data is longer than the raw bytes: U+FFFD is 3 UTF-8 bytes.
    assert!(
        c.data.len() as u64 > raw_len,
        "lossy decode of the high byte inflates the in-memory data length"
    );
}

#[test]
fn date_metadata_is_always_none_for_git_source() {
    // GitSource sets `date: None` unconditionally (source.rs:283); only
    // git-diff / git-history populate a date.
    let (_t, repo) = init_repo();
    commit_file(&repo, "d.txt", b"v=1\n", "date");

    let chunks = collect_chunks(&repo, 1);
    for c in &chunks {
        assert_eq!(
            c.metadata.date, None,
            "GitSource must never set a date; got {:?}",
            c.metadata.date
        );
    }
}

#[test]
fn base_offset_and_mtime_are_zero_and_none() {
    // base_offset is always 0 and mtime_ns is always None for git blobs.
    let (_t, repo) = init_repo();
    commit_file(&repo, "m.txt", b"v=1\n", "meta");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "m.txt").expect("m.txt present");
    assert_eq!(c.metadata.base_offset, 0);
    assert_eq!(c.metadata.mtime_ns, None);
}

#[test]
fn nested_path_is_slash_joined_under_prefix() {
    // collect_tree_blobs_metadata joins prefix with '/'. A file under a
    // subdirectory must carry the full relative path.
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "src/inner/deep.env",
        b"K=ghp_nestedPath00000000000000000001\n",
        "nested",
    );

    let chunks = collect_chunks(&repo, 1);
    let c = chunks
        .iter()
        .find(|c| c.data.contains("ghp_nestedPath00000000000000000001"))
        .expect("nested blob present");
    assert_eq!(
        c.metadata.path.as_deref(),
        Some("src/inner/deep.env"),
        "nested path must be slash-joined from the tree prefix"
    );
}

#[test]
fn source_name_is_git() {
    let source = GitSource::new(PathBuf::from("."));
    assert_eq!(source.name(), "git");
}

#[test]
fn tracked_head_blobs_match_filesystem_working_tree_text() {
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "src/app.env",
        b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        "app secret",
    );
    commit_file(
        &repo,
        "config/token.txt",
        b"GITHUB_TOKEN=ghp_trackedParity000000000000001\n",
        "token",
    );

    let filesystem = filesystem_text_map(&repo);
    let git_head = git_head_text_map(&repo);

    let expected = BTreeMap::from([
        (
            "config/token.txt".to_string(),
            "GITHUB_TOKEN=ghp_trackedParity000000000000001\n".to_string(),
        ),
        (
            "src/app.env".to_string(),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n".to_string(),
        ),
    ]);

    assert_eq!(
        filesystem, expected,
        "fixture guard: filesystem source must see exactly the tracked working-tree text files"
    );
    assert_eq!(
        git_head, filesystem,
        "GitSource git/head output must match the tracked working-tree text surface"
    );
}

// ----------------------------------------------------------------------------
// .gitignore interplay
// ----------------------------------------------------------------------------

#[test]
fn gitignore_file_itself_is_scanned() {
    // .gitignore is a tracked blob like any other; it is committed into the
    // tree and the source scans it (it is not in the excluded-name list).
    let (_t, repo) = init_repo();
    commit_file(&repo, ".gitignore", b"*.log\nsecrets.txt\n", "add ignore");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, ".gitignore").expect(".gitignore must be scanned");
    assert!(
        c.data.contains("*.log"),
        "the .gitignore contents are scannable"
    );
    assert_eq!(c.metadata.source_type, "git/head");
}

#[test]
fn untracked_ignored_file_is_not_in_any_tree() {
    // A file matched by .gitignore and never `git add`-ed is not in any commit
    // tree, so the GitSource (which walks committed trees) never sees it.
    let (_t, repo) = init_repo();
    commit_file(&repo, ".gitignore", b"ignored.env\n", "ignore rule");
    // Create the ignored file but do NOT add/commit it.
    std::fs::write(
        repo.join("ignored.env"),
        b"SECRET=ghp_neverCommitted0000000001\n",
    )
    .expect("write ignored");

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "ignored.env").is_none(),
        "an untracked, ignored file is in no commit tree -> never scanned"
    );
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_neverCommitted0000000001")),
        "its secret must not appear anywhere in git source output"
    );
}

#[test]
fn force_added_ignored_file_is_still_scanned() {
    // `.gitignore` only governs default `git add`. A force-added (`add -f`)
    // ignored file is committed into the tree, and the GitSource walks the
    // tree — so it IS scanned despite the ignore rule.
    let (_t, repo) = init_repo();
    commit_file(&repo, ".gitignore", b"forced.env\n", "ignore rule");
    std::fs::write(
        repo.join("forced.env"),
        b"SECRET=ghp_forceAddedSecret00000001\n",
    )
    .expect("write forced");
    git(&repo, &["add", "-f", "forced.env"]);
    commit_only(&repo, "force add ignored file");

    let chunks = collect_chunks(&repo, 5);
    let c = chunk_for(&chunks, "forced.env").expect("force-added file must be scanned");
    assert!(
        c.data.contains("ghp_forceAddedSecret00000001"),
        "git ignore does not protect a force-committed secret from history scan"
    );
}

// ----------------------------------------------------------------------------
// excluded directory / filename names (KH-59 skip list)
// ----------------------------------------------------------------------------

#[test]
fn node_modules_subtree_is_skipped() {
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "node_modules/pkg/leak.env",
        b"K=ghp_insideNodeModules0000000001\n",
        "vendored dep",
    );
    commit_file(
        &repo,
        "app.env",
        b"K=ghp_appLevelSecret00000000000001\n",
        "app secret",
    );

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "node_modules/pkg/leak.env").is_none(),
        "node_modules subtree must be skipped by name"
    );
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_insideNodeModules0000000001")),
        "no node_modules content may be emitted"
    );
    assert!(
        chunk_for(&chunks, "app.env").is_some(),
        "non-excluded sibling must still be scanned"
    );
}

#[test]
fn each_excluded_dir_name_is_skipped() {
    // All directory names owned by filesystem/filter.rs must drop their
    // subtrees when traversed through GitSource too.
    for dirname in [
        "node_modules",
        "target",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        "dist",
        "build",
        "out",
        ".next",
        ".nuxt",
        "vendor",
        "swagger-ui",
        "swagger",
    ] {
        let (_t, repo) = init_repo();
        let rel = format!("{dirname}/leak.env");
        commit_file(
            &repo,
            &rel,
            b"K=ghp_excludedDirSecret000000000001\n",
            "leak",
        );
        commit_file(
            &repo,
            "keep.env",
            b"K=ghp_keepMe000000000000000000001\n",
            "keep",
        );

        let chunks = collect_chunks(&repo, 5);
        assert!(
            chunk_for(&chunks, &rel).is_none(),
            "{dirname}/ subtree must be skipped"
        );
        assert!(
            !chunks
                .iter()
                .any(|c| c.data.contains("ghp_excludedDirSecret000000000001")),
            "{dirname} content must not be emitted"
        );
        assert!(
            chunk_for(&chunks, "keep.env").is_some(),
            "sibling outside {dirname} must survive"
        );
    }
}

#[test]
fn excluded_name_match_is_exact_not_prefix() {
    // The shared path classifier uses exact path segment matches. A directory
    // named "vendored" or "vendor_libs" is NOT excluded, and a directory named
    // "my_vendor" is NOT excluded. Their blobs must be scanned.
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "vendored/keep.env",
        b"K=ghp_vendoredNotExcluded000001\n",
        "vendored",
    );
    commit_file(
        &repo,
        "buildtools/keep.env",
        b"K=ghp_buildtoolsNotExcluded01\n",
        "buildtools",
    );

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunks
            .iter()
            .any(|c| c.data.contains("ghp_vendoredNotExcluded000001")),
        "'vendored' != 'vendor' so it must NOT be excluded"
    );
    assert!(
        chunks
            .iter()
            .any(|c| c.data.contains("ghp_buildtoolsNotExcluded01")),
        "'buildtools' != 'build' so it must NOT be excluded"
    );
}

#[test]
fn excluded_name_also_skips_plain_files_not_just_dirs() {
    // The shared default-exclude path classifier is path-shaped, so a regular
    // FILE named exactly "vendor", "build", or "out" is skipped too.
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "vendor",
        b"SECRET=ghp_fileNamedVendor00000001\n",
        "file vendor",
    );
    commit_file(
        &repo,
        "build",
        b"SECRET=ghp_fileNamedBuild000000001\n",
        "file build",
    );
    commit_file(
        &repo,
        "out",
        b"SECRET=ghp_fileNamedOut00000000001\n",
        "file out",
    );
    commit_file(&repo, "real.txt", b"ok=1\n", "real");

    let chunks = collect_chunks(&repo, 5);
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_fileNamedVendor00000001")),
        "a file named exactly 'vendor' is skipped by the shared classifier"
    );
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_fileNamedBuild000000001")),
        "a file named exactly 'build' is skipped by the shared classifier"
    );
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_fileNamedOut00000000001")),
        "a file named exactly 'out' is skipped by the shared classifier"
    );
    assert!(chunk_for(&chunks, "real.txt").is_some());
}

#[test]
fn default_excluded_filenames_and_suffixes_are_skipped_by_git_source() {
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "Cargo.lock",
        b"SECRET=ghp_lockfileShouldSkip000001\n",
        "lockfile",
    );
    commit_file(
        &repo,
        "assets/app.js.map",
        b"SECRET=ghp_mapFileShouldSkip000001\n",
        "map",
    );
    commit_file(
        &repo,
        "tsconfig.app.json",
        b"SECRET=ghp_tsconfigShouldSkip0001\n",
        "tsconfig",
    );
    commit_file(
        &repo,
        "src/keep.env",
        b"SECRET=ghp_keepDefaultPolicy000001\n",
        "keep",
    );

    let chunks = collect_chunks(&repo, 10);
    assert!(chunk_for(&chunks, "src/keep.env").is_some());
    for secret in [
        "ghp_lockfileShouldSkip000001",
        "ghp_mapFileShouldSkip000001",
        "ghp_tsconfigShouldSkip0001",
    ] {
        assert!(
            !chunks.iter().any(|chunk| chunk.data.contains(secret)),
            "GitSource must use the filesystem default-exclude owner for {secret}"
        );
    }
}

// ----------------------------------------------------------------------------
// large-blob bound (MAX_GIT_BLOB_BYTES = 10 MiB, strict `>`)
// ----------------------------------------------------------------------------

#[test]
fn blob_over_10_mib_is_skipped() {
    // header.size() > 10 MiB => the blob is skipped before decode. Build an
    // 11 MiB highly-compressible text blob (fast for git to store) with a
    // secret inside; the source must NOT emit it.
    let (_t, repo) = init_repo();
    let big_len = 11 * 1024 * 1024usize;
    let mut big = vec![b'a'; big_len];
    // Put a recognizable token at the end so a (wrong) partial read would
    // still surface it; correct behavior emits nothing for this file.
    big.extend_from_slice(b"\nSECRET=ghp_oversizeBlobShouldSkip01\n");
    commit_file(&repo, "huge.txt", &big, "oversize blob");
    commit_file(
        &repo,
        "small.txt",
        b"K=ghp_smallKept000000000000000001\n",
        "small",
    );

    let chunks = collect_chunks(&repo, 5);
    assert!(
        chunk_for(&chunks, "huge.txt").is_none(),
        "a blob larger than 10 MiB must be skipped (header.size() > MAX_GIT_BLOB_BYTES)"
    );
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_oversizeBlobShouldSkip01")),
        "the oversize blob's content must never reach a chunk"
    );
    assert!(
        chunk_for(&chunks, "small.txt").is_some(),
        "the under-cap sibling must still be scanned"
    );
}

#[test]
fn blob_just_under_10_mib_is_scanned() {
    // Strict `>` bound: a blob of exactly 10 MiB is NOT skipped, and a blob
    // just under it is certainly kept. Use (10 MiB - small) to stay safely
    // under and assert the embedded secret surfaces.
    let (_t, repo) = init_repo();
    let body = b"\nSECRET=ghp_underCapBlobScanned0001\n";
    let pad = 10 * 1024 * 1024 - body.len() - 1; // total < 10 MiB
    let mut blob = vec![b'b'; pad];
    blob.extend_from_slice(body);
    assert!((blob.len() as u64) < 10 * 1024 * 1024);
    commit_file(&repo, "near.txt", &blob, "near cap");

    let chunks = collect_chunks(&repo, 1);
    let c = chunk_for(&chunks, "near.txt").expect("near-cap blob must be scanned");
    assert!(
        c.data.contains("ghp_underCapBlobScanned0001"),
        "a blob just under the 10 MiB cap must be fully scanned"
    );
    assert_eq!(
        c.metadata.size_bytes,
        Some(blob.len() as u64),
        "size_bytes reflects the full under-cap blob size"
    );
}

// ----------------------------------------------------------------------------
// dedup: blob path identity and seen_commits (merge dup)
// ----------------------------------------------------------------------------

#[test]
fn identical_blob_content_is_emitted_once_per_path() {
    // Two distinct paths with byte-identical content share one git blob OID.
    // They are still two operator-visible scan locations; dedup is by
    // (blob-oid, path), not blob-oid alone.
    let (_t, repo) = init_repo();
    let content = b"DUPLICATE=ghp_sameContentTwoFiles01\n";
    std::fs::write(repo.join("first.env"), content).unwrap();
    std::fs::write(repo.join("second.env"), content).unwrap();
    git(&repo, &["add", "first.env", "second.env"]);
    commit_only(&repo, "two files identical content");

    let chunks = collect_chunks(&repo, 1);
    let paths = chunks
        .iter()
        .filter(|c| c.data.contains("ghp_sameContentTwoFiles01"))
        .map(|c| {
            (
                c.metadata.path.clone().expect("duplicate path"),
                c.metadata.source_type.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            ("first.env".to_string(), "git/head".to_string()),
            ("second.env".to_string(), "git/head".to_string())
        ],
        "identical content under different paths must not collapse to one chunk"
    );
}

#[test]
fn renamed_blob_keeps_head_and_history_path_identity() {
    // A pure git rename preserves the blob OID. HEAD contains the new path;
    // history contains the old path. OID-only dedup emits only the new path,
    // and OID-only HEAD labeling misclassifies the old path as git/head.
    let (_t, repo) = init_repo();
    let content = b"RENAMED=ghp_renamePathIdentity00000001\n";
    commit_file(&repo, "old.env", content, "old path");
    git(&repo, &["mv", "old.env", "new.env"]);
    commit_only(&repo, "rename same blob");

    let chunks = collect_chunks(&repo, 5);
    let paths = chunks
        .iter()
        .filter(|c| c.data.contains("ghp_renamePathIdentity00000001"))
        .map(|c| {
            (
                c.metadata.path.clone().expect("renamed path"),
                c.metadata.source_type.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            ("new.env".to_string(), "git/head".to_string()),
            ("old.env".to_string(), "git/history".to_string())
        ],
        "a rename must preserve both path identities with exact HEAD/history labels"
    );
}

#[test]
fn distinct_content_same_basename_in_different_dirs_both_emitted() {
    // Different content => different OIDs => both blobs emitted even though
    // they share a basename. Guards against over-dedup by filename.
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "a/conf.env",
        b"K=ghp_distinctA0000000000000000001\n",
        "a",
    );
    commit_file(
        &repo,
        "b/conf.env",
        b"K=ghp_distinctB0000000000000000001\n",
        "b",
    );

    let chunks = collect_chunks(&repo, 5);
    assert!(chunks
        .iter()
        .any(|c| c.data.contains("ghp_distinctA0000000000000000001")));
    assert!(chunks
        .iter()
        .any(|c| c.data.contains("ghp_distinctB0000000000000000001")));
}

// ----------------------------------------------------------------------------
// multi-ref coverage (git log --all): secret only on a non-HEAD branch
// ----------------------------------------------------------------------------

#[test]
fn secret_only_on_feature_branch_is_found_via_all_refs() {
    // `git log --all --branches --tags` walks every ref, so a secret committed
    // only on a feature branch (never merged to main/HEAD) is still scanned.
    let (_t, repo) = init_repo();
    commit_file(&repo, "main.txt", b"base=1\n", "base on main");
    git(&repo, &["checkout", "-b", "feature"]);
    commit_file(
        &repo,
        "feature.env",
        b"K=ghp_onlyOnFeatureBranch00000001\n",
        "feature secret",
    );
    // Return to main so HEAD does NOT contain the feature blob.
    git(&repo, &["checkout", "main"]);

    let chunks = collect_chunks(&repo, 50);
    let c = chunks
        .iter()
        .find(|c| c.data.contains("ghp_onlyOnFeatureBranch00000001"))
        .expect("feature-branch secret must be found via --all");
    // It is not in HEAD's (main) tree, so it is git/history.
    assert_eq!(
        c.metadata.source_type, "git/history",
        "a feature-branch-only blob is not in HEAD -> git/history"
    );
}

#[test]
fn secret_only_on_tag_is_found() {
    // Tagged-but-not-on-HEAD history is reachable via --tags.
    let (_t, repo) = init_repo();
    commit_file(&repo, "v1.env", b"K=ghp_taggedReleaseSecret0000001\n", "v1");
    git(&repo, &["tag", "v1.0"]);
    // Move HEAD forward, dropping the v1 blob from HEAD's tree.
    commit_file(&repo, "v1.env", b"K=scrubbed\n", "scrub for v2");

    let chunks = collect_chunks(&repo, 50);
    assert!(
        chunks
            .iter()
            .any(|c| c.data.contains("ghp_taggedReleaseSecret0000001")),
        "a secret reachable only through a tag must be scanned via --tags"
    );
}

#[test]
fn secret_only_in_deleted_branch_reflog_is_found() {
    let (_t, repo) = init_repo();
    commit_file(&repo, "main.txt", b"base=1\n", "base on main");
    git(&repo, &["checkout", "-b", "short_lived"]);
    commit_file(
        &repo,
        "reflog.env",
        b"K=ghp_deletedBranchReflogSecret0001\n",
        "deleted branch secret",
    );
    git(&repo, &["checkout", "main"]);
    git(&repo, &["branch", "-D", "short_lived"]);

    let chunks = collect_chunks(&repo, 50);
    let c = chunks
        .iter()
        .find(|c| c.data.contains("ghp_deletedBranchReflogSecret0001"))
        .expect("deleted-branch reflog commit must be scanned");
    assert_eq!(
        c.metadata.source_type, "git/history",
        "a deleted-branch reflog blob is not in HEAD -> git/history"
    );
}

#[test]
fn secret_only_in_stash_is_found() {
    let (_t, repo) = init_repo();
    commit_file(&repo, "main.txt", b"base=1\n", "base on main");
    std::fs::write(
        repo.join("stash.env"),
        b"K=ghp_stashOnlySecretScanned0000001\n",
    )
    .expect("write stash fixture");
    git(
        &repo,
        &["stash", "push", "--include-untracked", "-m", "secret stash"],
    );

    let chunks = collect_chunks(&repo, 50);
    assert!(
        chunks
            .iter()
            .any(|c| c.data.contains("ghp_stashOnlySecretScanned0000001")),
        "refs/stash and its stash parents must be scanned"
    );
}

#[test]
fn secret_only_in_unreachable_commit_is_found() {
    let (_t, repo) = init_repo();
    commit_file(&repo, "main.txt", b"base=1\n", "base on main");
    git(&repo, &["checkout", "-b", "dangling"]);
    commit_file(
        &repo,
        "ghost.env",
        b"K=ghp_unreachableCommitSecret000001\n",
        "dangling secret",
    );
    git(&repo, &["checkout", "main"]);
    git(&repo, &["branch", "-D", "dangling"]);

    let _ = std::fs::remove_file(repo.join(".git/logs/HEAD"));
    let _ = std::fs::remove_file(repo.join(".git/logs/refs/heads/main"));

    let chunks = collect_chunks(&repo, 100);
    assert!(
        chunks
            .iter()
            .any(|c| c.data.contains("ghp_unreachableCommitSecret000001")),
        "git fsck unreachable commit enumeration must feed the same blob scanner"
    );
}

#[test]
fn git_source_commit_enumerator_names_reflog_stash_and_unreachable_coverage() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/git/source.rs"))
            .expect("git source readable");
    assert!(
        source.contains("\"--reflog\"") && source.contains("\"--all\""),
        "GitSource must enumerate reflog commits, not only named refs"
    );
    assert!(
        source.contains("\"refs/stash\""),
        "GitSource must name refs/stash explicitly because --all misses it on current Git"
    );
    assert!(
        source.contains("\"fsck\"")
            && source.contains("\"--unreachable\"")
            && source.contains("\"--no-reflogs\"")
            && source.contains("unreachable commit "),
        "GitSource must enumerate commits that are neither refs nor reflogs"
    );
}

#[test]
fn git_blob_decode_uses_worker_local_parallel_repositories() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/git/source.rs"))
            .expect("git source readable");

    assert!(
        source.contains("decode_git_blob_candidates_parallel")
            && source.contains(".into_par_iter()")
            && source.contains(".map_init(")
            && source.contains("gix::open(&repo_path)"),
        "GitSource blob decoding must use rayon with worker-local gix repositories"
    );
    assert!(
        !source.contains("Serial blob decompression")
            && !source.contains("tracked as a follow-up")
            && !source.contains("let repo_cloned = repo.clone();"),
        "GitSource must not regress to the old serial/shared-repository blob path"
    );
}

#[test]
fn git_source_uses_filesystem_default_exclude_owner() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/git/source.rs"))
            .expect("git source readable");

    assert!(
        source.contains("crate::filesystem::is_default_excluded_path"),
        "GitSource must consume the filesystem default-exclude owner"
    );
    assert!(
        !source.contains("name == b\"node_modules\"")
            && !source.contains("name == b\"target\"")
            && !source.contains("name == b\"vendor\""),
        "GitSource must not carry a private hardcoded excluded-name table"
    );
}

// ----------------------------------------------------------------------------
// max_commits bound
// ----------------------------------------------------------------------------

#[test]
fn max_commits_one_limits_history_walk() {
    // With --max-count 1, only HEAD's commit tree is walked. A secret added in
    // an EARLIER commit but removed from HEAD must NOT appear.
    let (_t, repo) = init_repo();
    commit_file(
        &repo,
        "f.env",
        b"OLD=ghp_oldCommitOnly00000000000001\n",
        "old",
    );
    commit_file(&repo, "f.env", b"OLD=current\n", "new");

    let chunks = collect_chunks(&repo, 1);
    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("ghp_oldCommitOnly00000000000001")),
        "max_commits=1 walks only HEAD's tree; the removed-then older blob is excluded"
    );
    assert!(
        chunks.iter().any(|c| c.data.contains("current")),
        "HEAD's current blob is present"
    );
}

#[test]
fn without_max_commits_full_history_is_walked() {
    // No limit: an older, since-removed secret is still reachable.
    let (_t, repo) = init_repo();
    commit_file(&repo, "g.env", b"OLD=ghp_fullHistoryReachable0001\n", "old");
    commit_file(&repo, "g.env", b"OLD=current\n", "new");

    let bodies: Vec<String> = GitSource::new(repo.clone())
        .chunks() // no with_max_commits
        .map(|r| r.expect("chunk ok"))
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains("ghp_fullHistoryReachable0001")),
        "the full history walk must surface the removed older secret"
    );
}

#[test]
fn parallel_blob_decode_preserves_tree_order_and_metadata() {
    let (_t, repo) = init_repo();
    let expected_paths = (0..64)
        .map(|i| format!("ordered_{i:03}.txt"))
        .collect::<Vec<_>>();

    for (i, path) in expected_paths.iter().enumerate() {
        std::fs::write(repo.join(path), format!("parallel-order-marker-{i:03}\n"))
            .expect("write ordered fixture");
    }
    git(&repo, &["add", "."]);
    let commit = commit_only(&repo, "many ordered blobs");

    let chunks = collect_chunks(&repo, 1);
    let actual_paths = chunks
        .iter()
        .filter_map(|chunk| chunk.metadata.path.as_deref())
        .filter(|path| path.starts_with("ordered_"))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    assert_eq!(
        actual_paths, expected_paths,
        "parallel blob decoding must preserve deterministic Git tree order"
    );

    for (i, path) in expected_paths.iter().enumerate() {
        let chunk = chunk_for(&chunks, path).expect("ordered chunk present");
        assert_eq!(chunk.metadata.source_type, "git/head");
        assert_eq!(chunk.metadata.commit.as_deref(), Some(commit.as_str()));
        assert_eq!(chunk.metadata.author.as_deref(), Some("Gap Author"));
        assert_eq!(
            chunk.metadata.size_bytes,
            Some(format!("parallel-order-marker-{i:03}\n").len() as u64)
        );
        assert!(
            chunk
                .data
                .contains(format!("parallel-order-marker-{i:03}").as_str()),
            "decoded data must belong to the matching ordered path"
        );
    }
}

// ----------------------------------------------------------------------------
// error path: invalid repository path
// ----------------------------------------------------------------------------

#[test]
fn non_repo_directory_yields_single_error_chunk() {
    // validate_repo_path canonicalizes and requires a .git or HEAD; a plain
    // temp dir is not a repo, so chunks() yields exactly one Err and stops.
    let temp = tempfile::tempdir().expect("tempdir");
    let results: Vec<Result<Chunk, SourceError>> =
        GitSource::new(temp.path().to_path_buf()).chunks().collect();
    assert_eq!(
        results.len(),
        1,
        "non-repo path must yield exactly one error item"
    );
    let err = results
        .into_iter()
        .next()
        .unwrap()
        .expect_err("must be Err");
    let msg = err.to_string();
    assert!(
        msg.contains("not a git repository"),
        "error must explain the path is not a repo; got: {msg}"
    );
}

#[test]
fn nonexistent_path_yields_canonicalize_error() {
    // A path that does not exist fails std::fs::canonicalize first.
    let missing = PathBuf::from("/nonexistent/keyhog/gap/repo/path/xyzzy");
    let results: Vec<Result<Chunk, SourceError>> = GitSource::new(missing).chunks().collect();
    assert_eq!(results.len(), 1);
    let err = results
        .into_iter()
        .next()
        .unwrap()
        .expect_err("must be Err");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to canonicalize repo path"),
        "missing path must surface a canonicalize failure; got: {msg}"
    );
}

#[test]
fn repo_path_with_leading_dash_is_rejected() {
    // validate_repo_path rejects a raw path starting with '-' before any fs
    // access (argument-injection guard). Such a path also can't canonicalize,
    // but the check ordering means we still get a clean SourceError.
    let results: Vec<Result<Chunk, SourceError>> =
        GitSource::new(PathBuf::from("-oops")).chunks().collect();
    assert_eq!(results.len(), 1);
    let err = results
        .into_iter()
        .next()
        .unwrap()
        .expect_err("must be Err");
    // Either the unsafe-character guard or the canonicalize failure fires; both
    // are SourceError::Other. Assert it is an error, not a silent empty stream.
    assert!(matches!(err, SourceError::Other(_)));
}

// ----------------------------------------------------------------------------
// stream shape: drained, fused (done flag), no panics on re-poll
// ----------------------------------------------------------------------------

#[test]
fn iterator_is_fused_after_exhaustion() {
    // After the stream ends (done=true), further .next() calls return None.
    let (_t, repo) = init_repo();
    commit_file(&repo, "one.txt", b"v=1\n", "one");

    // Bind the source so `.chunks()` doesn't borrow a temporary dropped at the
    // end of the statement (E0716).
    let src = GitSource::new(repo.clone()).with_max_commits(1);
    let mut iter = src.chunks();
    // Drain.
    let mut count = 0;
    for r in iter.by_ref() {
        r.expect("ok");
        count += 1;
    }
    assert!(count >= 1, "at least the one.txt blob");
    // Re-poll: must keep returning None, not panic or restart.
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
}

#[test]
fn every_emitted_chunk_carries_path_and_commit() {
    // Invariant: GitSource always sets path and commit (Some) on every chunk.
    let (_t, repo) = init_repo();
    commit_file(&repo, "p1.txt", b"a=1\n", "c1");
    commit_file(&repo, "p2.txt", b"b=2\n", "c2");

    let chunks = collect_chunks(&repo, 5);
    assert!(!chunks.is_empty());
    for c in &chunks {
        assert!(c.metadata.path.is_some(), "every git chunk has a path");
        assert!(c.metadata.commit.is_some(), "every git chunk has a commit");
        assert!(c.metadata.author.is_some(), "every git chunk has an author");
        assert!(
            c.metadata.size_bytes.is_some(),
            "every git chunk has size_bytes"
        );
        assert!(
            c.metadata.source_type == "git/head" || c.metadata.source_type == "git/history",
            "source_type is one of the two git buckets; got {:?}",
            c.metadata.source_type
        );
    }
}
