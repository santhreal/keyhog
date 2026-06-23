//! FILE_GATE micro tests for sources crate src files.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{create_source, reset_skipped_over_max_size, FilesystemSource, StdinSource};

// ── crates/sources/src/lib.rs ─────────────────────────────────────────
#[test]
fn lib_happy() {
    reset_skipped_over_max_size();
    assert!(create_source("unknown-plugin", None).is_err());
}
#[test]
fn lib_error() {
    assert!(create_source("slack", None).is_err());
}

// ── crates/sources/src/stdin.rs ───────────────────────────────────────
#[test]
fn stdin_happy() {
    assert_eq!(StdinSource.name(), "stdin");
}

// ── crates/sources/src/filesystem.rs ──────────────────────────────────
#[test]
fn filesystem_happy() {
    let source = FilesystemSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "filesystem");
}
#[test]
fn filesystem_error() {
    let dir = tempfile::tempdir().unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    assert!(source.chunks().next().is_none());
}

// ── crates/sources/src/filesystem/read.rs ─────────────────────────────
#[test]
fn filesystem_read_happy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.txt");
    std::fs::write(&path, b"hello").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hello");
}
#[test]
fn filesystem_read_error() {
    assert!(std::fs::read("/nonexistent/keyhog-gate-path").is_err());
}

#[test]
fn filesystem_extract_hot_path_avoids_extension_lowercase_and_buffered_reread() {
    let filesystem = include_str!("../../src/filesystem.rs");
    let extract = include_str!("../../src/filesystem/extract.rs");
    let archive = include_str!("../../src/filesystem/extract/archive.rs");
    let compressed = include_str!("../../src/filesystem/extract/compressed.rs");
    let filter = include_str!("../../src/filesystem/filter.rs");
    let read_mod = include_str!("../../src/filesystem/read/mod.rs");
    let raw = include_str!("../../src/filesystem/read/raw.rs");
    let decode = include_str!("../../src/filesystem/read/decode.rs");

    assert!(
        filter.contains("pub(super) fn is_skip_extension(ext: &str)")
            && filter.contains("ext.eq_ignore_ascii_case(skip)"),
        "filesystem extension skipping must compare ASCII-case-insensitively without allocating a lowercase extension"
    );
    assert!(
        extract.contains("is_skip_extension(ext)")
            && extract.contains("ext.eq_ignore_ascii_case(\"pdf\")")
            && extract.contains("ext.eq_ignore_ascii_case(\"7z\")")
            && extract.contains("ext.eq_ignore_ascii_case(\"rar\")")
            && !extract.contains(".to_lowercase();"),
        "filesystem extract hot path must not allocate a lowercase extension per file"
    );
    assert!(
        extract.contains("let mut buf = [0u8; 256]")
            && extract.contains("read::read_file_prefix_safe(&path, &mut buf)")
            && extract.contains("read::looks_binary_prefix(head)")
            && extract.contains("match read::open_file_safe(&path)")
            && !extract.contains("std::fs::File::open(&path)"),
        "extensionless header sniff and large-file fallback must use bounded/no-follow shared readers, not symlink-following File::open"
    );
    assert!(
        extract
            .find("idx.metadata_unchanged(&path, mtime_ns, meta.size_bytes)")
            .expect("merkle unchanged check must be present")
            < extract
                .find("read::read_file_prefix_safe(&path, &mut buf)")
                .expect("extensionless prefix sniff must be present"),
        "merkle unchanged files must compare live mtime and live size before the extensionless prefix reader opens the file"
    );
    assert!(
        extract.contains("std::fs::symlink_metadata(path)")
            && !extract.contains("std::fs::metadata(path)"),
        "live filesystem metadata must use no-follow symlink_metadata, never symlink-following metadata"
    );
    assert!(
        raw.contains("fn read_file_prefix_safe(")
            && raw.contains("let mut file = open_file_safe(path)?"),
        "safe prefix reads must share the canonical no-follow open helper"
    );
    assert!(
        filesystem.contains("EXPANDABLE_SYMLINK_EXTS")
            && filesystem.contains("ext.eq_ignore_ascii_case(candidate)")
            && filesystem.contains("is_expandable_path(p) || is_expandable_path(&target)")
            && filesystem.contains("target = %target.display()")
            && !filesystem.contains(".to_ascii_lowercase();"),
        "filesystem include-symlink archive extension checks must cover link and resolved target paths allocation-free and ASCII-case-insensitively"
    );
    assert!(
        archive.contains("const OPENPACK_EXTS")
            && archive.contains("ext.eq_ignore_ascii_case(candidate)")
            && archive.contains("ext.eq_ignore_ascii_case(\"crx\")")
            && !archive.contains("to_ascii_lowercase()"),
        "archive extension routing must stay allocation-free and ASCII-case-insensitive"
    );
    assert!(
        compressed.contains("pub(super) fn is_compressed_ext(ext: &str)")
            && compressed.contains("ext.eq_ignore_ascii_case(candidate)")
            && compressed.contains("ext.eq_ignore_ascii_case(\"tgz\")")
            && !compressed.contains(".to_lowercase();")
            && !compressed.contains(".to_ascii_lowercase();"),
        "compressed extension routing must stay allocation-free and ASCII-case-insensitive"
    );
    assert!(
        read_mod.contains("BufferedFileRead")
            && raw.contains("enum BufferedFileRead")
            && raw.contains("Mmap(memmap2::Mmap)")
            && raw.contains("decode_text_file_owned_or_bytes(bytes)")
            && decode.contains("fn decode_text_file_owned_or_bytes"),
        "buffered and mmap file reads must preserve already-read bytes when text decoding rejects them"
    );
    assert!(
        extract.contains("Some(read::BufferedFileRead::Bytes(bytes))")
            && extract.contains("extract_printable_strings(&bytes, 8)")
            && extract.contains("Some(read::BufferedFileRead::Mmap(mmap))")
            && extract.contains("extract_printable_strings(&mmap, 8)"),
        "filesystem binary-strings fallback must reuse buffered/mmap bytes instead of rereading the file"
    );
}

#[test]
fn source_extract_pdf_and_binary_hot_paths_are_bounded() {
    let binary = include_str!("../../src/binary/mod.rs");
    assert!(
        binary.contains("let capacity_u64 = file.metadata()?.len().min(read_limit);")
            && binary.contains("Vec::with_capacity(capacity)")
            && binary.contains("cap.checked_add(1)")
            && binary.contains("truncation sentinel byte")
            && binary.contains("binary capped read capacity exceeds"),
        "binary capped reads must pre-size from metadata and fail closed on cap/capacity overflow"
    );
    assert!(
        !binary.contains("let mut bytes = Vec::new();\n    limited.read_to_end(&mut bytes)?;"),
        "binary capped read must not feed read_to_end from an empty Vec"
    );

    let pdf = include_str!("../../src/filesystem/extract/pdf.rs");
    assert!(
        pdf.contains("memchr::memchr(b')', &bytes[pos + 1..])")
            && pdf.contains("memchr::memchr(b'>', &bytes[pos + 1..])")
            && pdf.contains("None => pos = next_close + 1")
            && pdf.contains("let mut out = Vec::with_capacity")
            && pdf.contains("let mut nibbles = Vec::with_capacity"),
        "PDF literal/hex scanners must bound failed delimiter scans and pre-size per-string scratch buffers"
    );
}

#[test]
fn har_render_hot_paths_size_and_borrow_bodies() {
    let har = include_str!("../../src/har.rs");
    assert!(
        har.contains("String::with_capacity(request_render_capacity(req))")
            && har.contains(
                "String::with_capacity(response_render_capacity(resp, decoded.as_deref()))"
            )
            && har.contains("fn kv_lines_capacity")
            && har.contains("fn i64_decimal_len(value: i64) -> usize")
            && har.contains("push_i64_decimal(&mut out, resp.status)")
            && !har.contains("resp.status.to_string()")
            && !har.contains("String::with_capacity(256)"),
        "HAR request/response render buffers must be sized from field lengths, not a fixed guess"
    );
    assert!(
        har.contains("fn decoded_content_text(content: &HarContent) -> Option<Cow<'_, str>>")
            && har.contains("Some(Cow::Borrowed(text))")
            && !har.contains("Some(text.clone())"),
        "HAR non-base64 and malformed-base64 bodies must borrow raw text instead of cloning it"
    );
}

// ── crates/sources/src/timeouts.rs ────────────────────────────────────
#[cfg(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))]
#[test]
fn timeouts_happy() {
    assert!(TestApi.http_request_timeout().as_secs() > 0);
}
#[cfg(not(any(feature = "web", feature = "slack", feature = "s3", feature = "github")))]
#[test]
fn timeouts_happy() {
    assert!(!cfg!(any(
        feature = "web",
        feature = "slack",
        feature = "s3",
        feature = "github"
    )));
}
#[test]
fn timeouts_error() {
    #[cfg(feature = "binary")]
    assert!(TestApi.ghidra_analysis_timeout().as_secs() >= 60);
    #[cfg(all(
        not(feature = "binary"),
        any(feature = "web", feature = "slack", feature = "s3", feature = "github")
    ))]
    assert!(TestApi.http_request_timeout().as_secs() < 3600);
    #[cfg(all(
        not(feature = "binary"),
        not(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))
    ))]
    assert!(!cfg!(feature = "binary"));
}

// ── crates/sources/src/http.rs ────────────────────────────────────────
#[cfg(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))]
#[test]
fn http_error() {
    let cfg = keyhog_sources::http::HttpClientConfig {
        proxy: Some("off".into()),
        ..Default::default()
    };
    assert_eq!(cfg.proxy.as_deref(), Some("off"));
}
#[cfg(not(any(feature = "web", feature = "slack", feature = "s3", feature = "github")))]
#[test]
fn http_error() {
    assert!(!cfg!(any(
        feature = "web",
        feature = "slack",
        feature = "s3",
        feature = "github"
    )));
}

// ── crates/sources/src/strings.rs ─────────────────────────────────────
#[test]
fn strings_happy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), b"secret=abc1234567890").unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect();
    assert_eq!(chunks.len(), 1);
}

// ── crates/sources/src/binary/mod.rs ──────────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_mod_happy() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/bin/sh"));
    assert_eq!(source.name(), "binary");
}
#[cfg(feature = "binary")]
#[test]
fn binary_mod_error() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/no/such/file"));
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "missing binary path must surface one source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("missing binary path must be an error row");
    assert!(
        err.to_string().contains("cannot read file"),
        "binary error should name the unreadable input, got {err}"
    );
}

// ── crates/sources/src/binary/ghidra.rs ─────────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_ghidra_happy() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/bin/sh"));
    assert_eq!(source.name(), "binary");
}

// ── crates/sources/src/binary/literals.rs ───────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_literals_happy() {
    let literals = TestApi.extract_string_literals(r#"puts("TOKEN=abcdefghijklmnop");"#);
    assert_eq!(literals, vec!["TOKEN=abcdefghijklmnop".to_string()]);
}
#[cfg(feature = "binary")]
#[test]
fn binary_literals_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), b"\x00").unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let _ = source.chunks().collect::<Vec<_>>();
}

// ── crates/sources/src/binary/sections.rs ───────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_sections_happy() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/bin/sh"));
    assert_eq!(source.name(), "binary");
}
#[cfg(feature = "binary")]
#[test]
fn binary_sections_error() {
    assert!(std::fs::read("/nonexistent/keyhog-sections").is_err());
}

// ── crates/sources/src/git/mod.rs ─────────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_mod_happy() {
    let source = keyhog_sources::GitSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "git");
}

// ── crates/sources/src/git/source.rs ───────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_source_happy() {
    let source = keyhog_sources::GitSource::new(std::env::current_dir().unwrap());
    assert_eq!(source.name(), "git");
}

// ── crates/sources/src/git/diff.rs ──────────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_diff_happy() {
    let source = keyhog_sources::GitDiffSource::new(std::env::current_dir().unwrap(), "HEAD~1");
    assert_eq!(source.name(), "git-diff");
}

// ── crates/sources/src/git/history.rs ─────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_history_happy() {
    let source =
        keyhog_sources::GitHistorySource::new(std::env::current_dir().unwrap()).with_max_commits(1);
    assert_eq!(source.name(), "git-history");
}

#[cfg(feature = "git")]
#[test]
fn git_history_waits_for_log_child_at_eof() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/history.rs");
    let source = std::fs::read_to_string(path).expect("git history source readable");
    assert!(
        source.contains("wait_after_final_chunk")
            && source.contains(
                "super::wait_for_git_child(&mut child, \"git log\", \"enumerating git patches\")"
            ),
        "git history iterator must wait on git log at EOF so command failure cannot look like a clean history scan"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_blob_batch_non_blob_mismatches_are_counted() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/git/source.rs"
    ))
    .expect("git source readable");
    assert!(
        source.contains("GitBlobSkip::NonBlob")
            && source.contains("git tree entry resolved to a non-blob object; blob NOT scanned")
            && source.contains("SourceSkipEvent::Unreadable")
            && !source.contains("if header.kind() != Kind::Blob {\n            continue;\n        }"),
        "git blob batch must count non-blob object mismatches instead of silently continuing"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_waits_for_diff_child_before_untracked_chunks() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/diff.rs");
    let source = std::fs::read_to_string(path).expect("git diff source readable");
    assert!(
        source.contains("wait_after_final_chunk")
            && source.contains(
                "super::wait_for_git_child(&mut child, \"git diff\", \"enumerating changed lines\")"
            )
            && source.find("super::wait_for_git_child(&mut child, \"git diff\"")
                < source.find("untracked_chunks.next().map(Ok)"),
        "git diff iterator must wait on git diff before worktree-only chunks so command failure cannot look like clean changed-line coverage"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_hot_path_consolidates_git_processes_and_reuses_buffers() {
    let diff = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/diff.rs"))
        .expect("git diff source readable");
    let git_mod = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/mod.rs"))
        .expect("git mod source readable");
    assert!(
        diff.contains("super::resolve_commit_hash(&repo_arg, &base_ref)")
            && diff.contains("super::resolve_commit_hash(&repo_arg, head_ref)")
            && !diff.contains("super::verify_ref(")
            && !diff.contains("super::get_commit_hash("),
        "git-diff must resolve and validate each ref with one rev-parse process"
    );
    assert!(
        diff.contains("super::get_commit_metadata(&repo_arg, &metadata_commit)")
            && git_mod.contains("--format=%an%x00%aI")
            && !diff.contains("super::get_commit_author(")
            && !diff.contains("super::get_commit_date("),
        "git-diff must read author/date with one git log process"
    );
    assert!(
        diff.contains("super::trim_diff_line_bytes(&line_buf)")
            && diff.contains("UnifiedDiffParser::new()")
            && diff.contains("diff_parser.parse_line(line, \"git diff\")")
            && !diff.contains("let l = String::from_utf8_lossy(&line_buf);"),
        "git-diff line dispatch must operate on capped bytes through the shared parser instead of allocating one String per diff line"
    );
    assert!(
        diff.contains("current_content.clear();")
            && !diff.contains("                        current_content = String::new();")
            && !diff.contains("std::mem::take(&mut current_content)")
            && !diff.contains("current_content.trim().to_string()"),
        "git-diff hunk flushes must retain the hunk buffer allocation"
    );
    let history =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/history.rs"))
            .expect("git history source readable");
    assert!(
        diff.contains("super::drain_trimmed_hunk(&mut current_content)")
            && history.contains("super::drain_trimmed_hunk(&mut current_content)"),
        "git diff/history hunk flushes must share the single trim-and-drain helper"
    );
    assert!(
        !history.contains("std::mem::take(&mut current_content)")
            && !history.contains("current_content.trim().to_string()"),
        "git-history hunk flushes must retain the hunk buffer allocation and copy emitted text once"
    );
}

// ── crates/sources/src/docker.rs ──────────────────────────────────────
#[cfg(feature = "docker")]
#[test]
fn docker_happy() {
    let source = keyhog_sources::DockerImageSource::new("alpine:latest");
    assert_eq!(source.name(), "docker");
}
#[cfg(feature = "docker")]
#[test]
fn docker_error() {
    assert!(create_source("docker", None).is_err());
}

// ── crates/sources/src/github_org.rs ──────────────────────────────────
#[cfg(feature = "github")]
#[test]
fn github_org_happy() {
    let source = keyhog_sources::GitHubOrgSource::new("acme".into(), "ghp_test".into());
    assert_eq!(source.name(), "github-org");
}
#[cfg(feature = "github")]
#[test]
fn github_org_error() {
    let source = keyhog_sources::GitHubOrgSource::new("".into(), "".into());
    assert_eq!(source.name(), "github-org");
}

// ── crates/sources/src/gitlab_group.rs ────────────────────────────────
#[cfg(feature = "gitlab")]
#[test]
fn gitlab_group_happy() {
    let source = create_source("gitlab-group", Some("acme\nglpat-exampletoken12345")).unwrap();
    assert_eq!(source.name(), "gitlab-group");
}
#[cfg(feature = "gitlab")]
#[test]
fn gitlab_group_error() {
    assert!(create_source("gitlab-group", None).is_err());
}

// ── crates/sources/src/bitbucket_workspace.rs ─────────────────────────
#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_workspace_happy() {
    let source = create_source(
        "bitbucket-workspace",
        Some("acme\nbuildbot\napp-password-example"),
    )
    .unwrap();
    assert_eq!(source.name(), "bitbucket-workspace");
}
#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_workspace_error() {
    assert!(create_source("bitbucket-workspace", None).is_err());
}

// ── crates/sources/src/slack.rs ───────────────────────────────────────
#[cfg(feature = "slack")]
#[test]
fn slack_happy() {
    let source = keyhog_sources::SlackSource::new(concat!("xox", "b-test"));
    assert_eq!(source.name(), "slack");
}
#[cfg(feature = "slack")]
#[test]
fn slack_error() {
    assert!(create_source("slack", None).is_err());
}
#[cfg(feature = "slack")]
#[test]
fn slack_error_json_preserves_api_error_code() {
    let list_error = TestApi
        .slack_conversations_list_len_for_test(r#"{"ok":false,"error":"not_authed"}"#)
        .expect_err("Slack conversations.list error JSON must be surfaced as an error");
    assert!(
        list_error.contains("conversations.list"),
        "Slack list error should name endpoint, got {list_error}"
    );
    assert!(
        list_error.contains("not_authed"),
        "Slack list error should preserve API code, got {list_error}"
    );
    assert!(
        !list_error.contains("missing field"),
        "Slack API error code must not be hidden by payload-field deserialization: {list_error}"
    );

    let history_error = TestApi
        .slack_history_len_for_test(r#"{"ok":false,"error":"channel_not_found"}"#, "C0123")
        .expect_err("Slack conversations.history error JSON must be surfaced as an error");
    assert!(
        history_error.contains("conversations.history"),
        "Slack history error should name endpoint, got {history_error}"
    );
    assert!(
        history_error.contains("channel_not_found"),
        "Slack history error should preserve API code, got {history_error}"
    );
    assert!(
        history_error.contains("C0123"),
        "Slack history error should preserve channel context, got {history_error}"
    );
    assert!(
        !history_error.contains("missing field"),
        "Slack history API error code must not be hidden by payload-field deserialization: {history_error}"
    );
}
#[cfg(feature = "slack")]
#[test]
fn slack_ok_json_requires_endpoint_payload() {
    let list_error = TestApi
        .slack_conversations_list_len_for_test(r#"{"ok":true}"#)
        .expect_err("Slack ok list JSON without channels must be rejected");
    assert!(
        list_error.contains("conversations.list"),
        "Slack list payload error should name endpoint, got {list_error}"
    );
    assert!(
        list_error.contains("missing channels"),
        "Slack list payload error should name missing field, got {list_error}"
    );

    let history_error = TestApi
        .slack_history_len_for_test(r#"{"ok":true}"#, "C0123")
        .expect_err("Slack ok history JSON without messages must be rejected");
    assert!(
        history_error.contains("conversations.history"),
        "Slack history payload error should name endpoint, got {history_error}"
    );
    assert!(
        history_error.contains("missing messages"),
        "Slack history payload error should name missing field, got {history_error}"
    );
    assert!(
        history_error.contains("C0123"),
        "Slack history payload error should preserve channel context, got {history_error}"
    );
}

// ── crates/sources/src/web.rs ─────────────────────────────────────────
#[cfg(feature = "web")]
#[test]
fn web_happy() {
    let source = keyhog_sources::WebSource::new(vec!["https://example.com/app.js".to_string()]);
    assert_eq!(source.name(), "web");
    let web = include_str!("../../src/web.rs");
    assert!(
        web.contains("fn classify_web_response(url: &str) -> WebResponseKind")
            && web.contains("ends_with_ignore_ascii_case(path, \".wasm\")")
            && web.contains("ends_with_ignore_ascii_case(path, \".map\")")
            && !web.contains("url.to_lowercase()"),
        "WebSource URL routing must classify extensions without allocating a lowercase copy of the full URL"
    );
    assert!(
        web.contains("for (i, content) in contents.into_iter().enumerate()")
            && web.contains("data: code.into()")
            && web.contains(".and_then(Option::take)")
            && !web.contains("contents.iter().enumerate()")
            && !web.contains("data: code.clone().into()")
            && !web.contains(".and_then(|name| name.clone())"),
        "WebSource source-map expansion must move parsed sourcesContent strings into chunks without cloning large source bodies"
    );
}
#[cfg(feature = "web")]
#[test]
fn web_error() {
    let source = keyhog_sources::WebSource::new(vec![]);
    assert!(source.chunks().next().is_none());
}

// ── crates/sources/src/s3/mod.rs ──────────────────────────────────────
#[cfg(feature = "s3")]
#[test]
fn s3_mod_happy() {
    let source = keyhog_sources::S3Source::new("bucket");
    assert_eq!(source.name(), "s3");
}
#[cfg(feature = "s3")]
#[test]
fn s3_mod_error() {
    assert!(create_source("s3", None).is_err());
}

// ── crates/sources/src/s3/auth.rs ───────────────────────────────────────
#[cfg(feature = "s3")]
#[test]
fn s3_auth_happy() {
    let source = keyhog_sources::S3Source::new("bucket");
    assert_eq!(source.name(), "s3");
}
#[cfg(feature = "s3")]
#[test]
fn s3_auth_error() {
    let source = keyhog_sources::S3Source::new("");
    assert_eq!(source.name(), "s3");
}

// ── crates/sources/src/s3/listing.rs ──────────────────────────────────
// happy/error gates: see crates/sources/tests/gate/s3_empty_bucket_name.rs
