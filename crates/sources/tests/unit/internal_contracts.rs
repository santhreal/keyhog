use keyhog_sources::testing::{SourceTestApi, TestApi};

#[cfg(feature = "binary")]
static BINARY_SECTION_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(feature = "github")]
static GITHUB_SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(feature = "gitlab")]
static GITLAB_SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(feature = "bitbucket")]
static BITBUCKET_SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn core_windows_verbatim_prefix_contracts() {
    assert_eq!(
        keyhog_core::strip_windows_verbatim_prefix(r"\\?\C:\Users\me\src\app.env"),
        r"C:\Users\me\src\app.env"
    );
    assert_eq!(
        keyhog_core::strip_windows_verbatim_prefix(r"C:\Users\me"),
        r"C:\Users\me"
    );
    assert_eq!(
        keyhog_core::strip_windows_verbatim_prefix("/home/me/src/app.env"),
        "/home/me/src/app.env"
    );
    assert_eq!(
        keyhog_core::strip_windows_verbatim_prefix(r"\\?\UNC\server\share\file"),
        r"UNC\server\share\file"
    );
}

#[test]
fn sources_path_display_has_no_private_windows_verbatim_strip() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let filesystem = std::fs::read_to_string(root.join("src/filesystem.rs"))
        .expect("read filesystem module source");
    let path = std::fs::read_to_string(root.join("src/filesystem/path.rs"))
        .expect("read filesystem path source");
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("read sources lib");

    assert!(
        path.contains("keyhog_core::strip_windows_verbatim_prefix"),
        "filesystem display_path must call the canonical keyhog-core display helper"
    );
    assert!(
        !path.contains("fn strip_unc_prefix") && !filesystem.contains("strip_unc_prefix"),
        "sources must not own or re-export a duplicate strip_unc_prefix helper"
    );
    assert!(
        !lib.contains("strip_unc_prefix"),
        "sources testing facade must not expose the removed duplicate helper"
    );
    assert_eq!(
        path.matches(r#"strip_prefix(r"\\?\")"#).count(),
        0,
        "sources must not implement Windows verbatim-prefix stripping directly"
    );
}

#[test]
fn sources_testing_facade_is_direct_module_reexport() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("read sources lib");

    assert!(
        lib.contains("pub use testing_facade::testing;"),
        "sources should expose the testing module directly instead of wrapping a second facade"
    );
    assert!(
        !lib.contains("pub mod testing {\n    pub use crate::testing_facade::testing::*;\n}"),
        "sources lib.rs must not reintroduce a facade-of-facade testing shell"
    );
}

#[test]
fn sources_lib_rs_is_module_map_not_mixed_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("read sources lib");
    let skip = std::fs::read_to_string(root.join("src/skip.rs")).expect("read skip owner");
    let factory =
        std::fs::read_to_string(root.join("src/factory.rs")).expect("read source factory owner");
    let decode = std::fs::read_to_string(root.join("src/decode.rs")).expect("read decode owner");

    assert!(
        lib.contains("mod skip;") && lib.contains("mod factory;") && lib.contains("mod decode;"),
        "sources lib.rs must wire skip/factory/decode owners explicitly"
    );
    assert!(
        skip.contains("pub struct SkipCounts")
            && skip.contains("pub(crate) enum SourceSkipEvent")
            && skip.contains("fn counter(self)")
            && skip.contains("pub fn skip_counts()"),
        "skip.rs must own source coverage counters and typed skip recording"
    );
    assert!(
        factory.contains("pub fn create_source_with_http_config_and_limits")
            && factory.contains("match name")
            && factory.contains("fn optional_usize_source_param"),
        "factory.rs must own source construction and source parameter parsing"
    );
    assert!(
        decode.contains("pub fn decode_file_bytes")
            && decode.contains("crate::filesystem::decode_text_file"),
        "decode.rs must own the public filesystem-decoder facade"
    );
    for forbidden in [
        "static SKIPPED_",
        "enum SourceSkipEvent",
        "match name {",
        "fn optional_usize_source_param",
        "pub fn decode_file_bytes",
    ] {
        assert!(
            !lib.contains(forbidden),
            "sources lib.rs must stay a module map/re-export root, found {forbidden:?}"
        );
    }
}

#[test]
fn filesystem_binary_strings_empty_branches_are_counted() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let extract = std::fs::read_to_string(root.join("src/filesystem/extract.rs"))
        .expect("read filesystem extract owner");
    assert!(
        extract.contains("fn record_binary_without_printable_strings")
            && extract.contains("SourceSkipEvent::Binary"),
        "filesystem extraction must own one binary-without-strings skip counter helper"
    );

    for rel in [
        "src/filesystem/extract.rs",
        "src/filesystem/extract/archive.rs",
        "src/filesystem/extract/compressed.rs",
        "src/filesystem/extract/seven_zip.rs",
    ] {
        let src = std::fs::read_to_string(root.join(rel)).expect("read filesystem extractor");
        for (idx, _) in src.match_indices("if strings.is_empty()") {
            let tail = &src[idx..src.len().min(idx + 180)];
            assert!(
                tail.contains("record_binary_without_printable_strings"),
                "{rel} has a binary strings-empty branch that does not count skipped binary coverage"
            );
        }
    }
}

#[test]
fn cloud_object_fetch_pool_is_single_shared_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cloud = std::fs::read_to_string(root.join("src/cloud/mod.rs")).expect("read cloud owner");
    let blocking_thread =
        std::fs::read_to_string(root.join("src/blocking_thread.rs")).expect("read thread owner");
    let parallel =
        std::fs::read_to_string(root.join("src/parallel_fetch.rs")).expect("read fetch owner");
    assert!(
        parallel.contains("CLOUD_OBJECT_FETCH_THREADS")
            && parallel.contains("REMOTE_API_FETCH_THREADS")
            && parallel.contains("fn bounded_fetch_pool")
            && parallel.matches("ThreadPoolBuilder::new()").count() == 1,
        "parallel_fetch.rs must be the single bounded remote-fetch Rayon pool builder owner"
    );
    assert!(
        cloud.contains("OBJECT_FETCH_THREADS") && cloud.contains("fn object_fetch_pool"),
        "cloud/mod.rs must own the shared cloud object-fetch pool and thread cap"
    );
    assert!(
        blocking_thread.contains("fn collect_on_blocking_thread")
            && cloud.contains("fn blocking_client")
            && cloud.contains("fn parse_http_endpoint")
            && cloud.contains("fn credential_forward_allowed"),
        "blocking_thread.rs and cloud/mod.rs must own shared remote thread, cloud client, endpoint, and credential-forward primitives"
    );

    for rel in ["src/s3/mod.rs", "src/gcs.rs", "src/cloud/azure_blob.rs"] {
        let source = std::fs::read_to_string(root.join(rel)).expect("read cloud source");
        assert!(
            source.contains("object_fetch_pool("),
            "{rel} must use the shared cloud object-fetch pool"
        );
        assert_eq!(
            source.matches("ThreadPoolBuilder::new()").count(),
            0,
            "{rel} must not rebuild a Rayon pool inside its pagination loop"
        );
        assert!(
            source.contains("collect_on_blocking_thread("),
            "{rel} must use the shared cloud blocking-thread wrapper"
        );
        assert!(
            source.contains("blocking_client("),
            "{rel} must use the shared cloud blocking-client builder"
        );
        assert_eq!(
            source.matches("std::thread::scope").count(),
            0,
            "{rel} must not own a private scoped-thread wrapper"
        );
        assert_eq!(
            source.matches("blocking_client_builder(").count(),
            0,
            "{rel} must not build blocking HTTP clients outside cloud/mod.rs"
        );
        assert!(
            !source.contains("http.timeout = Some(crate::timeouts::HTTP_REQUEST)"),
            "{rel} must not own private cloud HTTP timeout fallback wiring"
        );
        assert!(
            !source.contains("fn credential_forward_allowed("),
            "{rel} must not own a private credential-forward policy helper"
        );
        assert!(
            source.contains("parse_http_endpoint("),
            "{rel} must route endpoint shape parsing through cloud/mod.rs"
        );
        assert!(
            source.contains("read_text_object_body("),
            "{rel} must use the shared cloud text-object response reader"
        );
        assert!(
            source.contains("take_listing_page("),
            "{rel} must use the shared cloud listing page cap helper"
        );
        assert!(
            source.contains("push_page_chunks("),
            "{rel} must use the shared cloud page chunk drain helper"
        );
        for forbidden in [
            ".take(max_object_bytes + 1)",
            ".take(max_blob_bytes + 1)",
            "String::from_utf8(body)",
            "response.content_length()",
            ".into_iter().take(remaining).collect()",
            "for result in page_chunks {",
            "Ok(Some(chunk)) => chunks.push(Ok(chunk))",
        ] {
            assert!(
                !source.contains(forbidden),
                "{rel} must not own duplicated cloud body/page handling `{forbidden}`"
            );
        }
    }

    for rel in ["src/slack.rs", "src/hosted_git.rs", "src/cloud/mod.rs"] {
        let source = std::fs::read_to_string(root.join(rel)).expect("read remote source");
        assert!(
            source.contains("bounded_fetch_pool("),
            "{rel} must use the shared bounded remote-fetch pool owner"
        );
        assert_eq!(
            source.matches("ThreadPoolBuilder::new()").count(),
            0,
            "{rel} must not own private Rayon pool builders"
        );
    }

    let web = std::fs::read_to_string(root.join("src/web.rs")).expect("read web source");
    assert!(
        web.contains("blocking_thread::collect_on_blocking_thread(\"web\""),
        "web source must use the shared blocking-thread wrapper"
    );
    assert_eq!(
        web.matches("std::thread::scope").count(),
        0,
        "web source must not own a private scoped-thread wrapper"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_collect_is_phase_orchestrator() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/docker.rs")).expect("read docker source");
    let collect = source
        .split("fn collect_docker_chunks(")
        .nth(1)
        .expect("collect_docker_chunks must exist")
        .split("struct DockerScanWorkspace")
        .next()
        .expect("collect_docker_chunks section must be bounded");

    for required in [
        "struct DockerScanWorkspace",
        "fn resolve_docker_binary(",
        "fn collect_docker_layer_chunks(",
        "fn scan_docker_layer(",
        "fn docker_layer_name(",
    ] {
        assert!(
            source.contains(required),
            "docker.rs must keep {required} as an explicit Docker collection phase boundary"
        );
    }

    for required_call in [
        "DockerScanWorkspace::new()",
        "resolve_docker_binary()",
        "find_manifest_config_chunks(",
        "collect_docker_layer_chunks(",
    ] {
        assert!(
            collect.contains(required_call),
            "collect_docker_chunks must orchestrate through {required_call}"
        );
    }

    for forbidden in [
        "tempfile::tempdir(",
        "tempfile::Builder::new()",
        "resolve_safe_bin(\"docker\")",
        "for layer_tar in",
        "unpack_layer_archive(",
        "FilesystemSource::new(",
        "sanitize_layer_name(",
    ] {
        assert!(
            !collect.contains(forbidden),
            "collect_docker_chunks must not own Docker workspace/export/layer implementation detail `{forbidden}`"
        );
    }
}

#[cfg(feature = "git")]
#[test]
fn git_hunk_headers_must_not_default_to_line_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let git_mod = std::fs::read_to_string(root.join("src/git/mod.rs")).expect("read git owner");
    assert!(
        git_mod.contains("fn parse_hunk_new_start_or_error")
            && git_mod.contains("refusing to guess line 1"),
        "git/mod.rs must own a loud hunk-header parser for line attribution"
    );

    for rel in ["src/git/diff.rs", "src/git/history.rs"] {
        let source = std::fs::read_to_string(root.join(rel)).expect("read git source");
        assert!(
            source.contains("parse_hunk_new_start_or_error"),
            "{rel} must fail on malformed hunk headers instead of inventing a base line"
        );
        assert!(
            !source.contains("parse_hunk_new_start(&line).unwrap_or(1)")
                && !source.contains("parse_hunk_new_start(&line).unwrap_or_else"),
            "{rel} must not resurrect the silent line-1 fallback"
        );
    }
}

#[test]
fn http_user_agent_contracts() {
    let ua = TestApi.user_agent(None);
    assert!(ua.starts_with("keyhog/"));
    assert!(ua.contains(env!("CARGO_PKG_VERSION")));
    assert!(TestApi.user_agent(Some("web")).contains("(web)"));
}

#[cfg(feature = "binary")]
#[test]
fn binary_literal_extraction_contracts() {
    let literal = TestApi.extract_string_literals(r#"x = "abcdefghij\é klmnop";"#);
    assert_eq!(literal.len(), 1, "expected one literal, got {literal:?}");
    assert!(literal[0].contains("abcdefghij"));

    assert_eq!(
        TestApi.extract_string_literals(r#"puts("hello\tworld\n");"#),
        vec!["hello\tworld\n".to_string()]
    );

    assert!(TestApi.extract_string_literals("\"abc\"").is_empty());
    assert!(TestApi.extract_string_literals("").is_empty());
    assert!(TestApi.extract_string_literals("\"").is_empty());
    assert!(TestApi.extract_string_literals("\"\"").is_empty());
}

#[cfg(feature = "binary")]
#[test]
fn binary_section_extraction_rejects_bad_inputs_without_panic() {
    assert!(TestApi
        .extract_sections(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc], "junk.bin")
        .is_none());
    assert!(TestApi.extract_sections(&[], "empty.bin").is_none());

    let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    bytes.extend(std::iter::repeat(0xFF).take(120));
    let _ = TestApi.extract_sections(&bytes, "trunc.elf");
}

#[cfg(feature = "binary")]
#[test]
fn binary_unresolvable_section_name_bumps_partial_parse_counter() {
    let _guard = BINARY_SECTION_COUNTER_GUARD.lock().expect("counter guard");
    TestApi.set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = TestApi.resolve_binary_section_name(None, 42);
    assert_eq!(name, "", "an unresolvable name yields the empty string");
    assert_eq!(
        keyhog_sources::skip_counts().binary_section_name_unresolved,
        1,
        "a corrupt-strtab name lookup must bump the loud partial-parse counter exactly once"
    );
}

#[cfg(feature = "binary")]
#[test]
fn binary_legitimate_unnamed_section_does_not_bump_counter() {
    let _guard = BINARY_SECTION_COUNTER_GUARD.lock().expect("counter guard");
    TestApi.set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = TestApi.resolve_binary_section_name(None, 0);
    assert_eq!(name, "");
    assert_eq!(
        keyhog_sources::skip_counts().binary_section_name_unresolved,
        0,
        "sh_name==0 is the strtab's empty entry, not an anomaly; counter must stay 0"
    );
}

#[cfg(feature = "binary")]
#[test]
fn binary_resolved_section_name_passes_through_without_counting() {
    let _guard = BINARY_SECTION_COUNTER_GUARD.lock().expect("counter guard");
    TestApi.set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = TestApi.resolve_binary_section_name(Some(".rodata"), 7);
    assert_eq!(name, ".rodata");
    assert_eq!(
        keyhog_sources::skip_counts().binary_section_name_unresolved,
        0
    );
}

#[cfg(feature = "github")]
#[test]
fn github_repo_name_and_clone_url_contracts() {
    for ok in ["santhsecurity", "SanthSecurity", "santh-security", "a0"].into_iter() {
        assert!(
            TestApi.validate_org_name(ok).is_ok(),
            "should accept org {ok:?}"
        );
    }

    for bad in [
        "",
        "-leading",
        "trailing-",
        "org/repo",
        "org?per_page=1",
        "org#frag",
        "org name",
        "org_name",
        ".dot",
    ] {
        assert!(
            TestApi.validate_org_name(bad).is_err(),
            "should reject org {bad:?}"
        );
    }
    let too_long_org = "x".repeat(40);
    assert!(TestApi.validate_org_name(&too_long_org).is_err());

    for ok in ["keyhog", "keyhog.rs", "Cool-Repo_2", "a"].into_iter() {
        assert!(
            TestApi.validate_repo_name(ok).is_ok(),
            "should accept {ok:?}"
        );
    }
    let long_ok = "x".repeat(100);
    assert!(TestApi.validate_repo_name(&long_ok).is_ok());

    for bad in [
        "..",
        ".",
        "",
        "../etc/passwd",
        "subdir/repo",
        "back\\slash",
        "weird*name",
        "name with space",
    ] {
        assert!(
            TestApi.validate_repo_name(bad).is_err(),
            "should reject {bad:?}"
        );
    }
    let too_long = "x".repeat(101);
    assert!(TestApi.validate_repo_name(&too_long).is_err());

    for ok in [
        "https://github.com/santhsecurity/keyhog.git",
        "https://ghe.example.com/org/repo.git",
    ] {
        assert!(
            TestApi.validate_clone_url(ok).is_ok(),
            "should accept {ok:?}"
        );
    }

    for bad in [
        "ext::sh -c whoami",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "file:///etc/passwd",
        "http://insecure.example/repo.git",
        "https://user:secret@example.com/repo.git",
        "https://example.com/repo.git?token=secret",
        "https://example.com/repo.git#secret",
        "https://a&calc.com/repo.git",
        "https://127.0.0.1/repo.git",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/repo.git",
        "https://example.com/repo with space.git",
        "https://example.com/repo\nwith\nnewlines",
    ] {
        assert!(
            TestApi.validate_clone_url(bad).is_err(),
            "should reject {bad:?}"
        );
    }
}

#[cfg(feature = "github")]
#[test]
fn github_org_rewrite_preserves_offsets_and_requires_real_repo_relative_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("src").join("secret.env");
    std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
    std::fs::write(
        &file,
        b"AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890abcd",
    )
    .expect("write");

    let chunk = keyhog_core::Chunk {
        data: "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890abcd".into(),
        metadata: keyhog_core::ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(file.display().to_string()),
            base_offset: 8192,
            base_line: 77,
            size_bytes: Some(64),
            mtime_ns: Some(1234),
            decoded_span: Some((4, 12)),
            ..Default::default()
        },
    };

    let rewritten = TestApi
        .github_org_rewrite_chunk_path(chunk, "santhsecurity", "keyhog", dir.path())
        .expect("rewrite succeeds");
    assert_eq!(rewritten.metadata.source_type, "github-org");
    assert_eq!(
        rewritten.metadata.path.as_deref(),
        Some("santhsecurity/keyhog/src/secret.env")
    );
    assert_eq!(rewritten.metadata.base_offset, 8192);
    assert_eq!(rewritten.metadata.base_line, 77);
    assert_eq!(rewritten.metadata.size_bytes, Some(64));
    assert_eq!(rewritten.metadata.mtime_ns, Some(1234));
    assert_eq!(rewritten.metadata.decoded_span, Some((4, 12)));
}

#[cfg(feature = "github")]
#[test]
fn github_org_rewrite_fails_loud_for_missing_or_outside_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("outside file");

    let missing_path_chunk = keyhog_core::Chunk {
        data: "x".into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };
    let err = TestApi
        .github_org_rewrite_chunk_path(missing_path_chunk, "santhsecurity", "keyhog", dir.path())
        .expect_err("missing path must be an error");
    assert!(
        err.to_string().contains("without a file path"),
        "unexpected missing-path error: {err}"
    );

    let outside_chunk = keyhog_core::Chunk {
        data: "x".into(),
        metadata: keyhog_core::ChunkMetadata {
            path: Some(outside.path().display().to_string()),
            ..Default::default()
        },
    };
    let err = TestApi
        .github_org_rewrite_chunk_path(outside_chunk, "santhsecurity", "keyhog", dir.path())
        .expect_err("outside path must be an error");
    assert!(
        err.to_string().contains("outside clone root"),
        "unexpected outside-root error: {err}"
    );
}

#[cfg(feature = "github")]
#[test]
fn github_org_scan_repo_chunks_propagates_source_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = TestApi
        .github_org_scan_repo_chunks(
            vec![Err(keyhog_core::SourceError::Other(
                "reader exploded".into(),
            ))],
            "santhsecurity",
            "keyhog",
            dir.path(),
        )
        .expect_err("source error must propagate");
    assert!(
        err.to_string().contains("reader exploded"),
        "unexpected propagated error: {err}"
    );
}

#[cfg(feature = "github")]
#[test]
fn github_org_listing_cap_counts_and_fails_loud() {
    let _guard = GITHUB_SKIP_COUNTER_GUARD
        .lock()
        .expect("github counter guard");
    TestApi.reset_skip_counters();
    let err = TestApi.github_org_listing_truncated_error("santhsecurity", 100_000, 1_000);
    assert!(
        err.to_string()
            .contains("refusing to scan a partial organization"),
        "unexpected truncation error: {err}"
    );
    assert_eq!(
        keyhog_sources::skip_counts().source_truncated,
        1,
        "repo-list page cap must record a partial-coverage source event"
    );
}

#[cfg(feature = "gitlab")]
#[test]
fn gitlab_group_validation_and_listing_cap_contracts() {
    for ok in ["santhsecurity", "platform/sub-group", "a.b_c-d"].into_iter() {
        assert!(
            TestApi.validate_gitlab_group_path(ok).is_ok(),
            "should accept group {ok:?}"
        );
    }

    for bad in ["", "/root", "root/", "root//child", "../root", "root child"] {
        assert!(
            TestApi.validate_gitlab_group_path(bad).is_err(),
            "should reject group {bad:?}"
        );
    }

    let _guard = GITLAB_SKIP_COUNTER_GUARD
        .lock()
        .expect("gitlab counter guard");
    TestApi.reset_skip_counters();
    let err = TestApi.gitlab_group_listing_truncated_error("santhsecurity", 100_000, 1_000);
    assert!(
        err.to_string()
            .contains("partial group repository collection"),
        "unexpected truncation error: {err}"
    );
    assert_eq!(
        keyhog_sources::skip_counts().source_truncated,
        1,
        "GitLab page cap must record a partial-coverage source event"
    );
}

#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_workspace_validation_and_listing_cap_contracts() {
    for ok in ["santhsecurity", "platform-team", "team_1"].into_iter() {
        assert!(
            TestApi.validate_bitbucket_workspace(ok).is_ok(),
            "should accept workspace {ok:?}"
        );
    }

    for bad in ["", "/root", "root/repo", "root child", "root?pagelen=1"] {
        assert!(
            TestApi.validate_bitbucket_workspace(bad).is_err(),
            "should reject workspace {bad:?}"
        );
    }

    let _guard = BITBUCKET_SKIP_COUNTER_GUARD
        .lock()
        .expect("bitbucket counter guard");
    TestApi.reset_skip_counters();
    let err = TestApi.bitbucket_workspace_listing_truncated_error("santhsecurity", 100_000, 1_000);
    assert!(
        err.to_string()
            .contains("partial workspace repository collection"),
        "unexpected truncation error: {err}"
    );
    assert_eq!(
        keyhog_sources::skip_counts().source_truncated,
        1,
        "Bitbucket page cap must record a partial-coverage source event"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_host_and_redaction_contracts() {
    for blocked in [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.5/",
        "http://[::1]/",
        "http://localhost/",
        "http://machine.local/",
        "http://svc.internal/api",
        "not a url",
        "file:///etc/passwd",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:10.0.0.1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:192.168.1.1]/",
        "http://[::ffff:172.16.0.5]/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://017700000001/",
        "http://127.1/",
        "http://0X7F000001/",
        "http://0x7f.0177.0.1/",
        "http://%31%32%37%2e%30%2e%30%2e%31/",
    ] {
        assert!(
            TestApi.is_disallowed_web_host(blocked),
            "should block {blocked:?}"
        );
    }

    for allowed in [
        "https://example.com/",
        "https://cdn.jsdelivr.net/app.js",
        "https://api.github.com/repos/foo/bar",
    ] {
        assert!(
            !TestApi.is_disallowed_web_host(allowed),
            "should allow {allowed:?}"
        );
    }

    assert_eq!(
        TestApi.redact_url("https://user:SECRET@host/path"),
        "https://***@host/path"
    );
    assert_eq!(
        TestApi.redact_url("https://user@host/path?q=1"),
        "https://***@host/path?q=1"
    );
    assert_eq!(
        TestApi.redact_url("http://x:y@example.com:8080/p#frag"),
        "http://***@example.com:8080/p#frag"
    );
    let path_at = "https://example.com/orgs/foo/users/@me";
    assert_eq!(TestApi.redact_url(path_at), path_at);
}

#[cfg(feature = "web")]
#[test]
fn web_ssrf_url_classifier_uses_verifier_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ssrf =
        std::fs::read_to_string(root.join("src/web/ssrf.rs")).expect("web ssrf source readable");
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).expect("sources Cargo readable");
    let http = std::fs::read_to_string(root.join("src/http.rs")).expect("sources HTTP readable");

    assert!(
        ssrf.contains("keyhog_verifier::ssrf::is_private_url(url)"),
        "WebSource URL-string SSRF classification must call the verifier owner"
    );
    assert!(
        !ssrf.contains("KEYHOG_AUTOROUTE_CALIBRATE") && !ssrf.contains("std::env::"),
        "WebSource calibration must be explicit caller state, not an ambient env read"
    );
    assert!(
        !ssrf.contains("url::Host::Domain")
            && !ssrf.contains("metadata.google.internal")
            && !ssrf.contains("ends_with(\".internal\")"),
        "WebSource must not keep a second domain/metadata suffix classifier"
    );
    assert!(
        !cargo.contains(r#"web = ["dep:reqwest", "dep:url", "dep:keyhog-verifier"]"#)
            && !cargo.contains("[dependencies.url]\n"),
        "keyhog-sources no longer needs a direct url crate dependency for the WebSource SSRF prefilter"
    );
    assert!(
        http.contains("timeout(cfg.timeout.unwrap_or(DEFAULT_TIMEOUT))"),
        "shared HTTP builder must own the Tier-A timeout default"
    );
    assert!(
        !ssrf.contains(".timeout(crate::timeouts::HTTP_REQUEST)"),
        "WebSource SSRF client builder must not clobber HttpClientConfig::timeout after the shared builder applies it"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_dns_screen_and_proxy_contracts() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    assert!(TestApi.is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(TestApi.is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(TestApi.is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(TestApi.is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))));
    assert!(TestApi.is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    assert!(TestApi.is_disallowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    let mapped = "::ffff:127.0.0.1".parse().expect("valid mapped IPv6");
    assert!(TestApi.is_disallowed_ip(IpAddr::V6(mapped)));
    assert!(!TestApi.is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

    let err = TestApi
        .resolve_and_screen("127.0.0.1", 80)
        .expect_err("loopback refused");
    assert!(err.to_string().contains("private / loopback"));

    let addrs = TestApi
        .resolve_and_screen("1.1.1.1", 443)
        .expect("public IP must pass");
    assert!(!addrs.is_empty(), "must return at least one pinned addr");
    assert!(addrs.iter().all(|a| !TestApi.is_disallowed_ip(a.ip())));

    let cfg = keyhog_sources::http::HttpClientConfig::default();
    assert!(TestApi
        .build_web_client(&cfg, "http://127.0.0.1:9/", false, false)
        .is_err());
    assert!(TestApi
        .build_web_client(&cfg, "http://127.0.0.1:9/", false, true)
        .is_ok());

    match TestApi.build_web_client(&cfg, "https://example.com/app.js", false, false) {
        Ok(_) => {}
        Err(e) => {
            let message = e.to_string();
            assert!(
                message.contains("DNS resolution failed") || message.contains("no addresses"),
                "public host should build or fail only on DNS, got: {message}"
            );
        }
    }

    let proxied = keyhog_sources::http::HttpClientConfig {
        proxy: Some("http://127.0.0.1:8080".into()),
        ..Default::default()
    };
    assert!(TestApi
        .build_web_client(&proxied, "http://127.0.0.1:9/", true, false)
        .is_ok());
}

#[cfg(feature = "s3")]
#[test]
fn s3_sigv4_uses_verifier_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let auth = std::fs::read_to_string(root.join("src/s3/auth.rs")).expect("s3 auth source");
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).expect("sources Cargo readable");

    assert!(
        auth.contains("keyhog_verifier::sigv4::sign_request_authorization"),
        "S3 request signing must call the verifier SigV4 owner"
    );
    for forbidden in [
        "Hmac<",
        "hmac::",
        "Sha256",
        "sha2::",
        "chrono::",
        "fn signing_key",
        "fn hmac_sha256",
        "fn canonical_query_string",
        "fn aws_uri_encode",
    ] {
        assert!(
            !auth.contains(forbidden),
            "S3 auth must not reintroduce private SigV4 primitive {forbidden:?}"
        );
    }
    assert!(
        cargo.contains(r#"s3 = ["#) && cargo.contains(r#""dep:keyhog-verifier""#),
        "S3 feature must depend on the verifier SigV4 owner"
    );
    for forbidden_dep in ["dep:hmac", "dep:sha2", "dep:hex", "dep:chrono"] {
        assert!(
            !cargo.contains(forbidden_dep),
            "keyhog-sources S3 feature must not own SigV4 dependency {forbidden_dep:?}"
        );
    }
}

#[cfg(feature = "binary")]
#[test]
fn ghidra_discovery_does_not_flatten_glob_errors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ghidra =
        std::fs::read_to_string(root.join("src/binary/ghidra.rs")).expect("ghidra source readable");
    assert!(
        !ghidra.contains(".flatten().flatten()"),
        "Ghidra discovery must not drop glob pattern or entry errors with flatten"
    );
    assert!(
        ghidra.contains("Ghidra discovery glob pattern failed")
            && ghidra.contains("Ghidra discovery glob entry failed"),
        "Ghidra discovery must log glob pattern and entry failures"
    );
}

#[test]
fn sources_tests_do_not_flatten_source_chunk_results() {
    fn collect_rs_files(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(root)
            .unwrap_or_else(|error| panic!("read_dir({}) failed: {error}", root.display()))
        {
            let path = entry
                .unwrap_or_else(|error| {
                    panic!("read_dir entry failed in {}: {error}", root.display())
                })
                .path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let support_path = root.join("tests/support/mod.rs");
    let support = std::fs::read_to_string(&support_path)
        .unwrap_or_else(|error| panic!("read {} failed: {error}", support_path.display()));
    assert!(
        support.contains("pub fn collect_chunks<")
            && support.contains("pub fn count_chunks<")
            && support.contains("pub fn split_chunk_results"),
        "source tests must keep fail-loud chunk-result collectors in tests/support/mod.rs"
    );

    let mut test_files = Vec::new();
    collect_rs_files(&root.join("tests"), &mut test_files);
    for path in test_files {
        if path.ends_with("unit/internal_contracts.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {} failed: {error}", path.display()));
        let compact: String = source.chars().filter(|ch| !ch.is_whitespace()).collect();
        assert!(
            !compact.contains(".chunks().flatten()"),
            "test {} must use support::collect_chunks/count_chunks or assert SourceError explicitly; a `chunks().flatten()` chain drops SourceError items even when split across lines",
            path.display()
        );
        assert!(
            !compact.contains(".into_iter().flatten()"),
            "test {} must not collect Source::chunks Result rows and flatten them afterward; assert SourceError rows explicitly or use the fail-loud collector",
            path.display()
        );
        assert!(
            !compact.contains(".filter_map(|row|row.as_ref().ok())")
                && !compact.contains(".filter_map(|row|row.as_ref().err())"),
            "test {} must use support::split_chunk_results when it expects both chunks and SourceError rows from Source::chunks",
            path.display()
        );
    }
}

#[cfg(feature = "binary")]
#[test]
fn ghidra_discovery_uses_trusted_paths_not_path_which() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ghidra =
        std::fs::read_to_string(root.join("src/binary/ghidra.rs")).expect("ghidra source readable");

    assert!(
        ghidra.contains(r#"resolve_safe_bin("analyzeHeadless")"#),
        "custom Ghidra support dirs must flow through [system].trusted_bin_dirs via resolve_safe_bin"
    );
    assert!(
        !ghidra.contains(r#"std::env::var("GHIDRA_HOME")"#),
        "GHIDRA_HOME must not alter shipped source extraction behavior; use [system].trusted_bin_dirs"
    );
    assert!(
        !ghidra.contains(r#"resolve_safe_bin("which")"#)
            && !ghidra.contains(r#"Command::new(&which_bin)"#)
            && !ghidra.contains(r#".arg("analyzeHeadless")"#),
        "Ghidra discovery must not shell through which/PATH to find analyzeHeadless"
    );
}

#[test]
fn hosted_git_askpass_uses_private_create_new_files() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hosted_git = std::fs::read_to_string(root.join("src/hosted_git.rs"))
        .expect("hosted_git source readable");

    assert!(
        hosted_git.contains("fn write_private_file(")
            && hosted_git.contains("options.write(true).create_new(true)")
            && hosted_git.contains("write_askpass_file(&path"),
        "hosted Git credentials and askpass scripts must share create_new private-file creation"
    );
    assert!(
        hosted_git.contains("options.mode(unix_mode)")
            && hosted_git.contains("write_private_file(path, bytes, 0o600)")
            && hosted_git.contains("write_private_file(path, bytes, 0o700)"),
        "Unix hosted Git auth files must set secret/script permissions before file creation"
    );
    assert!(
        !hosted_git.contains("std::fs::write(\n                &path")
            && !hosted_git.contains("std::fs::write(&path"),
        "hosted Git askpass material must not use plain fs::write"
    );
    assert!(
        !hosted_git.contains("echo %1 | findstr")
            && hosted_git.contains("setlocal EnableExtensions EnableDelayedExpansion")
            && hosted_git.contains(r#"set \"prompt=%~1\""#)
            && hosted_git.contains(r#"echo(!prompt!| findstr /I /C:\"Username\""#),
        "Windows hosted Git askpass must classify the prompt without expanding raw %1 through cmd metacharacter parsing"
    );
}

#[test]
fn hosted_git_wait_errors_kill_and_reap_child() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hosted_git = std::fs::read_to_string(root.join("src/hosted_git.rs"))
        .expect("hosted_git source readable");
    let wait_start = hosted_git
        .find("fn wait_for_command_with_timeout(")
        .expect("wait_for_command_with_timeout present");
    let auth_start = hosted_git[wait_start..]
        .find("#[derive(Debug)]")
        .map(|offset| wait_start + offset)
        .expect("wait helper boundary present");
    let wait_block = &hosted_git[wait_start..auth_start];

    assert!(
        wait_block.contains("Err(error) =>")
            && wait_block.contains("kill_and_reap_child(&mut child)")
            && wait_block.contains("fn kill_and_reap_child(")
            && wait_block.contains("child.kill()")
            && wait_block.contains("child.wait()"),
        "hosted Git clone wait errors and timeouts must kill and reap the child before returning"
    );
    assert!(
        !wait_block.contains("child.try_wait().map_err(|e| e.to_string())?"),
        "hosted Git clone wait must not return directly from try_wait errors before child cleanup"
    );
}
