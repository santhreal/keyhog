use keyhog_sources::testing::{TestApi};

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
fn http_user_agent_contracts() {let ua = TestApi.user_agent(None);
    assert!(ua.starts_with("keyhog/"));
    assert!(ua.contains(env!("CARGO_PKG_VERSION")));
    assert!(TestApi.user_agent(Some("web")).contains("(web)"));}

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
fn binary_section_extraction_rejects_bad_inputs_without_panic() {assert!(TestApi
        .extract_sections(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc], "junk.bin")
        .is_none());
    assert!(TestApi.extract_sections(&[], "empty.bin").is_none());

    let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 0];
    bytes.extend(std::iter::repeat(0xFF).take(120));
    let _ = TestApi.extract_sections(&bytes, "trunc.elf");}

#[cfg(feature = "binary")]
#[test]
fn binary_unresolvable_section_name_bumps_partial_parse_counter() {// Canonical SCAN_GATE guard, not a local mutex: this set_skip_counts zeroes
    // ALL process-global counters, and only the shared exclusive scan scope
    // serializes it against a concurrent counter-asserting scan in the same
    // `all_tests` process (a local mutex does not, which intermittently flaked
    // tests like zst_truncated_header_no_panic by zeroing their `unreadable`).
    let _guard = TestApi.skip_counter_guard();
    TestApi.set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = TestApi.resolve_binary_section_name(None, 42);
    assert_eq!(name, "", "an unresolvable name yields the empty string");
    assert_eq!(
        keyhog_sources::skip_counts().binary_section_name_unresolved, 1, "a corrupt-strtab name lookup must bump the loud partial-parse counter exactly once"
    );}

#[cfg(feature = "binary")]
#[test]
fn binary_legitimate_unnamed_section_does_not_bump_counter() {// Canonical SCAN_GATE guard, not a local mutex: this set_skip_counts zeroes
    // ALL process-global counters, and only the shared exclusive scan scope
    // serializes it against a concurrent counter-asserting scan in the same
    // `all_tests` process (a local mutex does not, which intermittently flaked
    // tests like zst_truncated_header_no_panic by zeroing their `unreadable`).
    let _guard = TestApi.skip_counter_guard();
    TestApi.set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = TestApi.resolve_binary_section_name(None, 0);
    assert_eq!(name, "");
    assert_eq!(
        keyhog_sources::skip_counts().binary_section_name_unresolved, 0, "sh_name==0 is the strtab's empty entry, not an anomaly; counter must stay 0"
    );}

#[cfg(feature = "binary")]
#[test]
fn binary_resolved_section_name_passes_through_without_counting() {// Canonical SCAN_GATE guard, not a local mutex: this set_skip_counts zeroes
    // ALL process-global counters, and only the shared exclusive scan scope
    // serializes it against a concurrent counter-asserting scan in the same
    // `all_tests` process (a local mutex does not, which intermittently flaked
    // tests like zst_truncated_header_no_panic by zeroing their `unreadable`).
    let _guard = TestApi.skip_counter_guard();
    TestApi.set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = TestApi.resolve_binary_section_name(Some(".rodata"), 7);
    assert_eq!(name, ".rodata");
    assert_eq!(
        keyhog_sources::skip_counts().binary_section_name_unresolved, 0
    );}

#[cfg(feature = "github")]
#[test]
fn github_repo_name_and_clone_url_contracts() {
    for ok in ["santhreal", "SanthSecurity", "santh-security", "a0"].into_iter() {
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

    for ok in ["https://github.com/santhreal/keyhog.git"] {
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
        "https://ghe.example.com/org/repo.git",
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

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hosted_git =
        std::fs::read_to_string(root.join("src/hosted_git.rs")).expect("hosted_git source");
    let github_org =
        std::fs::read_to_string(root.join("src/github_org.rs")).expect("github_org source");
    let gitlab_group =
        std::fs::read_to_string(root.join("src/gitlab_group.rs")).expect("gitlab_group source");
    let bitbucket_workspace = std::fs::read_to_string(root.join("src/bitbucket_workspace.rs"))
        .expect("bitbucket_workspace source");
    assert!(
        hosted_git.contains("expected_clone_origin: &ExpectedCloneOrigin")
            && hosted_git.contains("validate_clone_url_for_origin(")
            && hosted_git.contains("outside expected clone origin"),
        "hosted git clone validation must bind API-listed clone URLs to an expected origin before askpass credentials are installed"
    );
    assert!(
        github_org.contains("ExpectedCloneOrigin::host(\"github.com\")"),
        "GitHub org scans must only send GitHub PAT askpass credentials to github.com clone URLs"
    );
    assert!(
        gitlab_group.contains("ExpectedCloneOrigin::from_api_root(&api_root)"),
        "GitLab group scans must bind clone URLs to the configured GitLab origin"
    );
    assert!(
        bitbucket_workspace.contains("ExpectedCloneOrigin::bitbucket(&api_root)"),
        "Bitbucket scans must use the explicit Bitbucket clone-origin policy"
    );
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
            path: Some(file.display().to_string().into()),
            base_offset: 8192,
            base_line: 77,
            size_bytes: Some(64),
            mtime_ns: Some(1234),
            decoded_span: Some((4, 12)),
            ..Default::default()
        },
    };

    let rewritten = TestApi
        .github_org_rewrite_chunk_path(chunk, "santhreal", "keyhog", dir.path())
        .expect("rewrite succeeds");
    assert_eq!(rewritten.metadata.source_type.as_ref(), "github-org");
    assert_eq!(
        rewritten.metadata.path.as_deref(),
        Some("santhreal/keyhog/src/secret.env")
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
        .github_org_rewrite_chunk_path(missing_path_chunk, "santhreal", "keyhog", dir.path())
        .expect_err("missing path must be an error");
    assert!(
        err.to_string().contains("without a file path"),
        "unexpected missing-path error: {err}"
    );

    let outside_chunk = keyhog_core::Chunk {
        data: "x".into(),
        metadata: keyhog_core::ChunkMetadata {
            path: Some(outside.path().display().to_string().into()),
            ..Default::default()
        },
    };
    let err = TestApi
        .github_org_rewrite_chunk_path(outside_chunk, "santhreal", "keyhog", dir.path())
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
            "santhreal",
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
    // Canonical SCAN_GATE guard so this reset serializes against every other
    // counter-asserting scan in the `all_tests` process (a local mutex would
    // not, intermittently zeroing a concurrent test's counters).
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let err = TestApi.github_org_listing_truncated_error("santhreal", 100_000, 1_000);
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
    for ok in ["santhreal", "platform/sub-group", "a.b_c-d"].into_iter() {
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

    // Canonical SCAN_GATE guard so this reset serializes against every other
    // counter-asserting scan in the `all_tests` process (a local mutex would
    // not, intermittently zeroing a concurrent test's counters).
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let err = TestApi.gitlab_group_listing_truncated_error("santhreal", 100_000, 1_000);
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
    for ok in ["santhreal", "platform-team", "team_1"].into_iter() {
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

    // Canonical SCAN_GATE guard so this reset serializes against every other
    // counter-asserting scan in the `all_tests` process (a local mutex would
    // not, intermittently zeroing a concurrent test's counters).
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let err = TestApi.bitbucket_workspace_listing_truncated_error("santhreal", 100_000, 1_000);
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
        .resolve_and_screen("127.0.0.1", 80, std::time::Duration::from_secs(5))
        .expect_err("loopback refused");
    assert!(err.to_string().contains("private / loopback"));

    let addrs = TestApi
        .resolve_and_screen("1.1.1.1", 443, std::time::Duration::from_secs(5))
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
    assert!(
        TestApi
            .build_web_client(&proxied, "http://127.0.0.1:9/", true, false)
            .is_err(),
        "explicit proxy mode must not bypass WebSource's local URL SSRF prefilter"
    );
}

#[test]
fn skip_counter_reset_tests_hold_shared_guard() {
    fn visit_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read test directory") {
            let path = entry.expect("read test entry").path();
            if path.is_dir() {
                visit_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests_root = root.join("tests");
    let mut files = Vec::new();
    visit_rs_files(&tests_root, &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read source test");
        // Aggregator-binary modules (everything under a tests/ subdirectory) run
        // in parallel inside the single `all_tests` process and share the
        // process-global skip counters, so even a pure READ of `skip_counts()`
        // across a scan -- or a bare `reset_skipped_over_max_size()` that could
        // zero a concurrent test's counters -- must hold the exclusive scan
        // scope. Top-level `tests/*.rs` files are each their own binary (separate
        // process, private counter copy); a single-test standalone is race-free.
        let is_aggregator = path.parent() != Some(tests_root.as_path());
        let mut touches_counters = src.contains("TestApi.reset_skip_counters()")
            || src.contains("TestApi.set_skip_counts(");
        touches_counters |= src.contains("TestApi.bump_skipped_over_max_size(")
            || src.contains("TestApi.bump_git_object_unreadable(");
        if is_aggregator {
            touches_counters |=
                src.contains("skip_counts(") || src.contains("reset_skipped_over_max_size(");
        }
        if !touches_counters {
            continue;
        }
        let has_guard = if is_aggregator {// Aggregator modules share the single `all_tests` process, so only
            // the canonical SCAN_GATE guard (`TestApi.skip_counter_guard()`)
            // serializes a counter mutation against a concurrent counter-
            // asserting scan. A local `Mutex` does NOT -- it only serializes
            // within its own file -- which intermittently flaked tests like
            // zst_truncated_header_no_panic by zeroing their counters mid-scan.
            src.contains("skip_counter_guard()")} else {
            // Top-level `tests/*.rs` standalone binaries run in their own
            // process (private counter copy); a local mutex is sufficient there.
            src.contains("skip_counter_guard()")
                || src.contains("COUNTER_LOCK")
                || src.contains("SKIP_COUNTER_GUARD")
        };
        if !has_guard {
            offenders.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }

    assert!(
        offenders.is_empty(),
        "aggregator tests that read or mutate the process-global source skip counters must hold TestApi.skip_counter_guard() (or an existing local guard) so a parallel test cannot reset/record into the counters mid-measurement: {offenders:?}"
    );
}

/// Security boundary, kept as a source pin on purpose.
///
/// Hosted-Git auth writes the username, the token and the askpass helper into a
/// temp dir. Those files hold live credential material, so they must be created
/// with `create_new` (never truncating an attacker-planted path) and with the
/// restrictive Unix mode applied AT creation time, not chmod'ed afterwards: a
/// post-hoc chmod leaves a world-readable window. The behaviour is only
/// reachable through `GitAskpassAuth::create`, which is private and only runs
/// behind a real hosted-Git clone, so there is no cheap runtime oracle. Pinning
/// the creation call sites is the available check; if `hosted_git` ever grows a
/// testing-facade wrapper, replace this with a mode assertion on the real file.
#[test]
fn hosted_git_askpass_uses_private_create_new_files() {
    // Read the WHOLE hosted_git module, not one file. The credential-writing
    // helpers moved from `hosted_git.rs` into `hosted_git/process.rs` during the
    // module split, which silently made the negative assertions below vacuous:
    // "the file does not contain fs::write" is trivially true of a file that no
    // longer contains the code at all.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut module = std::fs::read_to_string(root.join("src/hosted_git.rs"))
        .expect("hosted_git.rs source readable");
    let submodules = root.join("src/hosted_git");
    if submodules.is_dir() {
        let mut parts: Vec<_> = std::fs::read_dir(&submodules)
            .expect("hosted_git module dir readable")
            .map(|e| e.expect("hosted_git module entry").path())
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .collect();
        parts.sort();
        for part in parts {
            module.push('\n');
            module.push_str(&std::fs::read_to_string(&part).expect("hosted_git submodule readable"));
        }
    }

    // Anchor first: every negative assertion below is only meaningful if the
    // credential-writing code is actually in what we just read. Without this the
    // test passes for free the next time the module is reorganised.
    assert!(
        module.contains("fn write_private_file("),
        "hosted Git private-file writer not found in the hosted_git module; \
         this test can no longer see the code it pins and every assertion below \
         would pass vacuously"
    );

    assert!(
        module.contains("options.write(true).create_new(true)")
            && module.contains("write_askpass_file(&path"),
        "hosted Git credentials and askpass scripts must share create_new private-file creation"
    );
    assert!(
        module.contains("options.mode(unix_mode)")
            && module.contains("write_private_file(path, bytes, 0o600)")
            && module.contains("write_private_file(path, bytes, 0o700)"),
        "Unix hosted Git auth files must set secret/script permissions before file creation"
    );
    assert!(
        !module.contains("std::fs::write(&path"),
        "hosted Git askpass material must not use plain fs::write"
    );
    assert!(
        !module.contains("echo %1 | findstr")
            && module.contains("setlocal EnableExtensions EnableDelayedExpansion")
            && module.contains(r#"set \"prompt=%~1\""#)
            && module.contains(r#"echo(!prompt!| findstr /I /C:\"Username\""#),
        "Windows hosted Git askpass must classify the prompt without expanding raw %1 through cmd metacharacter parsing"
    );
}
