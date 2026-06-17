use keyhog_sources::testing;

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
fn http_user_agent_contracts() {
    let ua = testing::user_agent(None);
    assert!(ua.starts_with("keyhog/"));
    assert!(ua.contains(env!("CARGO_PKG_VERSION")));
    assert!(testing::user_agent(Some("web")).contains("(web)"));
}

#[cfg(feature = "binary")]
#[test]
fn binary_literal_extraction_contracts() {
    let literal = testing::extract_string_literals(r#"x = "abcdefghij\é klmnop";"#);
    assert_eq!(literal.len(), 1, "expected one literal, got {literal:?}");
    assert!(literal[0].contains("abcdefghij"));

    assert_eq!(
        testing::extract_string_literals(r#"puts("hello\tworld\n");"#),
        vec!["hello\tworld\n".to_string()]
    );

    assert!(testing::extract_string_literals("\"abc\"").is_empty());
    assert!(testing::extract_string_literals("").is_empty());
    assert!(testing::extract_string_literals("\"").is_empty());
    assert!(testing::extract_string_literals("\"\"").is_empty());
}

#[cfg(feature = "binary")]
#[test]
fn binary_section_extraction_rejects_bad_inputs_without_panic() {
    assert!(testing::extract_sections(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc], "junk.bin").is_none());
    assert!(testing::extract_sections(&[], "empty.bin").is_none());

    let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    bytes.extend(std::iter::repeat(0xFF).take(120));
    let _ = testing::extract_sections(&bytes, "trunc.elf");
}

#[cfg(feature = "binary")]
#[test]
fn binary_unresolvable_section_name_bumps_partial_parse_counter() {
    let _guard = BINARY_SECTION_COUNTER_GUARD.lock().expect("counter guard");
    keyhog_sources::testing::set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = testing::resolve_binary_section_name(None, 42);
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
    keyhog_sources::testing::set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = testing::resolve_binary_section_name(None, 0);
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
    keyhog_sources::testing::set_skip_counts(keyhog_sources::SkipCounts::default());

    let name = testing::resolve_binary_section_name(Some(".rodata"), 7);
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
            testing::validate_org_name(ok).is_ok(),
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
            testing::validate_org_name(bad).is_err(),
            "should reject org {bad:?}"
        );
    }
    let too_long_org = "x".repeat(40);
    assert!(testing::validate_org_name(&too_long_org).is_err());

    for ok in ["keyhog", "keyhog.rs", "Cool-Repo_2", "a"].into_iter() {
        assert!(
            testing::validate_repo_name(ok).is_ok(),
            "should accept {ok:?}"
        );
    }
    let long_ok = "x".repeat(100);
    assert!(testing::validate_repo_name(&long_ok).is_ok());

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
            testing::validate_repo_name(bad).is_err(),
            "should reject {bad:?}"
        );
    }
    let too_long = "x".repeat(101);
    assert!(testing::validate_repo_name(&too_long).is_err());

    for ok in [
        "https://github.com/santhsecurity/keyhog.git",
        "https://ghe.example.com/org/repo.git",
    ] {
        assert!(
            testing::validate_clone_url(ok).is_ok(),
            "should accept {ok:?}"
        );
    }

    for bad in [
        "ext::sh -c whoami",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "file:///etc/passwd",
        "http://insecure.example/repo.git",
        "https://example.com/repo with space.git",
        "https://example.com/repo\nwith\nnewlines",
    ] {
        assert!(
            testing::validate_clone_url(bad).is_err(),
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

    let rewritten =
        testing::github_org_rewrite_chunk_path(chunk, "santhsecurity", "keyhog", dir.path())
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
    let err = testing::github_org_rewrite_chunk_path(
        missing_path_chunk,
        "santhsecurity",
        "keyhog",
        dir.path(),
    )
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
    let err = testing::github_org_rewrite_chunk_path(
        outside_chunk,
        "santhsecurity",
        "keyhog",
        dir.path(),
    )
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
    let err = testing::github_org_scan_repo_chunks(
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
    keyhog_sources::testing::reset_skip_counters();
    let err = testing::github_org_listing_truncated_error("santhsecurity", 100_000, 1_000);
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
            testing::validate_gitlab_group_path(ok).is_ok(),
            "should accept group {ok:?}"
        );
    }

    for bad in ["", "/root", "root/", "root//child", "../root", "root child"] {
        assert!(
            testing::validate_gitlab_group_path(bad).is_err(),
            "should reject group {bad:?}"
        );
    }

    let _guard = GITLAB_SKIP_COUNTER_GUARD
        .lock()
        .expect("gitlab counter guard");
    keyhog_sources::testing::reset_skip_counters();
    let err = testing::gitlab_group_listing_truncated_error("santhsecurity", 100_000, 1_000);
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
            testing::validate_bitbucket_workspace(ok).is_ok(),
            "should accept workspace {ok:?}"
        );
    }

    for bad in ["", "/root", "root/repo", "root child", "root?pagelen=1"] {
        assert!(
            testing::validate_bitbucket_workspace(bad).is_err(),
            "should reject workspace {bad:?}"
        );
    }

    let _guard = BITBUCKET_SKIP_COUNTER_GUARD
        .lock()
        .expect("bitbucket counter guard");
    keyhog_sources::testing::reset_skip_counters();
    let err = testing::bitbucket_workspace_listing_truncated_error("santhsecurity", 100_000, 1_000);
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
            testing::is_disallowed_web_host(blocked),
            "should block {blocked:?}"
        );
    }

    for allowed in [
        "https://example.com/",
        "https://cdn.jsdelivr.net/app.js",
        "https://api.github.com/repos/foo/bar",
    ] {
        assert!(
            !testing::is_disallowed_web_host(allowed),
            "should allow {allowed:?}"
        );
    }

    assert_eq!(
        testing::redact_url("https://user:SECRET@host/path"),
        "https://***@host/path"
    );
    assert_eq!(
        testing::redact_url("https://user@host/path?q=1"),
        "https://***@host/path?q=1"
    );
    assert_eq!(
        testing::redact_url("http://x:y@example.com:8080/p#frag"),
        "http://***@example.com:8080/p#frag"
    );
    let path_at = "https://example.com/orgs/foo/users/@me";
    assert_eq!(testing::redact_url(path_at), path_at);
}

#[cfg(feature = "web")]
#[test]
fn web_ssrf_url_classifier_uses_verifier_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ssrf =
        std::fs::read_to_string(root.join("src/web/ssrf.rs")).expect("web ssrf source readable");
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).expect("sources Cargo readable");

    assert!(
        ssrf.contains("keyhog_verifier::ssrf::is_private_url(url)"),
        "WebSource URL-string SSRF classification must call the verifier owner"
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
}

#[cfg(feature = "web")]
#[test]
fn web_dns_screen_and_proxy_contracts() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    assert!(testing::is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 1
    ))));
    assert!(testing::is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
        10, 0, 0, 5
    ))));
    assert!(testing::is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
        192, 168, 1, 1
    ))));
    assert!(testing::is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
        172, 16, 0, 5
    ))));
    assert!(testing::is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
        169, 254, 169, 254
    ))));
    assert!(testing::is_disallowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    let mapped = "::ffff:127.0.0.1".parse().expect("valid mapped IPv6");
    assert!(testing::is_disallowed_ip(IpAddr::V6(mapped)));
    assert!(!testing::is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(
        1, 1, 1, 1
    ))));

    let err = testing::resolve_and_screen("127.0.0.1", 80).expect_err("loopback refused");
    assert!(err.to_string().contains("private / loopback"));

    let addrs = testing::resolve_and_screen("1.1.1.1", 443).expect("public IP must pass");
    assert!(!addrs.is_empty(), "must return at least one pinned addr");
    assert!(addrs.iter().all(|a| !testing::is_disallowed_ip(a.ip())));

    let cfg = keyhog_sources::http::HttpClientConfig::default();
    assert!(testing::build_web_client(&cfg, "http://127.0.0.1:9/", false).is_err());

    match testing::build_web_client(&cfg, "https://example.com/app.js", false) {
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
    assert!(testing::build_web_client(&proxied, "http://127.0.0.1:9/", true).is_ok());
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
