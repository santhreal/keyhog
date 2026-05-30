use keyhog_sources::testing;

#[test]
fn strip_unc_prefix_contracts() {
    assert_eq!(
        testing::strip_unc_prefix(r"\\?\C:\Users\me\src\app.env"),
        r"C:\Users\me\src\app.env"
    );
    assert_eq!(testing::strip_unc_prefix(r"C:\Users\me"), r"C:\Users\me");
    assert_eq!(
        testing::strip_unc_prefix("/home/me/src/app.env"),
        "/home/me/src/app.env"
    );
    assert_eq!(
        testing::strip_unc_prefix(r"\\?\UNC\server\share\file"),
        r"UNC\server\share\file"
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

#[cfg(feature = "github")]
#[test]
fn github_repo_name_and_clone_url_contracts() {
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
