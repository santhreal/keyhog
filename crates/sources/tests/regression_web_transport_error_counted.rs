#[cfg(feature = "web")]
#[test]
fn web_transport_error_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use std::net::TcpListener;

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused web transport port");
    let addr = listener
        .local_addr()
        .expect("unused web transport port address");
    drop(listener);

    let rows: Vec<_> = TestApi
        .web_source_with_autoroute_loopback_calibration(vec![format!("http://{addr}/app.js")], true)
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "connection-refused web request must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("connection-refused web request must fail");
    assert!(
        error.to_string().contains("failed to fetch"),
        "error should name the failed fetch, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource transport errors must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_malformed_redirect_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/missing-location");
        then.status(302);
    });

    let rows: Vec<_> = TestApi
        .web_source_with_autoroute_loopback_calibration(vec![server.url("/missing-location")], true)
        .chunks()
        .collect();

    redirect.assert();
    assert_eq!(
        rows.len(),
        1,
        "malformed redirect response must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("malformed redirect response must fail");
    assert!(
        error.to_string().contains("missing Location header"),
        "error should name the malformed redirect, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource malformed redirects must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_unsupported_redirect_scheme_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/to-file");
        then.status(302).header("Location", "file:///tmp/secret.js");
    });

    let rows: Vec<_> = TestApi
        .web_source_with_autoroute_loopback_calibration(vec![server.url("/to-file")], true)
        .chunks()
        .collect();

    redirect.assert();
    assert_eq!(
        rows.len(),
        1,
        "unsupported redirect scheme must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("unsupported redirect scheme must fail");
    assert!(
        error.to_string().contains("unsupported URL scheme"),
        "error should name the unsupported redirect scheme, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource unsupported redirect schemes must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_unsupported_initial_scheme_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use keyhog_sources::WebSource;

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let rows: Vec<_> = WebSource::new(vec!["file:///tmp/secret.js".to_string()])
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "unsupported initial scheme must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("unsupported initial scheme must fail");
    assert!(
        error.to_string().contains("unsupported URL scheme"),
        "error should name the unsupported initial scheme, got {error}"
    );
    assert!(
        error.to_string().contains("http:// and https://"),
        "error should tell the operator which schemes WebSource supports, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource unsupported initial schemes must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_initial_disallowed_host_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use keyhog_sources::WebSource;

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let rows: Vec<_> = WebSource::new(vec!["http://127.0.0.1/app.js".to_string()])
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "initial disallowed host must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("initial disallowed host must fail");
    assert!(
        error.to_string().contains("private / loopback"),
        "error should name the private initial host, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource initial disallowed hosts must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_private_redirect_target_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/to-metadata");
        then.status(302)
            .header("Location", "http://169.254.169.254/latest/meta-data/");
    });

    let rows: Vec<_> = TestApi
        .web_source_with_autoroute_loopback_calibration(vec![server.url("/to-metadata")], true)
        .chunks()
        .collect();

    redirect.assert();
    assert_eq!(
        rows.len(),
        1,
        "private redirect target must produce one visible source error"
    );
    let error = rows[0]
        .as_ref()
        .expect_err("private redirect target must fail");
    assert!(
        error.to_string().contains("private / loopback"),
        "error should name the private redirect target, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource private redirect targets must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_dns_failure_is_counted_unreadable() {
    use keyhog_core::Source;
    use keyhog_sources::skip_counts;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use keyhog_sources::WebSource;

    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let rows: Vec<_> = WebSource::new(vec!["http://keyhog-dns-gap.invalid/app.js".to_string()])
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "DNS failure must produce one visible source error"
    );
    let error = rows[0].as_ref().expect_err("DNS failure must fail");
    assert!(
        error.to_string().contains("DNS resolution failed"),
        "error should name the DNS failure, got {error}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "WebSource DNS failures must bump SKIPPED_UNREADABLE"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_transport_error_is_counted_unreadable() {
    assert!(!cfg!(feature = "web"));
}
