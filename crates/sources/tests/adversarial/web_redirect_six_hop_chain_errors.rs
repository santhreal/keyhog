//! Sixth redirect hop must fail (5-hop cap).

#[cfg(feature = "web")]
#[test]
fn web_redirect_six_hop_chain_errors() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let server = httpmock::MockServer::start();
    let final_path = "/final.js";
    let _final = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path(final_path);
        then.status(200).body("PUBLIC=ok\n");
    });

    let mut next = server.url(final_path);
    let mut mocks = Vec::new();
    for i in (0..6).rev() {
        let path = format!("/hop{i}");
        let target = next.clone();
        mocks.push(server.mock(|when, then| {
            when.method(httpmock::Method::GET).path(&path);
            then.status(302).header("Location", &target);
        }));
        next = server.url(&path);
    }

    let start = next;
    let source = TestApi.web_source_with_autoroute_loopback_calibration(vec![start], true);
    let results: Vec<_> = source.chunks().collect();
    assert!(
        results.iter().any(|r| {
            r.as_ref()
                .expect_err("six-hop redirect chain must fail")
                .to_string()
                .contains("too many redirects")
        }),
        "six-hop redirect chain must not succeed; got {results:?}"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_redirect_non_http_scheme_errors() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let server = httpmock::MockServer::start();
    let _redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/to-file");
        then.status(302).header("Location", "file:///etc/passwd");
    });

    let source =
        TestApi.web_source_with_autoroute_loopback_calibration(vec![server.url("/to-file")], true);
    let results: Vec<_> = source.chunks().collect();
    assert_eq!(results.len(), 1, "scheme rejection should produce one error");
    let err = results[0]
        .as_ref()
        .expect_err("file redirect must fail closed")
        .to_string();
    assert!(
        err.contains("unsupported URL scheme"),
        "redirect scheme error must be explicit, got {err}"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_loopback_calibration_redirect_to_metadata_errors() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let server = httpmock::MockServer::start();
    let _redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/to-metadata");
        then.status(302)
            .header("Location", "http://169.254.169.254/latest/meta-data/");
    });

    let source = TestApi
        .web_source_with_autoroute_loopback_calibration(vec![server.url("/to-metadata")], true);
    let results: Vec<_> = source.chunks().collect();
    assert_eq!(
        results.len(),
        1,
        "metadata redirect rejection should produce one error"
    );
    let err = results[0]
        .as_ref()
        .expect_err("metadata redirect must fail closed")
        .to_string();
    assert!(
        err.contains("refusing to follow redirect") && err.contains("metadata-service"),
        "metadata redirect error must be explicit, got {err}"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_six_hop_chain_errors() {}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_non_http_scheme_errors() {}

#[cfg(not(feature = "web"))]
#[test]
fn web_loopback_calibration_redirect_to_metadata_errors() {}
