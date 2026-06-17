//! Sixth redirect hop must fail (5-hop cap).

#[cfg(feature = "web")]
#[test]
fn web_redirect_six_hop_chain_errors() {
    use keyhog_core::Source;
    use keyhog_sources::WebSource;

    let server = httpmock::MockServer::start();
    let final_path = "/final.js";
    let _final = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path(final_path);
        then.status(200).body("PUBLIC=ok\n");
    });

    let mut next = server.url(final_path);
    let mut mocks = Vec::new();
    for i in (0..5).rev() {
        let path = format!("/hop{i}");
        let target = next.clone();
        mocks.push(server.mock(|when, then| {
            when.method(httpmock::Method::GET).path(&path);
            then.status(302).header("Location", &target);
        }));
        next = server.url(&path);
    }

    let start = next;
    let results: Vec<_> = WebSource::new(vec![start]).chunks().collect();
    assert!(
        results.iter().any(|r| r.is_err()) || results.is_empty(),
        "six-hop redirect chain must not succeed; got {results:?}"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_redirect_six_hop_chain_errors() {}
