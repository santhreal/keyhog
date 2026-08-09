#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::{
    create_source_with_http_config_and_limits, http::HttpClientConfig, SourceLimits,
};

fn source(url: String, allow_private_endpoint: bool) -> Box<dyn Source> {
    create_source_with_http_config_and_limits(
        "web",
        Some(&url),
        HttpClientConfig {
            allow_private_endpoint,
            ..Default::default()
        },
        SourceLimits::default(),
    )
    .expect("construct WebSource")
}

/// WHY: the explicit private-endpoint flag is the operator's consent boundary; ignoring it makes on-prem WebSource scans and deterministic benchmark acquisition fail before HTTP while the default must remain SSRF-closed.
#[test]
fn explicit_private_endpoint_consent_controls_loopback_fetches() {
    let server = httpmock::MockServer::start();
    let endpoint = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/app.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body("const token = 'PRIVATE_WEB_CANARY';");
    });
    let url = server.url("/app.js");

    let blocked = source(url.clone(), false).chunks().collect::<Vec<_>>();
    assert_eq!(blocked.len(), 1);
    assert!(blocked[0]
        .as_ref()
        .expect_err("default WebSource must reject loopback")
        .to_string()
        .contains("private / loopback"));
    assert_eq!(endpoint.calls(), 0, "rejection must happen before HTTP");

    let chunks = source(url, true)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("explicitly permitted private endpoint must be fetched");
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "web:js");
    assert_eq!(
        chunks[0].data.as_ref(),
        "const token = 'PRIVATE_WEB_CANARY';"
    );
    assert_eq!(endpoint.calls(), 1);
}

/// WHY: private-endpoint consent applies to the complete acquisition route; re-screening an explicitly permitted same-host redirect as public-only breaks ordinary on-prem applications that redirect assets.
#[test]
fn explicit_private_endpoint_consent_survives_redirect_screening() {
    let server = httpmock::MockServer::start();
    let redirect = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/start");
        then.status(302).header("location", "/asset.js");
    });
    let asset = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/asset.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body("redirect_private_canary");
    });

    let chunks = source(server.url("/start"), true)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("permitted private redirect must be fetched");
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].data.as_ref(), "redirect_private_canary");
    assert_eq!(redirect.calls(), 1);
    assert_eq!(asset.calls(), 1);
}
