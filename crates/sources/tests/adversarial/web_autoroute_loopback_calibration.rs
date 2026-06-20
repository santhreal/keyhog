//! Autoroute calibration may fetch a loopback WebSource fixture; normal scans may not.

#[cfg(feature = "web")]
use super::support::collect_chunks;

#[cfg(feature = "web")]
#[test]
fn web_loopback_fetch_requires_explicit_autoroute_calibration() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};
    use keyhog_sources::WebSource;

    let server = httpmock::MockServer::start();
    let probe = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/probe.js");
        then.status(200)
            .header("Content-Type", "application/javascript")
            .body("const token = 'keyhog-web-autoroute-calibration';\n");
    });
    let url = server.url("/probe.js");

    let blocked: Vec<_> = WebSource::new(vec![url.clone()]).chunks().collect();
    assert!(
        blocked.iter().any(|result| result
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("private / loopback"))),
        "normal WebSource loopback fetch must fail closed, got {blocked:?}"
    );
    assert_eq!(
        probe.calls(),
        0,
        "normal loopback block must happen before HTTP"
    );

    let chunks =
        collect_chunks(&TestApi.web_source_with_autoroute_loopback_calibration(vec![url], true));
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("keyhog-web-autoroute-calibration")),
        "autoroute calibration loopback fetch must emit the JS chunk"
    );
}

#[cfg(feature = "web")]
#[test]
fn web_autoroute_calibration_does_not_read_legacy_env() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web/ssrf.rs"),
    )
    .expect("web SSRF owner source is readable");
    assert!(
        !source.contains("KEYHOG_AUTOROUTE_CALIBRATE") && !source.contains("std::env::"),
        "WebSource loopback calibration must be explicit; no ambient env reads are allowed"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_loopback_fetch_requires_explicit_autoroute_calibration() {
    assert!(!cfg!(feature = "web"));
}
