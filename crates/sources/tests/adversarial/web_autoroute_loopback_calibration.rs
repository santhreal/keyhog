//! Autoroute calibration may fetch a loopback WebSource fixture; normal scans may not.

#[cfg(feature = "web")]
#[test]
fn web_loopback_fetch_requires_autoroute_calibration_env() {
    use keyhog_core::Source;
    use keyhog_sources::WebSource;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_LOCK.lock().expect("env lock");
    let old = std::env::var_os("KEYHOG_AUTOROUTE_CALIBRATE");
    std::env::remove_var("KEYHOG_AUTOROUTE_CALIBRATE");

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

    std::env::set_var("KEYHOG_AUTOROUTE_CALIBRATE", "1");
    let allowed: Vec<_> = WebSource::new(vec![url]).chunks().collect();
    restore_env(old);

    let chunks: Vec<_> = allowed.into_iter().flatten().collect();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("keyhog-web-autoroute-calibration")),
        "autoroute calibration loopback fetch must emit the JS chunk"
    );
}

#[cfg(feature = "web")]
fn restore_env(old: Option<std::ffi::OsString>) {
    match old {
        Some(value) => std::env::set_var("KEYHOG_AUTOROUTE_CALIBRATE", value),
        None => std::env::remove_var("KEYHOG_AUTOROUTE_CALIBRATE"),
    }
}

#[cfg(not(feature = "web"))]
#[test]
fn web_loopback_fetch_requires_autoroute_calibration_env() {
    assert!(!cfg!(feature = "web"));
}
