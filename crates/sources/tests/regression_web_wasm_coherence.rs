#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

struct CounterGuard {
    _lock: MutexGuard<'static, ()>,
}

fn counter_guard() -> CounterGuard {
    let lock = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    CounterGuard { _lock: lock }
}

fn loopback_source(url: String) -> keyhog_sources::WebSource {
    TestApi.web_source_with_autoroute_loopback_calibration(vec![url], true)
}

#[test]
fn extensionless_wasm_content_type_error_names_classification_not_suffix() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _module = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/module");
        then.status(200)
            .header("content-type", "application/wasm")
            .body("not a wasm module");
    });

    let rows: Vec<_> = loopback_source(server.url("/module")).chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "invalid extensionless WASM response must yield one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("invalid extensionless WASM response must fail loud")
        .to_string();
    assert!(
        err.contains("classified as WebAssembly") && err.contains("WASM magic bytes"),
        "error must name the content classification path and magic failure, got {err}"
    );
    assert!(
        !err.contains("URL ended with .wasm"),
        "extensionless Content-Type-routed WASM must not claim suffix routing, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "invalid extensionless WASM response must increment the shared unreadable counter"
    );
}
