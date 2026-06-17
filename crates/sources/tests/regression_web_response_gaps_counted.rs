#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::{skip_counts, testing::reset_skip_counters, WebSource};
use std::sync::{Mutex, MutexGuard};

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

struct CounterGuard {
    _lock: MutexGuard<'static, ()>,
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("KEYHOG_AUTOROUTE_CALIBRATE");
        }
    }
}

fn counter_guard() -> CounterGuard {
    let lock = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        std::env::set_var("KEYHOG_AUTOROUTE_CALIBRATE", "1");
    }
    CounterGuard { _lock: lock }
}

#[test]
fn clean_javascript_response_is_scanned_and_counter_clean() {
    let _guard = counter_guard();
    reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _app = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/app.js");
        then.status(200)
            .header("content-type", "application/javascript")
            .body("const key = 'AKIAQYLPMN5HFIQR7XYA';\n"); // keyhog:ignore detector=aws-access-key
    });

    let chunks: Vec<_> = WebSource::new(vec![server.url("/app.js")])
        .chunks()
        .collect();
    let ok: Vec<_> = chunks
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    assert_eq!(ok.len(), 1, "clean JavaScript URL should produce one chunk");
    assert!(
        ok[0].data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key
        "chunk must carry response body"
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a scanned web body must not inflate skip counters"
    );
}

#[test]
fn non_success_status_is_error_and_counted_unreadable() {
    let _guard = counter_guard();
    reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _missing = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/missing.js");
        then.status(404).body("not found");
    });

    let chunks: Vec<_> = WebSource::new(vec![server.url("/missing.js")])
        .chunks()
        .collect();
    assert_eq!(chunks.len(), 1, "non-success URL must yield one error");
    let err = chunks[0]
        .as_ref()
        .expect_err("404 response must be an error");
    assert!(
        err.to_string().contains("HTTP status 404"),
        "error should name the status, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "non-success WebSource response MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn over_cap_content_length_is_error_and_counted_over_max_size() {
    let _guard = counter_guard();
    reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _huge = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/huge.js");
        then.status(200).body(vec![b'x'; 10_485_761]);
    });

    let chunks: Vec<_> = WebSource::new(vec![server.url("/huge.js")])
        .chunks()
        .collect();
    assert_eq!(chunks.len(), 1, "over-cap URL must yield one error");
    let err = chunks[0]
        .as_ref()
        .expect_err("over-cap response must be an error");
    assert!(
        err.to_string().contains("10485761") || err.to_string().contains("exceeds 10 MB"),
        "error should name the over-cap response size, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "over-cap WebSource response MUST bump SKIPPED_OVER_MAX_SIZE"
    );
}

#[test]
fn invalid_wasm_magic_is_error_and_counted_unreadable() {
    let _guard = counter_guard();
    reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _bad = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/module.wasm");
        then.status(200)
            .header("content-type", "application/wasm")
            .body("this is not wasm");
    });

    let chunks: Vec<_> = WebSource::new(vec![server.url("/module.wasm")])
        .chunks()
        .collect();
    assert_eq!(chunks.len(), 1, "invalid WASM URL must yield one error");
    let err = chunks[0]
        .as_ref()
        .expect_err("invalid WASM response must be an error");
    assert!(
        err.to_string().contains("WASM magic"),
        "error should name the invalid WASM magic, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "invalid WASM WebSource response MUST bump SKIPPED_UNREADABLE"
    );
}
