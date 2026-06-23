#![cfg(feature = "gcs")]

mod support;

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

const BUCKET: &str = "regression-bucket";
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn object(name: &str, size: u64) -> String {
    format!(r#"{{"name":"{name}","size":"{size}"}}"#)
}

fn listing(objects: &str) -> String {
    format!(r#"{{"items":[{objects}]}}"#)
}

#[test]
fn plain_text_object_is_scanned_and_not_counted_as_skipped() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing(&object("config.txt", 40)));
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/config.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("aws_key=AKIAQYLPMN5HFIQR7XYA\n"); // keyhog:ignore detector=aws-access-key
    });

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok.len(), 1, "GCS text object should produce one chunk");
    assert!(
        ok[0].data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key
        "chunk must carry object body"
    );
    assert_eq!(
        ok[0].metadata.path.as_deref(),
        Some("gs://regression-bucket/config.txt")
    );

    let after = skip_counts();
    assert_eq!(
        after.total(),
        before.total(),
        "a scanned text object must not inflate skip counters"
    );
}

#[test]
fn binary_extension_object_is_counted_binary_without_get() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let objects = support::CLOUD_PREFILTER_BINARY_EXTS
        .iter()
        .map(|ext| object(&format!("bundle.{ext}"), 512))
        .collect::<Vec<_>>()
        .join(",");
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing(&objects));
    });
    let object_gets: Vec<_> = support::CLOUD_PREFILTER_BINARY_EXTS
        .iter()
        .map(|ext| {
            server.mock(|when, then| {
                when.method(httpmock::Method::GET)
                    .path(format!("/storage/v1/b/{BUCKET}/o/bundle.{ext}"));
                then.status(200).body("SHOULD_NOT_BE_FETCHED");
            })
        })
        .collect();

    let ok: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok.len(), 0, "binary-extension object must not be scanned");

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        support::CLOUD_PREFILTER_BINARY_EXTS.len(),
        "GCS binary/container extension prefilter MUST bump SKIPPED_BINARY"
    );
    for object_get in object_gets {
        assert_eq!(
            object_get.calls(),
            0,
            "binary-extension object must not be fetched"
        );
    }
}

#[test]
fn non_success_get_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing(&object("forbidden.txt", 32)));
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/forbidden.txt"))
            .query_param("alt", "media");
        then.status(403).body("AccessDenied");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "failed object GET must surface one source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("failed object GET must be an error row");
    assert!(
        err.to_string().contains("GET returned 403")
            && err.to_string().contains("object was not scanned"),
        "error should name the unscanned GCS object, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "GCS non-success object GET MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn non_utf8_text_labelled_object_is_counted_unreadable() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing(&object("lies.txt", 4)));
    });
    let _obj = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/lies.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body(vec![0xFFu8, 0xFE, 0x00, 0x80]);
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint(BUCKET, server.url(""))
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "non-UTF-8 GCS object must surface one source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("non-UTF-8 GCS object must be an error row");
    assert!(
        err.to_string().contains("failed UTF-8 decode")
            && err.to_string().contains("object was not scanned"),
        "error should name the undecodable GCS object, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.unreadable - before.unreadable,
        1,
        "GCS non-UTF-8 text-labelled body MUST bump SKIPPED_UNREADABLE"
    );
}

#[test]
fn max_objects_limit_is_counted_source_truncated() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let server = httpmock::MockServer::start();
    let _list = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o"))
            .query_param("alt", "json");
        then.status(200)
            .header("content-type", "application/json")
            .body(listing(&format!(
                "{},{}",
                object("first.txt", 16),
                object("second.txt", 16)
            )));
    });
    let _first = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/first.txt"))
            .query_param("alt", "media");
        then.status(200)
            .header("content-type", "text/plain")
            .body("first object\n");
    });
    let second_get = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path(format!("/storage/v1/b/{BUCKET}/o/second.txt"));
        then.status(200).body("SHOULD_NOT_BE_FETCHED");
    });

    let rows: Vec<_> = TestApi
        .gcs_source_with_endpoint_max_objects(BUCKET, server.url(""), 1)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(ok.len(), 1, "first object within cap should be scanned");
    assert_eq!(
        errors.len(),
        1,
        "max_objects truncation must surface one source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("source scan was truncated")
            && err.contains("remaining objects were not scanned"),
        "error should describe partial GCS coverage, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "GCS max_objects truncation MUST bump SOURCE_TRUNCATED"
    );
    assert_eq!(
        second_get.calls(),
        0,
        "objects beyond the cap must not be fetched"
    );
}

#[test]
fn custom_endpoint_is_not_treated_as_google_for_token_forwarding() {
    assert!(TestApi.gcs_endpoint_is_google("https://storage.googleapis.com"));
    assert!(TestApi.gcs_endpoint_is_google("https://STORAGE.GOOGLEAPIS.COM"));
    assert!(!TestApi.gcs_endpoint_is_google("https://storage.googleapis.com.attacker.example"));
    assert!(!TestApi.gcs_endpoint_is_google("https://GOOGLEAPIS.COM.attacker.example"));
    assert!(!TestApi.gcs_endpoint_is_google("https://minio.example.test"));
}

#[test]
fn gcs_token_forward_opt_in_ignores_ambient_env() {
    let saved = std::env::var("KEYHOG_GCS_ALLOW_TOKEN_FORWARD").ok();
    struct Restore(Option<String>);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                match &self.0 {
                    Some(v) => std::env::set_var("KEYHOG_GCS_ALLOW_TOKEN_FORWARD", v),
                    None => std::env::remove_var("KEYHOG_GCS_ALLOW_TOKEN_FORWARD"),
                }
            }
        }
    }
    let _restore = Restore(saved);

    unsafe {
        std::env::set_var("KEYHOG_GCS_ALLOW_TOKEN_FORWARD", "1");
    }

    assert!(
        !TestApi.gcs_credential_forward_allowed(false),
        "ambient KEYHOG_GCS_ALLOW_TOKEN_FORWARD must not enable forwarding"
    );
    assert!(
        TestApi.gcs_credential_forward_allowed(true),
        "explicit caller opt-in must enable forwarding"
    );
}
