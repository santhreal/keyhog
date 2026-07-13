//! S3 `max_objects` numeric-parameter validation (`factory.rs`
//! `optional_usize_source_param`, `#[cfg(any(s3,gcs,azure))]`).
//!
//! The 5th S3 spec field (`s3:BUCKET\nPREFIX\nENDPOINT\nFORWARD\nMAX_OBJECTS`)
//! is an optional object-count cap parsed as `usize`. A malformed value must be
//! rejected with a NAMED error, never silently ignored (which would scan an
//! unbounded object set) or panic. This target is gated behind `--features s3`
//! because the parser and its only callers (`s3`/`gcs`/`azure` arms) are all
//! `#[cfg(feature = ...)]`: so this file compiles only under those features.
//!
//! Run: `cargo test -p keyhog-sources --features s3 --test regression_s3_numeric_param_validation`.
#![cfg(feature = "s3")]

use keyhog_core::SourceError;
use keyhog_sources::create_source;

/// Extract the error from a `create_source` result. `Box<dyn Source>` does not
/// implement `Debug`, so `expect_err` is unavailable (this matches instead).
fn expect_create_source_err(spec: &str) -> SourceError {
    match create_source("s3", Some(spec)) {
        Ok(_) => panic!("expected an error for spec {spec:?}, but the source built"),
        Err(err) => err,
    }
}

/// True iff `create_source("s3", spec)` builds a source (Ok). Avoids formatting
/// the non-`Debug` `Box<dyn Source>`.
fn s3_source_builds(spec: &str) -> bool {
    create_source("s3", Some(spec)).is_ok()
}

/// A benign 4-field S3 spec (bucket/prefix/endpoint/forward) plus a 5th
/// `max_objects` field. No network is touched, the factory only parses fields
/// and constructs the source struct, so the numeric-parse branch is reached
/// deterministically offline.
fn s3_spec_with_max_objects(max_objects: &str) -> String {
    format!("mybucket\nlogs/\nhttp://localhost:9000\nfalse\n{max_objects}")
}

#[test]
fn non_numeric_max_objects_is_a_named_error() {
    let err = expect_create_source_err(&s3_spec_with_max_objects("notanumber"));
    let msg = err.to_string();
    assert!(
        msg.contains("numeric parameter must be a non-negative integer"),
        "the error must name the numeric-parameter contract; got {msg:?}"
    );
    assert!(
        msg.contains("notanumber"),
        "the error must quote the offending value; got {msg:?}"
    );
    assert!(
        matches!(err, SourceError::Other(_)),
        "expected SourceError::Other, got {err:?}"
    );
}

#[test]
fn negative_max_objects_is_rejected() {
    // `usize` cannot be negative, so `-5` fails the parse exactly like garbage.
    let err = expect_create_source_err(&s3_spec_with_max_objects("-5"));
    assert!(
        err.to_string()
            .contains("numeric parameter must be a non-negative integer"),
        "got {err:?}"
    );
}

#[test]
fn valid_max_objects_builds_the_source() {
    // A well-formed cap parses cleanly and yields a source (no error), proving the
    // rejection above is specific to malformed input, not a blanket failure of the
    // 5-field spec.
    assert!(
        s3_source_builds(&s3_spec_with_max_objects("100")),
        "a valid numeric max_objects must build the source"
    );
}

#[test]
fn omitted_max_objects_is_allowed() {
    // The field is OPTIONAL: a 4-field spec (no max_objects) builds fine, the
    // parser returns `None`, not an error.
    assert!(
        s3_source_builds("mybucket\nlogs/\nhttp://localhost:9000\nfalse"),
        "omitting the optional cap must be allowed"
    );
}
