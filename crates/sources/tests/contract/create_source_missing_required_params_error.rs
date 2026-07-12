//! `create_source` factory error boundaries: a source that needs a required
//! parameter must reject its absence with a NAMED, fix-carrying error (the
//! Engineering-Standard "error messages include context and the fix"), and the
//! shared `parse_bool_source_param` validator must reject a non-boolean value and
//! echo the offending token. The `docker` / `s3` match arms are UNCONDITIONAL —
//! their required-param error fires in the default `git`+`web` feature set,
//! BEFORE any feature-gated backend construction — so the contract holds even
//! where those backends are not compiled. Sibling of
//! `create_source_slack_requires_token`; `optional_usize_source_param`
//! (numeric-param error) is `#[cfg(any(s3,gcs,azure))]`-only, so its own test
//! must run under one of those features — tracked in the backlog.

/// docker:IMAGE — an absent image is rejected with the fix-carrying message.
#[test]
fn create_source_docker_requires_an_image_name() {
    match keyhog_sources::create_source("docker", None) {
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("docker source requires an image name")
                    && msg.contains("docker:IMAGE"),
                "docker without an image must name the fix (docker:IMAGE); got {err}"
            );
        }
        Ok(_) => panic!("docker without an image must return Err"),
    }
}

/// s3:BUCKET — an absent bucket is rejected with the fix-carrying message.
#[test]
fn create_source_s3_requires_a_bucket_name() {
    match keyhog_sources::create_source("s3", None) {
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("s3 source requires a bucket name") && msg.contains("s3:BUCKET"),
                "s3 without a bucket must name the fix (s3:BUCKET); got {err}"
            );
        }
        Ok(_) => panic!("s3 without a bucket must return Err"),
    }
}

/// The shared `parse_bool_source_param` rejects a non-boolean value and echoes
/// the offending token — reached in the DEFAULT feature set through the web
/// source's `autoroute_loopback_calibration=<bool>` parameter.
#[test]
fn create_source_web_rejects_non_boolean_calibration_flag() {
    match keyhog_sources::create_source("web", Some("autoroute_loopback_calibration=notabool")) {
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("boolean parameter must be true/false") && msg.contains("notabool"),
                "a non-bool calibration flag must be rejected and echoed; got {err}"
            );
        }
        Ok(_) => panic!("a non-boolean calibration flag must return Err"),
    }
}

/// Positive twin: a VALID boolean calibration flag (`true`) on its own
/// newline-delimited field, followed by a real URL, builds the web source —
/// proving the validator ADMITS legitimate values and the flag field is consumed
/// (not mistaken for a URL). Guards against a reject-everything regression a
/// negative-only test would miss. (Params are `\n`-delimited per
/// `source_param_fields`.)
#[test]
fn create_source_web_accepts_valid_calibration_flag_with_url() {
    let result = keyhog_sources::create_source(
        "web",
        Some("autoroute_loopback_calibration=true\nhttps://example.com/"),
    );
    assert!(
        result.is_ok(),
        "a valid calibration flag + URL must build the web source; got {:?}",
        result.err().map(|e| e.to_string())
    );
}
