use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{AuthSpec, HttpMethod, OobPolicy, VerificationResult};
use reqwest::Client;

use crate::interpolate::{companions_with_oob, interpolate};
use crate::oob::{OobObservation, OobSession};
use crate::verify::multi_step::verify_multi_step;
use crate::verify::{
    body_indicates_error, build_request_for_step, evaluate_success, execute_request,
    extract_metadata, read_response_body, resolved_client_for_url, RequestBuildResult,
};

const MAX_VERIFY_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 500;

pub(crate) struct VerificationAttempt {
    pub result: VerificationResult,
    pub metadata: HashMap<String, String>,
    pub transient: bool,
}

pub(crate) async fn verify_with_retry(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
    oob_session: Option<&Arc<OobSession>>,
) -> (VerificationResult, HashMap<String, String>) {
    retry_loop(MAX_VERIFY_ATTEMPTS, RETRY_DELAY_MS, |_| {
        verify_credential(
            client,
            spec,
            credential,
            companions,
            timeout,
            allow_private_ips,
            allow_http,
            oob_session,
        )
    })
    .await
}

/// Generic retry loop with linear backoff. Extracted so the retry contract
/// can be unit-tested without HTTP.
///
/// The previous inline loop dropped the last transient attempt's `metadata`
/// when retries were exhausted — `(last_error.unwrap_or(...), HashMap::new())`
/// — which silently lost OOB observation IDs and any partially-extracted
/// fields on a server that 500'd every attempt. This helper preserves both.
async fn retry_loop<F, Fut>(
    max_attempts: usize,
    base_delay_ms: u64,
    mut attempt_fn: F,
) -> (VerificationResult, HashMap<String, String>)
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = VerificationAttempt>,
{
    let mut last_attempt: Option<(VerificationResult, HashMap<String, String>)> = None;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(base_delay_ms * attempt as u64)).await;
        }

        let result = attempt_fn(attempt).await;

        if !result.transient {
            return (result.result, result.metadata);
        }

        last_attempt = Some((result.result, result.metadata));
    }

    last_attempt.unwrap_or_else(|| {
        (
            VerificationResult::Error("max retries exceeded".into()),
            HashMap::new(),
        )
    })
}

pub(crate) async fn verify_credential(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
    oob_session: Option<&Arc<OobSession>>,
) -> VerificationAttempt {
    if !spec.steps.is_empty() {
        // Multi-step specs run the no-OOB `verify_multi_step` path —
        // threading OOB through per-step or per-flow minting is open
        // and unfinished. No bundled detector currently combines
        // `[[steps]]` with an `oob` block, so the gap doesn't bite
        // today; adding a detector that needs both must land the
        // per-step OOB plumbing too or it will silently lose the
        // out-of-band signal.
        return verify_multi_step(
            client,
            spec,
            credential,
            companions,
            timeout,
            allow_private_ips,
            allow_http,
        )
        .await;
    }

    // OOB context: mint a per-finding callback URL up front and weave it into
    // the companions map so every interpolation pass — URL, headers, body,
    // auth — picks up `{{interactsh}}` substitutions. We only mint when the
    // session is active; specs with `oob` set but no session degrade silently
    // to HTTP-only verification.
    let oob_ctx = match (spec.oob.as_ref(), oob_session) {
        (Some(oob_spec), Some(session)) => {
            let minted = session.mint();
            Some(OobContext {
                spec: oob_spec.clone(),
                session: Arc::clone(session),
                unique_id: minted.unique_id.clone(),
                augmented: companions_with_oob(
                    companions,
                    &minted.host,
                    &minted.url,
                    &minted.unique_id,
                ),
            })
        }
        _ => None,
    };
    let companions_ref: &HashMap<String, String> = match oob_ctx.as_ref() {
        Some(ctx) => &ctx.augmented,
        None => companions,
    };

    let url_template = spec.url.as_deref().unwrap_or("");
    let method = spec.method.as_ref().unwrap_or(&HttpMethod::Get);
    let auth = spec.auth.as_ref().unwrap_or(&AuthSpec::None);
    let success = spec.success.as_ref();

    let is_self_constructing_auth = matches!(auth, AuthSpec::AwsV4 { .. });

    if url_template.is_empty() && !is_self_constructing_auth {
        return VerificationAttempt {
            result: VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            transient: false,
        };
    }

    let timeout = verification_timeout(spec, timeout);

    let base_request = if is_self_constructing_auth && url_template.is_empty() {
        let placeholder_url = match reqwest::Url::parse("https://placeholder.invalid") {
            Ok(url) => url,
            Err(error) => {
                return VerificationAttempt {
                    result: VerificationResult::Error(format!(
                        "failed to build internal placeholder URL: {error}. Fix: report this verifier build"
                    )),
                    metadata: HashMap::new(),
                    transient: false,
                };
            }
        };
        build_request_for_step(
            client,
            method,
            auth,
            placeholder_url,
            credential,
            companions_ref,
            timeout,
        )
        .await
    } else {
        let raw_url = interpolate(url_template, credential, companions_ref);
        if let Err(reason) = crate::domain_allowlist::check_url_against_spec(&raw_url, spec) {
            return VerificationAttempt {
                result: VerificationResult::Error(reason),
                metadata: HashMap::new(),
                transient: false,
            };
        }
        let resolved_target =
            match resolved_client_for_url(client, &raw_url, timeout, allow_private_ips, allow_http)
                .await
            {
                Ok(resolved_target) => resolved_target,
                Err(result) => {
                    return VerificationAttempt {
                        result,
                        metadata: HashMap::new(),
                        transient: false,
                    };
                }
            };

        build_request_for_step(
            &resolved_target.client,
            method,
            auth,
            resolved_target.url.clone(),
            credential,
            companions_ref,
            timeout,
        )
        .await
    };
    let mut request = match base_request {
        RequestBuildResult::Ready(request) => request,
        RequestBuildResult::Final {
            result,
            metadata,
            transient,
        } => {
            return VerificationAttempt {
                result,
                metadata,
                transient,
            };
        }
    };

    for header in &spec.headers {
        let value = interpolate(&header.value, credential, companions_ref);
        request = request.header(&header.name, &value);
    }

    if let Some(body_template) = &spec.body {
        let body = interpolate(body_template, credential, companions_ref);
        request = request.body(body);
    }

    crate::rate_limit::get_rate_limiter()
        .wait(&spec.service)
        .await;

    let response = match execute_request(request).await {
        Ok(resp) => resp,
        Err(error) => {
            return VerificationAttempt {
                result: error.result,
                metadata: HashMap::new(),
                transient: error.transient,
            };
        }
    };

    let status = response.status().as_u16();
    let body = match read_response_body(response).await {
        Ok(body) => body,
        Err(error) => {
            return VerificationAttempt {
                result: error.result,
                metadata: HashMap::new(),
                transient: error.transient,
            };
        }
    };

    let is_live = if let Some(s) = success {
        evaluate_success(s, status, &body)
    } else {
        status == 200
    };

    let is_actually_live = is_live && !body_indicates_error(&body);
    let mut metadata = extract_metadata(&spec.metadata, &body);

    let http_only_result = if is_actually_live {
        VerificationResult::Live
    } else if status == 429 || (500..=504).contains(&status) {
        if status == 429 {
            crate::rate_limit::get_rate_limiter()
                .update_limit(&spec.service, 0.5)
                .await;
        }
        VerificationResult::RateLimited
    } else {
        VerificationResult::Dead
    };
    let transient = status == 429 || (500..=504).contains(&status);

    let verification_result = match oob_ctx {
        None => http_only_result,
        Some(ctx) => combine_oob(ctx, http_only_result, is_actually_live, &mut metadata).await,
    };

    VerificationAttempt {
        result: verification_result,
        metadata,
        transient,
    }
}

/// Per-finding OOB state. Held only across one `verify_credential` call;
/// the session itself is engine-scoped and lives much longer.
struct OobContext {
    spec: keyhog_core::OobSpec,
    session: Arc<OobSession>,
    unique_id: String,
    augmented: HashMap<String, String>,
}

/// Combine HTTP and OOB results per the detector's policy. Always populates
/// `metadata` with the OOB observation (or its absence) for downstream
/// reporters, regardless of which signal drove the final verdict.
async fn combine_oob(
    ctx: OobContext,
    http_only_result: VerificationResult,
    http_live: bool,
    metadata: &mut HashMap<String, String>,
) -> VerificationResult {
    let timeout = ctx
        .spec
        .timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(ctx.session.config_default_timeout());
    let observation = ctx
        .session
        .wait_for(&ctx.unique_id, ctx.spec.protocol.into(), timeout)
        .await;

    metadata.insert("oob_unique_id".to_string(), ctx.unique_id.clone());
    let observed = matches!(observation, OobObservation::Observed { .. });
    metadata.insert(
        "oob_observed".to_string(),
        if observed { "true" } else { "false" }.to_string(),
    );
    if let OobObservation::Observed {
        protocol,
        remote_address,
        timestamp,
        ..
    } = &observation
    {
        metadata.insert("oob_protocol".to_string(), format!("{protocol:?}"));
        metadata.insert("oob_remote_address".to_string(), remote_address.clone());
        metadata.insert("oob_timestamp".to_string(), timestamp.clone());
    }
    if let OobObservation::Disabled(reason) = &observation {
        metadata.insert("oob_disabled".to_string(), reason.clone());
        // Session unhealthy → fall back to HTTP-only verdict regardless of
        // policy. Better to report what we know than mark everything Dead.
        return http_only_result;
    }

    match ctx.spec.policy {
        OobPolicy::OobAndHttp => {
            if http_live && observed {
                VerificationResult::Live
            } else if http_live && !observed {
                // HTTP says key parses but the service didn't actually call
                // back — exfil-incapable. For the OobAndHttp policy that's
                // a soft-dead: we know the key is parsed but not exfil-live.
                VerificationResult::Dead
            } else {
                http_only_result
            }
        }
        OobPolicy::OobOnly => {
            if observed {
                VerificationResult::Live
            } else {
                VerificationResult::Dead
            }
        }
        OobPolicy::OobOptional => http_only_result,
    }
}

pub(crate) fn verification_timeout(
    spec: &keyhog_core::VerifySpec,
    default_timeout: Duration,
) -> Duration {
    spec.timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(default_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn attempt(result: VerificationResult, transient: bool) -> VerificationAttempt {
        let mut metadata = HashMap::new();
        metadata.insert("oob_unique_id".into(), "abc123".into());
        metadata.insert("trace_id".into(), "xyz-789".into());
        VerificationAttempt {
            result,
            metadata,
            transient,
        }
    }

    /// Regression for the silent-metadata-drop bug: when every attempt is
    /// transient and retries are exhausted, the last attempt's metadata
    /// must be returned, not `HashMap::new()`. The previous
    /// `(last_error.unwrap_or(...), HashMap::new())` flow lost OOB
    /// observation IDs that downstream reporters depend on.
    #[tokio::test]
    async fn retry_loop_preserves_last_metadata_on_exhaustion() {
        let calls = AtomicUsize::new(0);
        let (result, metadata) = retry_loop(3, 1, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { attempt(VerificationResult::RateLimited, true) }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(matches!(result, VerificationResult::RateLimited));
        assert_eq!(
            metadata.get("oob_unique_id").map(String::as_str),
            Some("abc123"),
            "OOB metadata from final transient attempt must survive retry exhaustion"
        );
        assert_eq!(metadata.get("trace_id").map(String::as_str), Some("xyz-789"));
    }

    /// On the first non-transient response the loop must return that
    /// attempt's metadata as-is (no retry, no merge).
    #[tokio::test]
    async fn retry_loop_returns_first_non_transient_attempt() {
        let calls = AtomicUsize::new(0);
        let (result, metadata) = retry_loop(3, 1, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { attempt(VerificationResult::Live, false) }
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "non-transient attempt must not be retried"
        );
        assert!(matches!(result, VerificationResult::Live));
        assert_eq!(metadata.get("oob_unique_id").map(String::as_str), Some("abc123"));
    }

    /// Retry until success: first two attempts transient, third succeeds.
    /// The successful attempt's metadata wins.
    #[tokio::test]
    async fn retry_loop_returns_successful_attempt_after_transient_failures() {
        let calls = AtomicUsize::new(0);
        let (result, metadata) = retry_loop(3, 1, |_| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    attempt(VerificationResult::RateLimited, true)
                } else {
                    let mut m = HashMap::new();
                    m.insert("winner".into(), "third".into());
                    VerificationAttempt {
                        result: VerificationResult::Live,
                        metadata: m,
                        transient: false,
                    }
                }
            }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(matches!(result, VerificationResult::Live));
        assert_eq!(metadata.get("winner").map(String::as_str), Some("third"));
        assert!(
            !metadata.contains_key("oob_unique_id"),
            "non-transient attempt's metadata replaces (does not merge with) transient attempts"
        );
    }

    /// `max_attempts == 0` is a degenerate config (treat as no attempts).
    /// Without a single attempt, `last_attempt` stays None — must fall
    /// through to the synthetic `max retries exceeded` error, not panic.
    #[tokio::test]
    async fn retry_loop_handles_zero_max_attempts() {
        let calls = AtomicUsize::new(0);
        let (result, metadata) = retry_loop(0, 1, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { attempt(VerificationResult::Live, false) }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        match result {
            VerificationResult::Error(msg) => assert!(msg.contains("max retries")),
            other => panic!("expected synthetic error, got {other:?}"),
        }
        assert!(metadata.is_empty());
    }
}
