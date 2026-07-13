use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{AuthSpec, HttpMethod, OobPolicy, VerificationResult};
use rand::Rng;
use reqwest::Client;

use crate::interpolate::{companions_with_oob, interpolate_url};
use crate::oob::{OobObservation, OobSession};
use crate::verify::multi_step::verify_multi_step;
use crate::verify::{
    apply_header_body_templates, build_request_for_step, evaluate_success,
    execute_and_read_response, extract_metadata, resolve_live_verdict, resolved_client_for_url,
    retryable_http_status, success_spec_is_explicit, validate_header_body_templates,
    validate_template_companions, RequestBuildResult,
};

const MAX_VERIFY_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 500;

/// Operator-facing reason when the retry loop exhausts every attempt. Leads with
/// the legacy `max retries exceeded` phrase (back-compat for downstream
/// `.contains` checks) then states the likely cause and the fix.
pub const MAX_RETRIES_ERROR: &str = "max retries exceeded: every verification \
     attempt returned a retryable error (rate-limit, 5xx, or transport failure). \
     Fix: the host may be rate-limiting or flapping, retry later, or lower \
     verification concurrency so the endpoint is not overwhelmed";

/// Process-lifetime guard so the OOB-required-but-no-session warning
/// fires once per process, not once per finding. A detector corpus
/// often has dozens of OOB-bound specs and they'd each warn on every
/// finding without this gate.
static OOB_REQUIRED_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn warn_oob_required_without_session_once() {
    if OOB_REQUIRED_WARNED.set(()).is_ok() {
        tracing::warn!(
            "verifier: a detector spec required OOB callback verification but \
no OOB session is active. Verification fails closed for this finding \
(and any further OOB-required findings in this process) before sending an \
HTTP probe. To enable OOB verification pass --verify-oob to the CLI."
        );
    }
}

fn oob_required_without_session() -> VerificationAttempt {
    warn_oob_required_without_session_once();
    let mut metadata = HashMap::new();
    metadata.insert(
        "oob_disabled".to_string(),
        "no active OOB session".to_string(),
    );
    VerificationAttempt {
        result: VerificationResult::Error(
            "OOB verification required by detector but no OOB session is active. \
             Fix: run with --verify-oob and a reachable --oob-server, or remove \
             [detector.verify.oob] from the detector."
                .into(),
        ),
        metadata,
        transient: false,
    }
}

fn multi_step_oob_refused() -> VerificationAttempt {
    let mut metadata = HashMap::new();
    metadata.insert(
        "oob_disabled".to_string(),
        "multi-step OOB verification has no per-step callback binding".to_string(),
    );
    VerificationAttempt {
        result: VerificationResult::Error(
            "invalid detector runtime contract: multi-step verify specs cannot use \
             [detector.verify.oob] because OOB minting must bind to a concrete \
             request step. Fix: move the interactsh probe to a single request \
             verifier or split the detector."
                .into(),
        ),
        metadata,
        transient: false,
    }
}

pub(crate) fn empty_credential_attempt() -> VerificationAttempt {
    VerificationAttempt {
        result: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        transient: false,
    }
}

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
    proxy_in_use: bool,
    insecure_tls: bool,
    allow_script_verify: bool,
    oob_session: Option<&Arc<OobSession>>,
) -> (VerificationResult, HashMap<String, String>) {
    retry_loop(
        MAX_VERIFY_ATTEMPTS,
        RETRY_DELAY_MS,
        Some(crate::rate_limit::get_rate_limiter()),
        &spec.service,
        |_| {
            verify_credential(
                client,
                spec,
                credential,
                companions,
                timeout,
                allow_private_ips,
                allow_http,
                proxy_in_use,
                insecure_tls,
                allow_script_verify,
                oob_session,
            )
        },
    )
    .await
}

/// Generic retry loop with exponential backoff plus bounded jitter. Extracted
/// so the retry contract can be unit-tested without HTTP.
///
/// The previous inline loop dropped the last transient attempt's `metadata`
/// when retries were exhausted (it returned `(last_error.unwrap_or(...),
/// HashMap::new())`), silently losing OOB observation IDs and any
/// partially-extracted fields on a server that 500'd every attempt. This
/// helper preserves both.
async fn retry_loop<F, Fut>(
    max_attempts: usize,
    base_delay_ms: u64,
    limiter: Option<&crate::rate_limit::RateLimiter>,
    service: &str,
    mut attempt_fn: F,
) -> (VerificationResult, HashMap<String, String>)
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = VerificationAttempt>,
{
    let mut last_attempt: Option<(VerificationResult, HashMap<String, String>)> = None;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            let (min_delay_ms, max_delay_ms) =
                retry_delay_bounds_for_attempt(attempt, base_delay_ms);
            let delay_ms = if min_delay_ms == max_delay_ms {
                min_delay_ms
            } else {
                rand::thread_rng().gen_range(min_delay_ms..=max_delay_ms)
            };
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let result = attempt_fn(attempt).await;
        if let Some(limiter) = limiter {
            record_rate_limit_feedback(limiter, service, &result);
        }

        if !result.transient {
            return (result.result, result.metadata);
        }

        last_attempt = Some((result.result, result.metadata));
    }

    last_attempt.unwrap_or_else(|| {
        // LAW10: exhausted retry loop emits an operator-visible Error finding; fail-closed.
        (
            VerificationResult::Error(MAX_RETRIES_ERROR.into()),
            HashMap::new(),
        )
    })
}

fn record_rate_limit_feedback(
    limiter: &crate::rate_limit::RateLimiter,
    service: &str,
    attempt: &VerificationAttempt,
) {
    match &attempt.result {
        VerificationResult::RateLimited => limiter.record_error(),
        VerificationResult::Error(_) if attempt.transient => limiter.record_error(),
        VerificationResult::Live | VerificationResult::Dead | VerificationResult::Revoked => {
            limiter.record_success();
            // Additive-increase: a completed round-trip means the service is
            // responding, so recover a step of any per-service 429 backoff.
            limiter.reward_service(service);
        }
        _ => {}
    }
}

pub(crate) fn retry_delay_bounds_for_attempt(attempt: usize, base_delay_ms: u64) -> (u64, u64) {
    if attempt == 0 || base_delay_ms == 0 {
        return (0, 0);
    }
    let exponent = attempt.saturating_sub(1).min(10);
    let base = base_delay_ms.saturating_mul(1u64 << exponent);
    let jitter = (base / 4).max(1);
    (base, base.saturating_add(jitter))
}

pub(crate) async fn retry_loop_preserves_metadata_on_exhaustion_for_test(
) -> (VerificationResult, HashMap<String, String>) {
    retry_loop(2, 0, None, "test-service", |_| async {
        let mut metadata = HashMap::new();
        metadata.insert("oob_id".to_string(), "abc".to_string());
        VerificationAttempt {
            result: VerificationResult::Error("transient verifier failure".into()),
            metadata,
            transient: true,
        }
    })
    .await
}

pub(crate) fn rate_limit_feedback_sequence_for_test() -> (usize, usize, usize, usize, usize) {
    let limiter = crate::rate_limit::RateLimiter::new(1_000.0);

    record_rate_limit_feedback(
        &limiter,
        "svc",
        &VerificationAttempt {
            result: VerificationResult::RateLimited,
            metadata: HashMap::new(),
            transient: true,
        },
    );
    let after_rate_limited = limiter.error_count_for_test();

    record_rate_limit_feedback(
        &limiter,
        "svc",
        &VerificationAttempt {
            result: VerificationResult::Error("transient verifier failure".to_string()),
            metadata: HashMap::new(),
            transient: true,
        },
    );
    let after_transient_error = limiter.error_count_for_test();

    record_rate_limit_feedback(
        &limiter,
        "svc",
        &VerificationAttempt {
            result: VerificationResult::Dead,
            metadata: HashMap::new(),
            transient: false,
        },
    );
    let after_dead_response = limiter.error_count_for_test();

    record_rate_limit_feedback(
        &limiter,
        "svc",
        &VerificationAttempt {
            result: VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            transient: false,
        },
    );
    let after_local_unverifiable = limiter.error_count_for_test();

    record_rate_limit_feedback(
        &limiter,
        "svc",
        &VerificationAttempt {
            result: VerificationResult::Revoked,
            metadata: HashMap::new(),
            transient: false,
        },
    );
    let after_revoked_response = limiter.error_count_for_test();

    (
        after_rate_limited,
        after_transient_error,
        after_dead_response,
        after_local_unverifiable,
        after_revoked_response,
    )
}

pub(crate) async fn retry_loop_records_rate_limit_feedback_for_test() -> usize {
    let limiter = crate::rate_limit::RateLimiter::new(1_000.0);
    let before = limiter.error_count_for_test();
    let _result = retry_loop(1, 0, Some(&limiter), "test-service", |_| async {
        VerificationAttempt {
            result: VerificationResult::RateLimited,
            metadata: HashMap::new(),
            transient: true,
        }
    })
    .await;
    limiter.error_count_for_test().saturating_sub(before)
}

pub(crate) async fn verify_credential(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
    proxy_in_use: bool,
    insecure_tls: bool,
    allow_script_verify: bool,
    oob_session: Option<&Arc<OobSession>>,
) -> VerificationAttempt {
    if credential.is_empty() {
        return empty_credential_attempt();
    }

    if !spec.steps.is_empty() {
        if spec.oob.is_some() {
            return multi_step_oob_refused();
        }
        return verify_multi_step(
            client,
            spec,
            credential,
            companions,
            timeout,
            allow_private_ips,
            allow_http,
            proxy_in_use,
            insecure_tls,
            allow_script_verify,
        )
        .await;
    }

    // OOB context: mint a per-finding callback URL up front and weave it into
    // the companions map so every interpolation pass - URL, headers, body,
    // auth - picks up `{{interactsh}}` substitutions. A spec with `oob` set
    // cannot be evaluated without an active session: sending an HTTP request
    // with empty interactsh substitutions is a malformed probe, not a
    // degraded but valid verification path.
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
        (Some(_), None) => {
            return oob_required_without_session();
        }
        _ => None,
    };
    let companions_ref: &HashMap<String, String> = match oob_ctx.as_ref() {
        Some(ctx) => &ctx.augmented,
        None => companions,
    };

    let url_template = spec.url.as_deref().unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
    let method = spec.method.as_ref().unwrap_or(&HttpMethod::Get); // LAW10: absent verify-spec field => documented default (GET / AuthSpec::None / first); recall-safe
    let default_auth = AuthSpec::None {};
    let auth = spec.auth.as_ref().unwrap_or(&default_auth); // LAW10: absent verify-spec field => documented default (GET / AuthSpec::None / first); recall-safe
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

    // AwsV4 self-constructs its own STS endpoint + client in `build_aws_probe`,
    // so it never consumes `url_template`. Resolving/SSRF-screening/pinning a
    // client for `url_template` here would be discarded, skip it entirely and
    // go straight to the self-constructing path (using a placeholder URL the
    // AwsV4 auth arm ignores). Non-AwsV4 auth still resolves + SSRF-screens.
    let base_request = if is_self_constructing_auth {
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
            allow_private_ips,
            allow_http,
            proxy_in_use,
            insecure_tls,
            allow_script_verify,
        )
        .await
    } else {
        if let Err(result) =
            validate_template_companions("verification URL", url_template, companions_ref)
        {
            return VerificationAttempt {
                result,
                metadata: HashMap::new(),
                transient: false,
            };
        }
        let raw_url = interpolate_url(url_template, credential, companions_ref);
        if let Err(reason) = crate::domain_allowlist::check_url_against_spec(&raw_url, spec) {
            return VerificationAttempt {
                result: VerificationResult::Error(reason),
                metadata: HashMap::new(),
                transient: false,
            };
        }
        let resolved_target = match resolved_client_for_url(
            client,
            &raw_url,
            timeout,
            allow_private_ips,
            allow_http,
            proxy_in_use,
            insecure_tls,
        )
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
            allow_private_ips,
            allow_http,
            proxy_in_use,
            insecure_tls,
            allow_script_verify,
        )
        .await
    };
    let request = match base_request {
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
    if let Err(result) =
        validate_header_body_templates(&spec.headers, spec.body.as_deref(), companions_ref)
    {
        return VerificationAttempt {
            result,
            metadata: HashMap::new(),
            transient: false,
        };
    }
    let request = apply_header_body_templates(
        request,
        &spec.headers,
        spec.body.as_deref(),
        credential,
        companions_ref,
    );

    crate::rate_limit::get_rate_limiter()
        .wait(&spec.service)
        .await;

    let response = match execute_and_read_response(request).await {
        Ok(response) => response,
        Err(error) => {
            return VerificationAttempt {
                result: error.result,
                metadata: HashMap::new(),
                transient: error.transient,
            };
        }
    };

    let status = response.status;
    let body = response.body;

    let retryable_status = retryable_http_status(status);
    let mut success_error = None;
    let is_live = success.map_or(status == 200, |s| {
        match evaluate_success(s, status, &body) {
            Ok(matched) => matched,
            Err(error) if retryable_status => {
                tracing::warn!(
                    %status,
                    %error,
                    "verifier success contract could not evaluate retryable response"
                );
                false
            }
            Err(error) => {
                success_error = Some(error);
                false
            }
        }
    });
    if let Some(error) = success_error {
        return VerificationAttempt {
            result: error.into_verification_error(),
            metadata: HashMap::new(),
            transient: false,
        };
    }

    let is_actually_live = resolve_live_verdict(
        is_live,
        success.is_some_and(success_spec_is_explicit),
        &body,
    );
    let http_only_result = if is_actually_live {
        VerificationResult::Live
    } else if retryable_status {
        if status == 429 {
            // Multiplicative-decrease backoff for this service (recovers on
            // subsequent successes via record_rate_limit_feedback → reward_service).
            crate::rate_limit::get_rate_limiter().penalize_service(&spec.service);
        }
        VerificationResult::RateLimited
    } else {
        VerificationResult::Dead
    };
    let transient = retryable_status;

    let mut metadata = if is_actually_live {
        match extract_metadata(&spec.metadata, &body) {
            Ok(metadata) => metadata,
            Err(error) => {
                return VerificationAttempt {
                    result: error.into_verification_error(),
                    metadata: HashMap::new(),
                    transient: false,
                };
            }
        }
    } else {
        HashMap::new()
    };

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
    // Short-circuit: under OobAndHttp the verdict is `http_only_result` whenever
    // HTTP already failed, the OOB observation cannot change it (see the
    // `!http_live` arm of `oob_combined_verdict`). Waiting up to `timeout` (30s
    // default) for a callback we will never consult is pure latency, so record
    // OOB's absence and return immediately. The only observation this skips is an
    // exfil callback firing for a credential whose HTTP probe already failed, a
    // doomed OobAndHttp verdict either way.
    if matches!(ctx.spec.policy, OobPolicy::OobAndHttp) && !http_live {
        metadata.insert("oob_unique_id".to_string(), ctx.unique_id.clone());
        metadata.insert("oob_observed".to_string(), "false".to_string());
        metadata.insert(
            "oob_skipped".to_string(),
            "http-failed-under-oob-and-http".to_string(),
        );
        return http_only_result;
    }
    let timeout = ctx
        .spec
        .timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(ctx.session.config_default_timeout()); // LAW10: absent per-spec timeout => session/config default; Tier-A knob, recall-irrelevant
    let observation = ctx
        .session
        .wait_for(&ctx.unique_id, ctx.spec.protocol.into(), timeout)
        .await;

    metadata.insert("oob_unique_id".to_string(), ctx.unique_id.clone());
    let observed = matches!(observation, OobObservation::Observed { .. });
    metadata.insert("oob_observed".to_string(), observed.to_string());
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
        return VerificationResult::Error(format!(
            "OOB verification disabled during callback wait: {reason}. \
             Fix: inspect collector connectivity and rerun with --verify-oob."
        ));
    }

    oob_combined_verdict(ctx.spec.policy, http_only_result, http_live, observed)
}

/// Pure verdict combiner: fold the HTTP outcome and the OOB observation into a
/// final [`VerificationResult`] per the detector's [`OobPolicy`]. Extracted from
/// `combine_oob` (which owns the async wait + metadata) so the policy truth
/// table is ONE testable owner, and so the `OobAndHttp` short-circuit above can
/// point at the exact arm (`!http_live` ⇒ `http_only_result`, independent of
/// `observed`) that proves skipping the wait is verdict-safe.
pub(crate) fn oob_combined_verdict(
    policy: OobPolicy,
    http_only_result: VerificationResult,
    http_live: bool,
    observed: bool,
) -> VerificationResult {
    match policy {
        OobPolicy::OobAndHttp => {
            if http_live && observed {
                VerificationResult::Live
            } else if http_live && !observed {
                // HTTP says key parses but the service didn't actually call
                // back - exfil-incapable. For the OobAndHttp policy that's
                // a soft-dead: we know the key is parsed but not exfil-live.
                VerificationResult::Dead
            } else {
                http_only_result
            }
        }
        OobPolicy::OobOnly => {
            if observed {
                VerificationResult::Live
            } else if matches!(
                http_only_result,
                VerificationResult::RateLimited | VerificationResult::Error(_)
            ) {
                http_only_result
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
        .unwrap_or(default_timeout) // LAW10: absent per-spec timeout => session/config default; Tier-A knob, recall-irrelevant
}
