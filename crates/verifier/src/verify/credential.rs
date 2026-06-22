use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{AuthSpec, HttpMethod, OobPolicy, VerificationResult};
use rand::Rng;
use reqwest::Client;

use crate::interpolate::{companions_with_oob, interpolate_http_value, interpolate_url};
use crate::oob::{OobObservation, OobSession};
use crate::verify::multi_step::verify_multi_step;
use crate::verify::{
    body_indicates_error, build_request_for_step, evaluate_success, execute_request,
    extract_metadata, read_response_body, resolved_client_for_url, RequestBuildResult,
};

const MAX_VERIFY_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 500;

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
    retry_loop(MAX_VERIFY_ATTEMPTS, RETRY_DELAY_MS, |_| {
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
    })
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

        if !result.transient {
            return (result.result, result.metadata);
        }

        last_attempt = Some((result.result, result.metadata));
    }

    match last_attempt {
        Some(attempt) => attempt,
        None => (
            VerificationResult::Error("max retries exceeded".into()),
            HashMap::new(),
        ),
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
    retry_loop(2, 0, |_| async {
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
    let auth = spec.auth.as_ref().unwrap_or(&AuthSpec::None); // LAW10: absent verify-spec field => documented default (GET / AuthSpec::None / first); recall-safe
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
            allow_private_ips,
            allow_http,
            proxy_in_use,
            insecure_tls,
            allow_script_verify,
        )
        .await
    } else {
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
        let value = interpolate_http_value(&header.value, credential, companions_ref);
        request = request.header(&header.name, &value);
    }

    if let Some(body_template) = &spec.body {
        let body = interpolate_http_value(body_template, credential, companions_ref);
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
        .unwrap_or(ctx.session.config_default_timeout()); // LAW10: absent per-spec timeout => session/config default; Tier-A knob, recall-irrelevant
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
        return VerificationResult::Error(format!(
            "OOB verification disabled during callback wait: {reason}. \
             Fix: inspect collector connectivity and rerun with --verify-oob."
        ));
    }

    match ctx.spec.policy {
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
