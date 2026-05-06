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
    let mut last_error = None;

    for attempt in 0..MAX_VERIFY_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS * attempt as u64)).await;
        }

        let attempt_result = verify_credential(
            client,
            spec,
            credential,
            companions,
            timeout,
            allow_private_ips,
            allow_http,
            oob_session,
        )
        .await;

        if !attempt_result.transient {
            return (attempt_result.result, attempt_result.metadata);
        }

        last_error = Some(attempt_result.result);
    }

    (
        last_error.unwrap_or(VerificationResult::Error("max retries exceeded".into())),
        HashMap::new(),
    )
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
        // Multi-step verification doesn't yet thread OOB through every step;
        // OOB-bearing multi-step specs would need to mint per-step or per-flow.
        // Until a real detector requires that combination, defer to the
        // simpler single-shot multi-step path.
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

    metadata.insert(
        "oob_unique_id".to_string(),
        ctx.unique_id.clone(),
    );
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
