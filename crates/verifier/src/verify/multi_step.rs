use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::VerificationResult;
use reqwest::Client;

use crate::interpolate::interpolate;
use crate::verify::credential::verification_timeout;
use crate::verify::{
    body_indicates_error, build_request_for_step, evaluate_success, execute_request,
    extract_metadata, read_response_body, resolved_client_for_url, RequestBuildResult,
    VerificationAttempt,
};

pub(crate) async fn verify_multi_step(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
) -> VerificationAttempt {
    let mut all_metadata = HashMap::new();
    let mut current_companions = companions.clone();
    let mut last_result = VerificationResult::Unverifiable;

    for step in &spec.steps {
        let step_timeout = verification_timeout(spec, timeout);
        let raw_url = interpolate(&step.url, credential, &current_companions);
        // SECURITY: per-step domain allowlist enforcement, same gate as
        // single-step verify. Multi-step URLs are interpolated from earlier
        // step responses (`extract` companions), so an attacker who controls
        // the response from step 1 could otherwise pivot the credential to
        // step 2's host. See kimi-wave1 audit finding 4.1.
        if let Err(reason) = crate::domain_allowlist::check_url_against_spec(&raw_url, spec) {
            return VerificationAttempt {
                result: VerificationResult::Error(reason),
                metadata: all_metadata,
                transient: false,
            };
        }
        let resolved_target = match resolved_client_for_url(
            client,
            &raw_url,
            step_timeout,
            allow_private_ips,
            allow_http,
        )
        .await
        {
            Ok(resolved_target) => resolved_target,
            Err(result) => {
                return VerificationAttempt {
                    result,
                    metadata: all_metadata,
                    transient: false,
                };
            }
        };

        let base_request = build_request_for_step(
            &resolved_target.client,
            &step.method,
            &step.auth,
            resolved_target.url.clone(),
            credential,
            &current_companions,
            step_timeout,
        )
        .await;

        let mut request = match base_request {
            RequestBuildResult::Ready(request) => request,
            RequestBuildResult::Final {
                result,
                metadata,
                transient,
            } => {
                all_metadata.extend(metadata);
                return VerificationAttempt {
                    result,
                    metadata: all_metadata,
                    transient,
                };
            }
        };

        for header in &step.headers {
            let value = interpolate(&header.value, credential, &current_companions);
            request = request.header(&header.name, &value);
        }

        if let Some(body_template) = &step.body {
            let body = interpolate(body_template, credential, &current_companions);
            request = request.body(body);
        }

        let service = step.auth.service_name().unwrap_or("unknown");
        crate::rate_limit::get_rate_limiter().wait(service).await;

        let response = match execute_request(request).await {
            Ok(resp) => resp,
            Err(error) => {
                return VerificationAttempt {
                    result: error.result,
                    metadata: all_metadata,
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
                    metadata: all_metadata,
                    transient: error.transient,
                };
            }
        };

        if status == 429 {
            crate::rate_limit::get_rate_limiter()
                .update_limit(service, 0.5)
                .await;
            return VerificationAttempt {
                result: VerificationResult::RateLimited,
                metadata: all_metadata,
                transient: true,
            };
        }

        if !evaluate_success(&step.success, status, &body) || body_indicates_error(&body) {
            return VerificationAttempt {
                result: VerificationResult::Dead,
                metadata: all_metadata,
                transient: false,
            };
        }

        let step_metadata = extract_metadata(&step.extract, &body);
        for (k, v) in &step_metadata {
            current_companions.insert(format!("{}.{}", step.name, k), v.clone());
        }
        all_metadata.extend(step_metadata);
        last_result = VerificationResult::Live;
    }

    VerificationAttempt {
        result: last_result,
        metadata: all_metadata,
        transient: false,
    }
}
