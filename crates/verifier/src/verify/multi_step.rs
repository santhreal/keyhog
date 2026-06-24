use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::VerificationResult;
use reqwest::Client;

use crate::interpolate::interpolate_url;
use crate::verify::credential::{empty_credential_attempt, verification_timeout};
use crate::verify::{
    apply_header_body_templates, body_indicates_error, build_request_for_step, evaluate_success,
    execute_and_read_response, extract_metadata, resolved_client_for_url,
    validate_header_body_templates, validate_template_companions, RequestBuildResult,
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
    proxy_in_use: bool,
    insecure_tls: bool,
    allow_script_verify: bool,
) -> VerificationAttempt {
    if credential.is_empty() {
        return empty_credential_attempt();
    }

    let mut all_metadata = HashMap::new();
    let mut current_companions = companions.clone();
    let mut last_result = VerificationResult::Unverifiable;

    for step in &spec.steps {
        let step_timeout = verification_timeout(spec, timeout);
        if let Err(result) =
            validate_template_companions("verification step URL", &step.url, &current_companions)
        {
            return VerificationAttempt {
                result,
                metadata: all_metadata,
                transient: false,
            };
        }
        let raw_url = interpolate_url(&step.url, credential, &current_companions);
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
            proxy_in_use,
            insecure_tls,
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
            allow_private_ips,
            allow_http,
            proxy_in_use,
            insecure_tls,
            allow_script_verify,
        )
        .await;

        let request = match base_request {
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
        if let Err(result) =
            validate_header_body_templates(&step.headers, step.body.as_deref(), &current_companions)
        {
            return VerificationAttempt {
                result,
                metadata: all_metadata,
                transient: false,
            };
        }
        let request = apply_header_body_templates(
            request,
            &step.headers,
            step.body.as_deref(),
            credential,
            &current_companions,
        );

        let service = rate_limit_service_name(spec, &step.auth);
        crate::rate_limit::get_rate_limiter().wait(service).await;

        let response = match execute_and_read_response(request).await {
            Ok(response) => response,
            Err(error) => {
                return VerificationAttempt {
                    result: error.result,
                    metadata: all_metadata,
                    transient: error.transient,
                };
            }
        };

        let status = response.status;
        let body = response.body;

        if retryable_http_status(status) {
            if status == 429 {
                crate::rate_limit::get_rate_limiter()
                    .update_limit(service, 0.5)
                    .await;
            }
            return VerificationAttempt {
                result: VerificationResult::RateLimited,
                metadata: all_metadata,
                transient: true,
            };
        }

        let success_matches = match evaluate_success(&step.success, status, &body) {
            Ok(matched) => matched,
            Err(error) => {
                return VerificationAttempt {
                    result: error.into_verification_error(),
                    metadata: all_metadata,
                    transient: false,
                };
            }
        };

        if !success_matches || body_indicates_error(&body) {
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

pub(crate) fn rate_limit_service_name<'a>(
    spec: &'a keyhog_core::VerifySpec,
    auth: &'a keyhog_core::AuthSpec,
) -> &'a str {
    match auth {
        keyhog_core::AuthSpec::AwsV4 { service, .. } => service,
        _ => spec.service.as_str(),
    }
}

fn retryable_http_status(status: u16) -> bool {
    status == 429 || (500..=504).contains(&status)
}
