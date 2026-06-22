use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::VerificationResult;
use reqwest::Client;
use sha2::{Digest, Sha256};

use crate::verify::request::{execute_request, resolved_client_for_url};
use crate::verify::response::read_response_body;

const AWS_VALID_ACCESS_KEY_PREFIXES: &[&str] = &["AKIA", "ASIA", "AROA", "AIDA", "AGPA"];
const AWS_ACCESS_KEY_LEN: usize = 20;
const AWS_MIN_SECRET_KEY_LEN: usize = 40;

pub(crate) async fn build_aws_probe(
    access_key: &str,
    secret_key: &str,
    session_token_template: &Option<String>,
    region: &str,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    client: &Client,
    allow_private_ips: bool,
    allow_http: bool,
    proxy_in_use: bool,
    insecure_tls: bool,
) -> super::request::RequestBuildResult {
    let access_key = crate::interpolate::resolve_field(access_key, credential, companions);
    let secret_key = crate::interpolate::resolve_field(secret_key, credential, companions);
    let session_token = session_token_template
        .as_ref()
        .map(|t| crate::interpolate::resolve_field(t, credential, companions))
        .filter(|t| !t.is_empty());

    // Canary short-circuit (fail-closed BEFORE any network egress): an access
    // key whose offline-decoded account belongs to a known canary issuer is a
    // tripwire — the STS `GetCallerIdentity` probe below would alert whoever
    // planted it. Refuse to verify it and surface the canary marker so the
    // operator learns why. Uses the fleet-canonical classifier in
    // `keyhog_core::aws` (same decode + list the scanner attaches as metadata),
    // so there is exactly one canary source of truth.
    match keyhog_core::key_id_canary_status(&access_key) {
        Ok(true) => {
            let metadata = match keyhog_core::finding_metadata(&access_key) {
                Some(metadata) => metadata,
                None => HashMap::from([("is_canary".to_string(), "true".to_string())]),
            }; // LAW10: canary classifier already matched; fallback preserves the canary marker if metadata enrichment is unavailable
            return super::request::RequestBuildResult::Final {
                result: VerificationResult::Unverifiable,
                metadata,
                transient: false,
            };
        }
        Ok(false) => {}
        Err(error) => {
            return super::request::RequestBuildResult::Final {
                result: VerificationResult::Error(format!(
                    "AWS canary account configuration invalid: {error}"
                )),
                metadata: HashMap::from([("canary_config_error".into(), error)]),
                transient: false,
            };
        }
    }

    if secret_key.is_empty() {
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            transient: false,
        };
    }

    if !valid_aws_format(&access_key, &secret_key) {
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Dead,
            metadata: HashMap::from([("format_valid".into(), "false".into())]),
            transient: false,
        };
    }

    // Validate region to prevent SSRF via malicious detector specs.
    // AWS regions are alphanumeric with hyphens only (e.g., us-east-1).
    if !region
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
        || region.is_empty()
        || region.len() > 30
    {
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Error("invalid AWS region".into()),
            metadata: HashMap::new(),
            transient: false,
        };
    }

    let host = format!("sts.{region}.amazonaws.com");
    let url = format!("https://{host}/");
    let body = "Action=GetCallerIdentity&Version=2011-06-15";
    let resolved_target = match resolved_client_for_url(
        client,
        &url,
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
            return super::request::RequestBuildResult::Final {
                result,
                metadata: HashMap::from([("format_valid".into(), "true".into())]),
                transient: false,
            };
        }
    };

    match build_sigv4_request(
        &resolved_target.client,
        resolved_target.url.as_str(),
        &host,
        body,
        &access_key,
        &secret_key,
        session_token.as_deref(),
        region,
        "sts",
        timeout,
    )
    .await
    {
        Ok((result, metadata, transient)) => super::request::RequestBuildResult::Final {
            result,
            metadata,
            transient,
        },
        Err(error_msg) => super::request::RequestBuildResult::Final {
            result: VerificationResult::Error(error_msg),
            metadata: HashMap::from([("format_valid".into(), "true".into())]),
            transient: true,
        },
    }
}

pub(crate) fn valid_aws_format(access_key: &str, secret_key: &str) -> bool {
    AWS_VALID_ACCESS_KEY_PREFIXES
        .iter()
        .any(|p| access_key.starts_with(p))
        && access_key.len() == AWS_ACCESS_KEY_LEN
        && access_key.chars().all(|c| c.is_ascii_alphanumeric())
        && secret_key.len() >= AWS_MIN_SECRET_KEY_LEN
        && secret_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

async fn build_sigv4_request(
    client: &Client,
    url: &str,
    host: &str,
    body: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    timeout: Duration,
) -> std::result::Result<(VerificationResult, HashMap<String, String>, bool), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let canonical_uri = "/";
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let (auth_header, amz_date, _) = crate::sigv4::sign_request_authorization(
        access_key,
        secret_key,
        session_token,
        region,
        service,
        "POST",
        canonical_uri,
        &[],
        host,
        &payload_hash,
        now_secs,
        &[],
    )?;

    let mut request = client
        .post(url)
        .header("Authorization", auth_header)
        .header("x-amz-date", amz_date)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .timeout(timeout);

    if let Some(token) = session_token {
        request = request.header("x-amz-security-token", token);
    }

    crate::rate_limit::get_rate_limiter().wait(service).await;

    let response = execute_request(request)
        .await
        .map_err(|e| format!("{:?}", e.result))?;
    let status = response.status().as_u16();
    let resp_body = read_response_body(response)
        .await
        .map_err(|e| format!("{:?}", e.result))?;

    if resp_body.contains("RequestTimeTooSkewed") || resp_body.contains("SignatureDoesNotMatch") {
        tracing::warn!(
            status,
            "AWS verification failure indicates clock skew or invalid signature. Check system time."
        );
    }

    if status == 200 {
        let mut metadata = HashMap::new();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_body) {
            if let Some(arn) =
                json.pointer("/GetCallerIdentityResponse/GetCallerIdentityResult/Arn")
            {
                if let Some(arn) = arn.as_str() {
                    metadata.insert("arn".into(), arn.into());
                } else {
                    tracing::warn!(
                        "AWS STS GetCallerIdentity Arn field was not a string; omitting metadata field"
                    );
                }
            }
            if let Some(account) =
                json.pointer("/GetCallerIdentityResponse/GetCallerIdentityResult/Account")
            {
                if let Some(account) = account.as_str() {
                    metadata.insert("account_id".into(), account.into());
                } else {
                    tracing::warn!(
                        "AWS STS GetCallerIdentity Account field was not a string; omitting metadata field"
                    );
                }
            }
        }
        Ok((VerificationResult::Live, metadata, false))
    } else if status == 403 {
        Ok((VerificationResult::Dead, HashMap::new(), false))
    } else {
        Ok((VerificationResult::RateLimited, HashMap::new(), true))
    }
}
