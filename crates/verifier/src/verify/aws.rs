use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::VerificationResult;
use quick_xml::de::{Deserializer, PredefinedEntityResolver};
use quick_xml::events::Event;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::verify::request::{execute_request, resolved_client_for_url, RequestError};
use crate::verify::response::read_response_body;

const AWS_VALID_ACCESS_KEY_PREFIXES: &[&str] = &["AKIA", "ASIA", "AROA", "AIDA", "AGPA"];
const AWS_ACCESS_KEY_LEN: usize = 20;
const AWS_MIN_SECRET_KEY_LEN: usize = 40;

/// Operator-facing reason when the region fails the SigV4 region-format check.
/// Leads with the legacy `invalid AWS region` phrase, then names the exact format
/// requirement and where to correct it.
pub const INVALID_AWS_REGION_ERROR: &str = "invalid AWS region: the region must be \
     non-empty, at most 30 characters, and contain only letters, digits, and \
     hyphens (e.g. us-east-1). Fix: correct the AWS region in the detector \
     verification spec or the credential's companion fields";

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
    // Sanitize+resolve every credential field the SigV4 probe signs. A captured
    // value can carry a trailing newline / control byte (line-anchored capture),
    // and `valid_aws_format` requires an EXACT 20-char all-alphanumeric access key,
    // so an unsanitized `AKIA…\n` would be misreported `Dead` — a LIVE key silently
    // missed. This mirrors the sibling `AuthSpec::Query` arm in `auth.rs`, which
    // already resolves + `sanitize_raw_value`s its field. `region` is resolved the
    // same way so a `companion.region` reference actually resolves instead of being
    // fed verbatim to the region-format screen (which only ever rejects it).
    let resolve = |field: &str| {
        crate::interpolate::sanitize_raw_value(&crate::interpolate::resolve_field(
            field, credential, companions,
        ))
    };
    let access_key = resolve(access_key);
    let secret_key = resolve(secret_key);
    let session_token = session_token_template
        .as_ref()
        .map(|template| resolve(template))
        .filter(|token| !token.is_empty());
    let region = resolve(region);

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

    if let Err(result) = validate_aws_region(&region) {
        return super::request::RequestBuildResult::Final {
            result,
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
        &region,
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
        Err(error) => super::request::RequestBuildResult::Final {
            result: error.result,
            metadata: HashMap::from([("format_valid".into(), "true".into())]),
            transient: error.transient,
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

pub(crate) fn validate_aws_region(region: &str) -> std::result::Result<(), VerificationResult> {
    // Validate region to prevent SSRF via malicious detector specs.
    // AWS regions are alphanumeric with hyphens only (e.g., us-east-1).
    if region
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !region.is_empty()
        && region.len() <= 30
    {
        Ok(())
    } else {
        Err(VerificationResult::Error(INVALID_AWS_REGION_ERROR.into()))
    }
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
) -> std::result::Result<(VerificationResult, HashMap<String, String>, bool), RequestError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RequestError {
            result: VerificationResult::Error(format!("failed to read system clock: {error}")),
            transient: false,
        })?
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
    )
    .map_err(|error| RequestError {
        result: VerificationResult::Error(error),
        transient: false,
    })?;

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

    let response = execute_request(request).await?;
    let status = response.status().as_u16();
    let resp_body = read_response_body(response).await?;

    if resp_body.contains("RequestTimeTooSkewed") || resp_body.contains("SignatureDoesNotMatch") {
        tracing::warn!(
            status,
            "AWS verification failure indicates clock skew or invalid signature. Check system time."
        );
    }

    if status == 200 {
        let metadata = match parse_aws_sts_success_metadata(&resp_body) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "AWS STS GetCallerIdentity returned HTTP 200 but identity metadata could \
                     not be parsed; reporting the credential as live with metadata_parse_error"
                );
                HashMap::from([("metadata_parse_error".into(), error)])
            }
        };
        Ok((VerificationResult::Live, metadata, false))
    } else {
        let (result, transient) = classify_aws_sts_failure(status, &resp_body);
        Ok((result, HashMap::new(), transient))
    }
}

pub(crate) fn classify_aws_sts_failure(status: u16, body: &str) -> (VerificationResult, bool) {
    if status == 403 {
        if body.contains("RequestTimeTooSkewed") {
            return (
                VerificationResult::Error(
                    "AWS STS rejected the request because system time is skewed; fix the host clock and retry verification"
                        .into(),
                ),
                true,
            );
        }
        return (VerificationResult::Dead, false);
    }
    (VerificationResult::RateLimited, true)
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsGetCallerIdentityResponse {
    #[serde(default)]
    get_caller_identity_result: StsGetCallerIdentityResult,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsGetCallerIdentityResult {
    #[serde(default)]
    arn: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
}

pub(crate) fn parse_aws_sts_success_metadata(
    body: &str,
) -> Result<HashMap<String, String>, String> {
    if body.trim_start().starts_with('{') {
        return parse_aws_sts_json_success_metadata(body);
    }
    parse_aws_sts_xml_success_metadata(body)
}

fn parse_aws_sts_json_success_metadata(body: &str) -> Result<HashMap<String, String>, String> {
    let json = serde_json::from_str::<serde_json::Value>(body)
        .map_err(|error| format!("failed to parse AWS STS success JSON: {error}"))?;
    let result = json
        .pointer("/GetCallerIdentityResponse/GetCallerIdentityResult")
        .ok_or_else(|| "AWS STS success JSON missing GetCallerIdentityResult".to_string())?;
    let mut metadata = HashMap::new();
    insert_json_string_field(&mut metadata, result, "arn", "Arn")?;
    insert_json_string_field(&mut metadata, result, "account_id", "Account")?;
    insert_json_string_field(&mut metadata, result, "user_id", "UserId")?;
    require_identity_metadata(metadata)
}

fn insert_json_string_field(
    metadata: &mut HashMap<String, String>,
    result: &serde_json::Value,
    key: &str,
    field: &str,
) -> Result<(), String> {
    let Some(value) = result.get(field) else {
        return Ok(());
    };
    let Some(value) = value.as_str() else {
        return Err(format!(
            "AWS STS GetCallerIdentity {field} field was not a string"
        ));
    };
    metadata.insert(key.to_string(), value.to_string());
    Ok(())
}

fn parse_aws_sts_xml_success_metadata(body: &str) -> Result<HashMap<String, String>, String> {
    reject_aws_sts_xml_doctype(body)?;
    let mut deserializer = Deserializer::from_str_with_resolver(body, PredefinedEntityResolver);
    let response = StsGetCallerIdentityResponse::deserialize(&mut deserializer)
        .map_err(|error| format!("failed to parse AWS STS success XML: {error}"))?;
    let mut metadata = HashMap::new();
    if let Some(arn) = response.get_caller_identity_result.arn {
        metadata.insert("arn".into(), arn);
    }
    if let Some(account) = response.get_caller_identity_result.account {
        metadata.insert("account_id".into(), account);
    }
    if let Some(user_id) = response.get_caller_identity_result.user_id {
        metadata.insert("user_id".into(), user_id);
    }
    require_identity_metadata(metadata)
}

fn reject_aws_sts_xml_doctype(body: &str) -> Result<(), String> {
    let mut reader = quick_xml::Reader::from_str(body);
    loop {
        match reader.read_event() {
            Ok(Event::DocType(_)) => {
                return Err("AWS STS success XML contains unsupported DOCTYPE declarations".into());
            }
            Ok(Event::Eof) => return Ok(()),
            Ok(_) => {}
            Err(error) => {
                return Err(format!("failed to validate AWS STS success XML: {error}"));
            }
        }
    }
}

fn require_identity_metadata(
    metadata: HashMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    if metadata.contains_key("arn") && metadata.contains_key("account_id") {
        Ok(metadata)
    } else {
        Err("AWS STS success response missing Arn or Account metadata".into())
    }
}
