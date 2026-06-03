use std::collections::HashMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use keyhog_core::VerificationResult;
use reqwest::Client;
use sha2::{Digest, Sha256};

use crate::verify::request::execute_request;
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
    if keyhog_core::aws::key_id_is_canary(&access_key) {
        let mut metadata = HashMap::from([("is_canary".to_string(), "true".to_string())]);
        if let Some(account) = keyhog_core::aws::aws_account_from_key_id(&access_key) {
            metadata.insert("account_id".to_string(), account);
        }
        metadata.insert(
            "canary_message".to_string(),
            keyhog_core::aws::CANARY_MESSAGE.to_string(),
        );
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Unverifiable,
            metadata,
            transient: false,
        };
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

    match build_sigv4_request(
        client,
        &url,
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
    let (date_stamp, amz_date) = format_sigv4_timestamps(now_secs);
    let date_stamp = &date_stamp;
    let amz_date = &amz_date;

    let canonical_uri = "/";
    let canonical_querystring = "";
    // Temporary (STS / ASIA) credentials carry a session token that MUST be part
    // of the signed canonical headers, otherwise AWS replies SignatureDoesNotMatch
    // (HTTP 403) and a live credential is misverified as Dead. Mirror the known-good
    // S3 signer in crates/sources/src/s3/auth.rs which signs x-amz-security-token.
    let (canonical_headers, signed_headers) = aws_signed_headers(host, amz_date, session_token);
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_request = format!(
        "POST\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = get_signature_key(secret_key, date_stamp, region, service)?;
    let signature = hex::encode(hmac_sha256(&signing_key, &string_to_sign)?);

    // The session token is NOT part of the Authorization header grammar; it travels
    // only as the (now-signed) x-amz-security-token request header set below.
    let auth_header = format!(
        "{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

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
                metadata.insert("arn".into(), arn.as_str().unwrap_or("").into());
            }
            if let Some(account) =
                json.pointer("/GetCallerIdentityResponse/GetCallerIdentityResult/Account")
            {
                metadata.insert("account_id".into(), account.as_str().unwrap_or("").into());
            }
        }
        Ok((VerificationResult::Live, metadata, false))
    } else if status == 403 {
        Ok((VerificationResult::Dead, HashMap::new(), false))
    } else {
        Ok((VerificationResult::RateLimited, HashMap::new(), true))
    }
}

/// Build the SigV4 `(canonical_headers, signed_headers)` pair for the STS probe.
///
/// `host` and `x-amz-date` are always signed. When a `session_token` is present
/// (temporary / STS `ASIA…` credentials) `x-amz-security-token` is appended to
/// both, keeping the headers lexicographically sorted (`host` < `x-amz-date` <
/// `x-amz-security-token`). Signing the token is mandatory for temporary
/// credentials; omitting it makes AWS return `SignatureDoesNotMatch` (HTTP 403),
/// which the probe would otherwise misread as a dead key. Mirrors the
/// known-good S3 signer in `crates/sources/src/s3/auth.rs`.
pub fn aws_signed_headers(
    host: &str,
    amz_date: &str,
    session_token: Option<&str>,
) -> (String, String) {
    let mut canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    let mut signed_headers = String::from("host;x-amz-date");
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
        signed_headers.push_str(";x-amz-security-token");
    }
    (canonical_headers, signed_headers)
}

fn hmac_sha256(key: &[u8], data: &str) -> std::result::Result<Vec<u8>, String> {
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| format!("failed to create AWS HMAC signer: {error}"))?;
    mac.update(data.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn get_signature_key(
    key: &str,
    date_stamp: &str,
    region_name: &str,
    service_name: &str,
) -> std::result::Result<Vec<u8>, String> {
    let k_date = hmac_sha256(format!("AWS4{key}").as_bytes(), date_stamp)?;
    let k_region = hmac_sha256(&k_date, region_name)?;
    let k_service = hmac_sha256(&k_region, service_name)?;
    hmac_sha256(&k_service, "aws4_request")
}

/// Format the SigV4 timestamps from a Unix epoch second value.
/// Returns `(date_stamp = "YYYYMMDD", amz_date = "YYYYMMDDTHHMMSSZ")`.
pub fn format_sigv4_timestamps(unix_secs: u64) -> (String, String) {
    // Civil-from-days, after Howard Hinnant's date algorithm.
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = (unix_secs % 86_400) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11
    let d = doy - (153 * mp + 2) / 5 + 1; // 1..=31
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // 1..=12
    let year = y + i64::from(m <= 2);

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let date_stamp = format!("{year:04}{m:02}{d:02}");
    let amz_date = format!("{year:04}{m:02}{d:02}T{hour:02}{minute:02}{second:02}Z");
    (date_stamp, amz_date)
}
