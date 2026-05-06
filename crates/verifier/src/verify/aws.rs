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
    let canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-date";
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

    let mut auth_header = format!(
        "{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    if let Some(token) = session_token {
        auth_header.push_str(&format!(", X-Amz-Security-Token={token}"));
    }

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
///
/// Hand-rolled UTC formatter — avoids pulling in `chrono` for the verifier crate
/// and keeps `SystemTime::now()` as the single source of truth (AWS rejects
/// signatures whose timestamp drifts more than ~15 minutes from server clock).
fn format_sigv4_timestamps(unix_secs: u64) -> (String, String) {
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

#[cfg(test)]
mod tests {
    use super::format_sigv4_timestamps;

    #[test]
    fn epoch_zero() {
        let (d, a) = format_sigv4_timestamps(0);
        assert_eq!(d, "19700101");
        assert_eq!(a, "19700101T000000Z");
    }

    #[test]
    fn known_aws_example() {
        // RFC 7231: 1970-01-01T00:00:00Z + 1_704_067_200s = 2024-01-01T00:00:00Z.
        let (d, a) = format_sigv4_timestamps(1_704_067_200);
        assert_eq!(d, "20240101");
        assert_eq!(a, "20240101T000000Z");
    }

    #[test]
    fn leap_year_feb_29() {
        // 2024-02-29T12:34:56Z = 1_709_210_096
        let (d, a) = format_sigv4_timestamps(1_709_210_096);
        assert_eq!(d, "20240229");
        assert_eq!(a, "20240229T123456Z");
    }

    #[test]
    fn year_end_to_year_start() {
        // 2025-12-31T23:59:59Z = 1_767_225_599
        let (d, a) = format_sigv4_timestamps(1_767_225_599);
        assert_eq!(d, "20251231");
        assert_eq!(a, "20251231T235959Z");

        // One second later — 2026-01-01T00:00:00Z = 1_767_225_600
        let (d, a) = format_sigv4_timestamps(1_767_225_600);
        assert_eq!(d, "20260101");
        assert_eq!(a, "20260101T000000Z");
    }

    #[test]
    fn non_leap_year_feb_28_to_mar_1() {
        // 2025-02-28T23:59:59Z = 1_740_787_199 (2025 is NOT a leap year)
        let (d, a) = format_sigv4_timestamps(1_740_787_199);
        assert_eq!(d, "20250228");
        assert_eq!(a, "20250228T235959Z");

        // One second later — 2025-03-01T00:00:00Z, NOT Feb 29.
        let (d, a) = format_sigv4_timestamps(1_740_787_200);
        assert_eq!(d, "20250301");
        assert_eq!(a, "20250301T000000Z");
    }

    #[test]
    fn century_year_2100_is_not_leap() {
        // 2100 is divisible by 100 but not 400 — Gregorian rule says NOT a
        // leap year. Verify Feb 28 → Mar 1 (no Feb 29).
        // 2100-02-28T00:00:00Z = 4_107_456_000
        let (d, _) = format_sigv4_timestamps(4_107_456_000);
        assert_eq!(d, "21000228");
        // +86400s → must skip to March 1, not Feb 29.
        let (d, _) = format_sigv4_timestamps(4_107_456_000 + 86_400);
        assert_eq!(d, "21000301");
    }

    #[test]
    fn year_2000_was_leap() {
        // 2000 IS divisible by 400 — leap year. Feb 29 must exist.
        // 2000-02-29T00:00:00Z = 951_782_400
        let (d, _) = format_sigv4_timestamps(951_782_400);
        assert_eq!(d, "20000229");
        // +86400s → 2000-03-01.
        let (d, _) = format_sigv4_timestamps(951_782_400 + 86_400);
        assert_eq!(d, "20000301");
    }
}
