use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

#[allow(clippy::too_many_arguments)]
pub fn sign_request_authorization(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    query_pairs: &[(String, String)],
    host: &str,
    payload_hash: &str,
    unix_secs: u64,
    extra_signed_headers: &[(&str, &str)],
) -> Result<(String, String, String), String> {
    let (date_stamp, amz_date) = format_sigv4_timestamps(unix_secs);
    let canonical_query = canonical_query_string(query_pairs);
    let mut headers = Vec::with_capacity(2 + extra_signed_headers.len() + 1);
    headers.push(("host".to_string(), host.to_string()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    for (name, value) in extra_signed_headers {
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers = canonical_header_block(&headers);
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let credential_scope = credential_scope(&date_stamp, region, service);
    let string_to_sign = string_to_sign(&amz_date, &credential_scope, &canonical_request);
    let signature = signature(secret_key, &date_stamp, region, service, &string_to_sign)?;
    let authorization =
        authorization_header(access_key, &credential_scope, &signed_headers, &signature);
    Ok((authorization, amz_date, signed_headers))
}

pub(crate) fn canonical_query_string(pairs: &[(String, String)]) -> String {
    let mut encoded = pairs
        .iter()
        .map(|(key, value)| (aws_uri_encode(key), aws_uri_encode(value)))
        .collect::<Vec<_>>();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_uri_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

pub(crate) fn canonical_header_block(headers: &[(String, String)]) -> String {
    let mut block = String::new();
    for (name, value) in headers {
        block.push_str(name);
        block.push(':');
        block.push_str(value);
        block.push('\n');
    }
    block
}

pub(crate) fn credential_scope(date_stamp: &str, region: &str, service: &str) -> String {
    format!("{date_stamp}/{region}/{service}/aws4_request")
}

pub(crate) fn string_to_sign(
    amz_date: &str,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    )
}

pub(crate) fn authorization_header(
    access_key: &str,
    credential_scope: &str,
    signed_headers: &str,
    signature: &str,
) -> String {
    format!(
        "{ALGORITHM} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

pub(crate) fn signature(
    secret: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Result<String, String> {
    let signing_key = signing_key(secret, date_stamp, region, service)?;
    Ok(hex::encode(hmac_sha256(
        &signing_key,
        string_to_sign.as_bytes(),
    )?))
}

fn signing_key(
    key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, String> {
    let k_date = hmac_sha256(format!("AWS4{key}").as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| format!("failed to create AWS SigV4 HMAC signer: {error}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Format the SigV4 timestamps from a Unix epoch second value.
/// Returns `(date_stamp = "YYYYMMDD", amz_date = "YYYYMMDDTHHMMSSZ")`.
pub(crate) fn format_sigv4_timestamps(unix_secs: u64) -> (String, String) {
    // Civil-from-days, after Howard Hinnant's date algorithm.
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = (unix_secs % 86_400) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let date_stamp = format!("{year:04}{m:02}{d:02}");
    let amz_date = format!("{year:04}{m:02}{d:02}T{hour:02}{minute:02}{second:02}Z");
    (date_stamp, amz_date)
}
