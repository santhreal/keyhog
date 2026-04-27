use std::time::SystemTime;

use hmac::{Hmac, Mac};
use keyhog_core::SourceError;
use sha2::{Digest, Sha256};

const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub(crate) struct AwsSigV4Config {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: String,
}

impl AwsSigV4Config {
    pub(crate) fn from_env(base_url: &str) -> Option<Self> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .ok()
            .or_else(|| infer_s3_region(base_url))
            .unwrap_or_else(|| "us-east-1".into());
        Some(Self {
            access_key_id,
            secret_access_key,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            region,
        })
    }

    pub(crate) fn sign(
        &self,
        request: reqwest::blocking::RequestBuilder,
        url: &str,
    ) -> Result<reqwest::blocking::RequestBuilder, SourceError> {
        let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now());
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| SourceError::Other(format!("invalid S3 URL for signing: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| SourceError::Other("missing host in S3 URL".into()))?;
        let canonical_uri = if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        };
        let canonical_query = canonical_query_string(&parsed);

        let mut canonical_headers = format!(
            "host:{host}\nx-amz-content-sha256:{EMPTY_PAYLOAD_SHA256}\nx-amz-date:{amz_date}\n"
        );
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();
        if let Some(token) = &self.session_token {
            canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
            signed_headers.push_str(";x-amz-security-token");
        }

        let canonical_request = format!(
            "GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{EMPTY_PAYLOAD_SHA256}"
        );
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{:x}",
            Sha256::digest(canonical_request.as_bytes())
        );
        let signature = hex::encode(signing_key(
            &self.secret_access_key,
            &date_stamp,
            &self.region,
            "s3",
            &string_to_sign,
        )?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={signature}",
            self.access_key_id, credential_scope, signed_headers
        );

        let mut request = request
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)
            .header("Authorization", authorization);
        if let Some(token) = &self.session_token {
            request = request.header("x-amz-security-token", token);
        }
        Ok(request)
    }
}

fn infer_s3_region(base_url: &str) -> Option<String> {
    let host = reqwest::Url::parse(base_url).ok()?.host_str()?.to_string();
    let parts: Vec<&str> = host.split('.').collect();
    let s3_idx = parts.iter().position(|part| *part == "s3")?;
    let region = parts.get(s3_idx + 1)?;
    if region.starts_with("amazonaws") {
        None
    } else {
        Some((*region).to_string())
    }
}

pub(crate) fn canonical_query_string(url: &reqwest::Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (aws_uri_encode(&key), aws_uri_encode(&value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
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

fn signing_key(
    secret: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Result<Vec<u8>, SourceError> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes())?;
    let region_key = hmac_sha256(&date_key, region.as_bytes())?;
    let service_key = hmac_sha256(&region_key, service.as_bytes())?;
    let signing_key = hmac_sha256(&service_key, b"aws4_request")?;
    hmac_sha256(&signing_key, string_to_sign.as_bytes())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SourceError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| SourceError::Other(format!("failed to initialize S3 signer: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
