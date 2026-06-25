use std::time::{SystemTime, UNIX_EPOCH};

use keyhog_core::SourceError;

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
    pub(crate) fn from_env(base_url: &str) -> Result<Option<Self>, SourceError> {
        // Both core static credentials absent is the EXPECTED "no static
        // credentials configured" state: `None` makes the caller fall through
        // to ANONYMOUS (unsigned) S3 access for public buckets. Exactly one
        // present is a broken credential configuration, not permission to
        // silently run unsigned.
        let access_key_id = env_credential("AWS_ACCESS_KEY_ID")?;
        let secret_access_key = env_credential("AWS_SECRET_ACCESS_KEY")?;
        let (Some(access_key_id), Some(secret_access_key)) = (access_key_id, secret_access_key)
        else {
            return match (
                std::env::var_os("AWS_ACCESS_KEY_ID").is_some(),
                std::env::var_os("AWS_SECRET_ACCESS_KEY").is_some(),
            ) {
                (false, false) => Ok(None),
                (true, false) => Err(SourceError::Other(
                    "AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is missing; refusing to run unsigned. Set both variables for signed S3 access or unset AWS_ACCESS_KEY_ID for anonymous S3 scans.".into(),
                )),
                (false, true) => Err(SourceError::Other(
                    "AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is missing; refusing to run unsigned. Set both variables for signed S3 access or unset AWS_SECRET_ACCESS_KEY for anonymous S3 scans.".into(),
                )),
                (true, true) => Err(SourceError::Other(
                    "AWS credentials are present but could not be decoded as Unicode; refusing to run unsigned. Set valid AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY values or unset both for anonymous S3 scans.".into(),
                )),
            };
        };
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .ok() // LAW10: env-absent region ⇒ infer from URL then us-east-1 default, see chain below
            .or_else(|| infer_s3_region(base_url))
            .unwrap_or_else(|| "us-east-1".into()); // LAW10: AWS's canonical default region, not a swallowed failure
        Ok(Some(Self {
            access_key_id,
            secret_access_key,
            // AWS_SESSION_TOKEN is optional (only for temporary STS creds);
            // `None` is the correct "long-lived key, no token" state.
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(), // LAW10: optional STS token, None is valid, see note
            region,
        }))
    }

    pub(crate) fn sign(
        &self,
        request: reqwest::blocking::RequestBuilder,
        url: &str,
    ) -> Result<reqwest::blocking::RequestBuilder, SourceError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SourceError::Other(format!("failed to read system clock: {e}")))?
            .as_secs();
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
        let query_pairs = parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let (authorization, amz_date, _) = keyhog_verifier::sigv4::sign_request_authorization(
            &self.access_key_id,
            &self.secret_access_key,
            self.session_token.as_deref(),
            &self.region,
            "s3",
            "GET",
            canonical_uri,
            &query_pairs,
            host,
            EMPTY_PAYLOAD_SHA256,
            now_secs,
            &[("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)],
        )
        .map_err(|e| SourceError::Other(format!("failed to sign S3 request: {e}")))?;

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

fn env_credential(name: &str) -> Result<Option<String>, SourceError> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(value) => value.into_string().map(Some).map_err(|_| {
            SourceError::Other(format!(
                "{name} is set but is not valid Unicode; refusing to run unsigned. Set a valid {name} value or unset it for anonymous S3 scans."
            ))
        }),
    }
}

fn infer_s3_region(base_url: &str) -> Option<String> {
    // An unparseable base URL yields `None` (inference declines), which the
    // caller turns into the `us-east-1` default — there is no region to infer
    // from a bad URL, so this is a sound fallback, not a swallowed error.
    let host = reqwest::Url::parse(base_url).ok()?.host_str()?.to_string(); // LAW10: bad URL ⇒ decline inference, caller defaults region, see note
    let parts: Vec<&str> = host.split('.').collect();
    let s3_idx = parts.iter().position(|part| *part == "s3")?;
    let region = parts.get(s3_idx + 1)?;
    if region.starts_with("amazonaws") {
        None
    } else {
        Some((*region).to_string())
    }
}
