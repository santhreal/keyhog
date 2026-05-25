use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{AuthSpec, VerificationResult};
use reqwest::Client;

use crate::interpolate::{interpolate, resolve_field, sanitize_raw_value};
use crate::verify::{build_aws_probe, RequestBuildResult};

pub(crate) async fn build_request_for_auth(
    request: reqwest::RequestBuilder,
    auth: &AuthSpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    client: &Client,
) -> RequestBuildResult {
    match auth {
        AuthSpec::None => RequestBuildResult::Ready(request),
        AuthSpec::Bearer { field } => {
            // SECURITY: kimi verifier audit LOW finding. Bearer token
            // values feed into `Authorization:` headers. If a credential
            // contains a CR/LF or NUL it must be stripped first, matching
            // the sanitization Header auth already applies via interpolate().
            // A raw newline in a bearer token would silently terminate the
            // header line and inject the next byte into the request stream.
            let token = sanitize_raw_value(&resolve_field(field, credential, companions));
            RequestBuildResult::Ready(request.bearer_auth(token))
        }
        AuthSpec::Basic { username, password } => {
            // SECURITY: same finding — Basic auth values land in the
            // Authorization header after reqwest base64-encodes them, but
            // a NUL byte in the raw username/password still propagates as
            // a `\0` byte through the encoding round-trip and can confuse
            // C-FFI HTTP parsers downstream. Strip controls first.
            let u = sanitize_raw_value(&resolve_field(username, credential, companions));
            let p = sanitize_raw_value(&resolve_field(password, credential, companions));
            RequestBuildResult::Ready(request.basic_auth(u, Some(p)))
        }
        AuthSpec::Header { name, template } => {
            let value = interpolate(template, credential, companions);
            RequestBuildResult::Ready(request.header(name, value))
        }
        AuthSpec::Query { param, field } => {
            // SECURITY: same finding — query params land in the URL.
            // reqwest percent-encodes safe chars but control bytes can
            // still survive in raw form depending on serializer path.
            let value = sanitize_raw_value(&resolve_field(field, credential, companions));
            RequestBuildResult::Ready(request.query(&[(param, value)]))
        }
        AuthSpec::AwsV4 {
            access_key,
            secret_key,
            session_token,
            region,
            ..
        } => {
            build_aws_probe(
                access_key,
                secret_key,
                session_token,
                region,
                credential,
                companions,
                timeout,
                client,
            )
            .await
        }
        AuthSpec::Script { engine, code } => {
            // SECURITY: kimi-wave1 audit finding 4.HIGH. The Script auth
            // path runs operator-supplied script source (from a detector
            // TOML) inside `codewalk::sandbox` with `companions` (which
            // can include credential-adjacent fields) in scope. The
            // sandbox's isolation guarantees are not re-audited inside
            // keyhog. Refuse by default; require an explicit opt-in env
            // var on the host running keyhog. This is NOT a feature flag
            // — it's an admin policy switch, not surfaced via CLI.
            if std::env::var("KEYHOG_ALLOW_SCRIPT_VERIFY").as_deref() != Ok("1") {
                return RequestBuildResult::Final {
                    result: VerificationResult::Error(
                        "blocked: AuthSpec::Script verification disabled (set \
                         KEYHOG_ALLOW_SCRIPT_VERIFY=1 to enable; sandbox isolation \
                         is not re-audited inside keyhog)"
                            .to_string(),
                    ),
                    metadata: HashMap::new(),
                    transient: false,
                };
            }
            // Even with the env var set, restrict engine to a known
            // allowlist. New engines need a code change + audit, not
            // a config knob.
            const ALLOWED_ENGINES: &[&str] = &["python3", "python", "node"];
            if !ALLOWED_ENGINES.contains(&engine.as_str()) {
                return RequestBuildResult::Final {
                    result: VerificationResult::Error(format!(
                        "blocked: AuthSpec::Script engine '{engine}' is not on \
                         the allowlist ({:?}); refuse to run unknown interpreters \
                         with credential context in scope",
                        ALLOWED_ENGINES
                    )),
                    metadata: HashMap::new(),
                    transient: false,
                };
            }
            let variables = companions.clone();
            match codewalk::sandbox::execute_script(
                engine,
                code,
                "verification_target",
                "custom_verify",
                &variables,
                timeout,
            )
            .await
            {
                Ok(output) => {
                    if output.contains("STATUS: LIVE") {
                        RequestBuildResult::Final {
                            result: VerificationResult::Live,
                            metadata: HashMap::new(),
                            transient: false,
                        }
                    } else {
                        RequestBuildResult::Final {
                            result: VerificationResult::Dead,
                            metadata: HashMap::new(),
                            transient: false,
                        }
                    }
                }
                Err(e) => RequestBuildResult::Final {
                    result: VerificationResult::Error(e.to_string()),
                    metadata: HashMap::new(),
                    transient: true,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::AuthSpec;
    use reqwest::Client;
    use std::collections::HashMap;

    fn make_client_and_req() -> (Client, reqwest::RequestBuilder) {
        let client = Client::builder().build().unwrap();
        let req = client.get("https://api.example.test/probe");
        (client, req)
    }

    /// Bearer credentials containing CR/LF must be stripped before reaching
    /// the Authorization header. Regression guard for the kimi-flagged gap
    /// where Header auth sanitized but Bearer did not.
    #[tokio::test]
    async fn bearer_strips_control_bytes_from_credential() {
        let (client, req) = make_client_and_req();
        let spec = AuthSpec::Bearer {
            field: "match".to_string(),
        };
        // Credential with embedded CRLF and NUL — must not appear verbatim
        // in the resulting Authorization header.
        let cred = "abc\r\nInjected: x\0DEF";
        let companions = HashMap::new();
        let result = build_request_for_auth(
            req,
            &spec,
            cred,
            &companions,
            Duration::from_secs(1),
            &client,
        )
        .await;
        match result {
            RequestBuildResult::Ready(rb) => {
                let built = rb.build().expect("build req");
                let auth = built
                    .headers()
                    .get("authorization")
                    .expect("authorization header present");
                let auth_str = auth.to_str().expect("auth header is ascii");
                // The header value must not contain CR or LF or NUL.
                assert!(!auth_str.contains('\r'), "CR survived sanitize");
                assert!(!auth_str.contains('\n'), "LF survived sanitize");
                assert!(!auth_str.contains('\0'), "NUL survived sanitize");
                // The good bytes (abc, Injected: x, DEF concatenated) must
                // be present — sanitize drops controls, never bodies.
                assert!(auth_str.starts_with("Bearer abcInjected: xDEF"));
            }
            _ => panic!("expected RequestBuildResult::Ready"),
        }
    }

    /// Basic auth username + password both pass through sanitize.
    #[tokio::test]
    async fn basic_strips_control_bytes_from_both_fields() {
        let (client, req) = make_client_and_req();
        let spec = AuthSpec::Basic {
            username: "user\r\nx".to_string(),
            password: "pass\0y".to_string(),
        };
        let companions = HashMap::new();
        let result = build_request_for_auth(
            req,
            &spec,
            "ignored",
            &companions,
            Duration::from_secs(1),
            &client,
        )
        .await;
        match result {
            RequestBuildResult::Ready(rb) => {
                let built = rb.build().expect("build req");
                let auth = built
                    .headers()
                    .get("authorization")
                    .expect("authorization header present");
                let auth_str = auth.to_str().expect("auth header is ascii");
                // Decode the basic auth value and check sanitized payload.
                let prefix = "Basic ";
                let b64_part = auth_str.strip_prefix(prefix).expect("has Basic prefix");
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_part)
                        .expect("valid base64");
                let decoded = String::from_utf8(decoded).expect("utf8");
                assert!(!decoded.contains('\r'));
                assert!(!decoded.contains('\n'));
                assert!(!decoded.contains('\0'));
                assert_eq!(decoded, "userx:passy");
            }
            _ => panic!("expected RequestBuildResult::Ready"),
        }
    }

    /// Query-auth values also pass through sanitize before URL encoding.
    #[tokio::test]
    async fn query_strips_control_bytes_from_value() {
        let (client, req) = make_client_and_req();
        let spec = AuthSpec::Query {
            param: "api_key".to_string(),
            field: "match".to_string(),
        };
        let companions = HashMap::new();
        let cred = "key\r\nbody";
        let result = build_request_for_auth(
            req,
            &spec,
            cred,
            &companions,
            Duration::from_secs(1),
            &client,
        )
        .await;
        match result {
            RequestBuildResult::Ready(rb) => {
                let built = rb.build().expect("build req");
                let url = built.url().to_string();
                // The URL must not contain raw CR/LF — even percent-encoded
                // would be acceptable, but sanitize drops them entirely.
                assert!(!url.contains('\r'));
                assert!(!url.contains('\n'));
                assert!(!url.contains("%0D"));
                assert!(!url.contains("%0A"));
                assert!(url.contains("api_key=keybody"));
            }
            _ => panic!("expected RequestBuildResult::Ready"),
        }
    }

    /// Tab is preserved — some JWT segments / Basic auth combinations
    /// legitimately include it. Sanitize must not strip 0x09.
    #[tokio::test]
    async fn bearer_preserves_tab() {
        let (client, req) = make_client_and_req();
        let spec = AuthSpec::Bearer {
            field: "match".to_string(),
        };
        let cred = "tok\ten";
        let companions = HashMap::new();
        let result = build_request_for_auth(
            req,
            &spec,
            cred,
            &companions,
            Duration::from_secs(1),
            &client,
        )
        .await;
        match result {
            RequestBuildResult::Ready(rb) => {
                let built = rb.build().expect("build req");
                let auth = built
                    .headers()
                    .get("authorization")
                    .expect("authorization header present");
                let auth_str = auth.to_str().expect("auth header is ascii");
                assert_eq!(auth_str, "Bearer tok\ten");
            }
            _ => panic!("expected RequestBuildResult::Ready"),
        }
    }
}
