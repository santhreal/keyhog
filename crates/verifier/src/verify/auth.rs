use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{AuthSpec, VerificationResult};
use reqwest::Client;

use crate::interpolate::{
    interpolate_http_value, missing_companion_field, missing_companion_refs, resolve_field,
    sanitize_raw_value,
};
use crate::verify::{build_aws_probe, missing_companion_error, RequestBuildResult};

pub(crate) async fn build_request_for_auth(
    request: reqwest::RequestBuilder,
    auth: &AuthSpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    client: &Client,
    allow_private_ips: bool,
    allow_http: bool,
    proxy_in_use: bool,
    insecure_tls: bool,
    allow_script_verify: bool,
) -> RequestBuildResult {
    match auth {
        AuthSpec::None => RequestBuildResult::Ready(request),
        AuthSpec::Bearer { field } => {
            if let Some(missing) = missing_companion_field(field, companions) {
                return missing_auth_companion("bearer auth field", vec![missing]);
            }
            // SECURITY: kimi verifier audit LOW finding. Bearer token
            // values feed into `Authorization:` headers. If a credential
            // contains a CR/LF or NUL it must be stripped first, matching
            // the sanitization Header auth already applies via
            // interpolate_http_value().
            // A raw newline in a bearer token would silently terminate the
            // header line and inject the next byte into the request stream.
            let token = sanitize_raw_value(&resolve_field(field, credential, companions));
            RequestBuildResult::Ready(request.bearer_auth(token))
        }
        AuthSpec::Basic { username, password } => {
            let missing = missing_auth_fields([username.as_str(), password.as_str()], companions);
            if !missing.is_empty() {
                return missing_auth_companion("basic auth field", missing);
            }
            // SECURITY: same finding - Basic auth values land in the
            // Authorization header after reqwest base64-encodes them, but
            // a NUL byte in the raw username/password still propagates as
            // a `\0` byte through the encoding round-trip and can confuse
            // C-FFI HTTP parsers downstream. Strip controls first.
            let u = sanitize_raw_value(&resolve_field(username, credential, companions));
            let p = sanitize_raw_value(&resolve_field(password, credential, companions));
            RequestBuildResult::Ready(request.basic_auth(u, Some(p)))
        }
        AuthSpec::Header { name, template } => {
            let missing = missing_companion_refs(template, companions);
            if !missing.is_empty() {
                return missing_auth_companion("header auth template", missing);
            }
            let value = interpolate_http_value(template, credential, companions);
            RequestBuildResult::Ready(request.header(name, value))
        }
        AuthSpec::Query { param, field } => {
            if let Some(missing) = missing_companion_field(field, companions) {
                return missing_auth_companion("query auth field", vec![missing]);
            }
            // SECURITY: same finding - query params land in the URL.
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
            let missing =
                missing_auth_fields([access_key.as_str(), secret_key.as_str()], companions);
            if !missing.is_empty() {
                return missing_auth_companion("AWS auth field", missing);
            }
            if let Some(token) = session_token.as_deref() {
                if let Some(missing) = missing_companion_field(token, companions) {
                    return missing_auth_companion("AWS session-token field", vec![missing]);
                }
            }
            build_aws_probe(
                access_key,
                secret_key,
                session_token,
                region,
                credential,
                companions,
                timeout,
                client,
                allow_private_ips,
                allow_http,
                proxy_in_use,
                insecure_tls,
            )
            .await
        }
        AuthSpec::Script { engine, code } => {
            // SECURITY: kimi-wave1 audit finding 4.HIGH. The Script auth
            // path runs operator-supplied script source (from a detector
            // TOML) inside `codewalk::sandbox` with `companions` (which
            // can include credential-adjacent fields) in scope. The
            // sandbox's isolation guarantees are not re-audited inside keyhog.
            // Refuse by default; require an explicit runtime opt-in carried by
            // the caller. This is an admin policy switch, not ambient env.
            if !allow_script_verify {
                return RequestBuildResult::Final {
                    result: VerificationResult::Error(
                        "blocked: AuthSpec::Script verification disabled (pass \
                         --allow-script-verify with trusted detector corpora; \
                         sandbox isolation is not re-audited inside keyhog)"
                            .to_string(),
                    ),
                    metadata: HashMap::new(),
                    transient: false,
                };
            }
            if !engine.is_allowed_for_verify() {
                return RequestBuildResult::Final {
                    result: VerificationResult::Error(format!(
                        "blocked: AuthSpec::Script engine '{engine}' is not on \
                         the allowlist ({:?}); refuse to run unknown interpreters \
                         with credential context in scope",
                        keyhog_core::ScriptEngine::ALLOWED_FOR_VERIFY
                    )),
                    metadata: HashMap::new(),
                    transient: false,
                };
            }
            let variables = companions.clone();
            match codewalk::sandbox::execute_script(
                engine.as_str(),
                code,
                "verification_target",
                "custom_verify",
                &variables,
                timeout,
            )
            .await
            {
                Ok(output) => RequestBuildResult::Final {
                    result: script_auth_result(&output),
                    metadata: HashMap::new(),
                    transient: false,
                },
                Err(e) => RequestBuildResult::Final {
                    result: VerificationResult::Error(e.to_string()),
                    metadata: HashMap::new(),
                    transient: true,
                },
            }
        }
    }
}

fn missing_auth_fields<const N: usize>(
    fields: [&str; N],
    companions: &HashMap<String, String>,
) -> Vec<String> {
    let mut missing = Vec::new();
    for field in fields {
        if let Some(name) = missing_companion_field(field, companions) {
            if !missing.iter().any(|known| known == &name) {
                missing.push(name);
            }
        }
    }
    missing
}

fn missing_auth_companion(context: &str, missing: Vec<String>) -> RequestBuildResult {
    RequestBuildResult::Final {
        result: missing_companion_error(context, &missing),
        metadata: HashMap::new(),
        transient: false,
    }
}

fn script_auth_result(output: &str) -> VerificationResult {
    if output.contains("STATUS: LIVE") {
        VerificationResult::Live
    } else if output.contains("STATUS: DEAD") {
        VerificationResult::Dead
    } else {
        VerificationResult::Error(
            "AuthSpec::Script verification returned no explicit status; expected \
             STATUS: LIVE or STATUS: DEAD"
                .to_string(),
        )
    }
}
