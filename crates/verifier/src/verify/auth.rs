use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{AuthSpec, VerificationResult};
use reqwest::Client;

use crate::interpolate::{interpolate, resolve_field};
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
            let token = resolve_field(field, credential, companions);
            RequestBuildResult::Ready(request.bearer_auth(token))
        }
        AuthSpec::Basic { username, password } => {
            let u = resolve_field(username, credential, companions);
            let p = resolve_field(password, credential, companions);
            RequestBuildResult::Ready(request.basic_auth(u, Some(p)))
        }
        AuthSpec::Header { name, template } => {
            let value = interpolate(template, credential, companions);
            RequestBuildResult::Ready(request.header(name, value))
        }
        AuthSpec::Query { param, field } => {
            let value = resolve_field(field, credential, companions);
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
