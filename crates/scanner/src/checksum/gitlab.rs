use super::{ChecksumResult, ChecksumValidator};

/// Validates GitLab token structure.
///
/// GitLab PATs: classic tokens are `glpat-` + 20 base64url chars, but the
/// routable tokens GitLab ships since 16.x (`glpat-`, `glrt-`, `glcbt-`, …)
/// are LONGER and embed their own CRC32 in a base64-encoded trailer. This
/// validator does structural checks only — it does not recompute the routable
/// CRC — so it must not claim checksum proof for structurally valid tokens, or
/// claim a token is fabricated merely because its length is not the classic 20:
/// that false `Invalid` verdict makes the engine DROP every modern GitLab
/// token (the `atlantis-credentials` / `gitlab-personal-access-token` contract
/// regressions). The rule is:
///   - body contains a char a GitLab token cannot                → `Invalid`
///   - body is base64url-shaped and within the real-world length → `StructurallyValid`
///   - anything else (too short / absurdly long to model)        → `NotApplicable`
/// so we only ever DROP on a positively-malformed body, never on an
/// unrecognised-but-plausible length.
pub(crate) struct GitlabTokenValidator;

/// Real-world GitLab token body lengths: classic PAT is 20; routable 16.x+
/// tokens run longer (random + base64 CRC trailer). 64 is a generous ceiling
/// that still rejects pathological inputs.
const GITLAB_BODY_MIN: usize = 20;
/// Routable CI-build / runner tokens (`glcbt-`, `glrt-`) have no fixed classic
/// length; 16 is the floor below which the encoded body is too short to be a
/// real token. Named so the band check and the too-short guard cannot drift.
const GITLAB_ROUTABLE_BODY_MIN: usize = 16;
const GITLAB_BODY_MAX: usize = 64;

fn gitlab_body_charset_ok(payload: &str) -> bool {
    // base64url body chars, plus `.` — the single separator GitLab routable
    // tokens (`glrt-t<n>_<body>.<suffix>`, and the routable `glpat-`/`glcbt-`
    // variants) place between the encoded body and its short CRC suffix.
    // Classic tokens never contain `.` (their detector regex forbids it), so
    // admitting `.` here cannot turn a classic token Valid — it only stops the
    // validator from false-dropping a legitimately `.`-bearing routable token.
    payload
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

impl ChecksumValidator for GitlabTokenValidator {
    fn validate(&self, credential: &str) -> ChecksumResult {
        if let Some(payload) = credential.strip_prefix("glpat-") {
            if !gitlab_body_charset_ok(payload) {
                return ChecksumResult::Invalid;
            }
            return match payload.len() {
                // classic 20 .. routable-token band: structural pass.
                GITLAB_BODY_MIN..=GITLAB_BODY_MAX => ChecksumResult::StructurallyValid,
                // a `glpat-` prefix with fewer than 20 body chars cannot be any
                // real GitLab token: fabricated/truncated -> drop.
                n if n < GITLAB_BODY_MIN => ChecksumResult::Invalid,
                // implausibly long: a format we don't model. Don't false-drop a
                // possible future token shape; let entropy/other gates decide.
                _ => ChecksumResult::NotApplicable,
            };
        }
        if let Some(payload) = credential
            .strip_prefix("glcbt-")
            .or_else(|| credential.strip_prefix("glrt-"))
        {
            if !gitlab_body_charset_ok(payload) {
                return ChecksumResult::Invalid;
            }
            // CI-build / runner tokens have no fixed classic length; 16 is the
            // floor below which the body is too short to be real.
            return match payload.len() {
                GITLAB_ROUTABLE_BODY_MIN..=GITLAB_BODY_MAX => ChecksumResult::StructurallyValid,
                n if n < GITLAB_ROUTABLE_BODY_MIN => ChecksumResult::Invalid,
                _ => ChecksumResult::NotApplicable,
            };
        }
        ChecksumResult::NotApplicable
    }
}
