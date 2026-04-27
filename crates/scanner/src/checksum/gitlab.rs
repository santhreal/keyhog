use super::{ChecksumResult, ChecksumValidator};

/// Validates GitLab token structure.
///
/// GitLab PATs: `glpat-` + 20 alphanumeric chars
/// GitLab CI tokens: `glcbt-` + variable length
/// GitLab runner tokens: `glrt-` + variable length
pub struct GitlabTokenValidator;

impl ChecksumValidator for GitlabTokenValidator {
    fn validator_id(&self) -> &str {
        "gitlab-token"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        if let Some(payload) = credential.strip_prefix("glpat-") {
            // GitLab PATs are exactly 20 alphanumeric characters after prefix
            if payload.len() == 20
                && payload
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return ChecksumResult::Valid;
            }
            return ChecksumResult::Invalid;
        }
        if let Some(payload) = credential
            .strip_prefix("glcbt-")
            .or_else(|| credential.strip_prefix("glrt-"))
        {
            if payload.len() >= 16
                && payload
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return ChecksumResult::Valid;
            }
            return ChecksumResult::Invalid;
        }
        ChecksumResult::NotApplicable
    }
}
