use std::sync::LazyLock;

use super::{ChecksumResult, ChecksumValidator};

/// Validates Slack token structure.
///
/// Slack tokens do not expose a public checksum algorithm, but their format is
/// highly regular. This validator performs strict structural matching and
/// rejects tokens that violate known segment rules.
pub struct SlackTokenValidator;

// Compile once, reuse across all validate() calls.
//
// The bot regex MUST accept both shapes the `slack-bot-token` detector emits
// (`detectors/slack-bot-token.toml` is the source of truth for what the scanner
// surfaces, and this validator is the checksum GATE that the emitted match is
// routed through in `checksum_adjusted_confidence` -> a `ChecksumResult::Invalid`
// DROPS the finding):
//   * 3-segment canonical: `xoxb-{10-13 digits}-{10-13 digits}-{24-32 alnum}`
//   * 2-segment / "mixed":  `xoxb-{10-13 digits}-{15-36 alnum}` (older installs)
// The second numeric segment is therefore OPTIONAL. A prior `-[0-9]{10,15}-`
// (mandatory) regex rejected every legitimate 2-segment bot token as Invalid,
// so the engine silently dropped a real, contract-required ("both must surface")
// `xoxb-…` finding. Widening the numeric/secret bounds to `{10,15}`/`{15,40}`
// keeps the wider validator superset of the detector while still anchoring (`$`)
// and rejecting wrong character classes and too-short/too-long segments.
static SLACK_BOT_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    regex::Regex::new(r"^xoxb-[0-9]{10,15}(?:-[0-9]{10,15})?-[a-zA-Z0-9]{15,40}$").ok()
});
static SLACK_USER_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    regex::Regex::new(r"^xoxp-[0-9]{10,15}-[0-9]{10,15}(?:-[0-9]{10,13})?-[a-zA-Z0-9]{24,40}$").ok()
});

pub(crate) fn warm_runtime_regexes() {
    let _ = SLACK_BOT_RE.as_ref();
    let _ = SLACK_USER_RE.as_ref();
}

impl SlackTokenValidator {
    fn is_valid_slack_bot(credential: &str) -> bool {
        SLACK_BOT_RE
            .as_ref()
            .is_some_and(|regex| regex.is_match(credential))
    }

    fn is_valid_slack_user(credential: &str) -> bool {
        SLACK_USER_RE
            .as_ref()
            .is_some_and(|regex| regex.is_match(credential))
    }
}

impl ChecksumValidator for SlackTokenValidator {
    fn validator_id(&self) -> &str {
        "slack-token"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        if credential.starts_with("xoxb-") {
            if Self::is_valid_slack_bot(credential) {
                ChecksumResult::Valid
            } else {
                ChecksumResult::Invalid
            }
        } else if credential.starts_with("xoxp-") {
            if Self::is_valid_slack_user(credential) {
                ChecksumResult::Valid
            } else {
                ChecksumResult::Invalid
            }
        } else {
            ChecksumResult::NotApplicable
        }
    }
}
