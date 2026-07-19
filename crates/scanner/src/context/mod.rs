//! Structural context analysis: understand WHERE in code a potential secret appears.
//!
//! Instead of treating code as flat text, we infer the structural context of
//! each match (assignment, comment, test code, encrypted block, documentation)
//! and adjust confidence accordingly. Not an AST parser - just fast,
//! language-agnostic structural inference.

mod documentation;
mod false_positive;
mod inference;
mod placeholder;

pub(crate) use documentation::documentation_line_flags;
#[cfg(test)]
pub(crate) use false_positive::parse_disclaimer_phrases;
pub(crate) use false_positive::{has_disclaimer_comment_bytes, is_integrity_hash_bytes};
pub(crate) use false_positive::{is_false_positive_context, is_false_positive_match_context};
pub use inference::infer_context;
pub(crate) use inference::infer_context_with_documentation;
#[cfg(test)]
pub(crate) use inference::parse_test_path_rules;
pub(crate) use inference::{is_in_test_function, is_rust_fn_signature, strip_comment_prefix};
pub(crate) use placeholder::is_known_example_credential;
#[cfg(feature = "entropy")]
pub(crate) use placeholder::is_monotonic_sequence_placeholder;
#[cfg(test)]
pub(crate) use placeholder::is_sequential_placeholder;

const ASSIGNMENT_CONFIDENCE_MULTIPLIER: f64 = 1.0;
const STRING_LITERAL_CONFIDENCE_MULTIPLIER: f64 = 0.9;
const UNKNOWN_CONFIDENCE_MULTIPLIER: f64 = 0.8;
const DOCUMENTATION_CONFIDENCE_MULTIPLIER: f64 = 0.3;
const COMMENT_CONFIDENCE_MULTIPLIER: f64 = 0.4;
const TEST_CODE_CONFIDENCE_MULTIPLIER: f64 = 0.3;
const ENCRYPTED_CONFIDENCE_MULTIPLIER: f64 = 0.05;
const SOFT_CONTEXT_HARD_SUPPRESSION_THRESHOLD: f64 = 0.5;
const ENCRYPTED_CONTEXT_HARD_SUPPRESSION_THRESHOLD: f64 = 0.8;

/// The structural context of a code location.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CodeContext {
    /// Direct assignment: `key = value`, `key: value`, `KEY=value`.
    Assignment,
    /// Inside a comment (`//`, `#`, `/*`, `--`, and similar).
    Comment,
    /// Inside a test function or test file.
    TestCode,
    /// Inside an encrypted/sealed block.
    Encrypted,
    /// Inside documentation (docstring, markdown code fence).
    Documentation,
    /// Inside a string literal in ordinary code.
    StringLiteral,
    /// Unknown or unstructured context.
    Unknown,
}

impl CodeContext {
    /// Legacy baseline multiplier for callers that classify context without a
    /// detector plan. Production candidate scoring uses the active detector's
    /// compiled `match_confidence` multipliers instead.
    pub fn confidence_multiplier(&self) -> f64 {
        match self {
            Self::Assignment => ASSIGNMENT_CONFIDENCE_MULTIPLIER,
            Self::StringLiteral => STRING_LITERAL_CONFIDENCE_MULTIPLIER,
            Self::Unknown => UNKNOWN_CONFIDENCE_MULTIPLIER,
            Self::Documentation => DOCUMENTATION_CONFIDENCE_MULTIPLIER,
            Self::Comment => COMMENT_CONFIDENCE_MULTIPLIER,
            Self::TestCode => TEST_CODE_CONFIDENCE_MULTIPLIER,
            Self::Encrypted => ENCRYPTED_CONFIDENCE_MULTIPLIER,
        }
    }

    /// Legacy baseline hard-suppression decision for callers without a detector
    /// plan. Production finalization uses the active detector's compiled
    /// context thresholds.
    pub fn should_hard_suppress(&self, confidence: f64) -> bool {
        self.hard_suppression_threshold()
            .is_some_and(|threshold| confidence < threshold)
    }

    /// Legacy baseline threshold paired with [`CodeContext::should_hard_suppress`].
    pub const fn hard_suppression_threshold(&self) -> Option<f64> {
        match self {
            Self::Documentation | Self::TestCode | Self::Comment => {
                Some(SOFT_CONTEXT_HARD_SUPPRESSION_THRESHOLD)
            }
            Self::Encrypted => Some(ENCRYPTED_CONTEXT_HARD_SUPPRESSION_THRESHOLD),
            _ => None,
        }
    }
}
