//! Structural context analysis: understand WHERE in code a potential secret appears.
//!
//! Instead of treating code as flat text, we infer the structural context of
//! each match (assignment, comment, test code, encrypted block, documentation)
//! and adjust confidence accordingly. Not an AST parser — just fast,
//! language-agnostic structural inference.

mod documentation;
mod false_positive;
mod inference;

pub use documentation::documentation_line_flags;
pub use false_positive::{
    is_false_positive_context, is_false_positive_context_with_path, is_false_positive_match_context,
};
pub use inference::{infer_context, infer_context_with_documentation, is_known_example_credential};

const ASSIGNMENT_CONFIDENCE_MULTIPLIER: f64 = 1.0;
const STRING_LITERAL_CONFIDENCE_MULTIPLIER: f64 = 0.9;
const UNKNOWN_CONFIDENCE_MULTIPLIER: f64 = 0.8;
const DOCUMENTATION_CONFIDENCE_MULTIPLIER: f64 = 0.3;
const COMMENT_CONFIDENCE_MULTIPLIER: f64 = 0.4;
const TEST_CODE_CONFIDENCE_MULTIPLIER: f64 = 0.3;
const ENCRYPTED_CONFIDENCE_MULTIPLIER: f64 = 0.05;

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
    /// Confidence multiplier for this context.
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

    /// Returns `true` if this context should trigger hard suppression for low-confidence findings.
    pub fn should_hard_suppress(&self, confidence: f64) -> bool {
        match self {
            Self::Documentation | Self::TestCode | Self::Comment => confidence < 0.5,
            Self::Encrypted => confidence < 0.8,
            _ => false,
        }
    }
}
