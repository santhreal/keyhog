//! Anchored verifier regexes with whole-chunk-equivalent left context.

use regex::{Regex, RegexBuilder};
use std::sync::{Arc, OnceLock};

/// Lazily compiled anchored copies of a detector regex.
pub(crate) struct AnchoredRegex {
    src: Arc<str>,
    case_insensitive: bool,
    cell: OnceLock<Option<Arc<Regex>>>,
    left_context_cell: OnceLock<Option<Arc<Regex>>>,
}

impl AnchoredRegex {
    pub(crate) fn new(src: &str, case_insensitive: bool) -> Self {
        Self {
            src: Arc::from(src),
            case_insensitive,
            cell: OnceLock::new(),
            left_context_cell: OnceLock::new(),
        }
    }

    pub(crate) fn get(&self) -> Option<&Regex> {
        self.cell
            .get_or_init(|| self.compile(r"\A(?:", ")"))
            .as_deref()
    }

    pub(crate) fn get_with_left_context(&self) -> Option<&Regex> {
        self.left_context_cell
            .get_or_init(|| self.compile(r"\A(?s:.)(?:", ")"))
            .as_deref()
    }

    fn compile(&self, prefix: &str, suffix: &str) -> Option<Arc<Regex>> {
        let anchored = format!("{prefix}{}{suffix}", self.src);
        match RegexBuilder::new(&anchored)
            .case_insensitive(self.case_insensitive)
            .size_limit(crate::types::REGEX_SIZE_LIMIT_BYTES)
            .dfa_size_limit(crate::types::regex_dfa_limit())
            .crlf(self.case_insensitive)
            .build()
        {
            Ok(rx) => Some(Arc::new(rx)),
            Err(error) => {
                tracing::error!(
                    pattern = %self.src,
                    %error,
                    "anchored-regex failed to compile; pattern keeps the whole-chunk path"
                );
                None
            }
        }
    }
}
