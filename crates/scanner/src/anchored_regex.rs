//! Anchored verifier regexes with whole-chunk-equivalent left context.

use regex::{Regex, RegexBuilder};
use std::sync::{Arc, OnceLock};

/// Lazily compiled anchored copies of a detector regex.
pub(crate) struct AnchoredRegex {
    src: Arc<str>,
    case_insensitive: bool,
    cell: OnceLock<Arc<Regex>>,
    left_context_cell: OnceLock<Arc<Regex>>,
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

    /// The `\A`-anchored verifier. FAIL CLOSED in this LazyLock init: see
    /// [`AnchoredRegex::compile`]. A build failure panics rather than returning
    /// `None`, so consumers can never silently drop this pattern's matches.
    pub(crate) fn get(&self) -> &Regex {
        self.cell.get_or_init(|| self.compile(r"\A(?:", ")"))
    }

    /// The left-context anchored verifier (`\A(?s:.)(?:<src>)`). Same
    /// fail-closed contract as [`AnchoredRegex::get`].
    pub(crate) fn get_with_left_context(&self) -> &Regex {
        self.left_context_cell
            .get_or_init(|| self.compile(r"\A(?s:.)(?:", ")"))
    }

    fn compile(&self, prefix: &str, suffix: &str) -> Arc<Regex> {
        // A lazily anchored copy of a pattern the plan already carries is not a
        // plan compile; `record_lazy_regex_compile` is this work's only counter.
        crate::types::record_lazy_regex_compile();
        let anchored = format!("{prefix}{}{suffix}", self.src);
        match RegexBuilder::new(&anchored)
            .case_insensitive(self.case_insensitive)
            .size_limit(crate::types::REGEX_SIZE_LIMIT_BYTES)
            .dfa_size_limit(crate::types::regex_dfa_limit())
            .crlf(self.case_insensitive)
            .build()
        {
            Ok(rx) => Arc::new(rx),
            // Law 10 / fail-closed: the base detector regex ALREADY compiled, so
            // wrapping it as `{prefix}<src>{suffix}` failing is a build-invariant
            // violation of a HARDCODED transform baked into the binary, never a
            // valid runtime condition. The former handling returned `None`, which
            // the anchored-scan consumer swallowed into an early `return`, silently
            // dropping every match for this pattern (recall loss with no fallback on
            // the anchored fast path). A build bug must abort loudly, not degrade
            // recall invisibly: panic in the init exactly as the CLAUDE.md Law-10
            // guidance for baked-in patterns requires.
            Err(error) => panic!(
                "keyhog BUILD-INVARIANT VIOLATION: anchored verifier regex failed to compile \
though its base detector regex already compiled. Wrapper `{prefix}…{suffix}` over source \
`{src}` is a compile-time-constant transform, so this can only be a build bug (or a \
size/DFA-limit edge), never valid runtime input. Failing closed instead of silently \
dropping this pattern's matches (Law 10). error={error}",
                src = self.src,
            ),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/anchored_regex_cases.rs"]
mod tests;
