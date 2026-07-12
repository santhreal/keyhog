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
            // violation of a HARDCODED transform baked into the binary — never a
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
mod fail_closed_tests {
    use super::AnchoredRegex;

    #[test]
    fn get_returns_a_working_anchor_at_start() {
        // A well-formed detector source compiles into a `\A`-anchored verifier:
        // it matches only when the pattern begins at offset 0 of the haystack.
        let ar = AnchoredRegex::new("[A-Z]{3}[0-9]{2}", false);
        let re = ar.get();
        let mut locs = re.capture_locations();
        let m = re
            .captures_read(&mut locs, "ABC12tail")
            .expect("anchored verifier must match a value at the start");
        assert_eq!(m.start(), 0);
        assert_eq!(m.end(), 5, "matches exactly the 5-char shape ABC12");
        // Embedded (not at offset 0): `\A` blocks it — proving the anchor is real.
        assert!(
            re.captures_read(&mut locs, "xxABC12").is_none(),
            "\\A must reject a value that does not start at offset 0"
        );
    }

    #[test]
    #[should_panic(expected = "BUILD-INVARIANT VIOLATION")]
    fn no_context_compile_failure_panics_fail_closed() {
        // A source that makes the hardcoded `\A(?:<src>)` wrapper unbalanced forces
        // the anchored build to fail. Per Law 10 that is a build-invariant violation
        // of a baked-in transform and MUST abort loudly — the former handling
        // returned `None`, which the anchored-scan consumer swallowed into a silent
        // early `return`, dropping every match for this pattern.
        let ar = AnchoredRegex::new(")unbalanced", false);
        ar.get();
    }

    #[test]
    #[should_panic(expected = "BUILD-INVARIANT VIOLATION")]
    fn left_context_compile_failure_panics_fail_closed() {
        // The left-context variant (`\A(?s:.)(?:<src>)`) fails closed identically:
        // no path is allowed to swallow the compile failure into silent recall loss.
        let ar = AnchoredRegex::new(")unbalanced", false);
        ar.get_with_left_context();
    }

    // ── CRLF/case-flag parity with the two-branch base compile ──────────────
    // The anchored verifier couples BOTH `case_insensitive` and `crlf` to the
    // detector's `case_insensitive` bit. This is NOT a copy-paste of crlf<-ci:
    // the base detector regex (`LazyRegex::get`) is itself compiled on two
    // branches that pair the flags exactly the same way —
    //   ci detector  -> `shared_regex`  => case_insensitive(true)  + crlf(true)
    //   non-ci       -> `Regex::new`    => case_insensitive(false) + crlf(false)
    // The anchored verifier's whole purpose is whole-chunk-equivalence with that
    // base, so it MUST reproduce whichever branch applies. Under crlf(true) the
    // dot excludes `\r`; under crlf(false) it matches `\r`. That makes a ci and a
    // non-ci verifier legitimately DIVERGE on a CR-bearing haystack, mirroring
    // their base regexes. This pins the coupling so a future "crlf should always
    // be true" edit — which would silently break case-sensitive-detector parity
    // on CRLF input — fails loudly here instead.
    #[test]
    fn anchored_crlf_and_case_flags_mirror_the_two_branch_base_compile() {
        use regex::{Regex, RegexBuilder};

        let hay = "A\rB";

        // Base branch A — case-sensitive detector: `Regex::new` default, crlf
        // false, so the dot matches CR and the whole shape matches.
        let base_cs = Regex::new("A.B").expect("base cs regex compiles");
        assert!(
            base_cs.is_match(hay),
            "crlf(false) base: the dot matches CR, so `A.B` matches `A\\rB`"
        );
        // Base branch B — case-insensitive detector: `shared_regex` flags, crlf
        // true, so the dot excludes CR and the shape does NOT match.
        let base_ci = RegexBuilder::new("A.B")
            .case_insensitive(true)
            .crlf(true)
            .build()
            .expect("base ci regex compiles");
        assert!(
            !base_ci.is_match(hay),
            "crlf(true) base: the dot excludes CR, so `A.B` does NOT match `A\\rB`"
        );

        // The anchored verifier for each detector kind must AGREE with its own
        // base branch — proving the flag coupling reproduces the base, not that
        // crlf is uniformly true.
        let anch_cs = AnchoredRegex::new("A.B", false);
        assert!(
            anch_cs.get().is_match(hay),
            "case-sensitive anchored verifier mirrors crlf(false): dot matches CR"
        );
        let anch_ci = AnchoredRegex::new("A.B", true);
        assert!(
            !anch_ci.get().is_match(hay),
            "case-insensitive anchored verifier mirrors crlf(true): dot excludes CR"
        );
    }
}
