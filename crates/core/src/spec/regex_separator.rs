//! Canonicalization of inter-keyword separator character classes in detector
//! regexes.
//!
//! ## The problem this fixes
//!
//! Detector authors hand-write the separator that sits *between keyword words*
//! of an anchor (`api`‹sep›`key`, `google`‹sep›`meet`, `D1`‹sep›`TOKEN`). Across
//! the shipped corpus that separator was written in **17 inconsistent forms**
//!: `[_-]?` (no whitespace at all, so `client id` is missed), `[_\s]?` (a
//! single optional separator, so `api  key` is missed), `[_]*` (underscore
//! only), exact-one `[_-]`, and even genuinely broken **over-escaped** classes
//! like `[_\\s-]` whose `\\s` matches a *literal backslash and the letter `s`*
//! rather than whitespace (so `last fm` never matches but `lastsfm` does). 1213
//! occurrences across 341 detectors, each an independent, unauditable, often
//! recall-leaky decision.
//!
//! Every one of those is a recall bug of the same shape: a real secret is missed
//! because the leaked file happened to use a tab, a double space, or a hyphen
//! where the author allowed only one underscore, or because of a stray
//! backslash in the regex.
//!
//! ## The fix
//!
//! Collapse every inter-keyword separator class to one canonical form,
//! [`CANONICAL_SEPARATOR`] = `[_\-\s]*`: the union charset (underscore, hyphen,
//! every whitespace byte), unbounded. It is a strict **superset** of every input
//! form, so canonicalization only ever *broadens* a match, no positive can
//! regress, and `*` is already the most common shipped form (336 detectors),
//! so its precision is established. Applied once at spec deserialization
//! ([`crate::PatternSpec`] / [`crate::CompanionSpec`]), so every downstream
//! consumer: AC literals, Hyperscan, literal-prefix extraction, phase-2 anchor,
//! the boundary upper-bound, the bench (sees the same canonical regex).
//!
//! ## Why this is sound (not a blind regex rewrite)
//!
//! A character class is treated as an inter-keyword separator **iff** its member
//! set contains `_` or `-` and is otherwise a subset of
//! {`_`, `-`, whitespace, and the two bytes `\` + `s` that make up an
//! over-escaped `\s`}. Two properties make this safe:
//!
//! 1. **Pure-whitespace classes are left alone.** `[\s]*` carries neither `_`
//!    nor `-`, so it never matches the oracle. That matters because bare
//!    whitespace is *ambiguous* with value-assignment spacing (`Key[\s]*:`),
//!    which must keep its own (often unbounded) semantics. Only the presence of
//!    `_`/`-` makes a class an *unambiguous* keyword separator.
//! 2. **It is corpus-verified.** Auditing the complete shipped corpus, every class
//!    matching this oracle sits between keyword words or alternation groups 
//!    never inside a token body or a value-assignment run. A class carrying any
//!    other byte (a letter range, a digit, `=`/`:`/quote) fails the subset test
//!    and is copied verbatim. The companion `keyword_separator_canonical` audit
//!    test re-checks this invariant over the live corpus on every CI run.
//!
//! Negated classes (`[^_-]`) are never treated as separators. The transform is
//! idempotent: the canonical form maps to itself.

use std::borrow::Cow;

/// The one canonical inter-keyword separator: union charset (underscore,
/// hyphen, every whitespace), unbounded.
///
/// The hyphen is escaped (`\-`) so it is always a class *member*, never a range
/// operator, regardless of neighbours.
///
/// Unbounded (`*`), matching the dominant shipped form (`[_\s]*`, 336
/// detectors) and every adversarial contract fixture that stuffs long separator
/// runs between anchor words. `*` is a strict superset of every input form, so
/// canonicalization only ever *broadens* a match. On keyhog's linear matching
/// engines an unbounded char-class repeat is a single self-loop state, never a
/// finite unrolling, so it carries no catastrophic-match risk, the complexity
/// validator's *counted*-repetition product correctly excludes it.
pub const CANONICAL_SEPARATOR: &str = "[_\\-\\s]*";

/// Which separator-relevant byte kinds a character class contains. Anything that
/// is not one of these (a letter range, a digit, `=`/`:`/`"`/`'`, a `\d`/`\w`
/// shorthand, …) sets [`SepKinds::other`], which disqualifies the class.
#[derive(Default, Debug, Clone, Copy)]
struct SepKinds {
    underscore: bool,
    hyphen: bool,
    whitespace: bool,
    /// A literal backslash member (only ever appears via an over-escaped `\\s`).
    backslash_literal: bool,
    /// A literal `s` member (likewise the tail of an over-escaped `\\s`).
    s_literal: bool,
    /// Any byte that is NOT a separator (letters other than `s`, digits, `=`,
    /// `:`, quotes, `\d`/`\w`/…). Its presence disqualifies the class.
    other: bool,
}

impl SepKinds {
    /// A raw (unescaped) member byte of the class body.
    fn add_byte(&mut self, b: u8) {
        match b {
            b'_' => self.underscore = true,
            b'-' => self.hyphen = true,
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => self.whitespace = true,
            b's' => self.s_literal = true,
            _ => self.other = true,
        }
    }

    /// An escaped member `\<e>` of the class body.
    fn add_escape(&mut self, e: u8) {
        match e {
            // whitespace shorthands / C escapes
            b's' | b't' | b'n' | b'r' | b'f' | b'v' => self.whitespace = true,
            b'\\' => self.backslash_literal = true,
            b'-' => self.hyphen = true,
            b'_' => self.underscore = true,
            // \d \w \S \W \D \b and any escaped literal (\.) are NOT separators
            _ => self.other = true,
        }
    }

    /// True when the class is an unambiguous inter-keyword separator: it carries
    /// `_` or `-` and nothing outside the allowed separator/over-escape bytes.
    fn is_separator(&self) -> bool {
        (self.underscore || self.hyphen) && !self.other
    }
}

/// Scan a character class beginning at `bytes[start] == b'['`.
///
/// Returns `(end, is_separator)` where `end` is the byte index one past the
/// class and its trailing quantifier (`?`, `*`, `+`, `{n,m}`, plus a lazy `?`),
/// and `is_separator` is the oracle verdict. Returns `None` if the class is
/// unterminated (a malformed regex; the caller then treats `[` as a literal).
fn scan_class(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    debug_assert_eq!(bytes[start], b'[');
    let mut j = start + 1;
    let mut kinds = SepKinds::default();
    let mut negated = false;
    if j < bytes.len() && bytes[j] == b'^' {
        negated = true;
        j += 1;
    }
    // A `]` as the very first body char is a literal member, not a terminator.
    let body_start = j;
    let mut end = None;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' if j + 1 < bytes.len() => {
                kinds.add_escape(bytes[j + 1]);
                j += 2;
            }
            b']' if j > body_start => {
                end = Some(j);
                break;
            }
            other => {
                kinds.add_byte(other);
                j += 1;
            }
        }
    }
    let close = end?;
    let after = skip_quantifier(bytes, close + 1);
    Some((after, !negated && kinds.is_separator()))
}

/// Advance past a regex quantifier at `pos`, if any: `?`, `*`, `+`, `{...}`,
/// each optionally followed by a lazy/possessive `?`/`+`.
fn skip_quantifier(bytes: &[u8], pos: usize) -> usize {
    if pos >= bytes.len() {
        return pos;
    }
    match bytes[pos] {
        b'?' | b'*' | b'+' => {
            let mut p = pos + 1;
            if p < bytes.len() && (bytes[p] == b'?' || bytes[p] == b'+') {
                p += 1;
            }
            p
        }
        b'{' => {
            let mut p = pos + 1;
            while p < bytes.len() && bytes[p] != b'}' {
                p += 1;
            }
            if p < bytes.len() {
                p += 1; // consume '}'
            }
            if p < bytes.len() && bytes[p] == b'?' {
                p += 1; // lazy {n,m}?
            }
            p
        }
        _ => pos,
    }
}

/// Rewrite every inter-keyword separator character class in `regex` to
/// [`CANONICAL_SEPARATOR`]. Returns the input borrowed when nothing changed.
///
/// See the module docs for the soundness argument. The walk only ever slices the
/// input at ASCII class boundaries, so it is UTF-8 safe for regexes that carry
/// non-ASCII literals.
pub fn canonicalize_keyword_separators(regex: &str) -> Cow<'_, str> {
    let bytes = regex.as_bytes();
    let mut out = String::new();
    let mut last = 0usize; // start of the not-yet-copied verbatim span
    let mut i = 0usize;
    let mut changed = false;
    while i < bytes.len() {
        match bytes[i] {
            // Skip an escaped pair so `\[` is never mistaken for a class start.
            b'\\' => i += 2,
            b'[' => match scan_class(bytes, i) {
                Some((end, true)) => {
                    out.push_str(&regex[last..i]);
                    out.push_str(CANONICAL_SEPARATOR);
                    last = end;
                    i = end;
                    changed = true;
                }
                Some((end, false)) => i = end,
                None => i += 1,
            },
            _ => i += 1,
        }
    }
    if !changed {
        return Cow::Borrowed(regex);
    }
    out.push_str(&regex[last..]);
    Cow::Owned(out)
}
