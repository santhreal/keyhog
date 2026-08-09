//! A detector anchor of three letters or fewer must refuse to start after a
//! letter.
//!
//! `africastalking-api-key` matched `(?:africas?talking|...|at|AT)[_.-]?API...`
//! with nothing in front of the alternation. `SNAPCHAT_API_KEY=<64 hex>`
//! contains a literal `AT_API_KEY=`, so every Snapchat token in the corpus was
//! also reported as an Africa's Talking key. Cross-detector deduplication hid
//! it from the report, because both matches carry the same credential, so the
//! only place it surfaced was autoroute calibration, where the GPU
//! region-presence route found the extra raw matches and the scalar route did
//! not. That divergence blocked GPU calibration for the whole workload class.
//!
//! `\b` was the obvious fix and it was wrong. `_` is a word character, so a
//! word boundary cannot tell `SNAPCHAT_API_KEY` from `MY_AT_API_KEY`, and
//! anchoring with it silently stopped finding the second. Measured across
//! sixteen `PREFIX_<TOKEN>_...` forms, every single one was lost.
//!
//! The condition that actually distinguishes them is the character CLASS
//! before the token: a letter means the token is the tail of a longer word, and
//! `_`, `-`, `.`, a space or start of input means it stands alone. Rust's regex
//! engine has no lookbehind, so the guard consumes that character. The reported
//! credential is capture group 1, so consuming one leading byte does not move
//! it.
//!
//! The guard goes on the SHORT alternative, never on the whole group. Putting
//! it in front of `(?:GOVTECH|SG|singapore)` also constrains `GOVTECH`, which
//! legitimately follows an underscore in `SINGAPORE_GOVTECH_API_KEY`.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The prefix a short bare alternative must carry.
///
/// Kept as a constant so the gate and the corpus cannot drift on the exact
/// spelling; a near-miss like `[^a-zA-Z]` would still be correct but would make
/// the corpus inconsistent to read.
const GUARD: &str = "(?:^|[^A-Za-z])";

/// Patterns still admitting a short bare token with no guard.
///
/// Empty. All thirty-one across nineteen detectors carry the guard now,
/// including the three `wix-api-credentials` patterns that were blocked while
/// guarding them suppressed `datadog-application-key`; that turned out to be a
/// missing `required_literals` declaration rather than anything about wix, and
/// is fixed.
///
/// The list stays rather than being deleted because a new detector arriving
/// with a bare short anchor should fail against something that already exists.
const KNOWN_UNANCHORED: &[(&str, usize)] = &[];

fn detector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

/// The pattern bodies of one detector file, in declaration order.
///
/// Read as text rather than through the loader: the loader normalises and this
/// gate is about the authored source, which is what a reviewer edits.
fn pattern_bodies(source: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("regex = '''") {
        let after = &rest[start + "regex = '''".len()..];
        let Some(end) = after.find("'''") else {
            break;
        };
        bodies.push(&after[..end]);
        rest = &after[end + 3..];
    }
    bodies
}

/// Whether the whole pattern is already fenced before its first alternative.
///
/// A leading `\b` counts as fenced for the purpose of this scan even though it
/// is the wrong tool for a short token, because a pattern carrying one is not
/// silently unguarded; the false positives it fails to stop are a different
/// question from the one this gate asks.
fn starts_at_a_boundary(pattern: &str) -> bool {
    pattern.starts_with("\\b")
        || pattern.starts_with('^')
        || pattern.starts_with(GUARD)
        || pattern.starts_with("(?i)\\b")
}

/// The short bare alternatives in a leading `(?:a|b|c)` group.
///
/// Only the leading group matters: a short token later in the pattern is
/// already fenced by whatever had to match before it.
///
/// Alternatives are split at the TOP level only. A nested group makes the
/// naive split wrong in the direction that matters: `COUNTLY[_-\s]*(?:API|APP)`
/// is one alternative containing `APP`, and reading `APP` as a bare
/// alternative reports a detector that is already anchored by the literal
/// `COUNTLY`. Four of the thirty-four originally listed were this mistake.
fn leading_short_tokens(pattern: &str) -> BTreeSet<&str> {
    let Some(rest) = pattern.strip_prefix("(?:") else {
        return BTreeSet::new();
    };
    let mut depth = 0usize;
    let mut escaped = false;
    let mut alternatives = Vec::new();
    let mut start = 0usize;
    let mut end = None;
    for (index, ch) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '(' => depth += 1,
            ')' if depth == 0 => {
                alternatives.push(&rest[start..index]);
                end = Some(index);
                break;
            }
            ')' => depth -= 1,
            '|' if depth == 0 => {
                alternatives.push(&rest[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if end.is_none() {
        return BTreeSet::new();
    }
    alternatives
        .into_iter()
        .filter(|token| {
            // An alternative carrying the guard is anchored; the bare form is
            // what this gate is looking for.
            !token.starts_with(GUARD)
                && !token.is_empty()
                && token.len() <= 3
                && token.chars().all(|ch| ch.is_ascii_alphabetic())
        })
        .collect()
}

fn unanchored_short_anchors() -> BTreeSet<(String, usize)> {
    let mut found = BTreeSet::new();
    let entries = std::fs::read_dir(detector_dir()).expect("detector corpus readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let source = std::fs::read_to_string(&path).expect("detector readable");
        for (index, pattern) in pattern_bodies(&source).into_iter().enumerate() {
            if starts_at_a_boundary(pattern) {
                continue;
            }
            if !leading_short_tokens(pattern).is_empty() {
                found.insert((stem.to_string(), index));
            }
        }
    }
    found
}

/// No detector pattern admits a short bare token any more.
///
/// The list is empty and a new entry means a new family of false positives and
/// a new cross-backend parity hazard, so both directions are asserted: nothing
/// added, and nothing left behind on the list either.
#[test]
fn detector_short_anchors_match_the_recorded_debt() {
    let found = unanchored_short_anchors();
    let known: BTreeSet<(String, usize)> = KNOWN_UNANCHORED
        .iter()
        .map(|(stem, index)| ((*stem).to_string(), *index))
        .collect();

    let added: Vec<_> = found.difference(&known).collect();
    assert!(
        added.is_empty(),
        "these patterns start with a short bare token and no `{GUARD}`, so the token matches \
         at the tail of an unrelated identifier: {added:?}"
    );

    let fixed: Vec<_> = known.difference(&found).collect();
    assert!(
        fixed.is_empty(),
        "these patterns are guarded now; delete their lines from KNOWN_UNANCHORED so the \
         remaining debt stays honest: {fixed:?}"
    );
}

/// The detector that caused the parity divergence carries the guard.
///
/// Pinned by name rather than only by absence from the list above, so the fix
/// cannot be undone by re-adding a line, and pinned on the guard rather than on
/// `\b`, which was the first attempt and cost recall on every `MY_AT_API_KEY=`.
#[test]
fn africastalking_requires_a_token_boundary_before_its_anchor() {
    let source = std::fs::read_to_string(detector_dir().join("africastalking-api-key.toml"))
        .expect("africastalking detector readable");
    let patterns = pattern_bodies(&source);

    assert_eq!(patterns.len(), 2, "africastalking declares two patterns");
    assert!(
        patterns[0].contains(&format!("{GUARD}at")) && patterns[0].contains(&format!("{GUARD}AT")),
        "both bare two-letter alternatives must carry the guard: {}",
        patterns[0]
    );
    for pattern in &patterns {
        assert!(
            leading_short_tokens(pattern).is_empty(),
            "africastalking must not match inside a larger identifier: {pattern}"
        );
    }
}

/// The gate would actually catch the bug it was written for.
///
/// A ratchet that cannot detect its own founding case is decoration, so the
/// pre-fix pattern is checked directly, and so is the shape that replaced it.
#[test]
fn the_detection_recognises_the_pattern_that_caused_the_divergence() {
    let before = "(?:africas?talking|AFRICAS?TALKING|at|AT)[_.-]?(?:api|API)[_.-]?(?:key|KEY)?";
    let after = format!(
        "(?:africas?talking|AFRICAS?TALKING|{GUARD}at|{GUARD}AT)[_.-]?(?:api|API)[_.-]?(?:key|KEY)?"
    );

    assert!(!starts_at_a_boundary(before));
    assert_eq!(
        leading_short_tokens(before),
        ["at", "AT"].into_iter().collect::<BTreeSet<_>>(),
        "the bare two-letter alternatives are what made the pattern reachable"
    );
    assert!(
        leading_short_tokens(&after).is_empty(),
        "a guarded alternative is not a bare one"
    );
}

/// A long leading anchor is not debt.
///
/// Without this the gate could pass by flagging everything, and every detector
/// that spells out its vendor name would be dragged into the list.
#[test]
fn a_long_leading_anchor_is_not_reported() {
    assert!(leading_short_tokens("(?:stripe|STRIPE)[_-]?key").is_empty());
    assert!(leading_short_tokens("(?:github|GITHUB)[_-]?token").is_empty());
}

/// A short token inside a NESTED group is not a bare alternative.
///
/// Splitting the leading group on every `|` reported `COUNTLY[_-\s]*(?:API|APP)`
/// as admitting a bare `APP`, when the alternative is the whole
/// `COUNTLY...` branch and the literal `COUNTLY` already anchors it. Three
/// detectors were listed as debt on that mistake, which is worse than useless:
/// it inflates the count and sends someone to "fix" a pattern that is correct.
#[test]
fn a_short_token_inside_a_nested_group_is_not_a_bare_alternative() {
    assert!(
        leading_short_tokens(r"(?:COUNTLY[_\-\s]*(?:API|APP)[_\-\s]*KEY|countly)").is_empty(),
        "APP belongs to the COUNTLY branch, not to the top-level alternation"
    );
    assert!(
        leading_short_tokens(r"(?:lepton\.(?:ai|run).{0,120}\btoken|LEPTON)").is_empty(),
        "run belongs to the lepton.(ai|run) branch"
    );
    assert_eq!(
        leading_short_tokens(r"(?:CARBON[_\-\s]*BLACK|carbon[_\-\s]*black|CB|vmware_cb)"),
        ["CB"].into_iter().collect::<BTreeSet<_>>(),
        "a genuine top-level short alternative is still reported"
    );
}

/// An unterminated leading group reports nothing rather than guessing.
///
/// A pattern the parser cannot bound is not evidence of debt, and treating it
/// as one would put an un-fixable entry on the list forever.
#[test]
fn an_unterminated_leading_group_reports_nothing() {
    assert!(leading_short_tokens("(?:at|AT").is_empty());
    assert!(leading_short_tokens("no group here").is_empty());
}
