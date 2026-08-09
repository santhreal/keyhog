//! Every prefixless pattern must declare the literal the prefilter routes on.
//!
//! A pattern with no literal prefix and no `required_literals` does not just
//! scan more slowly. It degrades the shared prefilter for the whole corpus, and
//! the damage lands on OTHER detectors: adding a leading character-class guard
//! to `wix-api-credentials` pattern 0 made `datadog-application-key` stop
//! reporting eight credentials on the mirror corpus, on input containing no
//! `wix` at all. Declaring `required_literals = ["wix"]` restored them.
//!
//! This gate used to ask a narrower question, whether the pattern had inner
//! literals worth routing on, and that hole is exactly where the bug went
//! through: it flagged wix pattern 1 and let pattern 0 past, and pattern 0
//! alone is enough to suppress datadog. The question is now the one that
//! matters, which is simply whether a prefixless pattern declares a literal.

use keyhog_scanner::testing::extract_literal_prefixes;

/// Patterns that genuinely cannot declare a routing literal.
///
/// A shape-only detector has no literal to require: an Asana PAT is
/// `1/<16-20 digits>/<32-48 alnum>`, a Telegram bot token is
/// `<8-10 digits>:<35 url-safe>`, a Kubernetes bootstrap token is
/// `<6 alnum>.<16 alnum>`. Demanding a declaration would either be impossible
/// or force a fabricated one, and a fabricated literal is worse than none: the
/// compiler proves declarations are necessary conditions, so an invented one
/// would simply be rejected, and working around that would mean weakening the
/// proof.
///
/// `generic-password` and `huawei-cloud-api-credentials` are here because their
/// alternations are case-insensitive over branches with no shared literal run.

const LITERAL_FREE: &[(&str, usize)] = &[
    ("asana-pat", 0),
    ("asana-pat", 1),
    ("fullstory-api-key", 1),
    ("generic-password", 0),
    ("generic-password", 1),
    ("generic-password", 5),
    ("huawei-cloud-api-credentials", 0),
    ("kubernetes-bootstrap-token", 0),
    ("sanity-api-token", 0),
    ("telegram-bot-token", 0),
    ("twilio-auth-token", 1),
];

/// A prefixless pattern with no declared literal is a corpus-wide hazard, not a
/// local slowdown, so the assertion names the mechanism rather than the style
/// rule.
#[test]
fn prefixless_inner_literal_routes_are_declared_in_detector_toml() {
    let literal_free: std::collections::BTreeSet<(String, usize)> = LITERAL_FREE
        .iter()
        .map(|(id, index)| ((*id).to_string(), *index))
        .collect();
    let mut undeclared = Vec::new();
    let mut declared_but_listed = Vec::new();
    for detector in
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
    {
        for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
            if !extract_literal_prefixes(&pattern.regex).is_empty() {
                continue;
            }
            let key = (detector.id.to_string(), pattern_index);
            match (
                pattern.required_literals.is_empty(),
                literal_free.contains(&key),
            ) {
                (true, false) => undeclared.push(format!("{}[{pattern_index}]", detector.id)),
                (false, true) => {
                    declared_but_listed.push(format!("{}[{pattern_index}]", detector.id))
                }
                _ => {}
            }
        }
    }
    assert!(
        undeclared.is_empty(),
        "these patterns have no literal prefix and declare no required_literals, so the \
         prefilter has nothing to route them on and OTHER detectors lose recall: {undeclared:?}"
    );
    assert!(
        declared_but_listed.is_empty(),
        "these patterns declare a routing literal after all; remove them from LITERAL_FREE: \
         {declared_but_listed:?}"
    );
}
