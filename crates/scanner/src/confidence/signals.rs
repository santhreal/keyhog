/// Confidence signals for a potential match.
pub(crate) struct ConfidenceSignals {
    /// Pattern has a distinctive literal prefix (e.g., `sk-proj-`, `ghp_`).
    pub has_literal_prefix: bool,
    /// Pattern uses a capture group with context anchoring.
    pub has_context_anchor: bool,
    /// Shannon entropy of the matched credential in **bits per byte** (range
    /// `0.0..=8.0`) - NOT normalized to `0..1`. Use
    /// `crate::entropy::normalized_entropy` for the rescaled value.
    pub entropy: f64,
    /// A secret-related keyword appears nearby.
    pub keyword_nearby: bool,
    /// File extension suggests config/env/secret file.
    pub sensitive_file: bool,
    /// Matched credential length.
    pub match_length: usize,
    /// Companion credential was found.
    pub has_companion: bool,
}

#[derive(serde::Deserialize)]
struct SensitivePathMarkers {
    markers: Vec<String>,
}

fn parse_sensitive_path_markers(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<SensitivePathMarkers>(raw)
        .map(|parsed| parsed.markers)
        .map_err(|error| error.to_string())
}

/// Tier-B sensitive-path marker substrings. Single owner; loaded from
/// `rules/sensitive-path-markers.toml` so operators extend coverage by editing
/// data, not code. Panics on invalid embedded Tier-B data (a build-time bug).
static SENSITIVE_PATH_MARKERS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_sensitive_path_markers(include_str!(
        "../../../../rules/sensitive-path-markers.toml"
    )) {
        Ok(markers) => markers,
        Err(error) => panic!(
            "rules/sensitive-path-markers.toml is invalid: {error}. \
                 Fix the bundled Tier-B sensitive-path marker list."
        ),
    }
});

/// Check if a file path suggests a sensitive file using Aho-Corasick.
///
/// Single AC automaton replaces O(n*m) nested loop with O(n) scan.
pub(crate) fn is_sensitive_path(path: &str) -> bool {
    use std::sync::OnceLock;

    static AC: OnceLock<Option<aho_corasick::AhoCorasick>> = OnceLock::new();

    let ac = AC.get_or_init(|| {
        match aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(SENSITIVE_PATH_MARKERS.iter())
        {
            Ok(ac) => Some(ac),
            Err(error) => {
                // Law 10: never silently swallow the build error. The marker
                // list is Tier-B data (rules/sensitive-path-markers.toml) already
                // validated as TOML at load, so a build failure can only mean an
                // INVALID marker (e.g. an empty string), a data bug. The old
                // `.ok()` turned that into `None` and then returned `false` for
                // EVERY path, silently deleting the sensitive-file confidence
                // signal fleet-wide. Surface it LOUDLY (this hot path forbids
                // panics, see the `confidence_signals_no_unwrap_expect` gate) and
                // fall through to the recall-preserving branch below.
                eprintln!(
                    "keyhog: BUG, the sensitive-path marker list failed to \
                     build an Aho-Corasick automaton ({error}); an invalid marker \
                     is present in rules/sensitive-path-markers.toml. Treating every \
                     path as sensitive (fail toward recall) until the list is fixed."
                );
                None
            }
        }
    });

    // On a successful build, the automaton answers precisely. On the
    // build-bug-only `None`, fail TOWARD recall: treat the path as sensitive so
    // the confidence boost is never silently lost, the loud `eprintln!` above
    // already told the operator why (Law 10: a loud, recall-preserving fallback
    // is permitted; a silent one is not).
    ac.as_ref().is_none_or(|ac| ac.is_match(path))
}
