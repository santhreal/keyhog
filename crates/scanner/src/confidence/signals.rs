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

/// Check if a file path suggests a sensitive file.
/// Check if a file path suggests a sensitive file using Aho-Corasick.
///
/// Single AC automaton replaces O(n*m) nested loop with O(n) scan.
pub(crate) fn is_sensitive_path(path: &str) -> bool {
    use std::sync::OnceLock;

    static AC: OnceLock<Option<aho_corasick::AhoCorasick>> = OnceLock::new();

    let ac = AC.get_or_init(|| {
        match aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build([
                // Sensitive filenames
                ".env",
                ".env.local",
                ".env.production",
                ".env.staging",
                "credentials",
                "secrets",
                "apikeys",
                "api_keys",
                ".npmrc",
                ".pypirc",
                ".netrc",
                ".pgpass",
                "terraform.tfvars",
                "variables.tf",
                "docker-compose",
                "application.yml",
                "application.properties",
                "config.json",
                "config.yaml",
                "config.toml",
                // Sensitive extensions (matched as substrings - works because
                // extensions are at end of path and names are distinctive)
                ".pem",
                ".key",
                ".p12",
                ".pfx",
                ".jks",
                ".keystore",
                ".cer",
                ".crt",
                // CI/CD secret files
                ".github/workflows",
                "gitlab-ci.yml",
                "Jenkinsfile",
                "buildspec.yml",
                // Cloud config
                "serverless.yml",
                "sam-template",
                "helm/values",
                "chart/values",
            ]) {
            Ok(ac) => Some(ac),
            Err(error) => {
                // Law 10: never silently swallow the build error. This marker
                // list is a fixed compile-time constant, so a build failure can
                // only mean an INVALID marker (e.g. an empty string) was added
                // above — a development-time bug. The old `.ok()` turned that
                // into `None` and then returned `false` for EVERY path, silently
                // deleting the sensitive-file confidence signal fleet-wide. Surface
                // it LOUDLY (this hot path forbids panics — see the
                // `confidence_signals_no_unwrap_expect` gate) and fall through to
                // the recall-preserving branch below.
                eprintln!(
                    "keyhog: BUG — the static sensitive-path marker list failed to \
                     build an Aho-Corasick automaton ({error}); an invalid marker \
                     was added in confidence/signals.rs. Treating every path as \
                     sensitive (fail toward recall) until the list is fixed."
                );
                None
            }
        }
    });

    // On a successful build, the automaton answers precisely. On the
    // build-bug-only `None`, fail TOWARD recall: treat the path as sensitive so
    // the confidence boost is never silently lost — the loud `eprintln!` above
    // already told the operator why (Law 10: a loud, recall-preserving fallback
    // is permitted; a silent one is not).
    ac.as_ref().is_none_or(|ac| ac.is_match(path))
}
