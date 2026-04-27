/// Confidence signals for a potential match.
pub struct ConfidenceSignals {
    /// Pattern has a distinctive literal prefix (e.g., `sk-proj-`, `ghp_`).
    pub has_literal_prefix: bool,
    /// Pattern uses a capture group with context anchoring.
    pub has_context_anchor: bool,
    /// Shannon entropy of the matched credential.
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
pub fn is_sensitive_path(path: &str) -> bool {
    use std::sync::OnceLock;

    static AC: OnceLock<Option<aho_corasick::AhoCorasick>> = OnceLock::new();

    let ac = AC.get_or_init(|| {
        aho_corasick::AhoCorasickBuilder::new()
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
                // Sensitive extensions (matched as substrings — works because
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
            ])
            .ok()
    });

    ac.as_ref().is_some_and(|ac| ac.is_match(path))
}
