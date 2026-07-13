//! Compile-time feature identity for an autoroute-capable KeyHog artifact.

use super::schema::AutorouteBuildFeatures;

impl AutorouteBuildFeatures {
    pub(crate) fn current() -> Self {
        Self {
            cli_features: current_cli_features(),
            scanner_features: current_scanner_dependency_features(),
            sources_features: current_sources_dependency_features(),
            verifier_features: current_verifier_dependency_features(),
        }
    }

    pub(super) fn describe(&self) -> String {
        format!(
            "cli=[{}] scanner=[{}] sources=[{}] verifier=[{}]",
            describe_feature_list(&self.cli_features),
            describe_feature_list(&self.scanner_features),
            describe_feature_list(&self.sources_features),
            describe_feature_list(&self.verifier_features)
        )
    }
}

fn current_cli_features() -> Vec<String> {
    let mut features = Vec::new();
    macro_rules! push_feature {
        ($name:literal) => {
            if cfg!(feature = $name) {
                features.push($name);
            }
        };
    }
    push_feature!("default");
    push_feature!("azure");
    push_feature!("binary");
    push_feature!("ci");
    push_feature!("ci-lean");
    push_feature!("docker");
    push_feature!("full");
    push_feature!("gcs");
    push_feature!("github");
    push_feature!("git");
    push_feature!("gitlab");
    push_feature!("bitbucket");
    push_feature!("gpu");
    push_feature!("mimalloc");
    push_feature!("portable");
    push_feature!("s3");
    push_feature!("simd");
    push_feature!("verify");
    push_feature!("web");
    normalize_feature_list(features)
}

fn current_scanner_dependency_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "default") {
        features.extend([
            "default",
            "decode",
            "entropy",
            "gpu",
            "ml",
            "multiline",
            "simd",
            "simdsieve",
        ]);
    }
    if cfg!(feature = "ci-lean") {
        features.extend([
            "ci-lean",
            "decode",
            "entropy",
            "ml",
            "multiline",
            "simd",
            "simdsieve",
        ]);
    }
    if cfg!(feature = "ci") {
        features.extend(["decode", "entropy", "ml", "multiline"]);
    }
    if cfg!(feature = "portable") || cfg!(feature = "full") {
        features.extend(["decode", "entropy", "ml", "multiline"]);
    }
    if keyhog_scanner::hw_probe::gpu_backend_compiled() {
        features.extend(["gpu", "simd"]);
    }
    if keyhog_scanner::hw_probe::simd_backend_compiled() {
        features.push("simd");
    }
    normalize_feature_list(features)
}

fn current_sources_dependency_features() -> Vec<String> {
    let mut features = Vec::new();
    macro_rules! push_feature {
        ($cli:literal, $source:literal) => {
            if cfg!(feature = $cli) {
                features.push($source);
            }
        };
    }
    push_feature!("binary", "binary");
    push_feature!("azure", "azure");
    push_feature!("docker", "docker");
    push_feature!("gcs", "gcs");
    push_feature!("github", "github");
    push_feature!("git", "git");
    push_feature!("gitlab", "gitlab");
    push_feature!("bitbucket", "bitbucket");
    push_feature!("s3", "s3");
    push_feature!("web", "web");
    normalize_feature_list(features)
}

fn current_verifier_dependency_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "verify") {
        features.push("live");
    }
    normalize_feature_list(features)
}

fn normalize_feature_list(features: Vec<&'static str>) -> Vec<String> {
    let mut features: Vec<String> = features.into_iter().map(str::to_string).collect();
    features.sort_unstable();
    features.dedup();
    features
}

fn describe_feature_list(features: &[String]) -> String {
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}
