use keyhog_scanner::confidence::is_sensitive_path;
#[test]
fn sensitive_paths() {
    assert!(is_sensitive_path(".env.production"));
    assert!(is_sensitive_path("config/credentials.json"));
    assert!(is_sensitive_path("server.key"));
    assert!(!is_sensitive_path("src/main.rs"));
    assert!(!is_sensitive_path("README.md"));
}

#[test]
fn sensitive_path_matches_case_insensitively() {
    assert!(is_sensitive_path("CONFIG/.ENV.PRODUCTION"));
    assert!(is_sensitive_path("Secrets/CREDENTIALS.JSON"));
    assert!(is_sensitive_path("keys/CLIENT.P12"));
}

#[test]
fn sensitive_path_rejects_empty_and_non_sensitive_values() {
    assert!(!is_sensitive_path(""));
    assert!(!is_sensitive_path("notes/environment.txt"));
    assert!(!is_sensitive_path("docs/secretary.txt"));
}

#[test]
fn sensitive_path_detects_embedded_sensitive_names_with_special_characters() {
    assert!(is_sensitive_path("deploy/docker-compose.override.yml"));
    assert!(is_sensitive_path("dir/my api_keys-backup.txt"));
    assert!(is_sensitive_path("nested/application.properties.template"));
}

#[test]
fn sensitive_path_handles_huge_input() {
    let long_prefix = "a/".repeat(4096);
    let long_sensitive = format!("{long_prefix}terraform.tfvars");
    let long_non_sensitive = format!("{long_prefix}plain-text-file.txt");
    assert!(is_sensitive_path(&long_sensitive));
    assert!(!is_sensitive_path(&long_non_sensitive));
}
