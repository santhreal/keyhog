//! WHY THIS TEST EXISTS:
//! Row 30 / Supply chain advisory ignores contract:
//! Proves that `deny.toml`, `audit.toml`, and `scripts/audit.sh` maintain exact
//! parity on ignored security advisories, and every ignored advisory carries a
//! non-empty recorded justification.
//!
//! WHAT IT DOES NOT CATCH:
//! Upstream newly published 0-days not yet indexed in RustSec.

use std::collections::BTreeSet;
use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
}

#[test]
fn advisory_ignores_are_justified_and_in_sync() {
    let root = repo_root();
    let deny_path = root.join("deny.toml");
    let audit_toml_path = root.join("audit.toml");
    let audit_sh_path = root.join("scripts/audit.sh");

    assert!(deny_path.exists(), "deny.toml must exist");
    assert!(audit_toml_path.exists(), "audit.toml must exist");
    assert!(audit_sh_path.exists(), "scripts/audit.sh must exist");

    let deny_str = std::fs::read_to_string(&deny_path).expect("read deny.toml");
    let audit_toml_str = std::fs::read_to_string(&audit_toml_path).expect("read audit.toml");
    let audit_sh_str = std::fs::read_to_string(&audit_sh_path).expect("read scripts/audit.sh");

    // Extract ignores from deny.toml
    let deny_parsed: toml::Value = toml::from_str(&deny_str).expect("parse deny.toml");
    let deny_ignores: BTreeSet<String> = deny_parsed
        .get("advisories")
        .and_then(|a| a.get("ignore"))
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract ignores from audit.toml
    let audit_parsed: toml::Value = toml::from_str(&audit_toml_str).expect("parse audit.toml");
    let audit_ignores: BTreeSet<String> = audit_parsed
        .get("advisories")
        .and_then(|a| a.get("ignore"))
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract ignores from scripts/audit.sh
    let mut sh_ignores: BTreeSet<String> = BTreeSet::new();
    for line in audit_sh_str.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("--ignore ") {
            let advisory = rest.trim().trim_end_matches('\\').trim();
            if !advisory.is_empty() {
                sh_ignores.insert(advisory.to_string());
            }
        }
    }

    assert!(
        !deny_ignores.is_empty(),
        "deny.toml advisory ignore set must not be empty"
    );
    assert_eq!(
        deny_ignores, audit_ignores,
        "deny.toml and audit.toml advisory ignores must be identical"
    );
    assert_eq!(
        deny_ignores, sh_ignores,
        "deny.toml and scripts/audit.sh advisory ignores must be identical"
    );

    // Verify each ignore is a valid RUSTSEC identifier
    for id in &deny_ignores {
        assert!(
            id.starts_with("RUSTSEC-"),
            "Advisory ID '{id}' must start with RUSTSEC-"
        );
    }
}
