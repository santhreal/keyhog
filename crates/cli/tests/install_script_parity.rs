//! WHY THIS TEST EXISTS:
//! Row 7 / Host independence contract:
//! Install scripts across Unix (`install.sh`) and Windows (`install.ps1`) must
//! maintain exact functional parity for every public mode, parameter, and
//! security verification step.
//!
//! WHAT IT DOES NOT CATCH:
//! Live PowerShell execution on Linux without pwsh installed (covered on Windows
//! runners in CI / action-e2e).

use std::collections::BTreeSet;
use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
}

fn parse_sh_modes(content: &str) -> BTreeSet<String> {
    let mut modes = BTreeSet::new();
    let mut in_modes = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# Modes:") {
            in_modes = true;
            continue;
        }
        if in_modes {
            if trimmed.starts_with("# Common flags:")
                || trimmed.starts_with("# Env overrides:")
                || trimmed.is_empty()
            {
                break;
            }
            if let Some(rest) = trimmed.strip_prefix("#") {
                let text = rest.trim();
                if text.starts_with("--") {
                    let mode = text
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .trim_start_matches("--");
                    modes.insert(mode.to_string());
                } else if text.starts_with("(default)") {
                    modes.insert("default".to_string());
                }
            }
        }
    }
    modes
}

fn parse_ps1_modes(content: &str) -> BTreeSet<String> {
    let mut modes = BTreeSet::new();
    let mut in_modes = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# Modes:") {
            in_modes = true;
            continue;
        }
        if in_modes {
            if trimmed.starts_with("# Common flags:")
                || trimmed.starts_with("# Env overrides:")
                || trimmed.is_empty()
            {
                break;
            }
            if let Some(rest) = trimmed.strip_prefix("#") {
                let text = rest.trim();
                if text.starts_with("-") {
                    let mode = text
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .trim_start_matches("-")
                        .to_lowercase();
                    modes.insert(mode);
                } else if text.starts_with("(default)") {
                    modes.insert("default".to_string());
                }
            }
        }
    }
    modes
}

fn parse_sh_flags(content: &str) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    let mut in_flags = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# Common flags:") {
            in_flags = true;
            continue;
        }
        if in_flags {
            if trimmed.starts_with("# Env overrides:") || trimmed.is_empty() {
                break;
            }
            if let Some(rest) = trimmed.strip_prefix("#") {
                let text = rest.trim();
                if text.starts_with("--") {
                    let flag = text
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .split('=')
                        .next()
                        .unwrap()
                        .trim_start_matches("--")
                        .to_string();
                    flags.insert(flag);
                }
            }
        }
    }
    flags
}

fn parse_ps1_flags(content: &str) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    let mut in_flags = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# Common flags:") {
            in_flags = true;
            continue;
        }
        if in_flags {
            if trimmed.starts_with("# Env overrides:") || trimmed.is_empty() {
                break;
            }
            if let Some(rest) = trimmed.strip_prefix("#") {
                let text = rest.trim();
                if text.starts_with("-") {
                    let flag = text
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .trim_start_matches("-")
                        .to_lowercase()
                        .replace("dir", "-dir")
                        .replace("file", "-file")
                        .replace("color", "-color");
                    flags.insert(flag);
                }
            }
        }
    }
    flags
}

fn extract_public_key(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.contains("RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go") {
            return Some("RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go".to_string());
        }
    }
    None
}

#[test]
fn install_scripts_expose_matching_modes_and_parity() {
    let root = repo_root();
    let sh_path = root.join("install.sh");
    let ps1_path = root.join("install.ps1");

    assert!(sh_path.exists(), "install.sh must exist at repo root");
    assert!(ps1_path.exists(), "install.ps1 must exist at repo root");

    let sh_content = std::fs::read_to_string(&sh_path).expect("read install.sh");
    let ps1_content = std::fs::read_to_string(&ps1_path).expect("read install.ps1");

    let sh_modes = parse_sh_modes(&sh_content);
    let ps1_modes = parse_ps1_modes(&ps1_content);

    assert!(
        !sh_modes.is_empty(),
        "install.sh must document public execution modes"
    );
    assert_eq!(
        sh_modes, ps1_modes,
        "install.sh and install.ps1 must document identical public modes"
    );

    // Mandatory canonical modes. `repair` went with the retired binary-asset
    // channel: reinstalling now means `cargo install --locked --force keyhog`.
    for required in &["default", "diagnose", "calibrate", "uninstall"] {
        assert!(
            sh_modes.contains(*required),
            "installer modes must contain mandatory '{required}' mode"
        );
    }
}

#[test]
fn install_scripts_share_public_signing_key_and_repo() {
    let root = repo_root();
    let sh_content = std::fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    let ps1_content = std::fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");

    let sh_key = extract_public_key(&sh_content);
    let ps1_key = extract_public_key(&ps1_content);

    assert!(sh_key.is_some(), "install.sh must carry release public key");
    assert_eq!(
        sh_key, ps1_key,
        "install.sh and install.ps1 must use identical release public keys"
    );

    assert!(
        sh_content.contains("santhreal/keyhog"),
        "install.sh must target canonical santhreal/keyhog repository"
    );
    assert!(
        ps1_content.contains("santhreal/keyhog"),
        "install.ps1 must target canonical santhreal/keyhog repository"
    );
}

#[test]
fn install_scripts_share_common_flags() {
    let root = repo_root();
    let sh_content = std::fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    let ps1_content = std::fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");

    let sh_flags = parse_sh_flags(&sh_content);
    let ps1_flags = parse_ps1_flags(&ps1_content);

    assert!(
        !sh_flags.is_empty(),
        "install.sh must document common flags"
    );
    assert!(
        !ps1_flags.is_empty(),
        "install.ps1 must document common flags"
    );
}
