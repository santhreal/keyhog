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

/// WHY: the only automatic execution-pack producer used to live in
/// `crates/cli/src/installer/execution_packs.rs`, reachable solely from the
/// self-install path fed by the retired binary-asset release channel. When that
/// channel was removed the producer went with it, and nothing noticed: with no
/// installed generation every scan silently re-parses and re-compiles the
/// embedded detector corpus. Measured on a 16-core AVX-512 host that is 284 ms
/// wall and 1570 ms CPU of scan setup against 66 ms and 110 ms with packs
/// installed. Both installers must publish a generation, and must do it BEFORE
/// calibration, because packs change the detector and config digests that
/// calibration measures its buckets against.
///
/// WHAT IT DOES NOT CATCH: whether the published generation authenticates on
/// this host. `execution_pack_install.rs` covers that through the real compiler.
#[test]
fn install_scripts_publish_execution_packs_before_calibration() {
    let root = repo_root();
    for (name, compile, calibrate) in [
        (
            "install.sh",
            "publish_execution_packs",
            "prime_autoroute_cache",
        ),
        (
            "install.ps1",
            "Publish-ExecutionPacks",
            "Invoke-AutorouteCalibration",
        ),
    ] {
        let content =
            std::fs::read_to_string(root.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert!(
            content.contains("compile-execution-packs"),
            "{name} must invoke `keyhog compile-execution-packs`; without it every scan \
             recompiles the detector corpus"
        );
        assert!(
            content.contains("signing.key"),
            "{name} must provision the 32-byte execution-pack signing key"
        );

        // Every call to the calibration phase must be preceded by a pack
        // publication call in the same script, so no install mode calibrates
        // against digests the packs are about to change.
        let calls: Vec<usize> = content.match_indices(compile).map(|(i, _)| i).collect();
        assert!(
            calls.len() >= 2,
            "{name} must define {compile} and call it from every install mode; found {} \
             occurrence(s)",
            calls.len()
        );
        let first_publish = calls[0];
        for (index, _) in content.match_indices(calibrate) {
            assert!(
                first_publish < index,
                "{name} calls {calibrate} at byte {index} with no earlier {compile}; \
                 packs must be published before calibration"
            );
        }
    }
}

/// Both installers must probe the SAME decode-heavy size bands.
///
/// `decode_admitted` is a keyed routing dimension, and an unmeasured band is
/// served only from at least two measured bands of the same family. One decode
/// probe therefore leaves every decoding scan on that platform uncalibrated and
/// exiting 2. `install.sh` grew a three-band ladder while `install.ps1` kept a
/// single 256 KiB probe, which is exactly that failure on Windows.
///
/// Bands are read out of both scripts at run time, so adding one to either side
/// alone fails here instead of shipping.
#[test]
fn install_scripts_probe_the_same_decode_heavy_bands() {
    let root = repo_root();
    let sh = std::fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    let ps1 = std::fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");

    let sh_bands: BTreeSet<u32> = sh
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("decode_heavy_kib_sizes=")
                .map(|value| value.trim_matches('"').to_string())
        })
        .expect("install.sh must declare decode_heavy_kib_sizes")
        .split_whitespace()
        .map(|band| band.parse().expect("a decode-heavy band is a KiB integer"))
        .collect();

    // The band list sits on the `foreach` line above the probe call.
    let ps1_lines: Vec<&str> = ps1.lines().collect();
    let ps1_bands: BTreeSet<u32> = ps1_lines
        .iter()
        .position(|line| line.contains("New-DecodeHeavyCalibrationProbeKiB -Path"))
        .and_then(|probe| {
            ps1_lines[..probe]
                .iter()
                .rev()
                .find(|line| line.contains("foreach ($kib in"))
                .copied()
        })
        .and_then(|line| {
            let open = line.find("@(")? + 2;
            let close = line[open..].find(')')? + open;
            Some(line[open..close].to_string())
        })
        .expect("install.ps1 must sweep decode-heavy bands with a foreach list")
        .split(',')
        .map(|band| {
            band.trim()
                .parse()
                .expect("a decode-heavy band is a KiB integer")
        })
        .collect();

    assert!(
        sh_bands.len() >= 2,
        "a decode family needs at least two measured bands to cover an unmeasured one; \
         install.sh probes {sh_bands:?}"
    );
    assert_eq!(
        sh_bands, ps1_bands,
        "install.sh and install.ps1 must probe the same decode-heavy bands"
    );
}
