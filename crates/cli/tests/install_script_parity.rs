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

/// PowerShell switches are PascalCase (`-NoCalibrate`); the shell spells the
/// same flag `--no-calibrate`. Fold the PowerShell name to the shell one so the
/// two documented sets are comparable as sets.
fn kebab_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() && index > 0 {
            out.push('-');
        }
        out.extend(ch.to_lowercase());
    }
    out
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
                if text.starts_with('-') {
                    let flag = text.split_whitespace().next().unwrap();
                    flags.insert(kebab_case(flag.trim_start_matches('-')));
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

/// WHY: this file's contract is "exact functional parity for every public mode,
/// parameter, and security verification step", and this test asserted only that
/// each script documents at least one flag. It could not fail on the bug it
/// names. It did not: `install.sh --no-calibrate` had no PowerShell
/// counterpart, so a Windows install had no way to skip the autoroute
/// measurement phase that a POSIX install skips with one flag, and neither did
/// `--no-prompt` or `--help`.
///
/// WHAT IT DOES NOT CATCH: a flag documented on both sides and implemented on
/// one. The behavior half is asserted below against the argument parsers.
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
    assert_eq!(
        sh_flags, ps1_flags,
        "install.sh and install.ps1 must document identical common flags\n  \
         only in install.sh: {:?}\n  only in install.ps1: {:?}",
        sh_flags.difference(&ps1_flags).collect::<Vec<_>>(),
        ps1_flags.difference(&sh_flags).collect::<Vec<_>>(),
    );

    // Every documented flag must be a real parameter, not prose. The shell
    // parses flags in a `case`; PowerShell declares them in `param()`.
    for flag in &sh_flags {
        assert!(
            sh_content.contains(&format!("--{flag}")),
            "install.sh documents --{flag} but never parses it"
        );
        let switch: String = flag
            .split('-')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                }
            })
            .collect();
        assert!(
            ps1_content.contains(&format!("${switch},"))
                || ps1_content.contains(&format!("${switch} ")),
            "install.ps1 documents -{switch} but never declares it as a parameter"
        );
    }
}

/// WHY: `--no-calibrate` is the flag that decides whether an install runs the
/// autoroute measurement ladder, minutes of probes, or finishes immediately.
/// Documenting it is not implementing it: the switch has to reach the finalize
/// step, skip the calibration call, and say so, on both platforms.
///
/// WHAT IT DOES NOT CATCH: that the skipped install is still usable with an
/// explicit `--backend`. The install-from-build fixtures cover that end to end.
#[test]
fn skipping_calibration_is_implemented_on_both_platforms() {
    let root = repo_root();
    let sh_content = std::fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    let ps1_content = std::fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");

    assert!(
        sh_content.contains("--no-calibrate)") && sh_content.contains("SKIP_CALIBRATION=1"),
        "install.sh must bind --no-calibrate to SKIP_CALIBRATION"
    );
    assert!(
        ps1_content.contains("if ($NoCalibrate) {"),
        "install.ps1 must branch on -NoCalibrate before calibrating"
    );

    // The notice and the calibration call must be the two arms of ONE branch.
    // A notice printed anywhere else is an install that says it skipped
    // calibration and then spends the minutes anyway.
    for (name, content, notice, guard, call) in [
        (
            "install.sh",
            &sh_content,
            "Skipped autoroute calibration by explicit --no-calibrate.",
            "SKIP_CALIBRATION",
            "prime_autoroute_cache",
        ),
        (
            "install.ps1",
            &ps1_content,
            "Skipped autoroute calibration by explicit -NoCalibrate.",
            "$NoCalibrate",
            "Invoke-AutorouteCalibration",
        ),
    ] {
        let lines: Vec<&str> = content.lines().collect();
        let notice_at = lines
            .iter()
            .position(|line| line.contains(notice))
            .unwrap_or_else(|| panic!("{name} must say out loud that it skipped calibration"));

        // Backwards: the branch the notice sits in must be the one the flag opens.
        // A notice printed above the branch is an install that reports a skip and
        // then spends the minutes anyway.
        let opener = lines[..notice_at]
            .iter()
            .rev()
            .find(|line| line.contains("if ") || line.contains("if("))
            .unwrap_or_else(|| panic!("{name}: the skip notice is not inside any branch"));
        assert!(
            opener.contains(guard),
            "{name}: the skip notice must be inside the {guard} branch, found: {opener}"
        );

        // Forwards: the opposite arm is the calibration the flag replaces.
        let alternative = lines[notice_at + 1..]
            .iter()
            .take(4)
            .find(|line| line.contains("elif") || line.contains("elseif"))
            .unwrap_or_else(|| {
                panic!("{name}: the skip notice must be one arm of the calibration branch")
            });
        assert!(
            alternative.contains(call),
            "{name}: the arm opposite the skip notice must be the {call} the flag replaces, \
             found: {alternative}"
        );
    }
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

/// WHY: an install can finish "successfully" and still be unusable. Calibration
/// publishes decisions under the configuration it measured, and `keyhog doctor`
/// cannot detect a mismatch: its self-test compiles one bundled detector and
/// scans with an explicit `ScanBackend::CpuFallback`, so it passes on an install
/// whose very next auto-routed scan exits 2. That shipped: the all-policy sweep
/// spawned isolated policy children without the parent's config mode, so every
/// calibrated decision landed under a digest no plain scan resolves. Both
/// installers must therefore end the calibration phase by running one ordinary
/// scan, with no backend override and no calibration flag, and fail the install
/// when routing refuses it.
///
/// WHAT IT DOES NOT CATCH: whether the check itself resolves the same digest on
/// a host whose `.keyhog.toml` sits above the temporary scan directory. The
/// probe runs in a fresh temp tree and asks for the baseline config explicitly.
#[test]
fn install_scripts_verify_a_plain_scan_after_calibration() {
    struct Wiring {
        script: &'static str,
        open: &'static str,
        call_site: &'static str,
        findings_exit_is_success: &'static str,
    }

    let root = repo_root();
    for wiring in [
        Wiring {
            script: "install.sh",
            open: "verify_autoroute_serves_a_scan() {",
            call_site: "elif ! verify_autoroute_serves_a_scan \"$INSTALL_DIR/keyhog\"; then",
            findings_exit_is_success: "\"$check_status\" = \"1\"",
        },
        Wiring {
            script: "install.ps1",
            open: "function Test-AutorouteServesAScan {",
            call_site: "elseif (-not (Test-AutorouteServesAScan -BinPath $BinPath)) {",
            findings_exit_is_success: "$scanExit -eq 1",
        },
    ] {
        let name = wiring.script;
        let content =
            std::fs::read_to_string(root.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
        let start = content
            .find(wiring.open)
            .unwrap_or_else(|| panic!("{name} must define the post-calibration scan check"));
        let body = content[start..]
            .split_once("\n}\n")
            .unwrap_or_else(|| panic!("{name}: post-calibration check has no closing brace"))
            .0;

        assert!(
            content.contains(wiring.call_site),
            "{name} defines the post-calibration scan check but never runs it after calibration"
        );
        assert!(
            body.contains("scan"),
            "{name}: the post-calibration check must run a real scan"
        );
        assert!(
            !body.contains("--backend"),
            "{name}: the post-calibration check must exercise the auto route, not a pinned backend"
        );
        assert!(
            !body.contains("--autoroute-calibrate"),
            "{name}: the post-calibration check must read the primed cache, not extend it"
        );
        assert!(
            body.contains("--no-config"),
            "{name}: the check must resolve the baseline configuration calibration measured"
        );
        assert!(
            body.contains(wiring.findings_exit_is_success),
            "{name}: exit 1 is findings, not a routing failure, and must pass the check"
        );
    }
}
