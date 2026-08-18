//! Install integrity bypasses must be explicit flags, never ambient env.

use std::collections::BTreeSet;

fn keyhog_env_tokens(script: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    collect_env_tokens_after_prefix(script, "$env:", &mut tokens);
    collect_env_tokens_after_prefix(script, "${env:", &mut tokens);
    collect_env_tokens_after_prefix(script, "${", &mut tokens);
    collect_env_tokens_after_prefix(script, "$", &mut tokens);
    collect_standalone_uppercase_env_tokens(script, &mut tokens);
    tokens
}

fn collect_env_tokens_after_prefix(script: &str, prefix: &str, tokens: &mut BTreeSet<String>) {
    let normalized = script.to_ascii_uppercase();
    let prefix = prefix.to_ascii_uppercase();
    for (prefix_start, _) in normalized.match_indices(&prefix) {
        let token_start = prefix_start + prefix.len();
        let tail = &normalized[token_start..];
        if !tail.starts_with("KEYHOG_") {
            continue;
        }
        let end = token_end(tail);
        tokens.insert(tail[..end].to_owned());
    }
}

fn collect_standalone_uppercase_env_tokens(script: &str, tokens: &mut BTreeSet<String>) {
    for (start, _) in script.match_indices("KEYHOG_") {
        let tail = &script[start..];
        let end = token_end(tail);
        tokens.insert(tail[..end].to_owned());
    }
}

fn token_end(tail: &str) -> usize {
    tail.find(|ch: char| !(ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'))
        .unwrap_or(tail.len())
}

#[test]
fn keyhog_env_token_inventory_normalizes_case_for_power_shell() {
    assert_eq!(
        keyhog_env_tokens(
            "$env:KeyHog_Insecure_Install = 1; ${env:KEYHOG_VERSION}; run_keyhog_calibration_scan"
        ),
        BTreeSet::from([
            "KEYHOG_INSECURE_INSTALL".to_owned(),
            "KEYHOG_VERSION".to_owned()
        ])
    );
}

/// WHY: every installer behavior must come from an explicit flag. Ambient
/// `KEYHOG_*` environment configuration is invisible at the call site, so a
/// stale exported value silently changes what gets installed. The last one,
/// `KEYHOG_VERSION`, went with the retired binary-asset channel: there is no
/// version to pin when there is nothing to download.
#[test]
fn installers_read_no_ambient_keyhog_env() {
    let allowed: BTreeSet<String> = BTreeSet::new();
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        let actual = keyhog_env_tokens(script);
        assert_eq!(
            actual, allowed,
            "{name} must not read ambient KEYHOG_* installer configuration. \
             Local files, destination, insecure mode, calibration, and behavior \
             all use explicit flags."
        );
    }
}

#[test]
fn install_scripts_do_not_accept_insecure_env_override() {
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        assert!(
            !script.contains("KEYHOG_INSECURE_INSTALL"),
            "{name} must not accept an ambient env var that weakens checksum verification"
        );
    }
}

#[test]
fn install_from_file_is_explicit_flag_not_env() {
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        assert!(
            !script.contains("KEYHOG_FROM_FILE"),
            "{name} must not accept KEYHOG_FROM_FILE; local/offline installs use --from-file/-FromFile explicitly"
        );
    }
}

#[test]
fn installer_destination_is_explicit_flag_not_env() {
    for (name, script, forbidden) in [
        (
            "install.sh",
            include_str!("../../../install.sh"),
            &["KEYHOG_INSTALL", "KEYHOG_VARIANT"][..],
        ),
        (
            "install.ps1",
            include_str!("../../../install.ps1"),
            &["KEYHOG_INSTALL", "KEYHOG_VARIANT"][..],
        ),
    ] {
        for token in forbidden {
            assert!(
                !script.contains(token),
                "{name} must not accept {token}; installer destination is an explicit flag"
            );
        }
    }
}

#[test]
fn install_scripts_keep_explicit_insecure_flags() {
    let sh = include_str!("../../../install.sh");
    assert!(
        sh.contains("--insecure"),
        "POSIX installer still needs the explicit emergency bypass flag"
    );
    assert!(
        sh.contains("INSECURE_INSTALL=0"),
        "POSIX installer default must remain fail-closed"
    );

    let ps1 = include_str!("../../../install.ps1");
    assert!(
        ps1.contains("-Insecure"),
        "PowerShell installer still needs the explicit emergency bypass flag"
    );
    assert!(
        ps1.contains("$Script:InsecureInstall = [bool]$Insecure"),
        "PowerShell installer must derive bypass state only from the explicit flag"
    );
}

/// WHY: `--from-file` is the only install path, so the pinned minisign key and
/// the fail-closed branch around it are the whole authenticity story. Both
/// scripts must pin the SAME key: a divergence would let one platform accept
/// an artifact the other rejects. Does not catch a key that is pinned
/// identically in both scripts but is the wrong key.
#[test]
fn installers_pin_one_minisign_key_and_fail_closed_on_a_bad_local_signature() {
    const PINNED: &str = "RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go";
    for (name, script) in [
        ("install.sh", include_str!("../../../install.sh")),
        ("install.ps1", include_str!("../../../install.ps1")),
    ] {
        assert!(
            script.contains(PINNED),
            "{name} must pin the shared minisign public key"
        );
        assert!(
            script.contains("minisign"),
            "{name} must invoke minisign to verify a supplied local signature"
        );
        assert!(
            script.contains("Refusing to install an unverified keyhog binary.")
                || script.contains(
                    "Refusing to install an artifact signed by the wrong key or modified after signing."
                ),
            "{name} must refuse an artifact whose signature does not verify"
        );
    }
}

/// WHY: the scripts install a bundle the operator already holds. A download
/// would resurrect the retired binary-asset channel, which failed silently by
/// searching backward for an older release that still had assets.
/// `scripts/gates/release_channel_coherence.py` enforces the same class from
/// the workflow side; this catches the script-side shapes directly.
#[test]
fn installers_have_no_network_fetch_path() {
    for (name, script, fetchers) in [
        (
            "install.sh",
            include_str!("../../../install.sh"),
            &["curl ", "wget ", "api.github.com", "releases/download"][..],
        ),
        (
            "install.ps1",
            include_str!("../../../install.ps1"),
            &[
                "Invoke-WebRequest",
                "Invoke-RestMethod",
                "api.github.com",
                "releases/download",
            ][..],
        ),
    ] {
        for fetcher in fetchers {
            assert!(
                !script.contains(fetcher),
                "{name} must not fetch anything; found `{fetcher}`. \
                 Installs take a local bundle via --from-file."
            );
        }
    }
}

/// WHY: a GPU literal sidecar seeds the compiled-matcher cache, so a hostile
/// archive would plant files outside it. The sidecar must be signature- and
/// checksum-checked and archive-validated BEFORE extraction, and a failure
/// must roll the cache back rather than leave it half-seeded.
#[test]
fn installers_verify_gpu_literal_sidecars_before_seeding_the_cache() {
    let sh = include_str!("../../../install.sh");
    assert!(
        sh.contains("stage_local_gpu_literal_sidecar")
            && sh.contains("verify_local_signature_if_present \"$local_sidecar\" \"$local_sig\"")
            && sh.contains("verify_local_checksum \"$local_sidecar\" \"$local_sum\"")
            && sh.contains("--from-file requires a sibling GPU literal sidecar")
            && sh.contains("validate_gpu_literal_sidecar_archive")
            && sh.contains("GPU literal artifact sidecar contains link entries.")
            && sh.contains("backup_gpu_programs_cache_for_install")
            && sh.contains("restore_gpu_programs_cache_backup")
            && sh.contains("clear_gpu_programs_cache_backup"),
        "install.sh must verify and inspect GPU literal sidecar archives before extraction"
    );

    let ps1 = include_str!("../../../install.ps1");
    assert!(
        ps1.contains("Stage-LocalGpuLiteralSidecar")
            && ps1.contains("Verify-LocalChecksum -BinaryPath $localSidecar -SumFile $localSum")
            && ps1.contains("-FromFile requires a sibling GPU literal sidecar")
            && ps1.contains("Test-GpuLiteralSidecarArchive")
            && ps1.contains("GPU literal artifact sidecar contains a link entry")
            && ps1.contains("Backup-GpuProgramsCacheForInstall")
            && ps1.contains("Restore-GpuProgramsCacheBackup")
            && ps1.contains("Clear-GpuProgramsCacheBackup"),
        "install.ps1 must verify and inspect GPU literal sidecar archives before extraction"
    );
}
