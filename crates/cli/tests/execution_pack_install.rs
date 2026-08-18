#![cfg(unix)]

use keyhog_scanner::execution_pack::{ExecutionPackSignature, ExecutionPackSigningKey};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// WHY: a fresh install must execute the production compiler and publish authenticated packs for every policy before autoroute calibration begins.
#[test]
fn hidden_install_command_publishes_authenticated_policy_generation() {
    let directory = tempfile::tempdir().expect("temporary install root");
    let cache_home = directory.path().join("cache");
    let pack_root = cache_home.join("keyhog/execution-packs");
    fs::create_dir_all(&pack_root).expect("execution-pack root");
    let key_path = pack_root.join("signing.key");
    let key_bytes = [0x4d; 32];
    fs::write(&key_path, key_bytes).expect("write signing key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("protect signing key");
    let output = pack_root.join("current");

    let result = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("compile-execution-packs")
        .arg("--output-dir")
        .arg(&output)
        .arg("--signing-key")
        .arg(&key_path)
        .output()
        .expect("run install pack compiler");
    assert!(
        result.status.success(),
        "install pack compiler failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let manifest_bytes = fs::read(output.join("manifest.json")).expect("read manifest");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest");
    assert_eq!(manifest["version"], 1);
    let packs = manifest["packs"].as_array().expect("pack rows");
    let policies: std::collections::BTreeSet<_> = packs
        .iter()
        .map(|row| row["policy"].as_str().expect("policy"))
        .collect();
    assert_eq!(
        policies,
        ["deep", "default", "fast", "precision"]
            .into_iter()
            .collect()
    );
    let allowed_backends = ["cpu", "simd", "gpu-cuda", "gpu-wgpu", "gpu-metal"];
    assert!(packs
        .iter()
        .all(|row| { allowed_backends.contains(&row["backend"].as_str().expect("backend")) }));
    for backend in packs
        .iter()
        .map(|row| row["backend"].as_str().expect("backend"))
        .collect::<std::collections::BTreeSet<_>>()
    {
        assert_eq!(
            packs.iter().filter(|row| row["backend"] == backend).count(),
            4,
            "each eligible backend must publish one pack for every policy"
        );
    }

    let key = ExecutionPackSigningKey::from_bytes(key_bytes).expect("load signing key");
    for row in packs {
        let pack_path = output.join(row["file"].as_str().expect("pack file"));
        let signature_path = output.join(row["signature_file"].as_str().expect("signature file"));
        let pack_bytes = fs::read(&pack_path).expect("read pack");
        assert_eq!(
            pack_bytes.len(),
            row["bytes"].as_u64().expect("pack bytes") as usize
        );
        let signature_bytes = fs::read(signature_path).expect("read signature");
        let signature = ExecutionPackSignature::decode(&signature_bytes).expect("decode signature");
        key.verify(&pack_bytes, &signature)
            .expect("authenticate installed pack");
        assert_eq!(
            keyhog_core::hex_encode(&signature.pack_digest),
            row["signed_pack_digest"].as_str().expect("signed digest")
        );
    }

    let calibrated = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args([
            "calibrate-autoroute",
            "--policy",
            "default",
            "--quiet",
            "--execution-packs",
        ])
        .arg(&output)
        .output()
        .expect("validate packs before calibration");
    assert!(
        calibrated.status.success(),
        "calibration rejected current authenticated packs: {}",
        String::from_utf8_lossy(&calibrated.stderr)
    );

    let scan_input = directory.path().join("runtime-pack-input.txt");
    fs::write(
        &scan_input,
        b"GITHUB_TOKEN=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\n",
    )
    .expect("write runtime pack scan input");
    let mut scan_backends = vec!["cpu"];
    if packs
        .iter()
        .any(|row| row["policy"] == "default" && row["backend"] == "simd")
    {
        scan_backends.push("simd");
    }
    for backend in scan_backends {
        let scan = Command::new(env!("CARGO_BIN_EXE_keyhog"))
            .args([
                "scan",
                "--backend",
                backend,
                "--format",
                "json-envelope",
                "--no-config",
            ])
            .arg(&scan_input)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("KEYHOG_REQUIRE_EXECUTION_PACKS", "1")
            .current_dir(directory.path())
            .output()
            .expect("scan through installed detector and matcher pack");
        assert_eq!(
            scan.status.code(),
            Some(1),
            "{backend} pack scan failed: {}",
            String::from_utf8_lossy(&scan.stderr)
        );
        let scan_json: Value =
            serde_json::from_slice(&scan.stdout).expect("pack scan JSON envelope");
        assert_eq!(
            scan_json["findings"].as_array().map(Vec::len),
            Some(1),
            "{backend} pack must preserve exact finding parity"
        );
    }

    let cpu_pack = output.join("default-cpu.khpack");
    let hidden_cpu_pack = output.join("default-cpu.khpack.hidden");
    fs::rename(&cpu_pack, &hidden_cpu_pack).expect("hide runtime detector pack");
    let missing = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args([
            "scan",
            "--backend",
            "cpu",
            "--format",
            "json-envelope",
            "--no-config",
        ])
        .arg(&scan_input)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("KEYHOG_REQUIRE_EXECUTION_PACKS", "1")
        .output()
        .expect("reject missing runtime detector pack");
    fs::rename(&hidden_cpu_pack, &cpu_pack).expect("restore runtime detector pack");
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr)
        .contains("loading authenticated detector execution pack"));

    let healthy = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["doctor", "--autoroute-cache", "off"])
        .env("XDG_CACHE_HOME", &cache_home)
        .output()
        .expect("inspect installed execution generation");
    assert!(
        healthy.status.success(),
        "doctor rejected authenticated packs: {}",
        String::from_utf8_lossy(&healthy.stdout)
    );
    let healthy_stdout = String::from_utf8_lossy(&healthy.stdout);
    assert!(healthy_stdout.contains("pack state") && healthy_stdout.contains("AUTHENTICATED"));

    let tampered_path = output.join("default-cpu.khpack");
    let mut tampered = fs::read(&tampered_path).expect("read pack for tamper");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    fs::write(&tampered_path, tampered).expect("tamper installed pack");
    let rejected = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args([
            "calibrate-autoroute",
            "--policy",
            "default",
            "--quiet",
            "--execution-packs",
        ])
        .arg(&output)
        .output()
        .expect("reject tampered packs before calibration");
    assert!(!rejected.status.success());
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        rejected_stderr.contains("content digest mismatch")
            || rejected_stderr.contains("signed digest does not match the pack bytes"),
        "corrupt pack diagnostic: {rejected_stderr}"
    );
    let unhealthy = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["doctor", "--autoroute-cache", "off"])
        .env("XDG_CACHE_HOME", &cache_home)
        .output()
        .expect("reject corrupt installed execution generation");
    assert_eq!(unhealthy.status.code(), Some(4));
    let unhealthy_stdout = String::from_utf8_lossy(&unhealthy.stdout);
    assert!(unhealthy_stdout.contains("pack state") && unhealthy_stdout.contains("INVALID"));
}

/// WHY: installer key permissions are a trust boundary; a group-readable key must fail without replacing a valid generation.
#[test]
fn hidden_install_command_rejects_exposed_signing_key() {
    let directory = tempfile::tempdir().expect("temporary install root");
    let key_path = directory.path().join("signing.key");
    fs::write(&key_path, [0x5e; 32]).expect("write signing key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("expose signing key");
    let output = directory.path().join("current");

    let result = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("compile-execution-packs")
        .arg("--output-dir")
        .arg(&output)
        .arg("--signing-key")
        .arg(&key_path)
        .output()
        .expect("run install pack compiler");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("must not grant group or other permissions"));
    assert!(!output.exists());
}

/// WHY: `read_signing_key` has three rejection branches and only the permission
/// one was covered live. The length and non-regular-file branches were covered
/// by `tests/unit/installer_execution_generation.rs` against the installer-side
/// `ensure_signing_key`, which no longer exists; that file was also declared in
/// no manifest, so it never compiled and its loss was silent. Every branch is
/// enumerated here, through the shipped binary, so a weakened check goes RED.
#[test]
fn hidden_install_command_rejects_every_malformed_signing_key() {
    let directory = tempfile::tempdir().expect("temporary install root");

    // Wrong length: 31 and 33 bytes both bracket the exact-32 requirement.
    for len in [0usize, 31, 33] {
        let key_path = directory.path().join(format!("short-{len}.key"));
        fs::write(&key_path, vec![0x7a; len]).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("protect signing key");
        let output = directory.path().join(format!("current-{len}"));
        let result = Command::new(env!("CARGO_BIN_EXE_keyhog"))
            .arg("compile-execution-packs")
            .arg("--output-dir")
            .arg(&output)
            .arg("--signing-key")
            .arg(&key_path)
            .output()
            .expect("run install pack compiler");
        assert!(
            !result.status.success(),
            "a {len}-byte signing key must be rejected"
        );
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("must be an exact 32-byte regular file"),
            "the {len}-byte rejection must name the exact-32 contract; stderr={}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists(), "a rejected key must publish nothing");
    }

    // Not a regular file: a symlink to a valid key is still refused, so the
    // permission and length checks cannot be bypassed through an indirection.
    let real = directory.path().join("real.key");
    fs::write(&real, [0x3c; 32]).expect("write signing key");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).expect("protect signing key");
    let link = directory.path().join("link.key");
    std::os::unix::fs::symlink(&real, &link).expect("create key symlink");
    let output = directory.path().join("current-symlink");
    let result = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("compile-execution-packs")
        .arg("--output-dir")
        .arg(&output)
        .arg("--signing-key")
        .arg(&link)
        .output()
        .expect("run install pack compiler");
    assert!(!result.status.success(), "a symlinked key must be rejected");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("must be an exact 32-byte regular file"),
        "the symlink rejection must name the regular-file contract; stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists(), "a rejected key must publish nothing");
}
