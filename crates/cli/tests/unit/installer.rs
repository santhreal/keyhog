use keyhog::testing::{CliTestApi as _, API};

fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn asset_name_matches_release_convention() {
    assert_eq!(
        API.asset_name("linux", "x86_64", false).as_deref(),
        Some("keyhog-linux-x86_64")
    );
    assert_eq!(
        API.asset_name("linux", "x86_64", true).as_deref(),
        Some("keyhog-linux-x86_64-cuda")
    );
    assert_eq!(
        API.asset_name("macos", "aarch64", false).as_deref(),
        Some("keyhog-macos-aarch64")
    );
    assert_eq!(
        API.asset_name("macos", "x86_64", false).as_deref(),
        Some("keyhog-macos-x86_64")
    );
    // macOS has no CUDA build - cuda flag is ignored, no `-cuda` suffix.
    assert_eq!(
        API.asset_name("macos", "aarch64", true).as_deref(),
        Some("keyhog-macos-aarch64")
    );
    // Windows x86_64: release.yml uploads keyhog-windows-x86_64.exe, so
    // `update`/`repair` must resolve it (previously returned None, which
    // left both commands dead on Windows). CUDA has no Windows asset, so
    // the flag is ignored - no `-cuda` suffix.
    assert_eq!(
        API.asset_name("windows", "x86_64", false).as_deref(),
        Some("keyhog-windows-x86_64.exe")
    );
    assert_eq!(
        API.asset_name("windows", "x86_64", true).as_deref(),
        Some("keyhog-windows-x86_64.exe")
    );
    // Unsupported (os, arch) pairs still yield None.
    assert_eq!(API.asset_name("windows", "aarch64", false), None);
    assert_eq!(API.asset_name("linux", "riscv64", false), None);
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_cuda_asset_selection_requires_cuda_asset() {
    let portable_only = ["keyhog-linux-x86_64"];
    let err = API
        .select_release_asset_name("v9.9.9", &portable_only, true)
        .expect_err("explicit CUDA update/repair must not install the portable asset");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("keyhog-linux-x86_64-cuda") && msg.contains("fail closed"),
        "error must name the missing exact CUDA asset and fail-closed semantics: {msg}"
    );

    let with_cuda = ["keyhog-linux-x86_64", "keyhog-linux-x86_64-cuda"];
    assert_eq!(
        API.select_release_asset_name("v9.9.9", &with_cuda, true)
            .expect("CUDA asset present"),
        "keyhog-linux-x86_64-cuda"
    );
}

#[test]
fn release_selector_has_no_portable_fallback_for_explicit_cuda() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/installer/release.rs"
    ))
    .expect("release installer source readable");
    let selector = src
        .split("pub(crate) fn select_asset")
        .nth(1)
        .and_then(|tail| tail.split("/// Download an asset").next())
        .expect("select_asset body is present");
    assert!(
        selector.contains("explicit release variants fail closed")
            && !selector.contains(".or_else(")
            && !selector.contains("portable fallback"),
        "select_asset must not silently downgrade explicit --variant cuda to the portable asset"
    );
}

#[test]
fn omitted_variant_uses_install_script_cuda_default_contract() {
    assert!(
        API.default_wants_cuda_variant_for_host("linux", "x86_64", true, true, true),
        "Linux x86_64 with NVIDIA GPU, libcuda, and CUDA toolkit must default to the CUDA asset"
    );
    for (os, arch, nvidia_gpu, libcuda, cuda_toolkit) in [
        ("macos", "aarch64", true, true, true),
        ("windows", "x86_64", true, true, true),
        ("linux", "aarch64", true, true, true),
        ("linux", "x86_64", false, true, true),
        ("linux", "x86_64", true, false, true),
        ("linux", "x86_64", true, true, false),
    ] {
        assert!(
            !API.default_wants_cuda_variant_for_host(os, arch, nvidia_gpu, libcuda, cuda_toolkit),
            "host tuple {os}-{arch} nvidia={nvidia_gpu} libcuda={libcuda} toolkit={cuda_toolkit} must default to the non-CUDA asset"
        );
    }
}

#[test]
fn omitted_variant_rejects_unsupported_host_before_cuda_probes() {
    let variant_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/installer/variant.rs"
    ))
    .expect("variant.rs readable");
    let body = variant_rs
        .split("pub(crate) fn default_wants_cuda_variant() -> bool")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(crate) fn default_wants_cuda_variant_for_host")
                .next()
        })
        .expect("default_wants_cuda_variant body extractable");
    let unsupported_host_gate = body
        .find("if !cuda_variant_supported_host(os, arch)")
        .expect("default variant selection must gate unsupported OS/arch before CUDA probes");
    for probe in [
        "nvidia_gpu_present()",
        "libcuda_present()",
        "cuda_toolkit_present()",
    ] {
        let probe_pos = body
            .find(probe)
            .unwrap_or_else(|| panic!("default variant selection must call {probe}"));
        assert!(
            unsupported_host_gate < probe_pos,
            "unsupported OS/arch must return the non-CUDA asset before running {probe}"
        );
    }
}

#[test]
fn explicit_variant_resolution_is_strict() {
    assert!(API.wants_cuda_variant(Some("cuda")).unwrap());
    assert!(!API.wants_cuda_variant(Some("cpu")).unwrap());
    let err = API
        .wants_cuda_variant(Some("portable"))
        .expect_err("unknown variants must not silently select portable");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("invalid release variant") && msg.contains("--variant cpu"),
        "invalid variant error must explain the accepted values: {msg}"
    );
}

#[test]
fn installer_variant_words_match_release_feature_matrix() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let release_yml =
        std::fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release.yml");
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let install_doc = std::fs::read_to_string(root.join("docs/src/install.md"))
        .expect("docs/src/install.md readable");
    let install_sh = std::fs::read_to_string(root.join("install.sh")).expect("install.sh");
    let install_ps1 = std::fs::read_to_string(root.join("install.ps1")).expect("install.ps1");
    let maintenance_rs = std::fs::read_to_string(root.join("crates/cli/src/args/maintenance.rs"))
        .expect("maintenance.rs");
    let variant_rs = std::fs::read_to_string(root.join("crates/cli/src/installer/variant.rs"))
        .expect("variant.rs");
    let readme_words = normalize_ws(&readme);
    let install_doc_words = normalize_ws(&install_doc);

    assert!(
        release_yml.contains("asset: keyhog-macos-aarch64")
            && release_yml.contains("asset: keyhog-windows-x86_64.exe")
            && release_yml.contains("features: '--no-default-features --features portable'")
            && release_yml.contains("artifact_features: 'ml,entropy,decode,multiline'"),
        "release matrix must keep macOS/Windows portable feature evidence visible"
    );

    for (name, text) in [
        ("README.md", readme.as_str()),
        ("docs/src/install.md", install_doc.as_str()),
        ("install.sh", install_sh.as_str()),
        ("install.ps1", install_ps1.as_str()),
        ("maintenance.rs", maintenance_rs.as_str()),
        ("variant.rs", variant_rs.as_str()),
    ] {
        for stale in [
            "portable WGPU+SIMD",
            "portable WGPU + SIMD",
            "macOS release assets run SIMD on CPU plus the WGPU",
            "Windows installer ships the WGPU + SIMD",
            "WGPU + SIMD Windows build",
            "default WGPU + SIMD build, skip GPU detection",
        ] {
            assert!(
                !text.contains(stale),
                "{name} must not claim portable macOS/Windows assets ship accelerators absent from release.yml: {stale}"
            );
        }
    }

    assert!(
        readme_words
            .contains("macOS and Windows release assets are portable no-system-library builds")
            && install_doc_words
                .contains("macOS release assets are portable no-system-library builds")
            && install_doc_words
                .contains("Windows installer ships the portable no-system-library build")
            && install_sh.contains("portable no-system-library macOS build")
            && install_ps1.contains("portable no-system-library Windows build")
            && maintenance_rs.contains("default non-CUDA release asset")
            && variant_rs.contains("default non-CUDA release asset"),
        "docs, installers, and CLI help must describe portable/non-CUDA variants honestly"
    );
}

#[test]
fn update_and_repair_use_shared_variant_resolver() {
    for rel in ["src/subcommands/update.rs", "src/subcommands/repair.rs"] {
        let src = std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel))
            .expect("subcommand source readable");
        assert!(
            src.contains("installer::wants_cuda_variant(args.variant.as_deref())?"),
            "{rel} must use the shared strict/default variant resolver"
        );
        let variant_pos = src
            .find("installer::wants_cuda_variant(args.variant.as_deref())?")
            .expect("variant resolver call present");
        let client_pos = src
            .find("installer::http_client()?")
            .expect("HTTP client call present");
        assert!(
            variant_pos < client_pos,
            "{rel} must reject invalid variants before network setup"
        );
        assert!(
            !src.contains("args.variant.as_deref() == Some(\"cuda\")"),
            "{rel} must not make omitted/invalid variants silently portable"
        );
    }
}

#[test]
fn semver_parsing_handles_v_prefix_and_suffix() {
    assert_eq!(API.parse_semver("v0.5.36"), Some((0, 5, 36)));
    assert_eq!(API.parse_semver("0.5.36"), Some((0, 5, 36)));
    assert_eq!(API.parse_semver("v1.2.3-rc1"), Some((1, 2, 3)));
    assert_eq!(API.parse_semver("garbage"), None);
    assert_eq!(API.parse_semver("v1.2"), None);
}

#[test]
fn is_newer_compares_correctly() {
    assert!(API.is_newer("0.5.35", "v0.5.36"));
    assert!(API.is_newer("0.5.35", "0.6.0"));
    assert!(API.is_newer("0.5.35", "1.0.0"));
    assert!(!API.is_newer("0.5.36", "v0.5.36"));
    assert!(!API.is_newer("0.5.36", "v0.5.35"));
    assert!(!API.is_newer("0.5.35", "garbage"));
}

#[test]
fn rejects_non_executable_download() {
    assert!(!API.looks_like_native_executable(b"<!DOCTYPE html><html>Not Found"));
    assert!(!API.looks_like_native_executable(b""));
    #[cfg(target_os = "linux")]
    assert!(API.looks_like_native_executable(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]));

    assert!(API.looks_like_native_executable_for_os(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0], "linux"));
    assert!(API.looks_like_native_executable_for_os(&[0xFE, 0xED, 0xFA, 0xCF, 0, 0, 0, 0], "macos"));
    assert!(API.looks_like_native_executable_for_os(&[b'M', b'Z', 0x90, 0x00], "windows"));
    assert!(!API.looks_like_native_executable_for_os(b"<!DOCTYPE html><html>Not Found", "windows"));
    assert!(!API.looks_like_native_executable_for_os(b"<!DOCTYPE html><html>Not Found", "freebsd"));
}

#[test]
fn self_test_detects_planted_secret() {
    // The doctor/repair self-test must actually fire end-to-end.
    assert!(API.scan_engine_self_test().expect("self-test runs"));
}

// A real minisign signature of FIXTURE_DATA, produced by the keyhog release
// secret key whose public half is embedded as installer::RELEASE_PUBLIC_KEY.
// This proves the embedded key verifies a genuine release signature and that
// any tampering (wrong data, mangled signature) is rejected.
const FIXTURE_DATA: &[u8] = b"keyhog-signature-test-v1\n";
const FIXTURE_SIG: &str = "untrusted comment: signature from rsign secret key\n\
RUTPnJ/p6xVJ3REkJ9dhxwKQpEisq7Y2A4uIZlUzPRM0zDjWidV3sIXjHB8d558++9M0KpCpz6T8efYlVFl/RZhrKIznrUZSGww=\n\
trusted comment: timestamp:1780025193\tfile:/tmp/claude-1000/tmp.JTQWgRt5FO/fixture.bin\tprehashed\n\
L/wvGiwIhpaBlkEUaQ364Q8ph9ksqIxJyIMy1RQbs/QS4+q8biUaJGt+0weV4E0IV/pPHywDFtZhvUD03un2CA==\n";

#[test]
fn release_signature_verifies_against_embedded_key() {
    API.verify_release_signature(FIXTURE_DATA, FIXTURE_SIG)
        .expect("a genuine signature must verify against the embedded public key");
}

#[test]
fn release_signature_rejects_tampered_payload() {
    // Same signature, different bytes: the update must be refused.
    assert!(
        API.verify_release_signature(b"tampered binary contents", FIXTURE_SIG)
            .is_err(),
        "a signature must not verify against payload it didn't sign"
    );
}

#[test]
fn release_signature_rejects_malformed_signature() {
    assert!(API
        .verify_release_signature(FIXTURE_DATA, "not a minisig file")
        .is_err());
    assert!(API.verify_release_signature(FIXTURE_DATA, "").is_err());
}

// ── Moved from src/installer.rs (#[cfg(test)] mod rename_away_tests) per the
//    no_inline_tests_in_src gate. Cross-platform rename-away self-replace that
//    backs `keyhog update`/`repair` on Windows; same std::fs::rename semantics
//    on every OS, so the Linux host exercises the exact Windows code path.

#[test]
fn replace_success_installs_new_and_returns_stash() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"OLD-WORKING-BINARY").unwrap();

    let stash = API
        .replace_running_binary(&exe, b"NEW-GOOD-BINARY", |_| true)
        .expect("replace should succeed when verify passes");

    assert_eq!(std::fs::read(&exe).unwrap(), b"NEW-GOOD-BINARY");
    let stash = stash.expect("a prior binary existed, so a stash is returned");
    // The caller reaps the stash; until then it holds the old bytes.
    assert_eq!(std::fs::read(&stash).unwrap(), b"OLD-WORKING-BINARY");
    API.reap_stale_binaries(&exe);
    assert!(!stash.exists(), "reap must remove the stash");
}

#[test]
fn replace_failure_rolls_back_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    // Arbitrary bytes incl. NULs/high bytes: rollback must be exact.
    let original: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    std::fs::write(&exe, &original).unwrap();

    let err = API
        .replace_running_binary(&exe, b"NEW-BROKEN-BINARY", |_| false)
        .expect_err("replace must fail when verify rejects the new binary");
    assert!(format!("{err}").contains("rolled back"));
    assert_eq!(
        std::fs::read(&exe).unwrap(),
        original,
        "rollback must restore the original binary byte-for-byte"
    );
    // No stash left orphaned beside the exe after a rollback.
    API.reap_stale_binaries(&exe);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("keyhog-old"))
        .collect();
    assert!(leftovers.is_empty(), "rollback must not leave a stash");
}

#[test]
fn fresh_install_failure_removes_broken_binary() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    // No prior binary: a failed verify must not leave a broken executable.
    let err = API
        .replace_running_binary(&exe, b"BROKEN", |_| false)
        .expect_err("fresh install must fail when verify rejects it");
    assert!(format!("{err}").contains("no prior binary"));
    assert!(!exe.exists(), "broken fresh install must be removed");
}

#[test]
fn reap_only_touches_this_binarys_stashes() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"bin").unwrap();
    let mine = dir.path().join(".keyhog.keyhog-old-4294967295");
    let other = dir.path().join("unrelated.txt");
    std::fs::write(&mine, b"old").unwrap();
    std::fs::write(&other, b"keep").unwrap();

    API.reap_stale_binaries(&exe);
    assert!(!mine.exists(), "matching stash must be reaped");
    assert!(other.exists(), "unrelated files must be left alone");
    assert!(exe.exists(), "the live binary must never be reaped");
}

#[test]
#[cfg(unix)]
fn reap_stale_binaries_preserves_live_peer_pid_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"bin").unwrap();

    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("sleep 30")
        .spawn()
        .expect("spawn live peer process");
    let live_pid = child.id();
    let live_stash = dir.path().join(format!(".keyhog.keyhog-old-{live_pid}"));
    let live_backup = dir.path().join(format!(".keyhog.keyhog-bak-{live_pid}"));
    let live_tmp = dir.path().join(format!(".keyhog-update-{live_pid}.tmp"));
    for path in [&live_stash, &live_backup, &live_tmp] {
        std::fs::write(path, b"in-flight").unwrap();
    }

    API.reap_stale_binaries(&exe);

    assert!(live_stash.exists(), "live process stash must not be reaped");
    assert!(
        live_backup.exists(),
        "live process rollback backup must not be reaped"
    );
    assert!(
        live_tmp.exists(),
        "live process staging tmp must not be reaped"
    );

    child.kill().expect("stop live peer process");
    let _ = child.wait();
}

#[test]
fn reap_stale_binaries_requires_parseable_pid_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"bin").unwrap();

    let malformed = [
        dir.path().join(".keyhog.keyhog-old-"),
        dir.path().join(".keyhog.keyhog-bak-not-a-pid"),
        dir.path().join(".keyhog-update-123.tmp.extra"),
    ];
    for path in &malformed {
        std::fs::write(path, b"keep").unwrap();
    }

    API.reap_stale_binaries(&exe);

    for path in &malformed {
        assert!(
            path.exists(),
            "malformed installer artifact name must not be reaped: {}",
            path.display()
        );
    }
}

#[test]
fn reap_stale_binaries_reaps_digit_only_overflow_pid_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"bin").unwrap();

    let overflow_pid = "42949672950000000000000000000000000000000000000000";
    let artifacts = [
        dir.path()
            .join(format!(".keyhog.keyhog-old-{overflow_pid}")),
        dir.path()
            .join(format!(".keyhog.keyhog-bak-{overflow_pid}")),
        dir.path()
            .join(format!(".keyhog-update-{overflow_pid}.tmp")),
    ];
    for path in &artifacts {
        std::fs::write(path, b"stale").unwrap();
    }

    API.reap_stale_binaries(&exe);

    for path in &artifacts {
        assert!(
            !path.exists(),
            "numeric overflow PID installer artifact must be treated as stale: {}",
            path.display()
        );
    }
}

#[test]
fn reap_stale_binaries_does_not_flatten_read_dir_errors() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/installer.rs"))
        .expect("installer source readable");
    assert!(
        !src.contains("entries.flatten()"),
        "installer stale-artifact reap must match read_dir entry errors explicitly"
    );
    assert!(
        src.contains("cannot read installer artifact directory entry"),
        "installer stale-artifact reap must log unreadable directory entries"
    );
    assert!(
        src.contains("fn remove_installer_artifact_best_effort(")
            && src.contains("failed to remove installer artifact; it may need manual cleanup")
            && src.contains("remove_installer_artifact_best_effort(")
            && !src.contains("let _ = std::fs::remove_file"),
        "installer artifact cleanup must be best-effort but visible, not anonymous let-_ remove_file"
    );
    assert!(
        src.contains("fn installer_artifact_pid(")
            && src.contains("fn process_is_running(")
            && src.contains("!process_is_running(pid)")
            && !src.contains("fname.starts_with(stash_prefix.as_str())\n            || fname.starts_with(backup_prefix.as_str())"),
        "installer stale-artifact reap must parse PID suffixes and skip live owners"
    );
}

#[test]
fn rollback_cleanup_failures_are_operator_visible() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/installer.rs"))
        .expect("installer source readable");
    for required in [
        "ROLLBACK FAILED after a failed binary write",
        "It is stranded at",
        "it could NOT be removed from",
        "delete it manually",
    ] {
        assert!(
            src.contains(required),
            "installer rollback/cleanup failure must surface `{required}`"
        );
    }
    assert!(
        !src.contains("installed binary failed its post-install health check: {verify_error}; removed it because no prior \\\n         binary to roll back to)."),
        "installer fresh-install verify failure must not claim a broken binary was removed without checking remove_file"
    );
}

#[test]
fn install_with_rollback_bool_wrapper_has_one_owner() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/installer.rs"))
        .expect("installer source readable");
    let wrapper = "pub(crate) fn install_with_rollback<F>";
    let wrapper_count = src.matches(wrapper).count();
    assert_eq!(
        wrapper_count, 1,
        "install_with_rollback bool compatibility wrapper must have one cfg-neutral owner"
    );
    assert!(
        src.contains("install_with_rollback_checked(exe, bytes, bool_verify_as_result(verify))"),
        "install_with_rollback must delegate through the shared bool-to-Result verifier adapter"
    );
    assert!(
        src.matches("fn bool_verify_as_result<F>").count() == 1
            && src.matches("post-install verifier returned false").count() == 1,
        "boolean verifier compatibility text must live in one adapter, not per-platform wrappers"
    );
}

#[test]
fn current_binary_surfaces_canonicalize_failure() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/installer.rs"))
        .expect("installer source readable");
    assert!(
        src.contains("std::fs::canonicalize(&exe).with_context(||")
            && src.contains("resolve current executable symlink target")
            && !src.contains("std::fs::canonicalize(&exe).unwrap_or(exe)")
            && !src.contains("canonicalize failure => original path"),
        "current_binary must not silently install through a non-canonical symlink path"
    );
}

// Supply-chain: a missing `.minisig` must FAIL CLOSED. A forged 404 on the
// signature URL (active MITM / compromised CDN serving a tampered binary)
// otherwise bypassed the entire minisign gate. Linux-gated because the served
// asset must pass `looks_like_native_executable` (ELF magic) to reach the
// signature-fetch branch; the CI test/integration jobs run on linux.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn unsigned_release_download_fails_closed() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let mut elf = vec![0x7F, b'E', b'L', b'F'];
    elf.extend_from_slice(&[0u8; 64]);
    let asset_path = "/download/keyhog-linux-x86_64";
    let body = elf.clone();
    server.mock(|when, then| {
        when.method(GET).path(asset_path);
        then.status(200).body(body);
    });
    server.mock(|when, then| {
        when.method(GET).path(format!("{asset_path}.minisig"));
        then.status(404).body("Not Found");
    });
    let res = API
        .download_verified_asset(
            &API.http_client().unwrap(),
            "keyhog-linux-x86_64",
            format!("{}{}", server.base_url(), asset_path),
        )
        .await;
    assert!(
        res.is_err(),
        "a missing .minisig must fail closed (refuse), not install on HTTPS-only trust"
    );
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains(".minisig") || msg.to_lowercase().contains("signature"),
        "error must name the missing signature as the reason: {msg}"
    );
}
