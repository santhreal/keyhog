use keyhog::testing::{CliTestApi as _, API};

/// WHY: releases publish crates.io packages only. If release.yml ever grows an
/// asset-upload step again, or the docs start promising a binary download, the
/// install story splits in two and users follow the half that does not exist.
/// `scripts/gates/release_channel_coherence.py` closes the same class from the
/// consumer side; this pins the producer side and the prose.
#[test]
fn installer_words_match_crates_only_release_contract() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let release_yml =
        std::fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release.yml");
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let install_doc = std::fs::read_to_string(root.join("docs/src/install.md"))
        .expect("docs/src/install.md readable");

    assert!(
        release_yml.contains("bash scripts/publish.sh")
            && release_yml.contains("CARGO_REGISTRY_TOKEN")
            && !release_yml.contains("asset:")
            && !release_yml.contains("upload-release-asset")
            && !release_yml.contains("gh release upload"),
        "automatic releases must publish crates.io packages without claiming binary assets"
    );
    assert!(
        readme.contains("cargo install --locked keyhog")
            && install_doc.contains("cargo install --locked --force keyhog")
            && install_doc
                .contains("cargo install --locked --force --version '=MAJOR.MINOR.PATCH' keyhog")
            && install_doc.contains("does\nnot publish binary release assets or installer bundles")
            && !readme.contains("macOS release assets")
            && !readme.contains("Windows assets")
            && !install_doc.contains("macOS assets")
            && !install_doc.contains("Windows assets"),
        "README and install guide must describe crates.io install, update, and rollback truthfully"
    );
}

/// WHY: `keyhog doctor` reports install health from this probe. If it stops
/// firing end to end, doctor reports a healthy scan engine on a host where
/// detection is broken.
#[test]
fn self_test_detects_planted_secret() {
    assert!(API.scan_engine_self_test().expect("self-test runs"));
}
