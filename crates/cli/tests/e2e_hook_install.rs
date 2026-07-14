//! End-to-end tests for the canonical `keyhog hook install` and `uninstall`
//! surface.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn repository() -> TempDir {
    let dir = TempDir::new().expect("create temporary repository");
    let output = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(dir.path())
        .output()
        .expect("initialize git repository");
    assert!(
        output.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    dir
}

fn run_hook(dir: &TempDir, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .arg("hook")
        .args(args)
        .current_dir(dir.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run keyhog hook command")
}

#[test]
fn hook_install_is_executable_and_idempotent() {
    let dir = repository();
    let hook_path = dir.path().join(".git/hooks/pre-commit");

    let first = run_hook(&dir, &["install"]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "install failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let installed = std::fs::read(&hook_path).expect("read installed hook");
    let installed_text = String::from_utf8_lossy(&installed);
    assert!(
        installed_text.contains("exec keyhog scan --fast --git-staged --backend cpu"),
        "installed hook must execute the canonical staged scan: {installed_text}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            std::fs::metadata(&hook_path)
                .expect("read installed hook metadata")
                .permissions()
                .mode()
                & 0o111,
            0,
            "installed hook must be executable"
        );
    }

    let second = run_hook(&dir, &["install"]);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(
        std::fs::read(&hook_path).expect("reread installed hook"),
        installed,
        "idempotent install must preserve the managed hook bytes"
    );
}

#[test]
fn hook_install_preserves_an_unmanaged_hook_unless_forced() {
    let dir = repository();
    let hook_path = dir.path().join(".git/hooks/pre-commit");
    std::fs::create_dir_all(hook_path.parent().expect("hook parent")).expect("create hooks dir");
    let original = b"#!/bin/sh\necho existing-hook\n";
    std::fs::write(&hook_path, original).expect("write unmanaged hook");

    let refused = run_hook(&dir, &["install"]);
    assert_ne!(refused.status.code(), Some(0));
    assert_eq!(
        std::fs::read(&hook_path).expect("read preserved unmanaged hook"),
        original,
        "ordinary install must not overwrite an unmanaged hook"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--force"),
        "refusal must name the explicit replacement control"
    );

    let forced = run_hook(&dir, &["install", "--force"]);
    assert_eq!(
        forced.status.code(),
        Some(0),
        "forced install failed: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(
        String::from_utf8_lossy(&std::fs::read(&hook_path).expect("read replaced hook"))
            .contains("KeyHog pre-commit hook"),
        "forced install must replace the unmanaged hook with the managed hook"
    );
}

#[test]
fn hook_uninstall_removes_only_the_managed_hook() {
    let dir = repository();
    let hook_path = dir.path().join(".git/hooks/pre-commit");
    assert_eq!(run_hook(&dir, &["install"]).status.code(), Some(0));

    let removed = run_hook(&dir, &["uninstall"]);
    assert_eq!(
        removed.status.code(),
        Some(0),
        "uninstall failed: {}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(
        !hook_path.exists(),
        "uninstall must remove the managed hook"
    );
    assert_eq!(
        run_hook(&dir, &["uninstall"]).status.code(),
        Some(0),
        "repeated uninstall must be idempotent"
    );

    std::fs::write(&hook_path, "#!/bin/sh\necho unmanaged\n").expect("write unmanaged hook");
    let refused = run_hook(&dir, &["uninstall"]);
    assert_ne!(refused.status.code(), Some(0));
    assert!(
        hook_path.exists(),
        "uninstall must preserve an unmanaged hook"
    );
}

#[test]
fn staged_hook_scope_differs_from_a_full_working_tree_scan() {
    let dir = repository();
    std::fs::write(dir.path().join("tracked.txt"), "ordinary tracked content\n")
        .expect("write tracked file");
    let added = Command::new("git")
        .args(["add", "tracked.txt"])
        .current_dir(dir.path())
        .output()
        .expect("stage tracked file");
    assert!(added.status.success(), "git add must succeed");
    std::fs::write(dir.path().join("untracked.txt"), "token = demo_ABCDEFGH\n")
        .expect("write untracked secret");

    let detectors = TempDir::new().expect("create detector directory");
    std::fs::write(
        detectors.path().join("demo.toml"),
        r#"[detector]
id = "demo-token"
name = "Demo token"
service = "demo"
severity = "high"
keywords = ["demo_"]
min_confidence = 0.0

[[detector.patterns]]
regex = '(?-i)demo_[A-Z0-9]{8}'
"#,
    )
    .expect("write detector");
    let detector_path = detectors.path().to_string_lossy().to_string();

    let staged = Command::new(binary())
        .args([
            "scan",
            "--fast",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--detectors",
            &detector_path,
            "--git-staged",
        ])
        .current_dir(dir.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run staged scan");
    assert_eq!(
        staged.status.code(),
        Some(0),
        "staged scan must ignore the untracked secret: {}",
        String::from_utf8_lossy(&staged.stderr)
    );

    let full = Command::new(binary())
        .args([
            "scan",
            "--fast",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--detectors",
            &detector_path,
            ".",
        ])
        .current_dir(dir.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run full working-tree scan");
    assert_eq!(
        full.status.code(),
        Some(1),
        "full scan must find the untracked secret: {}",
        String::from_utf8_lossy(&full.stderr)
    );
    assert!(
        String::from_utf8_lossy(&full.stdout).contains("demo-token"),
        "full scan must identify the custom detector"
    );
}
