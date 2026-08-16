use std::path::Path;
use std::process::Command;

#[test]
fn embedded_git_hash_matches_checkout_head() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .expect("core manifest must be nested under the workspace root");
    if !workspace.join(".git").exists() {
        return;
    }

    let expected = if let Ok(sha) = std::env::var("KEYHOG_GIT_HASH") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            Some(sha)
        } else {
            None
        }
    } else if let Ok(sha) = std::env::var("GITHUB_SHA") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            Some(sha)
        } else {
            None
        }
    } else {
        None
    };

    let head = match expected {
        Some(sha) => sha,
        None => {
            let output = Command::new("git")
                .args([
                    "-C",
                    workspace.to_str().expect("workspace path is UTF-8"),
                    "rev-parse",
                    "HEAD",
                ])
                .output()
                .expect("git must be available in a source-checkout test");
            assert!(output.status.success(), "git rev-parse HEAD must succeed");
            String::from_utf8(output.stdout).expect("git HEAD is UTF-8")
        }
    };
    assert_eq!(
        keyhog_core::git_hash(),
        head.trim(),
        "the embedded build provenance must match the checkout used by this test"
    );
}
