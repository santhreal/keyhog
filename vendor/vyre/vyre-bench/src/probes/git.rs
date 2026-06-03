use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn capture_git_info() -> BTreeMap<String, String> {
    capture_git_info_at(Path::new("."))
}

pub fn capture_git_info_at(workspace_root: &Path) -> BTreeMap<String, String> {
    let mut info = BTreeMap::new();

    if let Ok(commit) = shell(workspace_root, &["rev-parse", "HEAD"]) {
        info.insert("commit".to_string(), commit);
    }
    if let Ok(branch) = shell(workspace_root, &["rev-parse", "--abbrev-ref", "HEAD"]) {
        info.insert("branch".to_string(), branch);
    }
    let dirty_status = shell_bytes(
        workspace_root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    );
    let dirty = match dirty_status.as_ref() {
        Ok(status) if status.is_empty() => "false",
        Ok(status) => {
            if let Some(fingerprint) = dirty_worktree_fingerprint(workspace_root, status) {
                info.insert("dirty_worktree_fingerprint".to_string(), fingerprint);
            }
            "true"
        }
        Err(_) => "unknown",
    };
    info.insert("dirty".to_string(), dirty.to_string());

    if let Ok(parent) = shell(workspace_root, &["rev-parse", "HEAD^"]) {
        info.insert("parent_commit".to_string(), parent);
    }
    if let Ok(timestamp) = shell(workspace_root, &["log", "-1", "--format=%ct"]) {
        info.insert("commit_timestamp".to_string(), timestamp);
    }

    info
}

pub fn source_fingerprint(git: &BTreeMap<String, String>) -> String {
    if let Some(commit) = git.get("commit").filter(|commit| !commit.is_empty()) {
        let dirty = git.get("dirty").map(String::as_str).unwrap_or("unknown");
        if dirty == "true" {
            let worktree = git
                .get("dirty_worktree_fingerprint")
                .filter(|fingerprint| !fingerprint.is_empty())
                .map(String::as_str)
                .unwrap_or("unknown");
            return format!("git:{commit}:dirty=true:worktree={worktree}");
        }
        return format!("git:{commit}:dirty={dirty}");
    }
    format!(
        "crate:{}:{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}

pub fn source_tree_fingerprint() -> String {
    source_tree_fingerprint_at(Path::new("."))
}

pub fn source_tree_fingerprint_at(workspace_root: &Path) -> String {
    match shell_bytes(
        workspace_root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    ) {
        Ok(paths) => format!(
            "source-tree-v1:{}",
            source_tree_fingerprint_from_paths(workspace_root, &paths)
        ),
        Err(_) => format!(
            "crate-source:{}:{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ),
    }
}

fn source_tree_fingerprint_from_paths(workspace_root: &Path, paths: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_field(&mut hasher, b"format", b"vyre-bench-source-tree-v1");
    for path in paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .filter(|path| !source_tree_path_is_generated_evidence(path))
    {
        update_hash_field(&mut hasher, b"path", path);
        let path = String::from_utf8_lossy(path);
        match fs::read(workspace_root.join(path.as_ref())) {
            Ok(bytes) => update_hash_field(&mut hasher, b"content", &bytes),
            Err(error) => {
                update_hash_field(&mut hasher, b"read-error", error.to_string().as_bytes())
            }
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn source_tree_path_is_generated_evidence(path: &[u8]) -> bool {
    path.starts_with(b"release/evidence/")
}

fn dirty_worktree_fingerprint(workspace_root: &Path, status: &[u8]) -> Option<String> {
    let diff = shell_bytes(workspace_root, &["diff", "--binary", "HEAD", "--"]).ok()?;
    let untracked = shell_bytes(
        workspace_root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )
    .unwrap_or_default();
    Some(dirty_worktree_fingerprint_from_parts(
        workspace_root,
        status,
        &diff,
        &untracked,
    ))
}

fn dirty_worktree_fingerprint_from_parts(
    workspace_root: &Path,
    status: &[u8],
    diff: &[u8],
    untracked: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_field(&mut hasher, b"format", b"vyre-bench-dirty-source-v1");
    update_hash_field(&mut hasher, b"status", status);
    update_hash_field(&mut hasher, b"diff", diff);
    for path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        update_hash_field(&mut hasher, b"untracked-path", path);
        let path = String::from_utf8_lossy(path);
        if let Ok(bytes) = fs::read(workspace_root.join(path.as_ref())) {
            update_hash_field(&mut hasher, b"untracked-content", &bytes);
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn update_hash_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn shell(workspace_root: &Path, args: &[&str]) -> Result<String, String> {
    let stdout = shell_bytes(workspace_root, args)?;
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

fn shell_bytes(workspace_root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_source_fingerprint_keeps_commit_dirty_contract() {
        let git = BTreeMap::from([
            ("commit".to_string(), "abc123".to_string()),
            ("dirty".to_string(), "false".to_string()),
        ]);

        assert_eq!(
            source_fingerprint(&git),
            "git:abc123:dirty=false",
            "Fix: clean source fingerprints must remain stable for existing release evidence contracts."
        );
    }

    #[test]
    fn dirty_source_fingerprint_carries_worktree_digest() {
        let git = BTreeMap::from([
            ("commit".to_string(), "abc123".to_string()),
            ("dirty".to_string(), "true".to_string()),
            (
                "dirty_worktree_fingerprint".to_string(),
                "worktree-hash".to_string(),
            ),
        ]);

        assert_eq!(
            source_fingerprint(&git),
            "git:abc123:dirty=true:worktree=worktree-hash",
            "Fix: dirty source fingerprints must distinguish different dirty worktree states."
        );
    }

    #[test]
    fn dirty_source_fingerprint_without_digest_fails_closed() {
        let git = BTreeMap::from([
            ("commit".to_string(), "abc123".to_string()),
            ("dirty".to_string(), "true".to_string()),
        ]);

        assert_eq!(
            source_fingerprint(&git),
            "git:abc123:dirty=true:worktree=unknown",
            "Fix: dirty source fingerprints must not fall back to the broad legacy dirty=true contract."
        );
    }

    #[test]
    fn dirty_worktree_digest_changes_with_status_diff_and_untracked_content() {
        let workspace = Path::new(".");
        let base =
            dirty_worktree_fingerprint_from_parts(workspace, b" M a.rs\0", b"-old\n+new\n", b"");
        let changed_status =
            dirty_worktree_fingerprint_from_parts(workspace, b" M b.rs\0", b"-old\n+new\n", b"");
        let changed_diff =
            dirty_worktree_fingerprint_from_parts(workspace, b" M a.rs\0", b"-old\n+newer\n", b"");
        let changed_untracked_inventory =
            dirty_worktree_fingerprint_from_parts(workspace, b"?? c.rs\0", b"", b"c.rs\0");
        let untracked_workspace = std::env::temp_dir().join(format!(
            "vyre-bench-dirty-fingerprint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Fix: system clock must support unix epoch duration for temp test id.")
                .as_nanos()
        ));
        fs::create_dir_all(&untracked_workspace)
            .expect("Fix: create temporary workspace for untracked content fingerprint test.");
        fs::write(untracked_workspace.join("c.rs"), b"one")
            .expect("Fix: write first untracked content fingerprint fixture.");
        let untracked_one = dirty_worktree_fingerprint_from_parts(
            &untracked_workspace,
            b"?? c.rs\0",
            b"",
            b"c.rs\0",
        );
        fs::write(untracked_workspace.join("c.rs"), b"two")
            .expect("Fix: write second untracked content fingerprint fixture.");
        let untracked_two = dirty_worktree_fingerprint_from_parts(
            &untracked_workspace,
            b"?? c.rs\0",
            b"",
            b"c.rs\0",
        );
        let _ = fs::remove_dir_all(&untracked_workspace);

        assert_ne!(
            base, changed_status,
            "Fix: dirty source fingerprints must change when modified paths change."
        );
        assert_ne!(
            base, changed_diff,
            "Fix: dirty source fingerprints must change when tracked diff bytes change."
        );
        assert_ne!(
            base, changed_untracked_inventory,
            "Fix: dirty source fingerprints must change when untracked inventory changes."
        );
        assert_ne!(
            untracked_one, untracked_two,
            "Fix: dirty source fingerprints must change when untracked file content changes."
        );
    }

    #[test]
    fn source_tree_fingerprint_ignores_generated_release_evidence() {
        let workspace = std::env::temp_dir().join(format!(
            "vyre-bench-source-tree-fingerprint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Fix: system clock must support unix epoch duration for temp test id.")
                .as_nanos()
        ));
        fs::create_dir_all(workspace.join("src")).expect("Fix: create source fixture directory.");
        fs::create_dir_all(workspace.join("release/evidence/benchmarks"))
            .expect("Fix: create generated evidence fixture directory.");
        fs::write(workspace.join("src/lib.rs"), b"pub fn source() {}\n")
            .expect("Fix: write source-tree fingerprint source fixture.");
        fs::write(
            workspace.join("release/evidence/benchmarks/workload.json"),
            b"{\"old\":true}\n",
        )
        .expect("Fix: write source-tree fingerprint evidence fixture.");
        let paths = b"src/lib.rs\0release/evidence/benchmarks/workload.json\0";

        let base = source_tree_fingerprint_from_paths(&workspace, paths);
        fs::write(
            workspace.join("release/evidence/benchmarks/workload.json"),
            b"{\"new\":true}\n",
        )
        .expect("Fix: mutate generated evidence fixture.");
        let evidence_changed = source_tree_fingerprint_from_paths(&workspace, paths);
        fs::write(
            workspace.join("src/lib.rs"),
            b"pub fn source_changed() {}\n",
        )
        .expect("Fix: mutate source fixture.");
        let source_changed = source_tree_fingerprint_from_paths(&workspace, paths);
        let _ = fs::remove_dir_all(&workspace);

        assert_eq!(
            base, evidence_changed,
            "Fix: generated release evidence must not invalidate committed benchmark source provenance."
        );
        assert_ne!(
            base, source_changed,
            "Fix: source-tree provenance must still change when real source files change."
        );
    }
}
