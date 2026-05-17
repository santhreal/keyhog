use std::collections::BTreeMap;
use std::process::Command;

pub fn capture_git_info() -> BTreeMap<String, String> {
    let mut info = BTreeMap::new();

    if let Ok(commit) = shell("git rev-parse HEAD") {
        info.insert("commit".to_string(), commit);
    }
    if let Ok(branch) = shell("git rev-parse --abbrev-ref HEAD") {
        info.insert("branch".to_string(), branch);
    }
    let dirty = match shell("git status --porcelain") {
        Ok(status) if status.is_empty() => "false",
        Ok(_) => "true",
        Err(_) => "unknown",
    };
    info.insert("dirty".to_string(), dirty.to_string());

    if let Ok(parent) = shell("git rev-parse HEAD^") {
        info.insert("parent_commit".to_string(), parent);
    }
    if let Ok(timestamp) = shell("git log -1 --format=%ct") {
        info.insert("commit_timestamp".to_string(), timestamp);
    }

    info
}

pub fn source_fingerprint(git: &BTreeMap<String, String>) -> String {
    if let Some(commit) = git.get("commit").filter(|commit| !commit.is_empty()) {
        let dirty = git.get("dirty").map(String::as_str).unwrap_or("unknown");
        return format!("git:{commit}:dirty={dirty}");
    }
    format!(
        "crate:{}:{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}

fn shell(cmd: &str) -> Result<String, String> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".to_string());
    }
    let output = Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}
