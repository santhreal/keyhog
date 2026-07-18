use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(serde::Deserialize)]
struct ConfigKeywords {
    known_prefixes: Vec<String>,
    secret_keywords: Vec<String>,
    test_keywords: Vec<String>,
    placeholder_keywords: Vec<String>,
}

#[derive(serde::Deserialize)]
struct DecoderNames {
    decoder_names: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|error| io::Error::other(format!("CARGO_MANIFEST_DIR is not set: {error}")))?;
    let out_dir = env::var("OUT_DIR")
        .map_err(|error| io::Error::other(format!("OUT_DIR is not set: {error}")))?;
    let output_path = Path::new(&out_dir).join("embedded_detectors.rs");

    // Build provenance: pin "what is benched" to a commit. The v32 F1=0.8896
    // vs HEAD F1=0.801 comparison was unverifiable because both binaries
    // reported the same `v0.5.37` and the result JSONs carried an empty
    // version - so a regression could not be bisected. Stamping the git SHA
    // into the binary makes every future scan trace back to an exact commit
    // and lets the bench fail-closed when it scores a stale build.
    stamp_git_hash(Path::new(&manifest_dir));

    let manifest_dir = Path::new(&manifest_dir);
    let mut candidates = vec![manifest_dir.join("detectors")];
    if let Some(workspace_root) = manifest_dir.parent().and_then(|p| p.parent()) {
        candidates.push(workspace_root.join("detectors"));
    }

    let detectors_dir = candidates
        .iter()
        .find(|path| path.exists() && path.is_dir());
    let Some(detectors_dir) = detectors_dir else {
        let searched = candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "detectors/ directory not found; searched: {searched}. Fix: build from the keyhog workspace, keep crates/core/detectors pointed at ../../detectors, or package the detector TOMLs with keyhog-core"
            ),
        )
        .into());
    };

    let toml_paths = detector_toml_paths(detectors_dir)?;
    if toml_paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "detectors directory '{}' contains no .toml files. Fix: add detector TOML files or remove the empty directory",
                detectors_dir.display()
            ),
        )
        .into());
    }
    let entries = read_detector_entries(&toml_paths)?;
    let config_keywords = read_toml::<ConfigKeywords>(
        &manifest_dir.join("rules/config-keywords.toml"),
        "Tier-B config keyword defaults",
    )?;
    validate_nonempty_unique("known_prefixes", &config_keywords.known_prefixes)?;
    validate_nonempty_unique("secret_keywords", &config_keywords.secret_keywords)?;
    validate_nonempty_unique("test_keywords", &config_keywords.test_keywords)?;
    validate_nonempty_unique(
        "placeholder_keywords",
        &config_keywords.placeholder_keywords,
    )?;
    let decoder_names = read_toml::<DecoderNames>(
        &manifest_dir.join("rules/decoder-source-suffixes.toml"),
        "Tier-B decoder source suffixes",
    )?;
    validate_nonempty_unique("decoder_names", &decoder_names.decoder_names)?;

    // Build provenance: stamp the digest of the EXACT detector set that is
    // about to be baked into the binary. The CLI surfaces this so the
    // benchmark can assert the running binary's embedded detectors match the
    // on-disk `detectors/` tree (cargo's `rerun-if-changed` cannot be trusted
    // across in-place TOML edits, so a fresh-from-this-build digest is the
    // authoritative answer to "what got compiled in"). Self-contained FNV-1a
    // (no build-dependency on a hashing crate), it identifies the set, it is
    // not a security primitive.
    let detector_digest = detector_set_digest(&entries);
    println!("cargo:rustc-env=KEYHOG_DETECTOR_DIGEST={detector_digest}");

    write_embedded_data(
        &output_path,
        &entries,
        &config_keywords,
        &decoder_names.decoder_names,
    )?;

    // Re-run when the directory contents change (file add/remove).
    println!("cargo:rerun-if-changed={}", detectors_dir.display());
    // Cargo'"'"'s `rerun-if-changed=<dir>` only watches the directory'"'"'s own
    // mtime - which most filesystems do NOT bump when a file INSIDE the
    // directory is modified in-place. Without per-file watchers, editing
    // an existing detector TOML would leave a stale `embedded_detectors.rs`
    // baked into the binary until `cargo clean`. Emit one
    // `rerun-if-changed` line per .toml so any individual edit triggers
    // a rebuild.
    for path in &toml_paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("rules/config-keywords.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir
            .join("rules/decoder-source-suffixes.toml")
            .display()
    );
    println!(
        "cargo:warning=Embedded {} detectors ({} bytes)",
        entries.len(),
        entries
            .iter()
            .map(|(_, content)| content.len())
            .sum::<usize>()
    );
    Ok(())
}

/// Sorted `.toml` paths in `detectors_dir`: the single directory walk both
/// the embedded table and the per-file `rerun-if-changed` lines derive from.
/// Sorting by path equals sorting by file name (shared parent), so the
/// embedded detector order is stable across platforms.
fn detector_toml_paths(detectors_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let read_dir = fs::read_dir(detectors_dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read detectors directory '{}': {}. Fix: check directory permissions",
                detectors_dir.display(),
                error
            ),
        )
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to enumerate detectors in '{}': {}. Fix: check directory permissions",
                    detectors_dir.display(),
                    error
                ),
            )
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_detector_entries(toml_paths: &[PathBuf]) -> io::Result<Vec<(String, String)>> {
    let mut entries = Vec::with_capacity(toml_paths.len());
    for path in toml_paths {
        let name = file_name(path)?;
        let content = fs::read_to_string(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to read detector '{}': {}. Fix: check file permissions and TOML encoding",
                    path.display(),
                    error
                ),
            )
        })?;
        entries.push((name, content));
    }
    Ok(entries)
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> io::Result<T> {
    let raw = fs::read_to_string(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to read {label} '{}': {error}", path.display()),
        )
    })?;
    toml::from_str(&raw).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {label} '{}': {error}", path.display()),
        )
    })
}

fn validate_nonempty_unique(label: &str, values: &[String]) -> io::Result<()> {
    if values.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} must not be empty"),
        ));
    }
    if let Some(value) = values.iter().find(|value| value.trim().is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} contains an empty or whitespace-only value {value:?}"),
        ));
    }
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    if let Some(duplicate) = values.iter().find(|value| !seen.insert(value.as_str())) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} contains duplicate value {duplicate:?}"),
        ));
    }
    Ok(())
}

fn write_string_slice(code: &mut String, name: &str, values: &[String]) {
    code.push_str(&format!("pub const {name}: &[&str] = &[\n"));
    for value in values {
        code.push_str(&format!("    {value:?},\n"));
    }
    code.push_str("];\n");
}

fn write_embedded_data(
    output_path: &Path,
    entries: &[(String, String)],
    config_keywords: &ConfigKeywords,
    decoder_names: &[String],
) -> io::Result<()> {
    let mut code = String::from("pub const EMBEDDED_DETECTORS: &[(&str, &str)] = &[\n");
    for (name, content) in entries {
        code.push_str(&format!("    ({name:?}, {content:?}),\n"));
    }
    code.push_str("];\n");
    write_string_slice(
        &mut code,
        "CONFIG_KNOWN_PREFIXES",
        &config_keywords.known_prefixes,
    );
    write_string_slice(
        &mut code,
        "CONFIG_SECRET_KEYWORDS",
        &config_keywords.secret_keywords,
    );
    write_string_slice(
        &mut code,
        "CONFIG_TEST_KEYWORDS",
        &config_keywords.test_keywords,
    );
    write_string_slice(
        &mut code,
        "CONFIG_PLACEHOLDER_KEYWORDS",
        &config_keywords.placeholder_keywords,
    );
    let decoder_suffixes = decoder_names
        .iter()
        .map(|name| format!("/{name}"))
        .collect::<Vec<_>>();
    write_string_slice(&mut code, "DECODER_SOURCE_SUFFIXES", &decoder_suffixes);
    fs::write(output_path, code).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to write generated detector table '{}': {}. Fix: verify OUT_DIR is writable",
                output_path.display(),
                error
            ),
        )
    })
}

/// Resolve the current git commit and emit it as `cargo:rustc-env=GIT_HASH`,
/// registering `rerun-if-changed` on the files that hold the SHA so a new
/// commit re-stamps the binary.
///
/// Failure is non-fatal: a `cargo package` / crates.io build has no `.git`
/// tree, and a worktree may be checked out without `git` on PATH. In those
/// cases we stamp the sentinel `unknown` rather than abort the build - the
/// detector digest and version still ship, and the CLI prints `unknown` for
/// the SHA. `CARGO_MANIFEST_DIR` is `crates/core`, so the workspace `.git`
/// lives two directories up.
fn stamp_git_hash(manifest_dir: &Path) {
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(manifest_dir);
    let git_dir = workspace_root.join(".git");

    // Re-run when HEAD moves (checkout / new commit on the same branch). HEAD
    // is usually `ref: refs/heads/<branch>`, so the branch ref file holds the
    // SHA that actually changes per commit - watch both. `.git/packed-refs`
    // covers a freshly cloned tree whose loose ref has been packed away.
    let head_file = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_file.display());
    if let Some(ref_path) = head_ref_path(&git_dir) {
        println!("cargo:rerun-if-changed={}", ref_path.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        git_dir.join("packed-refs").display()
    );

    let hash = git_hash(workspace_root).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={hash}");
}

/// Path to the ref file referenced by `.git/HEAD` (e.g.
/// `.git/refs/heads/main`), or `None` when HEAD is detached or unreadable.
fn head_ref_path(git_dir: &Path) -> Option<PathBuf> {
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let reference = head.trim().strip_prefix("ref:")?.trim();
    Some(git_dir.join(reference))
}

/// `git rev-parse HEAD`, trimmed. `None` if git is absent or the command
/// fails (no repo, shallow placeholder, etc.).
fn git_hash(workspace_root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?;
    let hash = hash.trim();
    if hash.is_empty() {
        None
    } else {
        Some(hash.to_string())
    }
}

/// Digest of the exact embedded detector set (sorted `(name, content)` pairs),
/// as a stable lowercase-hex string. FNV-1a 64-bit over name+content of every
/// entry, mirroring the scanner build script's `model_version` hash so both
/// build scripts speak the same self-contained, build-dependency-free dialect.
/// This identifies "which detectors got compiled in"; it is not a tamper seal.
fn detector_set_digest(entries: &[(String, String)]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for (name, content) in entries {
        mix(name.as_bytes());
        // NUL separator so ("ab","c") and ("a","bc") cannot collide.
        mix(&[0]);
        mix(content.as_bytes());
        mix(&[0]);
    }
    format!("{}-{hash:016x}", entries.len())
}

fn file_name(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "detector path '{}' does not have a valid UTF-8 file name. Fix: rename the detector file",
                    path.display()
                ),
            )
        })
}
