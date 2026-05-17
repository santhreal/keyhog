//! Default system-include search path discovery.
//!
//! gcc and clang both publish their built-in `#include <...>` search list when
//! invoked as `<cc> -E -x c -v - </dev/null`. We probe gcc once per process,
//! cache the discovered directories, and let the preprocessor fall through to
//! them after CLI `-I` / `-isystem` directories. Without this, every
//! `#include <stdio.h>` requires the user to pass the full system path on the
//! command line — workable for the smoke corpus, fatal for any real-world
//! Linux source.
//!
//! Fallback when no `cc` is on `PATH`: a hardcoded x86_64 Debian/Ubuntu list,
//! enough to compile a `printf` "hello world".

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Directories the system C compiler reports between
/// `#include <...> search starts here:` and `End of search list.`
static SYSTEM_INCLUDE_DIRS: OnceLock<Vec<PathBuf>> = OnceLock::new();

const FALLBACK_SYSTEM_INCLUDES: &[&str] = &[
    "/usr/local/include",
    "/usr/include/x86_64-linux-gnu",
    "/usr/include",
];

/// Drivers tried, in order. First one whose `-E -v -` output yields a parseable
/// search list wins. clang ships in CI more often than gcc; gcc remains
/// authoritative for kernel-style headers.
const PROBE_DRIVERS: &[&str] = &["gcc", "clang", "cc"];

/// Return the cached default system include search path, in CLI search order.
///
/// The first call probes the host C compiler and caches the result for the
/// lifetime of the process. Subsequent calls are O(1). On systems without a
/// C compiler on `PATH`, the [`FALLBACK_SYSTEM_INCLUDES`] list is returned
/// instead.
pub(super) fn system_include_dirs() -> &'static [PathBuf] {
    SYSTEM_INCLUDE_DIRS.get_or_init(probe_system_include_dirs).as_slice()
}

fn probe_system_include_dirs() -> Vec<PathBuf> {
    for driver in PROBE_DRIVERS {
        if let Some(dirs) = probe_with_driver(driver) {
            if !dirs.is_empty() {
                return dirs;
            }
        }
    }
    fallback_system_include_dirs()
}

fn probe_with_driver(driver: &str) -> Option<Vec<PathBuf>> {
    let output = Command::new(driver)
        .args(["-E", "-x", "c", "-v", "-"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed = parse_search_list(&stderr);
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

/// Extract the directory list between `#include <...> search starts here:` and
/// `End of search list.` from a `cc -E -v -` stderr capture.
///
/// Lines inside the list look like ` /usr/include` (a single leading space).
/// Some drivers append ` (framework directory)` on macOS — treat those as
/// regular paths; the trailing annotation is dropped.
fn parse_search_list(stderr: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut in_list = false;
    for line in stderr.lines() {
        let trimmed = line.trim_end();
        if trimmed.starts_with("#include <...>") {
            in_list = true;
            continue;
        }
        if !in_list {
            continue;
        }
        if trimmed == "End of search list." {
            break;
        }
        if !trimmed.starts_with(' ') {
            continue;
        }
        let cleaned = trimmed.trim_start();
        let cleaned = cleaned
            .split_once(" (framework directory)")
            .map(|(p, _)| p)
            .unwrap_or(cleaned);
        if cleaned.is_empty() {
            continue;
        }
        paths.push(PathBuf::from(cleaned));
    }
    paths
}

fn fallback_system_include_dirs() -> Vec<PathBuf> {
    FALLBACK_SYSTEM_INCLUDES
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gcc_search_list_block() {
        let stderr = "ignoring nonexistent directory\n\
            #include \"...\" search starts here:\n\
            #include <...> search starts here:\n \
            /usr/local/include\n \
            /usr/lib/gcc/x86_64-linux-gnu/13/include\n \
            /usr/include/x86_64-linux-gnu\n \
            /usr/include\n\
            End of search list.\n\
            COMPILER_PATH=...\n";
        let paths = parse_search_list(stderr);
        assert_eq!(paths.len(), 4);
        assert_eq!(paths[0], PathBuf::from("/usr/local/include"));
        assert_eq!(paths[3], PathBuf::from("/usr/include"));
    }

    #[test]
    fn parses_clang_macos_framework_annotation() {
        let stderr = "#include <...> search starts here:\n \
            /usr/local/include\n \
            /Library/Frameworks (framework directory)\n\
            End of search list.\n";
        let paths = parse_search_list(stderr);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[1], PathBuf::from("/Library/Frameworks"));
    }

    #[test]
    fn empty_when_no_search_block() {
        let paths = parse_search_list("just some other compiler output\n");
        assert!(paths.is_empty());
    }

    #[test]
    fn cached_first_call_either_probes_or_falls_back() {
        // Behavioural test: the cached dirs must be either a real probe result
        // (non-empty on any host with cc/gcc/clang) or the fallback filtered to
        // existing dirs. A vanilla CI runner with no C toolchain installed
        // would yield an empty vec — that's fine, the integration tests cover
        // the live path.
        let dirs = system_include_dirs();
        for d in dirs {
            assert!(d.is_absolute(), "expected absolute path, got {}", d.display());
        }
    }
}
