//! Git-LFS pointer recognition.
//!
//! A file tracked by [Git LFS](https://git-lfs.github.com) is committed not as
//! its real bytes but as a tiny text *pointer*, the actual blob lives in LFS
//! storage and is only materialised on `git lfs pull`. A canonical pointer is:
//!
//! ```text
//! version https://git-lfs.github.com/spec/v1
//! oid sha256:<64 lowercase hex>
//! size <decimal bytes>
//! ```
//!
//! The spec fixes the `version` line first and then lists the remaining keys in
//! alphabetical order, so `oid` always precedes `size`; optional `ext-*` lines
//! may appear between `version` and `oid`.
//!
//! Two consumers share this recognition, which is why it lives in `core`:
//!   * the scanner suppresses the pointer's 64-hex `oid` (it is a content hash,
//!     not a leaked secret, yet matches a generic high-entropy hex shape), and
//!   * a source records a coverage gap, the pointer's real blob (`size` bytes)
//!     was NOT scanned, so a repo of unmaterialised LFS pointers is not
//!     reported as a false-clean.
//!
//! Recognition is deliberately strict (all three well-formed lines, in order):
//! a false positive would suppress a real credential, and a whole-file pointer
//! is unambiguous, so strictness costs no recall.

/// The exact first line of every Git-LFS pointer. Compared case-insensitively
/// because the recognition is content-classification, not byte-exact parsing.
pub const GIT_LFS_VERSION_LINE: &str = "version https://git-lfs.github.com/spec/v1";

/// The number of hex characters in a `sha256` object id.
///
/// Canonical owner for the whole `keyhog-core` crate: a `sha256` digest is 32
/// bytes, i.e. 64 lowercase hex characters, whether it names a Git-LFS blob
/// (here) or a compiled-pattern cache file (`hardening.rs`).
pub const SHA256_HEX_LEN: usize = 64;

/// True if `line` (ignoring surrounding ASCII whitespace) is the Git-LFS
/// `version` line.
pub fn is_git_lfs_version_line(line: &[u8]) -> bool {
    line.trim_ascii()
        .eq_ignore_ascii_case(GIT_LFS_VERSION_LINE.as_bytes())
}

/// True if `line` is a Git-LFS `oid sha256:<64 hex>` line. The 64-hex body is
/// what the scanner must NOT flag as a secret.
pub fn is_git_lfs_oid_line(line: &[u8]) -> bool {
    let Some(rest) = line.trim_ascii().strip_prefix(b"oid sha256:") else {
        return false;
    };
    rest.len() == SHA256_HEX_LEN && rest.iter().all(u8::is_ascii_hexdigit)
}

/// True if `line` is a Git-LFS `size <decimal>` line.
pub fn is_git_lfs_size_line(line: &[u8]) -> bool {
    let Some(rest) = line.trim_ascii().strip_prefix(b"size ") else {
        return false;
    };
    !rest.is_empty() && rest.iter().all(u8::is_ascii_digit)
}

/// True if `content` is a whole Git-LFS pointer file: a `version` line, then an
/// `oid` line, then a `size` line, in that spec-mandated order. Lines that are
/// none of the three (e.g. optional `ext-*` lines, or blank lines) are tolerated
/// between the anchors, matching real pointers.
///
/// Cheap: an O(n) single pass over the (tiny, &lt;200 byte) pointer, and callers
/// that scan large files should gate on the size/prefix first, a real pointer
/// begins with [`GIT_LFS_VERSION_LINE`].
pub fn is_git_lfs_pointer(content: &[u8]) -> bool {
    let mut has_version = false;
    let mut has_oid = false;
    for line in content.split(|&b| b == b'\n' || b == b'\r') {
        if !has_version {
            has_version = is_git_lfs_version_line(line);
            continue;
        }
        if !has_oid {
            has_oid = is_git_lfs_oid_line(line);
            continue;
        }
        if is_git_lfs_size_line(line) {
            return true;
        }
    }
    false
}

// Tests live in `tests/unit/git_lfs_sha256_hex_len_owner.rs` (KH-GAP-004: no
// inline test modules in `src/`).
