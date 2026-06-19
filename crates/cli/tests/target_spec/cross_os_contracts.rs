//! CROSS-OS contracts — derived from a real cross-OS dogfood, not from a guess.
//!
//! These were produced by building and driving the real `keyhog` binary on
//! every reachable fleet host over SSH (work-linux hub + the boxes in
//! `~/.ssh/config`):
//!
//!   * tt-macbook   (Darwin 25.x, arm64, macOS 26.3) — REACHED. Built
//!     `--no-default-features --features portable` (release-fast, 1m10s, rc 0),
//!     then ran the full operator path: `keyhog doctor` (exit 0), seeded scan
//!     (exit 1, `aws-access-key` detector fired), clean scan (exit 0), SARIF
//!     2.1.0 with 1 result, `--git-history` on a non-repo (exit 13, fail-closed),
//!     `uninstall` dry-run (exit 0) and `uninstall --yes` (exit 0, binary
//!     unlinked). `tests/install/install_from_local_build.sh` => 11/11 PASS.
//!   * windows-thinkpad (Windows 10.0.26200, rustc/cargo 1.94.1) — REACHED.
//!     The Santh NFS share is NOT mounted there (`Test-Path Z:\... = False`), so
//!     an OFFLINE source ship is the only build path — and that ship exposed the
//!     portability blocker pinned RED below.
//!   * santhserver, axiomexec — UNREACHABLE (SSH connect hangs to timeout,
//!     rc 124). thamiya — UNREACHABLE (connect to :22 timed out). Recorded LOUD
//!     in `docs/CROSS_OS_STATUS.md`; NOT a silent skip (Law 10).
//!
//! Two contract classes live here:
//!   A. GREEN coherence pins (every OS) — lock the DELIBERATE cross-OS
//!      divergences so a later edit cannot silently erase one.
//!   B. A portability target — the one concrete cross-OS BUILD blocker the
//!      dogfood surfaced. It stays green only while Vyre resolves from registry
//!      pins or repo-contained paths, never from a tree-escaping NFS path.

use std::path::PathBuf;

/// Repo root = two levels up from this crate's manifest (`crates/cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root from crates/cli")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ===========================================================================
// A. GREEN coherence pins — DELIBERATE cross-OS divergences, locked in place.
// ===========================================================================

/// `keyhog uninstall --yes` is a documented, INTENTIONAL exit-code divergence:
///   * Unix    — the kernel lets you unlink a running executable's inode, so the
///               delete succeeds and `run()` returns `Ok(SUCCESS)` => exit 0.
///   * Windows — the OS refuses to delete a running `.exe`; `remove_binary`
///               returns a plain `anyhow` error (NOT an `io::Error`), which
///               `main.rs` maps to `EXIT_USER_ERROR = 2`.
///
/// This was CONFIRMED live on macOS (`uninstall --yes` => exit 0, binary gone).
/// The contract is the per-OS source shape: both `#[cfg]` arms must exist, the
/// Windows arm must FAIL CLOSED with the running-.exe diagnostic, and the Unix
/// arm must actually remove the file. A regression that made Windows silently
/// "succeed" (return Ok without deleting) would be a Law-10 silent fallback;
/// this pin makes that regression a red test on every OS, not a Windows-only
/// surprise the Linux CI never sees.
#[test]
fn uninstall_remove_binary_is_per_os_and_windows_fails_closed() {
    let src = read("crates/cli/src/subcommands/uninstall.rs");

    // Both platform arms are present and distinct.
    assert!(
        src.contains("#[cfg(unix)]\nfn remove_binary("),
        "uninstall must keep a #[cfg(unix)] remove_binary arm"
    );
    assert!(
        src.contains("#[cfg(windows)]\nfn remove_binary("),
        "uninstall must keep a #[cfg(windows)] remove_binary arm"
    );

    // Unix arm actually unlinks the file (the exit-0 behavior proven on macOS).
    let unix_arm = src
        .split("#[cfg(unix)]")
        .nth(1)
        .expect("unix arm")
        .split("#[cfg(windows)]")
        .next()
        .expect("unix arm body");
    assert!(
        unix_arm.contains("std::fs::remove_file(exe)"),
        "the unix uninstall arm must remove_file(exe) so `uninstall --yes` exits 0"
    );

    // Windows arm FAILS CLOSED (returns Err) — never a silent no-op success.
    let win_arm = src.split("#[cfg(windows)]").nth(1).expect("windows arm");
    assert!(
        win_arm.contains("Err(anyhow!("),
        "the windows uninstall arm must FAIL CLOSED (Err), not silently return Ok"
    );
    assert!(
        win_arm.contains("Windows can't delete a running .exe"),
        "the windows uninstall error must carry the running-.exe diagnostic + path"
    );
    // It must NOT contain a remove_file — that would be the silent-success regression.
    assert!(
        !win_arm.contains("remove_file"),
        "the windows uninstall arm must not attempt remove_file on a running .exe"
    );
}

/// `EXIT_USER_ERROR = 2` is the code the Windows `uninstall --yes` error lands
/// on (the anyhow error is not an `io::Error`, so `main.rs` chooses the user
/// bucket). Pin the constant so the cross-OS exit table in
/// `docs/CROSS_OS_STATUS.md` (Unix uninstall => 0, Windows uninstall => 2) stays
/// coherent with the source.
#[test]
fn main_defines_exit_user_error_two_for_windows_uninstall_path() {
    assert_eq!(keyhog::exit_codes::EXIT_USER_ERROR, 2);
    let src = read("crates/cli/src/main.rs");
    assert!(!src.contains("const EXIT_USER_ERROR"));
}

/// `keyhog daemon` is unix-only by design: it serves scans over a Unix-domain
/// socket, and the `#[cfg(not(unix))]` arm returns a clear error rather than a
/// missing-subcommand surprise. The dogfood relies on this: the cross-OS matrix
/// must NOT expect a daemon on Windows. Pin both arms so a refactor cannot drop
/// the Windows guidance and leave Windows users with an opaque failure.
#[test]
fn daemon_is_unix_only_with_explicit_windows_guidance() {
    let src = read("crates/cli/src/lib.rs");
    assert!(
        src.contains("#[cfg(unix)]")
            && src.contains(
                "Some(args::Command::Daemon(args)) => subcommands::daemon::run(args).await"
            ),
        "lib.rs must route `daemon` only under #[cfg(unix)]"
    );
    assert!(
        src.contains("#[cfg(not(unix))]")
            && src.contains("Some(args::Command::Daemon(_args))")
            && src.contains("`keyhog daemon` is a unix-only command")
            && src.contains("No Windows daemon transport ships")
            && src.contains("keyhog scan <path>"),
        "lib.rs must give Windows an explicit unix-only daemon error, not a missing command"
    );
    assert!(
        !src.contains("not yet implemented") && !src.contains("tracked but not yet"),
        "the Windows daemon guidance must state the current shipped contract, not roadmap language"
    );
}

// ===========================================================================
// B. Portability target — the cross-OS BUILD blocker the dogfood surfaced.
// ===========================================================================

/// THE CROSS-OS BUILD BLOCKER (kept green by self-contained Vyre dependencies).
///
/// Reproduced live: `tar`-shipping the keyhog source to windows-thinkpad (which
/// cannot mount the Santh NFS share) and running `cargo metadata` there fails:
///
///     error: failed to load manifest for workspace member `...\crates\core`
///     Caused by: failed to load manifest for dependency `vyre-libs`
///
/// because the old root `Cargo.toml` pinned all five `vyre*` crates to a path
/// that ESCAPES the repo tree:
///
///     vyre_libs = { ..., path = "../../libs/performance/matching/vyre/vyre-libs" }
///
/// `../..` from `software/keyhog/` lands OUTSIDE the shipped keyhog tree, so an
/// offline source distribution is not self-contained and cannot build on any
/// host that lacks the NFS share. macOS only built because its share IS mounted.
///
/// It stays GREEN only when every `vyre*` dependency in the root `Cargo.toml` is
/// either a registry pin (no `path`) or a path that stays inside the repo tree
/// (does not start with `../`). Keyhog now uses exact crates.io `=0.6.2` pins,
/// so a share-less offline source ship can resolve the Vyre runtime fleet.
#[test]
fn vyre_pins_are_self_contained_for_offline_cross_os_build() {
    let cargo = read("Cargo.toml");

    // Collect every `vyre*` dependency line that carries a tree-escaping path.
    let escaping: Vec<&str> = cargo
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            (t.starts_with("vyre ")
                || t.starts_with("vyre_libs ")
                || t.starts_with("vyre-driver-wgpu ")
                || t.starts_with("vyre-driver-cuda ")
                || t.starts_with("vyre-runtime "))
                && t.contains("path = \"../")
        })
        .collect();

    assert!(
        escaping.is_empty(),
        "CROSS-OS BUILD BLOCKER: {} vyre dependenc{} use a repo-escaping path \
         override (`path = \"../...\"`), so an offline source ship cannot build \
         on a host without the Santh NFS share (proven on windows-thinkpad: \
         `cargo metadata` => failed to load manifest for dependency `vyre-libs`). \
         Resolve by pinning vyre 0.6.2 from the registry (drop `path`) or moving \
         the source inside the repo tree. Offending lines:\n{}",
        escaping.len(),
        if escaping.len() == 1 { "y" } else { "ies" },
        escaping.join("\n")
    );
}
