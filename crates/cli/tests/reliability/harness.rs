//! Reliability harness: drive the real `keyhog` binary under hostile
//! environments and assert product-grade invariants (exit code, no ANSI leak,
//! no panic, determinism), per the CLAUDE.md product-integration contract.
//!
//! The bar is "a customer's experience CANNOT be bad," so every profile here
//! is NASTIER than a normal user's box: HOME unset, read-only cwd, TERM=dumb,
//! a 1-column terminal, and a bogus forced backend. A
//! subcommand that panics, leaks raw escape codes, or returns a nonsense exit
//! code under any of these is a defect, not an edge case.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use tempfile::TempDir;

/// The freshly-built binary under test (cargo points this at target/<p>/keyhog).
pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Shared slot for reliability tests that spawn timeout-sensitive subprocesses.
/// The matrix intentionally fans out many lightweight CLI invocations in
/// parallel, but heavy scan watchdogs and installer release verifiers should
/// not compete with each other for process scheduling and produce false policy
/// failures.
pub fn subprocess_slot() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("reliability subprocess slot")
}

/// The full list of CLI subcommands. Kept here as the single source the matrix
/// macros fan out over so adding a subcommand surfaces as a compile-time gap
/// (the `surface_*` matrices reference this list).
pub const SUBCOMMANDS: &[&str] = &[
    "scan",
    "hook",
    "detectors",
    "explain",
    "diff",
    "calibrate",
    "config",
    "watch",
    "completion",
    "backend",
    "doctor",
    "update",
    "repair",
    "uninstall",
    "scan-system",
    "daemon",
    "calibrate-autoroute",
];

/// A hostile-environment profile. Each variant flips a real runtime branch
/// (color decision, config/IO path, terminal-size math, backend probe), so a
/// matrix over `(subcommand × Profile)` is genuinely distinct coverage, not
/// one assertion repeated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Inherited env, piped stdio (the non-TTY baseline).
    Plain,
    /// `NO_COLOR=1` - output must contain zero ANSI escapes.
    NoColor,
    /// `CLICOLOR_FORCE=1` - color forced; we still forbid escapes leaking into
    /// machine-readable formats (json/sarif), which a premium tool keeps clean.
    ClicolorForce,
    /// `TERM=dumb` - no terminal capabilities; must not emit cursor/color codes.
    DumbTerm,
    /// `TERM=""` - empty terminal type.
    EmptyTerm,
    /// `COLUMNS=1` - a one-column terminal; layout math must not panic/overflow.
    TinyCols,
    /// `COLUMNS=100000` - absurdly wide; no allocation blowups.
    HugeCols,
    /// `HOME` unset - config/dirs lookups must degrade, not crash.
    NoHome,
    /// `HOME=""` - empty home; dirs crate returns surprising paths.
    EmptyHome,
    /// `LANG=C LC_ALL=C` - the C locale.
    CLocale,
    /// `LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8`.
    Utf8Locale,
    /// `TMPDIR=/keyhog-nonexistent-tmp` - tempfile creation will fail; commands
    /// that stage temp files must error cleanly, never panic.
    BadTmpdir,
    /// cwd is a `chmod 0555` directory - cannot write into the working dir.
    ReadOnlyCwd,
    /// `KEYHOG_BACKEND=__bogus__` - an unknown forced backend; must reject with
    /// a clean error, not a panic or silent wrong behavior.
    BogusBackend,
    /// `KEYHOG_THREADS=1` - single-threaded scan path.
    OneThread,
    /// `KEYHOG_THREADS=4096` - absurd thread count; must clamp, not OOM/panic.
    ManyThreads,
}

pub const ALL_PROFILES: &[Profile] = &[
    Profile::Plain,
    Profile::NoColor,
    Profile::ClicolorForce,
    Profile::DumbTerm,
    Profile::EmptyTerm,
    Profile::TinyCols,
    Profile::HugeCols,
    Profile::NoHome,
    Profile::EmptyHome,
    Profile::CLocale,
    Profile::Utf8Locale,
    Profile::BadTmpdir,
    Profile::ReadOnlyCwd,
    Profile::BogusBackend,
    Profile::OneThread,
    Profile::ManyThreads,
];

impl Profile {
    /// True when this profile explicitly REQUESTS color even on a pipe
    /// (`CLICOLOR_FORCE`). On these, ANSI on a human surface is correct, not a
    /// leak - but machine formats (json/sarif) must STILL stay clean.
    pub fn forces_color(self) -> bool {
        matches!(self, Profile::ClicolorForce)
    }

    pub fn label(self) -> &'static str {
        match self {
            Profile::Plain => "plain",
            Profile::NoColor => "no_color",
            Profile::ClicolorForce => "clicolor_force",
            Profile::DumbTerm => "dumb_term",
            Profile::EmptyTerm => "empty_term",
            Profile::TinyCols => "tiny_cols",
            Profile::HugeCols => "huge_cols",
            Profile::NoHome => "no_home",
            Profile::EmptyHome => "empty_home",
            Profile::CLocale => "c_locale",
            Profile::Utf8Locale => "utf8_locale",
            Profile::BadTmpdir => "bad_tmpdir",
            Profile::ReadOnlyCwd => "read_only_cwd",
            Profile::BogusBackend => "bogus_backend",
            Profile::OneThread => "one_thread",
            Profile::ManyThreads => "many_threads",
        }
    }
}

/// The captured result of one invocation.
pub struct Outcome {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_raw: Vec<u8>,
    pub stderr_raw: Vec<u8>,
    /// Human label for assertion messages (the command line + profile).
    pub what: String,
}

impl Outcome {
    /// Combined stdout+stderr, for substring checks that don't care which
    /// stream carried the text.
    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn apply_profile(profile: Profile, cmd: &mut Command) -> Option<TempDir> {
    match profile {
        Profile::Plain => {}
        Profile::NoColor => {
            cmd.env("NO_COLOR", "1");
        }
        Profile::ClicolorForce => {
            cmd.env("CLICOLOR_FORCE", "1").env_remove("NO_COLOR");
        }
        Profile::DumbTerm => {
            cmd.env("TERM", "dumb");
        }
        Profile::EmptyTerm => {
            cmd.env("TERM", "");
        }
        Profile::TinyCols => {
            cmd.env("COLUMNS", "1").env("LINES", "1");
        }
        Profile::HugeCols => {
            cmd.env("COLUMNS", "100000").env("LINES", "100000");
        }
        Profile::NoHome => {
            cmd.env_remove("HOME").env_remove("XDG_CONFIG_HOME");
        }
        Profile::EmptyHome => {
            cmd.env("HOME", "");
        }
        Profile::CLocale => {
            cmd.env("LANG", "C").env("LC_ALL", "C");
        }
        Profile::Utf8Locale => {
            cmd.env("LANG", "en_US.UTF-8").env("LC_ALL", "en_US.UTF-8");
        }
        Profile::BadTmpdir => {
            cmd.env("TMPDIR", "/keyhog-nonexistent-tmp-7f3a");
        }
        Profile::ReadOnlyCwd => {
            // A directory we cannot write into. Kept alive via the returned
            // guard; TempDir's drop will chmod-restore enough to delete it.
            let dir = TempDir::new().expect("tempdir for read-only cwd");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555));
            }
            cmd.current_dir(dir.path());
            return Some(dir);
        }
        Profile::BogusBackend => {
            cmd.env("KEYHOG_BACKEND", "__bogus_backend__");
        }
        Profile::OneThread => {
            cmd.env("KEYHOG_THREADS", "1");
        }
        Profile::ManyThreads => {
            cmd.env("KEYHOG_THREADS", "4096");
        }
    }
    None
}

/// Run `keyhog <args>` under `profile`, feeding `stdin`, capturing everything.
pub fn run_stdin(profile: Profile, args: &[&str], stdin: &[u8]) -> Outcome {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let _guard = apply_profile(profile, &mut cmd);

    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("spawn keyhog {args:?} [{}]: {e}", profile.label()));
    use std::io::Write;
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(stdin);
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait keyhog {args:?} [{}]: {e}", profile.label()));

    Outcome {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        stdout_raw: out.stdout,
        stderr_raw: out.stderr,
        what: format!("`keyhog {}` [{}]", args.join(" "), profile.label()),
    }
}

pub fn run(profile: Profile, args: &[&str]) -> Outcome {
    run_stdin(profile, args, b"")
}

// ── Shared assertions ──────────────────────────────────────────────────────

/// No raw ANSI/VT escape (ESC = 0x1b) may appear when output is piped (never a
/// TTY here). A premium CLI gates color on TTY detection; a leak means a code
/// path bypassed the palette.
pub fn assert_no_ansi(o: &Outcome) {
    let leak = |buf: &[u8]| buf.contains(&0x1b);
    assert!(
        !leak(&o.stdout_raw),
        "{}: raw ANSI escape leaked to stdout when piped:\n{:?}",
        o.what,
        o.stdout.chars().take(200).collect::<String>()
    );
    assert!(
        !leak(&o.stderr_raw),
        "{}: raw ANSI escape leaked to stderr when piped:\n{:?}",
        o.what,
        o.stderr.chars().take(200).collect::<String>()
    );
}

/// The binary must never surface a Rust panic / backtrace to the user. That is
/// always a bug: either handle the error and exit cleanly, or don't reach it.
pub fn assert_no_panic(o: &Outcome) {
    let hay = o.combined();
    for needle in [
        "panicked at",
        "RUST_BACKTRACE",
        "note: run with `RUST_BACKTRACE",
        "internal error: entered unreachable code",
        "called `Option::unwrap()`",
        "called `Result::unwrap()`",
        "index out of bounds",
        "attempt to subtract with overflow",
        "attempt to add with overflow",
    ] {
        assert!(
            !hay.contains(needle),
            "{}: panic/backtrace marker {needle:?} in output (exit {:?}):\n{}",
            o.what,
            o.code,
            hay.chars().take(600).collect::<String>()
        );
    }
    // Exit 101 is the Rust panic exit code; with panic=abort it's a signal
    // (None) but 101 specifically means an unwound panic escaped main.
    assert_ne!(
        o.code,
        Some(101),
        "{}: process exited 101 (escaped panic)",
        o.what
    );
}

/// The process must terminate with a real exit code, not a signal (crash).
/// `code == None` means it was killed by a signal (SIGSEGV/SIGABRT/SIGILL) -
/// a hard crash, the worst customer experience.
pub fn assert_clean_exit(o: &Outcome) {
    assert!(
        o.code.is_some(),
        "{}: process terminated by a signal (no exit code) - a crash",
        o.what
    );
}

/// Exit code must be one of keyhog's documented codes. Anything else is an
/// undocumented surprise the integration contract forbids.
pub fn assert_documented_exit(o: &Outcome) {
    if let Some(c) = o.code {
        let documented: Vec<i32> = keyhog::exit_codes::DEFINITIONS
            .iter()
            .map(|definition| i32::from(definition.code))
            .collect();
        assert!(
            documented.contains(&c),
            "{}: undocumented exit code {c} (documented: {documented:?})\nstderr:\n{}",
            o.what,
            o.stderr.chars().take(400).collect::<String>()
        );
    }
}

/// Stdout claiming to be JSON must parse as JSON. Catches the "error happened
/// but we still printed half a JSON doc / a plain-text error into a --format
/// json stream" class, which breaks every machine consumer.
pub fn assert_valid_json_if_nonempty(o: &Outcome) {
    let s = o.stdout.trim();
    if s.is_empty() {
        return;
    }
    serde_json::from_str::<serde_json::Value>(s).unwrap_or_else(|e| {
        panic!(
            "{}: --format json produced non-JSON stdout: {e}\n{}",
            o.what,
            s.chars().take(400).collect::<String>()
        )
    });
}
