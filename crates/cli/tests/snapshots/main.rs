//! Round-1 binary end-to-end snapshot battery.
//!
//! Drive the real `keyhog` binary (`CARGO_BIN_EXE_keyhog`) through seven
//! representative invocations and byte-compare each invocation's stdout,
//! stderr, and exit code against a committed snapshot in
//! `crates/cli/tests/snapshots/data/`.
//!
//! This is the only test in the suite that exercises every code path from
//! `main()` to the byte that hits stdout/stderr/exit. Per the testing
//! contract, per-module tests with mocks are decoration unless paired with a
//! whole-binary surface like this one. Drift here is the loudest signal
//! keyhog has that user-visible behaviour changed; if a snapshot file does
//! not yet exist or a change is intentional, re-run with
//! `KEYHOG_UPDATE_SNAPSHOTS=1` to write the new bytes, then commit them in
//! the same change as the code that produced the new bytes.
//!
//! Each invocation produces three files:
//!   `data/<case>.stdout`  - normalized stdout bytes
//!   `data/<case>.stderr`  - normalized stderr bytes
//!   `data/<case>.exit`    - exit code in ASCII followed by `\n`, or
//!                            `signal:<n>\n` if the process was killed
//!
//! Normalization rewrites volatile substrings (tempdir paths, scan timings,
//! ISO timestamps, version+commit strings, the SARIF GUID, host-dependent
//! "scanned N files" counts) to fixed placeholders so the snapshot reflects
//! behaviour, not the wall clock or the host.
//!
//! Cases:
//!   case_01_scan_single_file      - `scan <tmp>/planted.txt`
//!   case_02_scan_directory        - `scan <tmp>/tree/`
//!   case_03_scan_format_json      - `scan --format json <tmp>/tree/`
//!   case_04_scan_format_sarif     - `scan --format sarif <tmp>/tree/`
//!   case_05_scan_format_jsonl     - `scan --format jsonl <tmp>/tree/`
//!   case_06_scan_severity_high    - `scan --severity high <tmp>/tree/`
//!   case_07_scan_no_default_excl  - `scan --no-default-excludes <tmp>/tree/`
//!   case_08_scan_format_csv       - `scan --format csv <tmp>/tree/`
//!   case_09_scan_format_junit     - `scan --format junit <tmp>/tree/`
//!   case_10_scan_clean_format_csv   - `scan --format csv <tmp>/clean-tree/`
//!   case_11_scan_clean_format_junit - `scan --format junit <tmp>/clean-tree/`
//!   case_12_scan_clean_format_html  - `scan --format html <tmp>/clean-tree/`
//!
//! Cases 10-12 scan a tree with NO planted secret so every format's
//! zero-finding shape is pinned (CSV header-only, JUnit `tests="0"
//! failures="0"`, HTML `rawFindings = []`). The with-findings HTML report is
//! still not byte-snapshotted because its `rawFindings` payload embeds a serde
//! JSON dump whose field set tracks `VerifiedFinding`, so that byte snapshot
//! would churn on every unrelated struct change; `html_format_report_contains_finding`
//! drives the real binary and asserts the document is well-formed (DOCTYPE)
//! and carries the planted key's detector inside the embedded findings
//! payload. The CLEAN HTML report (case_12) has an empty `rawFindings` array
//! and is otherwise a static template, so it IS byte-stable and safe to pin.
//!
//! Byte stability proves output did not change; it does not prove the output
//! is a valid document. `csv_format_is_valid_and_row_count_matches_findings`
//! and `junit_format_is_well_formed_and_counts_match_findings` close that gap:
//! they parse the binary's CSV (RFC-4180 record parser) and JUnit (XML
//! attribute/element reader) output and assert the document's own count
//! metadata agrees with the ground-truth finding count from the JSON format,
//! so a malformed CSV row or a torn / miscounted JUnit envelope fails even
//! when its bytes are stable.
//!
//! Each case uses `--no-daemon` so the in-process pipeline runs (snapshots
//! must not depend on whether a `keyhog daemon` happens to be up on the
//! developer's machine) and `--no-color` semantics are forced by
//! `NO_COLOR=1` in the spawned env so colour escapes never enter the file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

/// A planted AWS access-key pair. Split across two writes so this source
/// file does not itself trip a scanner (the same trick the e2e_binary suite
/// uses). The AKIA-prefixed key is a well-known shape every named-detector
/// AWS rule will fire on.
const AWS_KEY_PREFIX: &str = "AKIA";
const AWS_KEY_BODY: &str = "QYLPMN5HFIQR7XYA";
const AWS_SECRET_PREFIX: &str = "wJalrXUtnFEMI";
const AWS_SECRET_BODY: &str = "/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// Build the same directory tree for cases 02-07 so each format/flag case
/// observes the same underlying inputs and we get clean differential
/// snapshots across formats.
///
/// Layout:
///   tree/planted.txt   - one planted AWS key + secret
///   tree/clean.txt     - prose, no secret
///   tree/sub/also.cfg  - second planted AWS key under a subdir, exercises
///                         the directory walker
fn write_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).expect("mkdir tree");
    std::fs::create_dir(tree.join("sub")).expect("mkdir tree/sub");

    let key = format!("{AWS_KEY_PREFIX}{AWS_KEY_BODY}");
    let secret = format!("{AWS_SECRET_PREFIX}{AWS_SECRET_BODY}");
    std::fs::write(
        tree.join("planted.txt"),
        format!("AWS_ACCESS_KEY_ID=\"{key}\"\nAWS_SECRET_ACCESS_KEY=\"{secret}\"\n"),
    )
    .expect("write planted.txt");

    std::fs::write(
        tree.join("clean.txt"),
        "the quick brown fox jumps over the lazy dog\n",
    )
    .expect("write clean.txt");

    std::fs::write(
        tree.join("sub").join("also.cfg"),
        format!("# config\naccess_key = {key}\n"),
    )
    .expect("write sub/also.cfg");

    dir
}

fn write_single_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    let key = format!("{AWS_KEY_PREFIX}{AWS_KEY_BODY}");
    std::fs::write(&path, format!("AWS_ACCESS_KEY_ID=\"{key}\"\n")).expect("write planted.txt");
    (dir, path)
}

/// Build a tree that plants NO credential, so every output format must emit
/// its zero-finding shape (CSV header-only, JUnit `tests="0" failures="0"`,
/// HTML with `const rawFindings = []`). The clean-input snapshots pin that
/// shape so a regression that, say, started emitting a spurious data row on a
/// finding-less scan, or dropped the CSV header, or produced a malformed
/// empty JUnit envelope, is caught even though the happy-path tree-scan
/// snapshots would not move.
///
/// Layout mirrors `write_tree()` minus the planted keys: same directory
/// depth and same file names, just prose contents, so the only behavioural
/// difference from the finding-bearing cases is the absence of secrets.
fn write_clean_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).expect("mkdir tree");
    std::fs::create_dir(tree.join("sub")).expect("mkdir tree/sub");

    std::fs::write(
        tree.join("planted.txt"),
        "AWS_ACCESS_KEY_ID=not-a-key\nAWS_SECRET_ACCESS_KEY=also-not-a-secret\n",
    )
    .expect("write planted.txt");

    std::fs::write(
        tree.join("clean.txt"),
        "the quick brown fox jumps over the lazy dog\n",
    )
    .expect("write clean.txt");

    std::fs::write(
        tree.join("sub").join("also.cfg"),
        "# config\naccess_key = placeholder\n",
    )
    .expect("write sub/also.cfg");

    dir
}

// -----------------------------------------------------------------------------
// Run + capture
// -----------------------------------------------------------------------------

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join("data")
}

struct Captured {
    stdout: String,
    stderr: String,
    exit_repr: String,
}

fn run_keyhog(args: &[&str], tempdir_root: &Path) -> Captured {
    let output = Command::new(binary())
        // Keep the in-process path: snapshots cannot depend on whether
        // `keyhog daemon` happens to be running on the host.
        .args(args)
        .env("NO_COLOR", "1")
        // Silence colour from anything that consults TERM directly.
        .env("TERM", "dumb")
        // Pin the working directory so any relative path the binary
        // emits (currently none, but defensive) lands on a stable root.
        .current_dir(tempdir_root)
        .output()
        .expect("spawn keyhog");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_repr = match output.status.code() {
        Some(c) => format!("exit:{c}\n"),
        None => {
            // On Unix the only way `code()` is None is a signal kill.
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                match output.status.signal() {
                    Some(s) => format!("signal:{s}\n"),
                    None => "exit:unknown\n".into(),
                }
            }
            #[cfg(not(unix))]
            {
                "exit:unknown\n".into()
            }
        }
    };

    Captured {
        stdout,
        stderr,
        exit_repr,
    }
}

// -----------------------------------------------------------------------------
// Normalization
// -----------------------------------------------------------------------------

/// Apply ordered substring/regex-light substitutions that replace volatile
/// bytes with fixed placeholders. The substitutions are kept deliberately
/// boring (no `regex` crate dep) so the harness has zero failure surface
/// of its own.
///
/// Order matters: longer/more-specific replacements run first.
fn normalize(raw: &str, tempdir_root: &Path) -> String {
    let mut out = raw.to_string();

    // 1. Tempdir-rooted paths (longest match first). Replace any absolute
    //    path that starts with the tempdir root with `<TMP>/<rest>`. We
    //    canonicalize the tempdir root because tempfile returns a path
    //    that may include a symlinked `/tmp` prefix on some hosts.
    let root_strs: Vec<String> = {
        let mut v = vec![tempdir_root.display().to_string()];
        if let Ok(canon) = tempdir_root.canonicalize() {
            let s = canon.display().to_string();
            if !v.contains(&s) {
                v.push(s);
            }
        }
        // Longest first so a canonicalised prefix doesn't get partially
        // replaced by a shorter literal one.
        v.sort_by_key(|s| std::cmp::Reverse(s.len()));
        v
    };
    for root in &root_strs {
        if !root.is_empty() {
            out = out.replace(root, "<TMP>");
        }
    }

    // 2. CARGO target dir (debug binary path may leak into error messages).
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_default();
    if !target_dir.is_empty() {
        out = out.replace(&target_dir, "<TARGET>");
    }

    // 3. Workspace path. The detector corpus path may show up in error
    //    contexts; pin it.
    let manifest = env!("CARGO_MANIFEST_DIR");
    out = out.replace(manifest, "<MANIFEST>");
    // Strip the `crates/cli` tail so the *workspace* root also normalises.
    if let Some(ws) = Path::new(manifest).parent().and_then(|p| p.parent()) {
        out = out.replace(&ws.display().to_string(), "<WORKSPACE>");
    }

    // 4. ISO-8601-ish timestamps in SARIF / JSON output.
    //    Pattern: 2026-05-29T14:23:45.123456Z   or with offset / no frac.
    out = replace_re_like(&out, |c| c.is_ascii_digit(), &TIMESTAMP_TEMPLATES);

    // 5. Duration strings. Common emit shapes from the scanner: "in 1.23s",
    //    "in 12ms", "(1.234s)", "took 1.23s", "elapsed: 1.23s". We rewrite
    //    every "<number>ms" / "<number>s" / "<number>µs" / "<number>us" /
    //    "<number>ns" to the placeholder. False positives on these tokens
    //    in real findings are vanishingly unlikely (matches require an
    //    immediately preceding ASCII digit run + the unit suffix).
    out = rewrite_durations(&out);

    // 6. "files scanned: N" / "files skipped: N" / "Scanned N files".
    //    The walker's exact file count depends on tempdir contents PLUS
    //    any hidden files the harness might pick up; pin the digit-run.
    for needle in [
        "files scanned: ",
        "files skipped: ",
        "files ignored: ",
        "findings: ",
        "Scanned ",
    ] {
        out = rewrite_after_needle(&out, needle);
    }

    // 7. Version + build strings. The build target is host-arch-dependent
    //    and the version moves with the release dial; pin both.
    out = rewrite_after_needle(&out, "KeyHog v");
    out = rewrite_after_needle(&out, "Build Target: ");
    out = rewrite_after_needle(&out, "ML Model Version: ");
    // SARIF tool.driver.version: `"version":"0.5.37"`
    out = rewrite_quoted_after(&out, "\"version\":");
    out = rewrite_quoted_after(&out, "\"semanticVersion\":");

    // 8. SARIF GUID. tool.driver.guid in SARIF reports is randomised per
    //    run on some builds; if not, this is a cheap no-op.
    out = rewrite_quoted_after(&out, "\"guid\":");

    // 9. Per-finding fingerprints / IDs that include a hash of file path.
    //    Most keyhog finding IDs include a path-derived suffix; pin them.
    out = rewrite_quoted_after(&out, "\"fingerprint\":");
    out = rewrite_quoted_after(&out, "\"finding_id\":");
    out = rewrite_quoted_after(&out, "\"id\":");

    // 10. Drop keyhog's GPU/CUDA backend-probe diagnostics, then trim trailing
    //     whitespace. The GPU lines are emitted only when a discrete GPU is
    //     present but unusable (VRAM exhausted, driver error); they never
    //     appear on a no-GPU host or CI runner, so they are host/moment noise
    //     that must not enter a snapshot. Trailing whitespace is dropped to
    //     avoid editor nits causing drift.
    let trimmed: String = out
        .lines()
        .filter(|l| !is_gpu_backend_diagnostic(l))
        .map(|l| l.trim_end_matches([' ', '\t']).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    // Preserve a trailing newline only when real content survives filtering.
    // Stripping a GPU-diagnostic-only stderr leaves an empty body; returning ""
    // (not "\n") makes it byte-identical to a clean no-GPU run, so the snapshot
    // no longer drifts with transient VRAM pressure.
    if trimmed.is_empty() {
        String::new()
    } else if out.ends_with('\n') && !trimmed.ends_with('\n') {
        format!("{trimmed}\n")
    } else {
        trimmed
    }
}

/// Templates for the ISO-8601 timestamp replacement, longest first.
const TIMESTAMP_TEMPLATES: &[(&str, &str)] = &[
    ("YYYY-MM-DDTHH:MM:SS.ffffffZ", "<TS>"),
    ("YYYY-MM-DDTHH:MM:SS.fffZ", "<TS>"),
    ("YYYY-MM-DDTHH:MM:SSZ", "<TS>"),
    ("YYYY-MM-DD HH:MM:SS", "<TS>"),
];

/// Tiny scanner that matches one of `templates` (treating `Y`/`M`/`D`/`H`/`S`/`f`
/// as "any ASCII digit", and `T`/`Z`/`-`/`:`/`.`/` ` as literal) and
/// rewrites the matched span to the replacement. Caller passes a
/// per-position digit predicate.
fn replace_re_like(
    raw: &str,
    _is_digit: impl Fn(char) -> bool,
    templates: &[(&str, &str)],
) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let mut matched = None;
        for (tpl, repl) in templates {
            let tb = tpl.as_bytes();
            if i + tb.len() > bytes.len() {
                continue;
            }
            let mut ok = true;
            for (k, &t) in tb.iter().enumerate() {
                let r = bytes[i + k];
                let want_digit = matches!(t, b'Y' | b'M' | b'D' | b'H' | b'S' | b'f');
                if want_digit {
                    if !r.is_ascii_digit() {
                        ok = false;
                        break;
                    }
                } else if t != r {
                    ok = false;
                    break;
                }
            }
            if ok {
                matched = Some((tb.len(), *repl));
                break;
            }
        }
        match matched {
            Some((len, repl)) => {
                out.push_str(repl);
                i += len;
            }
            None => {
                // Push exactly one UTF-8 char to advance correctly through
                // multi-byte sequences in stderr error messages.
                let ch_end = next_char_boundary(raw, i);
                out.push_str(&raw[i..ch_end]);
                i = ch_end;
            }
        }
    }
    out
}

/// True for keyhog's GPU-probe stderr diagnostics, emitted only when a discrete
/// GPU is present but unusable (VRAM exhausted, driver error). Matched on the
/// specific backend phrases, not bare "gpu"/"cuda", so a real finding line is
/// never dropped. These lines are absent on no-GPU hosts and CI, so stripping
/// them keeps the snapshot stable across hardware and transient VRAM pressure.
fn is_gpu_backend_diagnostic(line: &str) -> bool {
    line.contains("CUDA backend")
        || line.contains("CUDA context")
        || line.contains("CUDA_ERROR")
        || line.contains("backend unavailable")
        || line.contains("backend acquisition failed")
        || line.contains("DriverError")
}

fn next_char_boundary(s: &str, mut i: usize) -> usize {
    i += 1;
    while !s.is_char_boundary(i) && i < s.len() {
        i += 1;
    }
    i
}

/// Replace runs like `1.234s` / `123ms` / `12.5us` with `<DUR>`. Looks for
/// a digit run optionally followed by `.<digit-run>`, then one of the
/// recognised time suffixes (longest first).
fn rewrite_durations(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    let suffixes: &[&str] = &["ns", "us", "µs", "ms", "s"];
    while i < bytes.len() {
        // Try to match a digit-run-with-optional-fraction starting here.
        let start = i;
        if !bytes[i].is_ascii_digit() {
            let end = next_char_boundary(raw, i);
            out.push_str(&raw[i..end]);
            i = end;
            continue;
        }
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'.' {
            let mut k = j + 1;
            let frac_start = k;
            while k < bytes.len() && bytes[k].is_ascii_digit() {
                k += 1;
            }
            if k > frac_start {
                j = k;
            }
        }
        // j now points just past the numeric run. Look for a suffix.
        let mut suffix_len = 0;
        for s in suffixes {
            let sb = s.as_bytes();
            if j + sb.len() <= bytes.len() && &bytes[j..j + sb.len()] == sb {
                // Reject things like "1ssomething" - the suffix must end
                // at a non-alnum boundary so we don't eat real words.
                let after = j + sb.len();
                let next_ok =
                    after == bytes.len() || !bytes[after].is_ascii_alphanumeric();
                if next_ok {
                    suffix_len = sb.len();
                    break;
                }
            }
        }
        if suffix_len > 0 {
            // Also require we are not in the middle of an identifier - the
            // byte BEFORE `start` must not be an ascii letter/digit/underscore.
            let prev_ok = if start == 0 {
                true
            } else {
                let p = bytes[start - 1];
                !(p.is_ascii_alphanumeric() || p == b'_')
            };
            if prev_ok {
                out.push_str("<DUR>");
                i = j + suffix_len;
                continue;
            }
        }
        // No duration here; emit the digit run we ate verbatim.
        out.push_str(&raw[start..j]);
        i = j;
    }
    out
}

/// If `needle` is a literal that appears in `raw`, replace the immediately
/// following digit-or-version run with `<N>`. Stops at the first whitespace
/// or punctuation that isn't part of a version (digits + `.`).
fn rewrite_after_needle(raw: &str, needle: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(idx) = rest.find(needle) {
        out.push_str(&rest[..idx + needle.len()]);
        let tail = &rest[idx + needle.len()..];
        let mut j = 0;
        for (k, c) in tail.char_indices() {
            if c.is_ascii_digit() || c == '.' || c == '-' {
                j = k + c.len_utf8();
            } else if k == 0 {
                // No digit follows; don't rewrite this occurrence.
                break;
            } else {
                break;
            }
        }
        if j > 0 {
            out.push_str("<N>");
            rest = &tail[j..];
        } else {
            // No digit run: continue past this match without rewriting.
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// Replace the next quoted JSON string value after `prefix` (e.g.
/// `"version":` -> `"version":"<S>"`). Handles `"foo"` and `"foo bar"`.
/// Leaves non-string values (numbers, booleans) untouched.
fn rewrite_quoted_after(raw: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(idx) = rest.find(prefix) {
        out.push_str(&rest[..idx + prefix.len()]);
        let mut tail = &rest[idx + prefix.len()..];
        // Skip whitespace.
        let trim_start = tail.len() - tail.trim_start().len();
        out.push_str(&tail[..trim_start]);
        tail = &tail[trim_start..];
        if let Some(b) = tail.as_bytes().first() {
            if *b == b'"' {
                // Find matching closing quote (no escape handling needed
                // for version strings, GUIDs, fingerprints, IDs - none of
                // which contain quotes).
                if let Some(end) = tail[1..].find('"') {
                    out.push_str("\"<S>\"");
                    rest = &tail[1 + end + 1..];
                    continue;
                }
            }
        }
        // Nothing to rewrite at this occurrence; continue scanning.
        rest = tail;
    }
    out.push_str(rest);
    out
}

// -----------------------------------------------------------------------------
// Snapshot compare / write
// -----------------------------------------------------------------------------

fn compare_or_write(case: &str, captured: &Captured) {
    let dir = data_dir();
    std::fs::create_dir_all(&dir).expect("mkdir data dir");

    let mut artifacts: BTreeMap<&str, &str> = BTreeMap::new();
    artifacts.insert("stdout", &captured.stdout);
    artifacts.insert("stderr", &captured.stderr);
    artifacts.insert("exit", &captured.exit_repr);

    let update = std::env::var("KEYHOG_UPDATE_SNAPSHOTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut drift = Vec::<String>::new();
    let mut missing = Vec::<String>::new();

    for (kind, actual) in &artifacts {
        let path = dir.join(format!("{case}.{kind}"));
        match std::fs::read_to_string(&path) {
            Ok(expected) => {
                if expected != **actual {
                    if update {
                        std::fs::write(&path, actual.as_bytes())
                            .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
                    } else {
                        drift.push(format!(
                            "DRIFT {case}.{kind} ({} bytes expected vs {} bytes actual)\n\
                             expected first 200 bytes: {:?}\n\
                             actual   first 200 bytes: {:?}\n\
                             snapshot path: {}\n\
                             To accept this change, rerun with KEYHOG_UPDATE_SNAPSHOTS=1.",
                            expected.len(),
                            actual.len(),
                            &expected.chars().take(200).collect::<String>(),
                            &actual.chars().take(200).collect::<String>(),
                            path.display(),
                        ));
                    }
                }
            }
            Err(_) => {
                if update {
                    std::fs::write(&path, actual.as_bytes())
                        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
                } else {
                    missing.push(format!(
                        "MISSING snapshot {} (no on-disk file; rerun with \
                         KEYHOG_UPDATE_SNAPSHOTS=1 to create it).",
                        path.display(),
                    ));
                }
            }
        }
    }

    if !missing.is_empty() || !drift.is_empty() {
        let mut msg = String::new();
        for m in &missing {
            msg.push_str(m);
            msg.push('\n');
        }
        for d in &drift {
            msg.push_str(d);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// -----------------------------------------------------------------------------
// Cases
// -----------------------------------------------------------------------------

#[test]
fn case_01_scan_single_file() {
    let (dir, path) = write_single_file();
    let path_s = path.to_string_lossy().into_owned();
    let captured = run_keyhog(&["scan", "--no-daemon", &path_s], dir.path());
    snap("case_01_scan_single_file", captured, dir.path());
}

#[test]
fn case_02_scan_directory() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(&["scan", "--no-daemon", &tree_s], dir.path());
    snap("case_02_scan_directory", captured, dir.path());
}

#[test]
fn case_03_scan_format_json() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "json", &tree_s],
        dir.path(),
    );
    snap("case_03_scan_format_json", captured, dir.path());
}

#[test]
fn case_04_scan_format_sarif() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "sarif", &tree_s],
        dir.path(),
    );
    snap("case_04_scan_format_sarif", captured, dir.path());
}

#[test]
fn case_05_scan_format_jsonl() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "jsonl", &tree_s],
        dir.path(),
    );
    snap("case_05_scan_format_jsonl", captured, dir.path());
}

#[test]
fn case_06_scan_severity_high() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--severity", "high", &tree_s],
        dir.path(),
    );
    snap("case_06_scan_severity_high", captured, dir.path());
}

#[test]
fn case_07_scan_no_default_excludes() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--no-default-excludes", &tree_s],
        dir.path(),
    );
    snap("case_07_scan_no_default_excludes", captured, dir.path());
}

#[test]
fn case_08_scan_format_csv() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "csv", &tree_s],
        dir.path(),
    );
    snap("case_08_scan_format_csv", captured, dir.path());
}

#[test]
fn case_09_scan_format_junit() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "junit", &tree_s],
        dir.path(),
    );
    snap("case_09_scan_format_junit", captured, dir.path());
}

// -----------------------------------------------------------------------------
// Clean-input (zero-finding) snapshots.
//
// The happy-path cases above all scan a tree that contains a planted key, so
// they only pin the WITH-findings shape of each format. The testing contract
// requires every output format be byte-compared on >=1 realistic scenario;
// "a scan that finds nothing" is the other realistic scenario, and its empty
// shape is exactly where a format regression (dropped CSV header, malformed
// empty JUnit envelope, HTML that renders `undefined` instead of `[]`) hides.
// These cases pin that shape through the real binary on `write_clean_tree()`.
// -----------------------------------------------------------------------------

#[test]
fn case_10_scan_clean_format_csv() {
    let dir = write_clean_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "csv", &tree_s],
        dir.path(),
    );
    snap("case_10_scan_clean_format_csv", captured, dir.path());
}

#[test]
fn case_11_scan_clean_format_junit() {
    let dir = write_clean_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "junit", &tree_s],
        dir.path(),
    );
    snap("case_11_scan_clean_format_junit", captured, dir.path());
}

#[test]
fn case_12_scan_clean_format_html() {
    let dir = write_clean_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "html", &tree_s],
        dir.path(),
    );
    snap("case_12_scan_clean_format_html", captured, dir.path());
}

/// HTML is verified structurally rather than by byte snapshot (see the module
/// header): the embedded `rawFindings` JSON tracks `VerifiedFinding`'s field
/// set, which would make a byte snapshot churn on unrelated struct changes.
/// This still drives the REAL binary end-to-end and asserts the document is a
/// well-formed HTML page that actually carries the planted AWS key finding,
/// so it fails loudly if the HTML path ever emits an empty or finding-less
/// report.
#[test]
fn html_format_report_contains_finding() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "html", &tree_s],
        dir.path(),
    );
    let out = captured.stdout;

    assert!(
        out.contains("<!DOCTYPE html>"),
        "html report is not a well-formed document: {:?}",
        &out[..out.len().min(120)]
    );
    assert!(
        out.contains("<title>KeyHog Secret Scan Report</title>"),
        "html report missing title"
    );

    // The in-page script renders from `const rawFindings = [...]`. Pull the
    // array literal and assert it is non-empty and carries the planted AWS
    // key. The scanner redacts the credential to `first4...last4`, so the
    // `AKIA` prefix of the planted key survives into `credential_redacted`.
    let line = out
        .lines()
        .find(|l| l.trim_start().starts_with("const rawFindings = "))
        .expect("rawFindings assignment present in html report");
    let start = line.find('[').expect("rawFindings array opens");
    let end = line.rfind(']').expect("rawFindings array closes");
    let json = &line[start..=end];
    assert_ne!(json, "[]", "html report embedded zero findings for a planted key");
    assert!(
        json.contains("\"service\":\"aws\""),
        "html findings payload missing the planted AWS finding: {json}"
    );
    assert!(
        json.contains(AWS_KEY_PREFIX),
        "html findings payload missing the redacted AKIA key prefix: {json}"
    );
}

fn snap(case: &str, captured: Captured, tempdir_root: &Path) {
    let captured = Captured {
        stdout: normalize(&captured.stdout, tempdir_root),
        stderr: normalize(&captured.stderr, tempdir_root),
        exit_repr: captured.exit_repr,
    };
    compare_or_write(case, &captured);
}

// -----------------------------------------------------------------------------
// Structural validity of CSV / JUnit (not just byte stability).
//
// A byte snapshot proves the output did not CHANGE; it does not prove the
// output is a VALID document. A regression that emitted an unescaped comma in
// a credential preview, or dropped a closing `</testsuite>`, would sail
// through the snapshot the moment its bytes stabilised. The two tests below
// drive the real binary and parse its output with a real reader (RFC-4180 CSV
// field/record parser; well-formed-XML element/attribute extractor), then
// assert the document's own count metadata agrees with the ground-truth
// finding count taken from the binary's JSON output on the same tree. If CSV
// or JUnit ever emits a malformed document, the parse fails or the counts
// disagree and the test fails loudly.
// -----------------------------------------------------------------------------

/// Ground-truth finding count for a tree: run the binary in `--format json`
/// (a separately-tested, structurally-stable format) and count the entries in
/// its top-level findings array. The JSON format emits a top-level JSON array
/// of finding objects (one element per top-level finding; `additional_locations`
/// live inside an element and do NOT add array entries), which is exactly the
/// granularity CSV rows and JUnit `<testcase>`s use. Used as the oracle that
/// CSV row count and JUnit `tests`/`failures` must agree with, so no
/// host-dependent finding count is hardcoded.
fn json_finding_count(tree_s: &str, root: &Path) -> usize {
    let captured = run_keyhog(&["scan", "--no-daemon", "--format", "json", tree_s], root);
    let v: serde_json::Value =
        serde_json::from_str(&captured.stdout).expect("json output parses as JSON");
    v.as_array()
        .map(|a| a.len())
        .expect("json output is a top-level array of findings")
}

/// Minimal RFC-4180 CSV parser: splits `text` into records, each a vector of
/// fields, honouring `"`-quoted fields, doubled `""` escapes, and commas /
/// newlines embedded inside quotes. Returns one inner `Vec<String>` per
/// record. Trailing blank line (from the final `\n`) is dropped. This is a
/// real parse, not a `split(',')`, so it fails on unbalanced quotes exactly
/// as a downstream CSV consumer would choke.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut field = String::new();
    let mut record = Vec::new();
    let mut in_quotes = false;
    let mut field_started = false;
    let mut any_field_on_record = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => {
                in_quotes = true;
                field_started = true;
                any_field_on_record = true;
            }
            ',' => {
                record.push(std::mem::take(&mut field));
                field_started = false;
                any_field_on_record = true;
            }
            '\r' => { /* swallow; the following \n terminates the record */ }
            '\n' => {
                if field_started || any_field_on_record || !record.is_empty() {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                field_started = false;
                any_field_on_record = false;
            }
            other => {
                field.push(other);
                field_started = true;
                any_field_on_record = true;
            }
        }
    }
    // Final record with no trailing newline.
    if field_started || any_field_on_record || !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    assert!(!in_quotes, "CSV ended inside an unterminated quoted field: malformed output");
    records
}

/// Drive the real binary in `--format csv` on a finding-bearing tree, parse
/// the output as RFC-4180 CSV, and assert: the header is the exact 15-column
/// header keyhog promises, every data row has exactly 15 fields (no row
/// torn by an unescaped comma), and the data-row count equals the JSON
/// ground-truth finding count.
#[test]
fn csv_format_is_valid_and_row_count_matches_findings() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "csv", &tree_s],
        dir.path(),
    );

    let expected = json_finding_count(&tree_s, dir.path());
    assert!(expected > 0, "fixture must plant >=1 finding for a meaningful csv row-count check");

    let records = parse_csv(&captured.stdout);
    assert!(!records.is_empty(), "csv output had no records at all: {:?}", captured.stdout);

    const HEADER: &[&str] = &[
        "detector_id", "detector_name", "service", "severity", "credential_redacted",
        "credential_hash", "source", "file_path", "line", "offset", "commit", "author",
        "date", "verification", "confidence",
    ];
    assert_eq!(
        records[0], HEADER,
        "csv header row is not the promised 15-column schema: {:?}",
        records[0]
    );

    let data_rows = &records[1..];
    for (i, row) in data_rows.iter().enumerate() {
        assert_eq!(
            row.len(),
            HEADER.len(),
            "csv data row {i} has {} fields, expected {} (likely an unescaped comma/quote): {row:?}",
            row.len(),
            HEADER.len()
        );
    }
    assert_eq!(
        data_rows.len(),
        expected,
        "csv data-row count ({}) disagrees with json finding count ({expected})",
        data_rows.len()
    );
}

/// Extract the value of attribute `attr` from the first occurrence of element
/// `tag` in `xml`. Returns the unescaped attribute text. A tiny, deliberately
/// boring XML attribute reader (no `quick-xml` dep so this harness keeps zero
/// failure surface of its own); it locates `<tag ` then the `attr="..."`
/// inside that start tag.
fn xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after = &xml[start..];
    let tag_end = after.find('>')?;
    let start_tag = &after[..tag_end];
    let needle = format!("{attr}=\"");
    let aidx = start_tag.find(&needle)?;
    let rest = &start_tag[aidx + needle.len()..];
    let end = rest.find('"')?;
    Some(
        rest[..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// Count non-overlapping occurrences of `needle` in `hay`.
fn count_occurrences(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut n = 0;
    let mut rest = hay;
    while let Some(i) = rest.find(needle) {
        n += 1;
        rest = &rest[i + needle.len()..];
    }
    n
}

/// Drive the real binary in `--format junit` on a finding-bearing tree, then
/// assert the document is a well-formed JUnit envelope whose own counts agree
/// with the JSON ground-truth: the XML prolog and `<testsuites>` open/close
/// frame the body, `<testsuite tests=N failures=N errors="0">` carries the
/// finding count, and exactly N `<testcase>`/`<failure>` pairs are present.
/// A torn or count-mismatched envelope (the classic JUnit regression) fails
/// here rather than passing a stable byte snapshot.
#[test]
fn junit_format_is_well_formed_and_counts_match_findings() {
    let dir = write_tree();
    let tree = dir.path().join("tree");
    let tree_s = tree.to_string_lossy().into_owned();
    let captured = run_keyhog(
        &["scan", "--no-daemon", "--format", "junit", &tree_s],
        dir.path(),
    );
    let xml = &captured.stdout;

    let expected = json_finding_count(&tree_s, dir.path());
    assert!(expected > 0, "fixture must plant >=1 finding for a meaningful junit count check");

    // Envelope: prolog + balanced <testsuites> + a single <testsuite>.
    assert!(
        xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "junit output missing XML prolog: {xml:?}"
    );
    assert_eq!(
        count_occurrences(xml, "<testsuites>"),
        1,
        "junit output must open exactly one <testsuites>: {xml:?}"
    );
    assert_eq!(
        count_occurrences(xml, "</testsuites>"),
        1,
        "junit output must close <testsuites> exactly once: {xml:?}"
    );
    assert!(
        xml.find("<testsuites>").unwrap() < xml.find("</testsuites>").unwrap(),
        "junit <testsuites> close precedes its open: {xml:?}"
    );

    // <testsuite> count attributes must equal the ground-truth finding count.
    let tests = xml_attr(xml, "testsuite", "tests")
        .expect("junit <testsuite> has a tests attribute");
    let failures = xml_attr(xml, "testsuite", "failures")
        .expect("junit <testsuite> has a failures attribute");
    let errors = xml_attr(xml, "testsuite", "errors")
        .expect("junit <testsuite> has an errors attribute");
    assert_eq!(
        tests,
        expected.to_string(),
        "junit testsuite tests=\"{tests}\" disagrees with json finding count {expected}"
    );
    assert_eq!(
        failures,
        expected.to_string(),
        "junit testsuite failures=\"{failures}\" disagrees with json finding count {expected}"
    );
    assert_eq!(errors, "0", "junit testsuite errors should be 0, got {errors}");

    // Exactly N testcase/failure pairs, balanced open/close.
    assert_eq!(
        count_occurrences(xml, "<testcase "),
        expected,
        "junit <testcase> count disagrees with finding count {expected}: {xml:?}"
    );
    assert_eq!(
        count_occurrences(xml, "</testcase>"),
        expected,
        "junit <testcase> open/close imbalance: {xml:?}"
    );
    assert_eq!(
        count_occurrences(xml, "<failure "),
        expected,
        "junit <failure> count disagrees with finding count {expected}: {xml:?}"
    );
    assert_eq!(
        count_occurrences(xml, "</failure>"),
        expected,
        "junit <failure> open/close imbalance: {xml:?}"
    );
}

// -----------------------------------------------------------------------------
// Inner tests of the normalizer itself.
//
// The normalizer is the only piece of harness logic with a non-trivial fail
// mode (over-replacing real bytes, missing a volatile substring, eating an
// identifier). These tests assert truth on the normalizer, not the binary.
// -----------------------------------------------------------------------------

#[test]
fn normalize_replaces_durations_only_at_token_boundaries() {
    let p = Path::new("/nonexistent");
    let got = normalize("scan took 1.234s and 12ms\n", p);
    assert_eq!(got, "scan took <DUR> and <DUR>\n");

    // Must not eat the trailing 's' in identifiers like `findings`.
    let got = normalize("findings: 0\n", p);
    // "findings: " is a rewrite-after-needle target, so it becomes
    // "findings: <N>". Crucially the "s" in "findings" survives.
    assert_eq!(got, "findings: <N>\n");
}

#[test]
fn normalize_rewrites_iso_timestamps() {
    let p = Path::new("/nonexistent");
    let got = normalize("at 2026-05-29T14:23:45.123456Z log\n", p);
    assert_eq!(got, "at <TS> log\n");
    let got = normalize("at 2026-05-29T14:23:45.123Z log\n", p);
    assert_eq!(got, "at <TS> log\n");
    let got = normalize("at 2026-05-29T14:23:45Z log\n", p);
    assert_eq!(got, "at <TS> log\n");
}

#[test]
fn normalize_redacts_tempdir_paths() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, b"x").expect("write");
    let input = format!("scanned {}\n", path.display());
    let got = normalize(&input, dir.path());
    assert!(got.contains("<TMP>"), "expected <TMP> placeholder in: {got}");
    assert!(
        !got.contains(dir.path().to_str().unwrap()),
        "raw tempdir path leaked into normalised output: {got}"
    );
}

#[test]
fn normalize_rewrites_version_strings() {
    let p = Path::new("/nonexistent");
    let got = normalize("KeyHog v0.5.37\n", p);
    assert_eq!(got, "KeyHog v<N>\n");
    let got = normalize("Build Target: x86_64-linux\n", p);
    // Build target has no leading digit so it must NOT be rewritten - the
    // "Build Target: " needle only fires on digit runs. The host arch
    // string can still drift, but that is acceptable here because the only
    // surface that emits it is `--version`, and that is not one of the
    // seven snapshotted invocations.
    assert_eq!(got, "Build Target: x86_64-linux\n");
}

#[test]
fn normalize_preserves_aws_key_literals() {
    // Critical invariant: the normaliser must NOT eat the AKIA / wJalrXUt
    // literals planted in fixtures. If it does, snapshot drift can mask a
    // real regression where the binary stops emitting the planted key.
    let p = Path::new("/nonexistent");
    let key = "AKIAQYLPMN5HFIQR7XYA";
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let input = format!("found {key} and {secret}\n");
    let got = normalize(&input, p);
    assert!(
        got.contains(key),
        "AKIA literal must survive normalisation: {got}"
    );
    assert!(
        got.contains(secret),
        "secret literal must survive normalisation: {got}"
    );
}

#[test]
fn normalize_rewrites_quoted_json_field() {
    let p = Path::new("/nonexistent");
    let input = "\"version\":\"0.5.37\",\"other\":42\n";
    let got = normalize(input, p);
    assert!(
        got.contains("\"version\":\"<S>\""),
        "expected version field rewrite: {got}"
    );
    assert!(
        got.contains("\"other\":42"),
        "non-target field must survive: {got}"
    );
}
