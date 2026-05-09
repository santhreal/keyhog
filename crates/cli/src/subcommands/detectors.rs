//! Logic for the `detectors` subcommand.

use crate::args::DetectorArgs;
use anyhow::{Context, Result};
use keyhog_core::{validate_detector, DetectorFile, DetectorSpec, QualityIssue};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Exit code for `detectors --audit` when one or more `Error`-severity
/// issues were found. Distinct from the scan exit codes (10 = live
/// credentials, 11 = scanner panic) so a CI gate can treat detector
/// quality as its own signal.
const EXIT_AUDIT_FAILED: u8 = 3;

pub fn run(args: DetectorArgs) -> Result<ExitCode> {
    if args.fix {
        return run_fix(&args);
    }
    if args.audit {
        return run_audit(&args);
    }
    run_list(args)?;
    Ok(ExitCode::SUCCESS)
}

fn run_list(args: DetectorArgs) -> Result<()> {
    let detectors = if args.detectors.exists() && args.detectors.is_dir() {
        keyhog_core::load_detectors(&args.detectors)?
    } else {
        load_embedded_or_bail(&args.detectors)?
    };
    let source = if args.detectors.exists() {
        format!("{}", args.detectors.display())
    } else {
        "embedded".to_string()
    };

    // Apply --search filter case-insensitively against the four most useful
    // fields. The 888-strong corpus is otherwise hard to navigate by eye —
    // `keyhog detectors --search aws` should beat `grep -r aws detectors/`.
    fn contains_ci(haystack: &str, needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return needle.is_empty();
        }
        haystack
            .as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    }
    let needle: Option<Vec<u8>> = args.search.as_ref().map(|s| s.as_bytes().to_vec());
    let filtered: Vec<&DetectorSpec> = detectors
        .iter()
        .filter(|d| match needle.as_deref() {
            None => true,
            Some(q) => {
                contains_ci(&d.id, q)
                    || contains_ci(&d.name, q)
                    || contains_ci(&d.service, q)
                    || d.keywords.iter().any(|k| contains_ci(k, q))
            }
        })
        .collect();

    if let Some(q) = args.search.as_deref() {
        println!(
            "Loaded {} detectors ({source}); {} match '{q}':",
            detectors.len(),
            filtered.len()
        );
    } else {
        println!("Loaded {} detectors ({source}):", detectors.len());
    }

    if args.verbose {
        for d in &filtered {
            print_detector_verbose(d);
        }
        return Ok(());
    }

    let mut by_service: std::collections::BTreeMap<String, Vec<&str>> =
        std::collections::BTreeMap::new();
    for d in &filtered {
        by_service
            .entry(d.service.clone())
            .or_default()
            .push(d.id.as_str());
    }

    for (service, ids) in &by_service {
        println!("  - {} ({} detectors)", service, ids.len());
        for id in ids {
            println!("    - {}", id);
        }
    }

    Ok(())
}

fn load_embedded_or_bail(detectors_path: &Path) -> Result<Vec<DetectorSpec>> {
    let embedded = keyhog_core::embedded_detector_tomls();
    if embedded.is_empty() {
        anyhow::bail!(
            "detector directory '{}' not found and no embedded detectors available. \
             Fix: rebuild with detectors/ directory or specify --detectors <path>",
            detectors_path.display()
        );
    }
    let mut dets = Vec::new();
    for (name, toml_content) in embedded {
        match toml::from_str::<DetectorFile>(toml_content) {
            Ok(file) => dets.push(file.detector),
            Err(e) => eprintln!("warning: failed to parse embedded detector {name}: {e}"),
        }
    }
    Ok(dets)
}

fn run_audit(args: &DetectorArgs) -> Result<ExitCode> {
    let detectors = if args.detectors.exists() && args.detectors.is_dir() {
        keyhog_core::load_detectors(&args.detectors)?
    } else {
        load_embedded_or_bail(&args.detectors)?
    };

    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;
    let mut affected = 0usize;

    for d in &detectors {
        let issues = validate_detector(d);
        if issues.is_empty() {
            continue;
        }
        affected += 1;
        let (e, w): (usize, usize) = issues
            .iter()
            .map(|i| match i {
                QualityIssue::Error(_) => (1, 0),
                QualityIssue::Warning(_) => (0, 1),
            })
            .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
        total_errors += e;
        total_warnings += w;
        println!("\n  {} ({} error(s), {} warning(s))", d.id, e, w);
        for issue in issues {
            match issue {
                QualityIssue::Error(m) => println!("    \x1b[31mERROR\x1b[0m: {m}"),
                QualityIssue::Warning(m) => println!("    \x1b[33mWARN\x1b[0m:  {m}"),
            }
        }
    }

    println!(
        "\nAudit complete: {} detector(s) checked, {} affected, {} error(s), {} warning(s).",
        detectors.len(),
        affected,
        total_errors,
        total_warnings
    );

    if total_errors > 0 {
        Ok(ExitCode::from(EXIT_AUDIT_FAILED))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_fix(args: &DetectorArgs) -> Result<ExitCode> {
    if !args.detectors.exists() || !args.detectors.is_dir() {
        anyhow::bail!(
            "--fix requires a real detectors directory; '{}' does not exist or is not a directory. \
             Embedded detectors are immutable — clone the detectors/ tree from the repo and pass \
             --detectors <DIR>.",
            args.detectors.display()
        );
    }

    let entries = list_toml_files(&args.detectors)?;
    if entries.is_empty() {
        anyhow::bail!(
            "no .toml files found under '{}'. Are you pointing at the right directory?",
            args.detectors.display()
        );
    }

    let mut total_files = 0usize;
    let mut files_changed = 0usize;
    let mut total_rewrites = 0usize;

    for entry in entries {
        total_files += 1;
        let raw = std::fs::read_to_string(&entry)
            .with_context(|| format!("reading {}", entry.display()))?;
        let (rewritten, count) = fix_single_brace_in_verify_blocks(&raw);
        if count == 0 {
            continue;
        }
        // Re-validate by parsing the rewritten content. If serde rejects
        // it (we corrupted the TOML), back off rather than save garbage.
        if toml::from_str::<DetectorFile>(&rewritten).is_err() {
            eprintln!(
                "warn: skipping {} — rewrite produced invalid TOML; please file a bug",
                entry.display()
            );
            continue;
        }
        files_changed += 1;
        total_rewrites += count;
        if args.dry_run {
            println!(
                "would fix {}: {} single-brace → double-brace rewrite(s)",
                entry.display(),
                count
            );
        } else {
            atomic_write(&entry, &rewritten)
                .with_context(|| format!("writing fixed {}", entry.display()))?;
            println!(
                "fixed {}: {} rewrite(s)",
                entry.display(),
                count
            );
        }
    }

    if args.dry_run {
        println!(
            "\nDry-run complete: {} file(s) inspected, {} would change, {} total rewrite(s).",
            total_files, files_changed, total_rewrites
        );
    } else {
        println!(
            "\nFix complete: {} file(s) inspected, {} updated, {} total rewrite(s).",
            total_files, files_changed, total_rewrites
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn list_toml_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let read = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in read {
        let entry = entry.with_context(|| format!("reading entry under {}", dir.display()))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Atomic file replace: write the new content into a tempfile in the same
/// directory, fsync, then rename onto the target. A crash mid-write
/// leaves the original file intact rather than truncating it.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating tempfile in {}", parent.display()))?;
    {
        use std::io::Write;
        let mut handle = tmp.as_file();
        handle.write_all(content.as_bytes())?;
        handle.flush()?;
        handle.sync_all()?;
    }
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Rewrite single-brace `{name}` references to `{{name}}` inside lines
/// that belong to a `[detector.verify*]` block. Returns the new content
/// and the number of rewrites performed.
///
/// Scoped to verify blocks because that's the only place the templating
/// engine runs — `detector.patterns[].regex` and `detector.companions[].regex`
/// also contain braces (regex quantifiers like `{4,6}`) and must not be
/// rewritten. The interpolator is tolerant of `{{var}}` outside verify
/// blocks too, but applying the rewrite there would risk corrupting
/// regex quantifiers.
fn fix_single_brace_in_verify_blocks(toml_text: &str) -> (String, usize) {
    let mut out = String::with_capacity(toml_text.len());
    let mut in_verify = false;
    let mut total = 0usize;
    for line in toml_text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix('[') {
            let header = rest.trim_end_matches(['\r', ' ', '\t']);
            // Header forms: `[detector.verify]`, `[[detector.verify.steps]]`,
            // `[detector.verify.oob]`, etc. Anything else flips us out.
            in_verify = header.starts_with("detector.verify")
                || header.starts_with("[detector.verify")
                || header == "detector.verify]"
                || header == "[detector.verify]]";
            if !in_verify {
                let stripped = header.trim_matches(['[', ']'].as_ref());
                in_verify = stripped.starts_with("detector.verify");
            }
        }
        if in_verify {
            let (rewritten, count) = rewrite_braces_in_string_literals(line);
            total += count;
            out.push_str(&rewritten);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    // Preserve absence of trailing newline if the original lacked one.
    if !toml_text.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    (out, total)
}

/// Rewrite `{name}` → `{{name}}` ONLY inside double-quoted (`"..."`) or
/// single-quoted (`'...'`) string literals on a TOML line. Skips
/// unquoted regions (so regex quantifiers in unkeyed positions don't
/// get touched) and skips already-doubled `{{var}}` patterns.
fn rewrite_braces_in_string_literals(line: &str) -> (String, usize) {
    let mut out = String::with_capacity(line.len());
    let mut count = 0usize;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            // Find matching quote (TOML doesn't support escapes inside
            // single-quoted literal strings; double-quoted strings allow
            // `\"`, which we honour).
            let quote = b;
            out.push(quote as char);
            let mut j = i + 1;
            let mut literal = String::new();
            while j < bytes.len() {
                let c = bytes[j];
                if quote == b'"' && c == b'\\' && j + 1 < bytes.len() {
                    literal.push(c as char);
                    literal.push(bytes[j + 1] as char);
                    j += 2;
                    continue;
                }
                if c == quote {
                    break;
                }
                literal.push(c as char);
                j += 1;
            }
            let (rewritten_literal, c) = rewrite_braces(&literal);
            count += c;
            out.push_str(&rewritten_literal);
            if j < bytes.len() {
                out.push(quote as char);
                i = j + 1;
            } else {
                i = j;
            }
        } else {
            out.push(b as char);
            i += 1;
        }
    }
    (out, count)
}

/// Replace `{name}` with `{{name}}` where `name` matches
/// `[A-Za-z_][A-Za-z0-9_.]*`. Leaves already-doubled `{{name}}` alone
/// and ignores braces that don't open an identifier.
fn rewrite_braces(s: &str) -> (String, usize) {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut count = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Already `{{`? Skip the run of opening braces unchanged.
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                out.push('{');
                out.push('{');
                i += 2;
                continue;
            }
            // Try to parse `{ident}` from here.
            let start = i + 1;
            if start < bytes.len() && (bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
                let mut end = start + 1;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric()
                        || bytes[end] == b'_'
                        || bytes[end] == b'.')
                {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b'}' {
                    // Successful `{ident}` capture — promote to `{{ident}}`.
                    out.push_str("{{");
                    out.push_str(&s[start..end]);
                    out.push_str("}}");
                    count += 1;
                    i = end + 1;
                    continue;
                }
            }
            // Not a templated identifier — pass through.
            out.push('{');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    (out, count)
}

fn print_detector_verbose(d: &DetectorSpec) {
    println!();
    println!("  {}", d.id);
    println!("    name:      {}", d.name);
    println!("    service:   {}", d.service);
    println!("    severity:  {:?}", d.severity);
    if !d.keywords.is_empty() {
        println!("    keywords:  {}", d.keywords.join(", "));
    }
    for (i, p) in d.patterns.iter().enumerate() {
        let label = if d.patterns.len() > 1 {
            format!("pattern[{i}]")
        } else {
            "pattern".to_string()
        };
        println!("    {label}:   {}", p.regex);
        if let Some(desc) = &p.description {
            println!("      desc:    {desc}");
        }
        if let Some(g) = p.group {
            println!("      group:   {g}");
        }
    }
    if !d.companions.is_empty() {
        println!("    companions:");
        for c in &d.companions {
            println!(
                "      - {} (within {} lines, required={}): {}",
                c.name, c.within_lines, c.required, c.regex
            );
        }
    }
    if d.verify.is_some() {
        println!("    verify:    yes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_single_brace_to_double() {
        let (out, n) = rewrite_braces("https://api.example.com/{shop}/orders/{id}");
        assert_eq!(out, "https://api.example.com/{{shop}}/orders/{{id}}");
        assert_eq!(n, 2);
    }

    #[test]
    fn leaves_already_doubled_alone() {
        let (out, n) = rewrite_braces("https://api.example.com/{{shop}}/orders/{{id}}");
        assert_eq!(out, "https://api.example.com/{{shop}}/orders/{{id}}");
        assert_eq!(n, 0);
    }

    #[test]
    fn dotted_identifier_is_recognised() {
        let (out, n) = rewrite_braces("https://api.example.com/{companion.shop}/charge");
        assert_eq!(out, "https://api.example.com/{{companion.shop}}/charge");
        assert_eq!(n, 1);
    }

    #[test]
    fn non_identifier_braces_left_intact() {
        // Regex quantifier shape — must NOT be rewritten.
        let (out, n) = rewrite_braces("[A-Z]{4,6}");
        assert_eq!(out, "[A-Z]{4,6}");
        assert_eq!(n, 0);
    }

    #[test]
    fn rewrites_only_inside_verify_block() {
        let toml = r#"
[detector]
id = "x"

[[detector.patterns]]
regex = "[A-Z]{4}"

[detector.verify]
url = "https://api.example.com/{shop}/orders"
"#;
        let (out, n) = fix_single_brace_in_verify_blocks(toml);
        assert_eq!(n, 1, "only the verify URL should be rewritten");
        assert!(out.contains("regex = \"[A-Z]{4}\""), "regex quantifier untouched");
        assert!(out.contains("/{{shop}}/orders"), "verify URL rewritten");
    }

    #[test]
    fn handles_string_with_escape_sequences() {
        let (out, n) =
            rewrite_braces_in_string_literals(r#"body = "Hello {name}, payload=\"{{value}}\"""#);
        assert!(out.contains("{{name}}"), "got: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn rewrite_is_noop_on_clean_file() {
        let toml = r#"
[detector]
id = "demo"

[detector.verify]
url = "https://api.example.com/{{companion.shop}}"
"#;
        let (out, n) = fix_single_brace_in_verify_blocks(toml);
        assert_eq!(n, 0);
        assert_eq!(out.trim(), toml.trim());
    }
}
