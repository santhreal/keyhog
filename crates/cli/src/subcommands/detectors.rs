//! Logic for the `detectors` subcommand.

mod brace_rewrite;

use brace_rewrite::{
    fix_single_brace_in_verify_blocks, rewrite_braces, rewrite_braces_in_string_literals,
};

use crate::args::DetectorArgs;
use crate::exit_codes::EXIT_DETECTOR_AUDIT_FAILED;
use crate::style;
use anyhow::{Context, Result};
use keyhog_core::{validate_detector, DetectorFile, DetectorSpec, QualityIssue};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn run(args: DetectorArgs) -> Result<ExitCode> {
    // The optional `list` verb names the default action explicitly, so it is
    // incompatible with the alternate actions `--audit` / `--fix`: `keyhog
    // detectors list --audit` would be asking for two different verbs at once.
    // Reject loudly instead of silently letting `--audit`/`--fix` win, so the
    // operator's intent and the action taken can never disagree.
    if args.verb.as_deref() == Some("list") && (args.audit || args.fix) {
        anyhow::bail!(
            "`keyhog detectors list` is the (default) list action and cannot be \
             combined with `--audit` or `--fix`. Drop `list` to audit/fix, or \
             drop the flag to list."
        );
    }
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
    // fields. The full embedded corpus is otherwise hard to navigate by eye -
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

    // Resolve the effective output format. `--format` is canonical (CLI-01);
    // `--json` is the back-compat alias. They are mutually exclusive at the clap
    // layer, so at most one is set — either selecting JSON yields JSON.
    let want_json = args.json || matches!(args.format, Some(crate::args::DetectorFormat::Json));
    if want_json {
        print_detectors_json(&filtered)?;
        return Ok(());
    }

    if args.search.is_some() && filtered.is_empty() {
        return Ok(());
    }

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

/// Programmatic detector discovery: emits a JSON array on stdout in
/// schema-stable form. Same field shape as `print_detector_verbose`
/// so the human and machine views stay in sync.
fn print_detectors_json(detectors: &[&DetectorSpec]) -> Result<()> {
    use serde_json::{json, Value};
    let items: Vec<Value> = detectors
        .iter()
        .map(|d| {
            let patterns: Vec<Value> = d
                .patterns
                .iter()
                .map(|p| {
                    json!({
                        "regex": p.regex,
                        "description": p.description,
                        "group": p.group,
                    })
                })
                .collect();
            let companions: Vec<Value> = d
                .companions
                .iter()
                .map(|c| {
                    json!({
                        "name": c.name,
                        "regex": c.regex,
                        "within_lines": c.within_lines,
                        "required": c.required,
                    })
                })
                .collect();
            json!({
                "id": d.id,
                "name": d.name,
                "service": d.service,
                "severity": format!("{:?}", d.severity),
                "keywords": d.keywords,
                "patterns": patterns,
                "companions": companions,
                "verify": d.verify.is_some(),
            })
        })
        .collect();
    let out =
        serde_json::to_string_pretty(&items).context("serializing detector listing to JSON")?;
    println!("{out}");
    Ok(())
}

fn load_embedded_or_bail(detectors_path: &Path) -> Result<Vec<DetectorSpec>> {
    let dets = keyhog_core::load_embedded_detectors_or_fail()
        .context("parsing embedded detector corpus")?;
    if dets.is_empty() {
        anyhow::bail!(
            "detector directory '{}' not found and no embedded detectors available. \
             Fix: rebuild with detectors/ directory or specify --detectors <path>",
            detectors_path.display()
        );
    }
    Ok(dets)
}

fn run_audit(args: &DetectorArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
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
                QualityIssue::Error(m) => println!("    {}: {m}", style::fail("ERROR", &palette)),
                QualityIssue::Warning(m) => {
                    println!("    {}:  {m}", style::warn("WARN", &palette));
                }
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
        Ok(ExitCode::from(EXIT_DETECTOR_AUDIT_FAILED))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_fix(args: &DetectorArgs) -> Result<ExitCode> {
    if !args.detectors.exists() || !args.detectors.is_dir() {
        anyhow::bail!(
            "--fix requires a real detectors directory; '{}' does not exist or is not a directory. \
             Embedded detectors are immutable: clone the detectors/ tree from the repo and pass \
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
                "warn: skipping {}: rewrite produced invalid TOML; please file a bug",
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
            crate::atomic_file::write_bytes(&entry, rewritten.as_bytes())
                .with_context(|| format!("atomically writing fixed {}", entry.display()))?;
            println!("fixed {}: {} rewrite(s)", entry.display(), count);
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
    let read =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
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

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) fn rewrite_braces(s: &str) -> (String, usize) {
        super::rewrite_braces(s)
    }

    pub(crate) fn fix_single_brace_in_verify_blocks(toml_text: &str) -> (String, usize) {
        super::fix_single_brace_in_verify_blocks(toml_text)
    }

    pub(crate) fn fix_verify_braces_for_test(toml_text: &str) -> (String, usize) {
        super::fix_single_brace_in_verify_blocks(toml_text)
    }

    pub(crate) fn rewrite_braces_in_string_literals(line: &str) -> (String, usize) {
        super::rewrite_braces_in_string_literals(line)
    }
}
