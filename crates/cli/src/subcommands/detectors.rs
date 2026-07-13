//! Logic for the `detectors` subcommand.

mod brace_rewrite;

use brace_rewrite::{
    fix_single_brace_in_verify_blocks, rewrite_braces, rewrite_braces_in_string_literals,
};

use crate::args::DetectorArgs;
use crate::exit_codes::EXIT_DETECTOR_AUDIT_FAILED;
use crate::style;
use anyhow::{Context, Result};
use keyhog_core::{
    contains_bytes_ignore_ascii_case, validate_detector, DetectorFile, DetectorSpec, QualityIssue,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn run(args: DetectorArgs) -> Result<ExitCode> {
    crate::orchestrator_config::validate_explicit_detector_path(
        &args.detectors,
        args.detectors_cli_explicit,
    )?;
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
    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&args.detectors)?;
    let source = if args.detectors.exists() {
        format!("{}", args.detectors.display())
    } else {
        "embedded".to_string()
    };

    // Apply --search filter case-insensitively against the four most useful
    // fields. The full embedded corpus is otherwise hard to navigate by eye -
    // `keyhog detectors --search aws` should beat `grep -r aws detectors/`.
    let needle: Option<Vec<u8>> = args.search.as_ref().map(|s| s.as_bytes().to_vec());
    let filtered: Vec<&DetectorSpec> = detectors
        .iter()
        .filter(|d| match needle.as_deref() {
            None => true,
            Some(q) => {
                contains_bytes_ignore_ascii_case(&d.id, q)
                    || contains_bytes_ignore_ascii_case(&d.name, q)
                    || contains_bytes_ignore_ascii_case(&d.service, q)
                    || d.keywords
                        .iter()
                        .any(|k| contains_bytes_ignore_ascii_case(k, q))
            }
        })
        .collect();

    let want_json = matches!(args.format, Some(crate::args::DetectorFormat::Json));
    if want_json {
        print_detectors_json(&filtered)?;
        return Ok(());
    }

    if args.search.is_some() && filtered.is_empty() {
        return Ok(());
    }

    let p = style::for_stdout();
    if let Some(q) = args.search.as_deref() {
        println!(
            "Loaded {green}{len}{reset} {dim}detectors{reset} {dim}({source}){reset}; {green}{match_len}{reset} match '{q}':",
            green = p.green,
            len = detectors.len(),
            reset = p.reset,
            dim = p.dim,
            source = source,
            match_len = filtered.len(),
        );
    } else {
        println!(
            "Loaded {green}{len}{reset} {dim}detectors{reset} {dim}({source}){reset}:",
            green = p.green,
            len = detectors.len(),
            reset = p.reset,
            dim = p.dim,
            source = source,
        );
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
        println!(
            "  - {bold}{cyan}{service}{reset} {dim}({reset}{green}{count}{reset}{dim} detectors){reset}",
            bold = p.bold,
            cyan = p.cyan,
            service = service,
            reset = p.reset,
            dim = p.dim,
            green = p.green,
            count = ids.len(),
        );
        for id in ids {
            println!("    - {}", id);
        }
    }

    Ok(())
}

/// Programmatic detector discovery: emits a JSON array on stdout in
/// schema-stable form. The `policy` object exposes detector-local admission
/// knobs so automation never has to reconstruct them from scanner defaults or
/// a Rust-side detector-id table.
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
                "policy": {
                    "kind": d.kind,
                    "min_confidence": d.min_confidence,
                    "entropy_floor": d.entropy_floor,
                    "entropy_high": d.entropy_high,
                    "entropy_low": d.entropy_low,
                    "entropy_very_high": d.entropy_very_high,
                    "mixed_alnum_floor": d.mixed_alnum_floor,
                    "bpe_enabled": d.bpe_enabled,
                    "bpe_max_bytes_per_token": d.bpe_max_bytes_per_token,
                    "decoded_hex_key_material_lengths": d.decoded_hex_key_material_lengths,
                    "canonical_hex_key_material": d.canonical_hex_key_material,
                    "keyword_free_min_len": d.keyword_free_min_len,
                    "min_len": d.min_len,
                    "max_len": d.max_len,
                    "allowlist_paths": d.allowlist_paths,
                    "allowlist_values": d.allowlist_values,
                    "stopwords": d.stopwords,
                    "structural_password_slot": d.structural_password_slot,
                    "weak_anchor": d.weak_anchor,
                    "private_key_block": d.private_key_block,
                    "credential_shape": d.credential_shape,
                },
            })
        })
        .collect();
    let out =
        serde_json::to_string_pretty(&items).context("serializing detector listing to JSON")?;
    println!("{out}");
    Ok(())
}

fn run_audit(args: &DetectorArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&args.detectors)?;

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
    let mut planned_rewrites: Vec<(PathBuf, String, usize)> = Vec::new();
    let mut invalid_rewrites: Vec<(PathBuf, String)> = Vec::new();

    for entry in entries {
        total_files += 1;
        let raw = keyhog_core::read_detector_toml_file(&entry)
            .with_context(|| format!("reading {}", entry.display()))?;
        let (rewritten, count) = fix_single_brace_in_verify_blocks(&raw);
        if count == 0 {
            continue;
        }
        // Re-validate by parsing the rewritten content. If serde rejects
        // it (or the input detector was already malformed), abort before
        // writing any file. A mutation command exiting 0 after skipping a
        // rewrite makes the operator believe the directory was fixed.
        if let Err(error) = toml::from_str::<DetectorFile>(&rewritten) {
            invalid_rewrites.push((entry, error.to_string()));
            continue;
        }
        planned_rewrites.push((entry, rewritten, count));
    }

    if !invalid_rewrites.is_empty() {
        let details = invalid_rewrites
            .iter()
            .map(|(path, error)| format!("  - {}: {error}", path.display()))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "--fix could not safely rewrite {} detector file(s); no files were written.\n{details}\n\
             Fix the detector TOML or file a bug with the rewrite candidate.",
            invalid_rewrites.len()
        );
    }

    let files_changed = planned_rewrites.len();
    let total_rewrites = planned_rewrites
        .iter()
        .map(|(_, _, count)| *count)
        .sum::<usize>();

    for (entry, rewritten, count) in planned_rewrites {
        if args.dry_run {
            println!(
                "would fix {}: {} single-brace -> double-brace rewrite(s)",
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
