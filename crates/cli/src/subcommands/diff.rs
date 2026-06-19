//! `keyhog diff <baseline-a.json> <baseline-b.json>` - finding-set diff.
//!
//! Tier-B moat innovation #10 from docs/EXECUTION_PLAN.md: surface the
//! delta between two scan results so CI can gate merges on "no NEW secrets"
//! regardless of how many baselined secrets remain.
//!
//! Inputs are baseline JSON files produced by `keyhog scan --create-baseline`
//! (so the same format applies to ad-hoc snapshots taken in CI).
//!
//! Outputs three sections:
//!   NEW       - entries present in `after` that were not in `before`.
//!   RESOLVED  - entries present in `before` that are no longer in `after`.
//!   UNCHANGED - entries present in both (suppressible with --hide-unchanged).
//!
//! Exit codes:
//!   0 - no NEW entries.
//!   1 - NEW entries exist (signals a regression to CI).

use crate::args::DiffArgs;
use crate::baseline::Baseline;
use crate::exit_codes::EXIT_FINDINGS;
use anyhow::Result;
use std::process::ExitCode;

pub(crate) fn run(args: DiffArgs) -> Result<ExitCode> {
    ensure_baseline_input(&args.before)?;
    ensure_baseline_input(&args.after)?;

    let before = Baseline::load(&args.before)?;
    let after = Baseline::load(&args.after)?;

    let before_index = before.index_set();
    let after_index = after.index_set();

    let mut new_entries: Vec<&crate::baseline::BaselineEntry> = after
        .entries
        .iter()
        .filter(|e| !before_index.contains(&(e.detector_id.clone(), e.credential_hash.clone())))
        .collect();
    let mut resolved_entries: Vec<&crate::baseline::BaselineEntry> = before
        .entries
        .iter()
        .filter(|e| !after_index.contains(&(e.detector_id.clone(), e.credential_hash.clone())))
        .collect();
    let mut unchanged_entries: Vec<&crate::baseline::BaselineEntry> = after
        .entries
        .iter()
        .filter(|e| before_index.contains(&(e.detector_id.clone(), e.credential_hash.clone())))
        .collect();

    new_entries.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    resolved_entries.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    unchanged_entries.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));

    if args.json {
        let payload = serde_json::json!({
            "new": new_entries,
            "resolved": resolved_entries,
            "unchanged": if args.hide_unchanged {
                serde_json::Value::Null
            } else {
                serde_json::to_value(&unchanged_entries)?
            },
            "summary": {
                "new": new_entries.len(),
                "resolved": resolved_entries.len(),
                "unchanged": unchanged_entries.len(),
                "new_count": new_entries.len(),
                "resolved_count": resolved_entries.len(),
                "unchanged_count": unchanged_entries.len(),
            }
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print_human(
            &new_entries,
            &resolved_entries,
            &unchanged_entries,
            args.hide_unchanged,
        );
    }

    if new_entries.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_FINDINGS))
    }
}

fn ensure_baseline_input(path: &std::path::Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    anyhow::bail!(
        "baseline file {} does not exist or is not a regular file",
        path.display()
    );
}

fn print_human(
    new: &[&crate::baseline::BaselineEntry],
    resolved: &[&crate::baseline::BaselineEntry],
    unchanged: &[&crate::baseline::BaselineEntry],
    hide_unchanged: bool,
) {
    let palette = crate::style::for_stdout();
    let red = |s: &str| format!("{}{}{}", palette.red, s, palette.reset);
    let green = |s: &str| format!("{}{}{}", palette.green, s, palette.reset);
    let dim = |s: &str| format!("{}{}{}", palette.dim, s, palette.reset);

    println!("keyhog diff");
    println!();
    println!(
        "  {} new   {} resolved   {} unchanged",
        red(&format!("FAIL {}", new.len())),
        green(&format!("PASS {}", resolved.len())),
        dim(&format!("= {}", unchanged.len()))
    );
    println!();

    if !new.is_empty() {
        println!("{}", red("NEW (regressions):"));
        for e in new {
            println!(
                "  {} {} @ {}{}",
                red("+"),
                e.detector_id,
                e.file_path.as_deref().unwrap_or("<unknown>"), // LAW10: absent path/field => display placeholder for REPORTING only; finding still emitted, recall-safe
                e.line.map(|l| format!(":{l}")).unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
            );
        }
        println!();
    }

    if !resolved.is_empty() {
        println!("{}", green("RESOLVED:"));
        for e in resolved {
            println!(
                "  {} {} @ {}{}",
                green("-"),
                e.detector_id,
                e.file_path.as_deref().unwrap_or("<unknown>"), // LAW10: absent path/field => display placeholder for REPORTING only; finding still emitted, recall-safe
                e.line.map(|l| format!(":{l}")).unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
            );
        }
        println!();
    }

    if !hide_unchanged && !unchanged.is_empty() {
        println!("{}", dim("UNCHANGED:"));
        for e in unchanged {
            println!(
                "  {} {} @ {}{}",
                dim("="),
                e.detector_id,
                e.file_path.as_deref().unwrap_or("<unknown>"), // LAW10: absent path/field => display placeholder for REPORTING only; finding still emitted, recall-safe
                e.line.map(|l| format!(":{l}")).unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
            );
        }
        println!();
    }

    if new.is_empty() {
        println!("{}", green("PASS no new findings"));
    } else {
        println!(
            "{}",
            red(&format!(
                "FAIL {} regression{}",
                new.len(),
                if new.len() == 1 { "" } else { "s" }
            ))
        );
    }
}
