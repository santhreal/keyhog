//! `keyhog diff <baseline-a.json> <baseline-b.json>` — finding-set diff.
//!
//! Tier-B moat innovation #10 from audits/legendary-2026-04-26: surface the
//! delta between two scan results so CI can gate merges on "no NEW secrets"
//! regardless of how many baselined secrets remain.
//!
//! Inputs are baseline JSON files produced by `keyhog scan --create-baseline`
//! (so the same format applies to ad-hoc snapshots taken in CI).
//!
//! Outputs three sections:
//!   NEW       — entries present in `after` that were not in `before`.
//!   RESOLVED  — entries present in `before` that are no longer in `after`.
//!   UNCHANGED — entries present in both (suppressible with --hide-unchanged).
//!
//! Exit codes:
//!   0 — no NEW entries.
//!   1 — NEW entries exist (signals a regression to CI).

use crate::args::DiffArgs;
use crate::baseline::Baseline;
use anyhow::Result;
use std::process::ExitCode;

pub fn run(args: DiffArgs) -> Result<ExitCode> {
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
        Ok(ExitCode::from(1))
    }
}

fn print_human(
    new: &[&crate::baseline::BaselineEntry],
    resolved: &[&crate::baseline::BaselineEntry],
    unchanged: &[&crate::baseline::BaselineEntry],
    hide_unchanged: bool,
) {
    use std::io::IsTerminal;
    let color = std::io::stdout().is_terminal();
    let red = |s: &str| {
        if color {
            format!("\x1b[31m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let green = |s: &str| {
        if color {
            format!("\x1b[32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let dim = |s: &str| {
        if color {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };

    println!("\u{1F500} keyhog diff");
    println!();
    println!(
        "  {} new   {} resolved   {} unchanged",
        red(&format!("\u{2716} {}", new.len())),
        green(&format!("\u{2714} {}", resolved.len())),
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
                e.file_path.as_deref().unwrap_or("<unknown>"),
                e.line.map(|l| format!(":{l}")).unwrap_or_default()
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
                e.file_path.as_deref().unwrap_or("<unknown>"),
                e.line.map(|l| format!(":{l}")).unwrap_or_default()
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
                e.file_path.as_deref().unwrap_or("<unknown>"),
                e.line.map(|l| format!(":{l}")).unwrap_or_default()
            );
        }
        println!();
    }

    if new.is_empty() {
        println!("{}", green("\u{2714} no new findings"));
    } else {
        println!(
            "{}",
            red(&format!(
                "\u{2716} {} regression{}",
                new.len(),
                if new.len() == 1 { "" } else { "s" }
            ))
        );
    }
}
