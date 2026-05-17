//! `vyre-lints` CLI. Runs the lint suite against a workspace.
//!
//! Usage:
//!   vyre-lints --workspace-root . [--allowlist vyre-lints/allowlist.toml] [--format json|text]
//!
//! Exits 0 if no violations (after allowlist filter). Exits 1 if any
//! violation. Exit 2 on I/O / parse failure.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use vyre_lints::{run_raw_ir_in_libs, Violation};

#[derive(Parser, Debug)]
#[command(
    name = "vyre-lints",
    version,
    about = "Lego-block enforcement lints for vyre"
)]
struct Cli {
    /// Workspace root (the dir containing vyre-libs/, vyre-foundation/, ...).
    #[arg(long, default_value = ".")]
    workspace_root: PathBuf,

    /// Allowlist file. If omitted, defaults to <workspace_root>/vyre-lints/allowlist.toml.
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Output format: text (default) or json.
    #[arg(long, default_value = "text")]
    format: Format,

    /// Override the lib roots scanned. Defaults to vyre-libs/src.
    #[arg(long)]
    lib_root: Option<PathBuf>,

    /// Run the allowlist drift sentinel: fail if any allowlist entry
    /// is older than `--drift-budget-days` (default 14). Skips the
    /// raw-IR scan when set.
    #[arg(long)]
    check_drift: bool,

    /// Age budget for the drift sentinel, in days.
    #[arg(long, default_value_t = vyre_lints::drift::DEFAULT_AGE_BUDGET_DAYS)]
    drift_budget_days: i64,

    /// Today's date in YYYY-MM-DD form. Defaults to the OS clock.
    #[arg(long)]
    today: Option<String>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let allowlist = cli
        .allowlist
        .clone()
        .unwrap_or_else(|| cli.workspace_root.join("vyre-lints/allowlist.toml"));

    if cli.check_drift {
        return run_drift(&allowlist, cli.drift_budget_days, cli.today.as_deref());
    }

    let lib_root = cli
        .lib_root
        .unwrap_or_else(|| cli.workspace_root.join("vyre-libs/src"));
    if !lib_root.exists() {
        anyhow::bail!("lib root not found: {}", lib_root.display());
    }
    let allowlist_arg = if allowlist.exists() {
        Some(allowlist.as_path())
    } else {
        None
    };

    let violations = run_raw_ir_in_libs(&[lib_root.as_path()], allowlist_arg)
        .context("running raw_ir_in_libs lint")?;

    match cli.format {
        Format::Text => emit_text(&violations),
        Format::Json => emit_json(&violations)?,
    }

    if violations.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn run_drift(allowlist: &std::path::Path, budget_days: i64, today_override: Option<&str>) -> Result<()> {
    if !allowlist.exists() {
        anyhow::bail!("allowlist not found: {}", allowlist.display());
    }
    let today = match today_override {
        Some(s) => s.to_string(),
        None => current_iso_date(),
    };
    let resolver = vyre_lints::drift::GitBlameResolver::with_today(today);
    let findings = vyre_lints::drift::run(allowlist, budget_days, &resolver)
        .context("running allowlist drift sentinel")?;
    if findings.is_empty() {
        println!("vyre-lints drift: 0 stale entries (budget {budget_days} days)");
        return Ok(());
    }
    println!(
        "vyre-lints drift: {} stale entry(ies) — every entry should land its migration ticket within {budget_days} days.",
        findings.len()
    );
    for f in &findings {
        println!("{}", vyre_lints::drift::format_finding(f, budget_days));
    }
    std::process::exit(1);
}

fn current_iso_date() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = now.div_euclid(86_400);
    iso_from_days(days)
}

fn iso_from_days(mut days: i64) -> String {
    let mut y = 1970i64;
    let is_leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    loop {
        let len = if is_leap(y) { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        y += 1;
    }
    let months: [i64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    while days >= months[m] {
        days -= months[m];
        m += 1;
    }
    format!("{y:04}-{:02}-{:02}", m + 1, days + 1)
}

fn emit_text(violations: &[Violation]) {
    if violations.is_empty() {
        println!("vyre-lints: 0 violations");
        return;
    }
    for v in violations {
        println!("{}:{}:{}: {}", v.file, v.line, v.column, v.message);
    }
    println!("vyre-lints: {} violation(s)", violations.len());
}

fn emit_json(violations: &[Violation]) -> Result<()> {
    use std::fmt::Write;
    let mut out = String::from("[\n");
    for (i, v) in violations.iter().enumerate() {
        let kind = match v.kind {
            vyre_lints::ViolationKind::RawNodeConstruction => "raw_node_construction",
            vyre_lints::ViolationKind::RawExprConstruction => "raw_expr_construction",
        };
        if i > 0 {
            out.push_str(",\n");
        }
        write!(
            out,
            "  {{\"file\":{:?},\"line\":{},\"column\":{},\"kind\":{:?},\"message\":{:?}}}",
            v.file, v.line, v.column, kind, v.message
        )?;
    }
    out.push_str("\n]\n");
    print!("{out}");
    Ok(())
}
