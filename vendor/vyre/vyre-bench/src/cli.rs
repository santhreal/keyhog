#![allow(missing_docs)]

use clap::{Parser, Subcommand};
use std::collections::BTreeMap;

use crate::api::case::BenchId;
use crate::api::suite::SuiteKind;
use crate::report::json::ReportSchema;
use crate::runner::{execute_suite, RunConfig};

const MAX_REPORT_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "vyre-bench")]
#[command(about = "Canonical performance and evolution harness for Vyre", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(long)]
        suite: String,
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        enforce_budgets: bool,
        #[arg(long = "case")]
        case_ids: Vec<String>,
        #[arg(long, default_value_t = 3)]
        warmup_samples: usize,
        #[arg(long)]
        measured_samples: Option<usize>,
        #[arg(long, default_value_t = 30)]
        sample_timeout_secs: u64,
        #[arg(long)]
        snapshot_on_pass: bool,
        #[arg(long, default_value_t = 1)]
        determinism_runs: usize,
        #[arg(long)]
        workgroup_size: Option<u32>,
        #[arg(long)]
        roofline_only: bool,
        #[arg(long)]
        output: Option<String>,
    },
    Compare {
        #[arg(long)]
        baseline: String,
        #[arg(long)]
        candidate: String,
    },
    SnapshotDiff {
        #[arg(long)]
        base: String,
    },
    List {
        #[arg(long, default_value = "table")]
        format: String,
    },
    Explain {
        id: String,
    },
    Dashboard {
        #[arg(long, default_value = "dashboard")]
        output: String,
    },
    ReleaseMatrix {
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        enforce: bool,
    },
    EvolveServer,
}

pub fn run_cli() -> anyhow::Result<()> {
    env_logger::init();
    run_cli_with(std::env::args_os())
}

pub fn run_cli_with<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    match &cli.command {
        Commands::Run {
            suite,
            format,
            backend,
            enforce_budgets,
            case_ids,
            warmup_samples,
            measured_samples,
            sample_timeout_secs,
            snapshot_on_pass,
            determinism_runs,
            workgroup_size,
            roofline_only,
            output,
        } => {
            let suite_kind: SuiteKind = suite
                .parse()
                .map_err(|error: String| anyhow::anyhow!("{error}"))?;
            let registry = crate::registry::collect_all();
            let config = RunConfig {
                backend_id: backend.clone(),
                enforce_budgets: *enforce_budgets,
                case_ids: case_ids.clone(),
                warmup_samples: *warmup_samples,
                measured_samples: *measured_samples,
                sample_timeout: std::time::Duration::from_secs(*sample_timeout_secs),
                determinism_runs: *determinism_runs,
                workgroup_override: workgroup_size.map(|size| [size, 1, 1]),
                baseline_warmup_runs: 0,
                snapshot_on_pass: *snapshot_on_pass,
            };
            let reports = execute_run_matrix(&registry, suite_kind, &config)?;
            if let Some(output) = output {
                write_run_reports(&reports, output)?;
            }
            for report in &reports {
                crate::runner::print_report(report, format, *roofline_only)?;
            }

            let failed: usize = reports.iter().map(|report| report.summary.failed).sum();
            if failed > 0 {
                anyhow::bail!("{failed} benchmark case(s) failed");
            }
        }
        Commands::Compare {
            baseline,
            candidate,
        } => {
            let baseline_report = load_report(baseline)?;
            let candidate_report = load_report(candidate)?;
            compare_reports(&baseline_report, &candidate_report)?;
        }
        Commands::SnapshotDiff { base } => {
            let snapshots_dir = std::path::Path::new("snapshots");
            let path = snapshots_dir.join(format!("{}.json", base));
            if !path.exists() {
                anyhow::bail!("snapshot for commit `{}` not found in snapshots/", base);
            }
            let baseline_report = load_report(&path.to_string_lossy())?;
            let registry = crate::registry::collect_all();
            let config = RunConfig::default();
            let current_report = execute_suite(&registry, SuiteKind::Release, &config);
            compare_reports(&baseline_report, &current_report)?;
        }
        Commands::List { format } => list_cases(format)?,
        Commands::Explain { id } => explain_case(id)?,
        Commands::Dashboard { output } => generate_dashboard(output)?,
        Commands::ReleaseMatrix {
            format,
            output,
            enforce,
        } => {
            let registry = crate::registry::collect_all();
            let matrix = crate::release_matrix::build_release_matrix(&registry);
            crate::release_matrix::emit_release_matrix(&matrix, format, output.as_deref())?;
            if *enforce {
                crate::release_matrix::enforce_release_matrix(&matrix)?;
            }
        }
        Commands::EvolveServer => crate::evolve::server::run_evolve_server()?,
    }
    Ok(())
}

fn execute_run_matrix(
    registry: &crate::registry::BenchRegistry,
    suite: SuiteKind,
    config: &RunConfig,
) -> anyhow::Result<Vec<ReportSchema>> {
    match suite {
        SuiteKind::CrossBackend if config.backend_id.is_none() => {
            let mut reports = Vec::new();
            for backend in dispatch_backend_ids() {
                let mut cfg = config.clone();
                cfg.backend_id = Some(backend.to_string());
                reports.push(execute_suite(registry, suite, &cfg));
            }
            Ok(reports)
        }
        SuiteKind::Sweep if config.workgroup_override.is_none() => {
            let mut reports = Vec::new();
            for size in [32, 64, 128, 256] {
                let mut cfg = config.clone();
                cfg.workgroup_override = Some([size, 1, 1]);
                reports.push(execute_suite(registry, suite, &cfg));
            }
            Ok(reports)
        }
        _ => Ok(vec![execute_suite(registry, suite, config)]),
    }
}

fn dispatch_backend_ids() -> Vec<&'static str> {
    vyre_driver::backend::registered_backends_by_precedence_slice()
        .iter()
        .filter(|backend| vyre_driver::backend::backend_dispatches(backend.id))
        .map(|backend| backend.id)
        .collect()
}

fn write_run_reports(reports: &[ReportSchema], output: &str) -> anyhow::Result<()> {
    let output = std::path::Path::new(output);
    if reports.len() == 1 {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            output,
            format!(
                "{}\n",
                crate::report::json::generate_json_report(&reports[0])?
            ),
        )?;
        return Ok(());
    }
    std::fs::create_dir_all(output)?;
    for (index, report) in reports.iter().enumerate() {
        let suite = sanitize_path_component(&report.suite);
        let backend = report
            .selected_backend
            .as_deref()
            .map(sanitize_path_component)
            .unwrap_or_else(|| "unknown-backend".to_string());
        let path = output.join(format!("{suite}-{backend}-{index:03}.json"));
        std::fs::write(
            path,
            format!("{}\n", crate::report::json::generate_json_report(report)?),
        )?;
    }
    Ok(())
}

fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn list_cases(format: &str) -> anyhow::Result<()> {
    let registry = crate::registry::collect_all();
    let metadata: Vec<_> = registry.iter().map(|case| case.metadata()).collect();
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&metadata)?);
        return Ok(());
    }
    for meta in metadata {
        println!("{} ({}) {}", meta.id.0, meta.name, meta.description);
    }
    Ok(())
}

fn explain_case(id: &str) -> anyhow::Result<()> {
    let registry = crate::registry::collect_all();
    let case = registry
        .get(&BenchId(id.to_string()))
        .ok_or_else(|| anyhow::anyhow!("unknown benchmark `{id}`"))?;
    let mut details = BTreeMap::new();
    details.insert("metadata", serde_json::to_value(case.metadata())?);
    details.insert("requirements", serde_json::to_value(case.requirements())?);
    details.insert(
        "performance_contract",
        serde_json::to_value(case.performance_contract())?,
    );
    println!("{}", serde_json::to_string_pretty(&details)?);
    Ok(())
}

fn compare_reports(baseline: &ReportSchema, candidate: &ReportSchema) -> anyhow::Result<()> {
    let baseline_cases: BTreeMap<_, _> = baseline
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect();

    let mut regressed = false;

    println!(
        "{:<30} | {:<12} | {:<12} | {:<10} | {:<12} | {:<10}",
        "Benchmark", "Baseline", "Candidate", "Delta", "p-value", "Verdict"
    );
    println!(
        "------------------------------------------------------------------------------------------------"
    );
    for case in &candidate.cases {
        let baseline_case = baseline_cases
            .get(case.id.as_str())
            .ok_or_else(|| anyhow::anyhow!("candidate case `{}` has no baseline", case.id))?;
        let baseline_stats = baseline_case
            .metrics
            .get("wall_ns")
            .ok_or_else(|| anyhow::anyhow!("baseline case `{}` lacks wall_ns", case.id))?;
        let candidate_stats = case
            .metrics
            .get("wall_ns")
            .ok_or_else(|| anyhow::anyhow!("candidate case `{}` lacks wall_ns", case.id))?;
        let baseline_p50 = baseline_stats.p50;
        let candidate_p50 = candidate_stats.p50;
        let delta_fraction = if baseline_p50 == 0 {
            None
        } else {
            Some((candidate_p50 as f64 - baseline_p50 as f64) / baseline_p50 as f64)
        };
        let delta = if let Some(delta_fraction) = delta_fraction {
            format!("{:+.2}%", delta_fraction * 100.0)
        } else {
            "n/a".to_string()
        };
        let p_value = welch_p_value(baseline_stats, candidate_stats);
        let p_value_str = p_value
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "n/a".to_string());
        let verdict = compare_verdict(delta_fraction, p_value);

        // check regression: regresses by > 1 sigma
        // regression means candidate mean > baseline mean + baseline stddev
        if candidate_stats.mean > baseline_stats.mean + baseline_stats.stddev {
            regressed = true;
        }

        println!(
            "{:<30} | {:<12} | {:<12} | {:<10} | {:<12} | {:<10}",
            case.id, baseline_p50, candidate_p50, delta, p_value_str, verdict
        );
    }

    if regressed {
        anyhow::bail!("One or more cases regressed by >1σ");
    }

    Ok(())
}

fn compare_verdict(delta_fraction: Option<f64>, p_value: Option<f64>) -> &'static str {
    match (delta_fraction, p_value) {
        (Some(delta), Some(p)) if delta > 0.05 && p < 0.05 => "regress",
        (Some(delta), Some(p)) if delta < -0.05 && p < 0.05 => "improve",
        (Some(delta), _) if delta.abs() <= 0.05 => "flat",
        _ => "noisy",
    }
}

fn welch_p_value(
    baseline: &crate::api::metric::MetricStats,
    candidate: &crate::api::metric::MetricStats,
) -> Option<f64> {
    if baseline.samples < 2 || candidate.samples < 2 {
        return None;
    }
    let n1 = f64::from(baseline.samples);
    let n2 = f64::from(candidate.samples);
    let variance = baseline.stddev.powi(2) / n1 + candidate.stddev.powi(2) / n2;
    if variance <= f64::EPSILON {
        return (baseline.mean != candidate.mean)
            .then_some(0.0)
            .or(Some(1.0));
    }
    let t = (candidate.mean - baseline.mean).abs() / variance.sqrt();
    Some((2.0 * (1.0 - normal_cdf(t))).clamp(0.0, 1.0))
}

fn normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
}

fn load_report(path: &str) -> anyhow::Result<ReportSchema> {
    let bytes = read_report_bounded(std::path::Path::new(path))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_report_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_REPORT_INPUT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("benchmark report exceeds {MAX_REPORT_INPUT_BYTES} byte limit"),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_REPORT_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REPORT_INPUT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "benchmark report exceeded bounded read limit",
        ));
    }
    Ok(bytes)
}

fn generate_dashboard(output_dir: impl AsRef<str>) -> anyhow::Result<()> {
    let output = std::path::Path::new(output_dir.as_ref());
    std::fs::create_dir_all(output)?;
    std::fs::create_dir_all(output.join("data"))?;
    std::fs::create_dir_all(output.join("history"))?;

    // Find latest snapshot
    let snapshots_dir = std::path::Path::new("snapshots");
    let latest = find_latest_snapshot(snapshots_dir)?;
    let report: ReportSchema = load_report(&latest.to_string_lossy())?;

    // Copy raw data
    std::fs::copy(&latest, output.join("data/results.json"))?;

    // Generate scorecard markdown
    let scorecard_md = generate_scorecard_md(&report);
    std::fs::write(output.join("scorecard.md"), &scorecard_md)?;

    // Generate per-case SVG bar charts
    for case in &report.cases {
        let svg = generate_case_svg(case);
        let filename = case.id.replace('.', "_") + ".svg";
        std::fs::write(output.join(&filename), &svg)?;
    }

    // Generate cross-backend SVG
    let cross_svg = generate_cross_backend_svg(&report);
    std::fs::write(output.join("cross-backend.svg"), &cross_svg)?;

    // Generate index.html
    let html = generate_index_html(&report, &scorecard_md);
    std::fs::write(output.join("index.html"), &html)?;

    println!(
        "Dashboard generated: {} ({} cases, {} files)",
        output.display(),
        report.cases.len(),
        4 + report.cases.len() // index.html + scorecard.md + data/results.json + cross-backend.svg + per-case SVGs
    );
    Ok(())
}

fn find_latest_snapshot(dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    if !dir.exists() {
        anyhow::bail!("snapshots directory does not exist: {}", dir.display());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| {
        e.metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });
    entries
        .last()
        .map(|e| e.path())
        .ok_or_else(|| anyhow::anyhow!("no snapshot files found in {}", dir.display()))
}

fn generate_scorecard_md(report: &ReportSchema) -> String {
    let mut md = String::new();
    md.push_str("# vyre-bench Scorecard\n\n");
    md.push_str(&format!(
        "Suite: **{}** | Cases: {}/{} passed\n\n",
        report.suite,
        report.cases.iter().filter(|c| c.status == "passed").count(),
        report.cases.len(),
    ));
    md.push_str("| Case | Status | p50 (ns) | p99 (ns) | Speedup | CV |\n");
    md.push_str("|------|--------|----------|----------|---------|----|\n");
    for case in &report.cases {
        let wall = case.metrics.get("wall_ns");
        let p50 = wall.map(|s| s.p50).unwrap_or(0);
        let p99 = wall.map(|s| s.p99).unwrap_or(0);
        let cv = wall
            .map(|s| {
                if s.mean > 0.0 {
                    format!("{:.3}", s.stddev / s.mean)
                } else {
                    " - ".into()
                }
            })
            .unwrap_or_else(|| " - ".into());
        let speedup = case
            .performance
            .as_ref()
            .and_then(|p| p.speedup_x)
            .map(|s| format!("{:.1}×", s))
            .unwrap_or_else(|| " - ".into());
        let status_emoji = match case.status.as_str() {
            "passed" => "✅",
            "failed" => "❌",
            "unstable" => "⚠️",
            _ => "❓",
        };
        md.push_str(&format!(
            "| {} | {} {} | {:>10} | {:>10} | {:>7} | {} |\n",
            case.id, status_emoji, case.status, p50, p99, speedup, cv
        ));
    }
    md
}

fn generate_case_svg(case: &crate::report::json::CaseReport) -> String {
    let wall = case.metrics.get("wall_ns");
    let p50 = wall.map(|s| s.p50).unwrap_or(1) as f64;
    let p99 = wall.map(|s| s.p99).unwrap_or(1) as f64;
    let max = wall.map(|s| s.max).unwrap_or(1) as f64;
    let scale = 300.0 / max.max(1.0);

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80" viewBox="0 0 400 80">
  <style>
    text {{ font-family: 'Inter', sans-serif; font-size: 11px; fill: #e0e0e0; }}
    .title {{ font-size: 12px; font-weight: 600; }}
    .bar {{ rx: 3; }}
  </style>
  <rect width="400" height="80" fill="#1a1a2e" rx="6"/>
  <text x="10" y="16" class="title">{id}</text>
  <rect class="bar" x="10" y="28" width="{w50}" height="14" fill="#00d2ff"/>
  <text x="{tw50}" y="39" fill="#fff">p50: {p50_ns}ns</text>
  <rect class="bar" x="10" y="48" width="{w99}" height="14" fill="#7b2ff7"/>
  <text x="{tw99}" y="59" fill="#fff">p99: {p99_ns}ns</text>
  <rect class="bar" x="10" y="68" width="{wmax}" height="8" fill="#ff6b6b" opacity="0.5"/>
</svg>"##,
        id = case.id,
        w50 = (p50 * scale) as u32,
        w99 = (p99 * scale) as u32,
        wmax = (max * scale) as u32,
        tw50 = (p50 * scale) as u32 + 14,
        tw99 = (p99 * scale) as u32 + 14,
        p50_ns = p50 as u64,
        p99_ns = p99 as u64,
    )
}

fn generate_cross_backend_svg(report: &ReportSchema) -> String {
    let case_count = report.cases.len();
    let height = 40 + case_count * 30;
    let mut bars = String::new();

    for (i, case) in report.cases.iter().enumerate() {
        let wall = case.metrics.get("wall_ns");
        let p50 = wall.map(|s| s.p50).unwrap_or(0);
        let y = 30 + i * 30;
        let width = (p50 as f64 / 1_000_000.0).clamp(5.0, 350.0) as u32; // scale to ms

        bars.push_str(&format!(
            r##"  <rect x="10" y="{y}" width="{w}" height="20" fill="#00d2ff" rx="3"/>
  <text x="{tx}" y="{ty}" fill="#e0e0e0" font-size="10">{id} ({p50_us}μs)</text>
"##,
            y = y,
            w = width,
            tx = width + 14,
            ty = y + 14,
            id = case.id,
            p50_us = p50 / 1000,
        ));
    }

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="600" height="{h}" viewBox="0 0 600 {h}">
  <style>text {{ font-family: 'Inter', sans-serif; }}</style>
  <rect width="600" height="{h}" fill="#1a1a2e" rx="6"/>
  <text x="10" y="20" fill="#e0e0e0" font-size="14" font-weight="600">Cross-Backend: {suite}</text>
{bars}</svg>"##,
        h = height,
        suite = report.suite,
        bars = bars,
    )
}

fn generate_index_html(report: &ReportSchema, _scorecard_md: &str) -> String {
    let cases_count = report.cases.len();
    let passed = report.cases.iter().filter(|c| c.status == "passed").count();

    let mut rows = String::new();
    for case in &report.cases {
        let wall = case.metrics.get("wall_ns");
        let p50 = wall.map(|s| s.p50).unwrap_or(0);
        let p99 = wall.map(|s| s.p99).unwrap_or(0);
        let cv = wall
            .map(|s| {
                if s.mean > 0.0 {
                    format!("{:.3}", s.stddev / s.mean)
                } else {
                    " - ".into()
                }
            })
            .unwrap_or_else(|| " - ".into());
        let speedup = case
            .performance
            .as_ref()
            .and_then(|p| p.speedup_x)
            .map(|s| format!("{:.1}×", s))
            .unwrap_or_else(|| " - ".into());
        let status_class = match case.status.as_str() {
            "passed" => "status-pass",
            "failed" => "status-fail",
            _ => "status-warn",
        };
        let svg_file = case.id.replace('.', "_") + ".svg";

        rows.push_str(&format!(
            r#"        <tr>
          <td><a href="{svg}">{id}</a></td>
          <td class="{cls}">{status}</td>
          <td class="num">{p50}</td>
          <td class="num">{p99}</td>
          <td class="num">{speedup}</td>
          <td class="num">{cv}</td>
        </tr>
"#,
            svg = svg_file,
            id = case.id,
            cls = status_class,
            status = case.status,
            p50 = p50,
            p99 = p99,
            speedup = speedup,
            cv = cv,
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>vyre-bench Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #0f0f23;
      --surface: #1a1a2e;
      --accent: #00d2ff;
      --accent2: #7b2ff7;
      --text: #e0e0e0;
      --pass: #00e676;
      --fail: #ff5252;
      --warn: #ffab40;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }}
    h1 {{
      font-size: 2rem;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }}
    .summary {{
      display: flex;
      gap: 2rem;
      margin: 1rem 0 2rem;
    }}
    .stat {{
      background: var(--surface);
      border-radius: 12px;
      padding: 1.5rem 2rem;
      min-width: 140px;
      text-align: center;
    }}
    .stat-value {{
      font-size: 2.5rem;
      font-weight: 700;
      color: var(--accent);
    }}
    .stat-label {{
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      opacity: 0.7;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border-radius: 12px;
      overflow: hidden;
    }}
    th {{
      text-align: left;
      padding: 0.8rem 1rem;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      border-bottom: 1px solid rgba(255,255,255,0.1);
      background: rgba(0,0,0,0.2);
    }}
    td {{
      padding: 0.6rem 1rem;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }}
    td a {{
      color: var(--accent);
      text-decoration: none;
    }}
    td a:hover {{ text-decoration: underline; }}
    .num {{ font-variant-numeric: tabular-nums; text-align: right; }}
    .status-pass {{ color: var(--pass); font-weight: 600; }}
    .status-fail {{ color: var(--fail); font-weight: 600; }}
    .status-warn {{ color: var(--warn); font-weight: 600; }}
    .footer {{
      margin-top: 2rem;
      font-size: 0.8rem;
      opacity: 0.5;
    }}
    tr:hover {{ background: rgba(0,210,255,0.05); }}
  </style>
</head>
<body>
  <h1>vyre-bench Dashboard</h1>
  <p>Suite: <strong>{suite}</strong> &mdash; Generated {timestamp}</p>

  <div class="summary">
    <div class="stat">
      <div class="stat-value">{passed}</div>
      <div class="stat-label">Passed</div>
    </div>
    <div class="stat">
      <div class="stat-value">{total}</div>
      <div class="stat-label">Total Cases</div>
    </div>
    <div class="stat">
      <div class="stat-value">{pass_rate}%</div>
      <div class="stat-label">Pass Rate</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Case</th>
        <th>Status</th>
        <th>p50 (ns)</th>
        <th>p99 (ns)</th>
        <th>Speedup</th>
        <th>CV</th>
      </tr>
    </thead>
    <tbody>
{rows}    </tbody>
  </table>

  <div class="footer">
    <p>Data: <a href="data/results.json">results.json</a> |
       Cross-backend: <a href="cross-backend.svg">cross-backend.svg</a> |
       Scorecard: <a href="scorecard.md">scorecard.md</a></p>
  </div>
</body>
</html>"##,
        suite = report.suite,
        timestamp = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{now} (unix)")
        },
        passed = passed,
        total = cases_count,
        pass_rate = if cases_count > 0 {
            passed * 100 / cases_count
        } else {
            0
        },
        rows = rows,
    )
}
