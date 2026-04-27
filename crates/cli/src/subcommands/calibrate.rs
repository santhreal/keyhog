//! `keyhog calibrate` — show or update per-detector Beta(α, β) counters.
//!
//! Tier-B moat innovation #4 from audits/legendary-2026-04-26.

use crate::args::CalibrateArgs;
use anyhow::{Context, Result};
use keyhog_core::calibration::Calibration;

pub fn run(args: CalibrateArgs) -> Result<()> {
    let cache_path = args
        .cache
        .clone()
        .or_else(keyhog_core::calibration::default_cache_path)
        .context("could not resolve calibration cache path; pass --cache <PATH> explicitly")?;

    let calibration = Calibration::load(&cache_path);

    if args.show && args.tp.is_empty() && args.fp.is_empty() {
        print_show(&calibration, &cache_path);
        return Ok(());
    }

    for detector_id in &args.tp {
        calibration.record_true_positive(detector_id);
    }
    for detector_id in &args.fp {
        calibration.record_false_positive(detector_id);
    }

    calibration
        .save(&cache_path)
        .with_context(|| format!("saving calibration cache to {}", cache_path.display()))?;

    if args.show {
        print_show(&calibration, &cache_path);
    } else {
        let updated = args.tp.len() + args.fp.len();
        println!(
            "\u{1F4CA} updated {updated} detector counter{} ({} TP, {} FP) at {}",
            if updated == 1 { "" } else { "s" },
            args.tp.len(),
            args.fp.len(),
            cache_path.display()
        );
    }
    Ok(())
}

fn print_show(calibration: &Calibration, cache_path: &std::path::Path) {
    let entries = calibration.entries();
    println!("\u{1F4CA} keyhog calibration ({} detectors)", entries.len());
    println!("    cache: {}", cache_path.display());
    if entries.is_empty() {
        println!();
        println!("    (no observations yet — record outcomes with `--tp <id>` or `--fp <id>`)");
        return;
    }

    println!();
    println!(
        "    {:<40}  {:>5}  {:>5}  {:>9}  {:>5}",
        "DETECTOR", "α", "β", "POSTERIOR", "OBS"
    );
    for (id, c) in entries {
        let mean = c.posterior_mean();
        let bar = bar_for(mean);
        println!(
            "    {:<40}  {:>5}  {:>5}  {:>6.3}  {} {:>4}",
            id,
            c.alpha,
            c.beta,
            mean,
            bar,
            c.observations()
        );
    }
}

fn bar_for(mean: f64) -> String {
    let ten = (mean * 10.0).round() as usize;
    let mut bar = String::with_capacity(12);
    bar.push('[');
    for i in 0..10 {
        bar.push(if i < ten { '#' } else { '.' });
    }
    bar.push(']');
    bar
}
