//! `keyhog calibrate` - show or update per-detector Beta(α, β) counters.
//!
//! Tier-B moat innovation #4 from the internal design notes.

use crate::args::CalibrateArgs;
use anyhow::{Context, Result};
use keyhog_core::{BetaCounters, Calibration};

pub(crate) fn run(args: CalibrateArgs) -> Result<()> {
    let cache_path = args
        .cache
        .clone()
        .or_else(keyhog_core::calibration_default_cache_path)
        .context("could not resolve calibration cache path; pass --cache <PATH> explicitly")?;
    if cache_path.is_dir() {
        anyhow::bail!(
            "calibration cache path '{}' is a directory. \
             Fix: pass a file path such as '{}'.",
            cache_path.display(),
            cache_path.join("calibration.json").display()
        );
    }

    let calibration = match Calibration::try_load(&cache_path) {
        Ok(Some(calibration)) => calibration,
        Ok(None) => Calibration::default(),
        Err(error) => {
            anyhow::bail!(
                "{error}. Fix: repair or remove the cache, or pass --cache <PATH> to a valid \
                 calibration file. No calibration counters were changed."
            );
        }
    };

    if args.show && args.tp.is_empty() && args.fp.is_empty() {
        print_show(&calibration, &cache_path);
        return Ok(());
    }

    for detector_id in &args.tp {
        calibration.record_outcome(detector_id, true);
    }
    for detector_id in &args.fp {
        calibration.record_outcome(detector_id, false);
    }

    calibration
        .save(&cache_path)
        .with_context(|| format!("saving calibration cache to {}", cache_path.display()))?;

    if args.show {
        print_show(&calibration, &cache_path);
    } else {
        let p = crate::style::for_stdout();
        let updated = args.tp.len() + args.fp.len();
        println!(
            "\u{1F4CA} updated {green}{updated}{reset} {dim}detector counter{suffix}{reset} ({green}{tp}{reset}{dim} TP{reset}, {green}{fp}{reset}{dim} FP){reset} at {dim}{path}{reset}",
            suffix = if updated == 1 { "" } else { "s" },
            tp = args.tp.len(),
            fp = args.fp.len(),
            path = cache_path.display(),
            green = p.green,
            reset = p.reset,
            dim = p.dim,
        );
    }
    Ok(())
}

fn print_show(calibration: &Calibration, cache_path: &std::path::Path) {
    let p = crate::style::for_stdout();
    let entries = calibration.entries();
    println!(
        "\u{1F4CA} keyhog calibration {dim}({reset}{green}{count}{reset}{dim} detectors){reset}",
        count = entries.len(),
        dim = p.dim,
        green = p.green,
        reset = p.reset,
    );
    println!(
        "    cache: {dim}{}{reset}",
        cache_path.display(),
        dim = p.dim,
        reset = p.reset
    );
    if entries.is_empty() {
        println!();
        println!("    (no observations yet; record outcomes with `--tp <id>` or `--fp <id>`)");
        return;
    }

    println!();
    println!(
        "    {}{:<40}  {:>5}  {:>5}  {:>9}  {:>5}{}",
        p.bold, "DETECTOR", "α", "β", "POSTERIOR", "OBS", p.reset
    );
    for (id, c) in entries {
        let mean = posterior_mean(c);
        let bar = bar_for(mean);
        println!(
            "    {id:<40}  {green}{alpha:>5}{reset}  {green}{beta:>5}{reset}  {green}{mean:>6.3}{reset}  {green}{bar}{reset} {green}{obs:>4}{reset}",
            id = id,
            alpha = c.alpha,
            beta = c.beta,
            mean = mean,
            bar = bar,
            obs = observations(c),
            green = p.green,
            reset = p.reset,
        );
    }
}

fn posterior_mean(counters: BetaCounters) -> f64 {
    let total = counters.alpha as f64 + counters.beta as f64;
    if total == 0.0 {
        0.5
    } else {
        counters.alpha as f64 / total
    }
}

fn observations(counters: BetaCounters) -> u32 {
    counters
        .alpha
        .saturating_sub(1)
        .saturating_add(counters.beta.saturating_sub(1))
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
