//! Shared statistical evidence for paired performance comparisons.

use std::time::Duration;

/// A two-sided 95% confidence interval for a paired candidate/reference ratio.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PairedRatioConfidence {
    /// Number of paired observations.
    pub sample_count: usize,
    /// Geometric mean of the paired candidate/reference ratios.
    pub geometric_mean_ratio: f64,
    /// Lower bound of the two-sided 95% interval.
    pub low_ratio: f64,
    /// Upper bound of the two-sided 95% interval.
    pub high_ratio: f64,
}

/// Overflow-safe midpoint for two ordered unsigned observations.
pub fn midpoint_u128(lower: u128, upper: u128) -> u128 {
    lower + (upper - lower) / 2
}

/// Compute a paired 95% confidence interval in log-ratio space.
///
/// Pairing removes shared trial-to-trial host noise. Every duration must be
/// positive, the slices must have equal length, and at least two pairs are
/// required so the interval has measured variance.
pub fn paired_ratio_confidence_95(
    reference: &[Duration],
    candidate: &[Duration],
) -> Option<PairedRatioConfidence> {
    if reference.len() != candidate.len() || reference.len() < 2 {
        return None;
    }
    let mut log_ratios = Vec::with_capacity(reference.len());
    for (&reference_duration, &candidate_duration) in reference.iter().zip(candidate) {
        let reference_secs = reference_duration.as_secs_f64();
        let candidate_secs = candidate_duration.as_secs_f64();
        if reference_secs <= 0.0 || candidate_secs <= 0.0 {
            return None;
        }
        log_ratios.push((candidate_secs / reference_secs).ln());
    }
    let count = log_ratios.len() as f64;
    let mean = log_ratios.iter().sum::<f64>() / count;
    let variance = log_ratios
        .iter()
        .map(|ratio| {
            let delta = ratio - mean;
            delta * delta
        })
        .sum::<f64>()
        / (count - 1.0);
    let half_width = two_sided_95_student_t_critical(log_ratios.len()) * (variance / count).sqrt();
    Some(PairedRatioConfidence {
        sample_count: log_ratios.len(),
        geometric_mean_ratio: mean.exp(),
        low_ratio: (mean - half_width).exp(),
        high_ratio: (mean + half_width).exp(),
    })
}

/// Median duration using the midpoint of the two central observations for an
/// even-length sample.
pub fn median_duration(samples: &[Duration]) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[middle])
    } else {
        let lower = sorted[middle - 1];
        let upper = sorted[middle];
        let midpoint_nanos = midpoint_u128(lower.as_nanos(), upper.as_nanos());
        let seconds = midpoint_nanos / 1_000_000_000;
        let nanos = (midpoint_nanos % 1_000_000_000) as u32;
        Some(Duration::new(seconds as u64, nanos))
    }
}

/// Conservative two-sided 95% Student-t critical value for a sample count.
pub fn two_sided_95_student_t_critical(sample_count: usize) -> f64 {
    match sample_count {
        0 | 1 => 0.0,
        2 => 12.706_204_736,
        3 => 4.302_652_73,
        4 => 3.182_446_305,
        5 => 2.776_445_105,
        6 => 2.570_581_836,
        7 => 2.446_911_851,
        8 => 2.364_624_252,
        9 => 2.306_004_135,
        10 => 2.262_157_163,
        11 => 2.228_138_852,
        12 => 2.200_985_16,
        13 => 2.178_812_83,
        14 => 2.160_368_656,
        15 => 2.144_786_688,
        16 => 2.131_449_546,
        17 => 2.119_905_299,
        18 => 2.109_815_578,
        19 => 2.100_922_04,
        20 => 2.093_024_054,
        21 => 2.085_963_447,
        22 => 2.079_613_845,
        23 => 2.073_873_068,
        24 => 2.068_657_61,
        25 => 2.063_898_562,
        26 => 2.059_538_553,
        27 => 2.055_529_439,
        28 => 2.051_830_516,
        29 => 2.048_407_142,
        30 => 2.045_229_642,
        31 => 2.042_272_456,
        _ => 2.042_272_456,
    }
}
