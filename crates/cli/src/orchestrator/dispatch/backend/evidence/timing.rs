//! Statistical timing evidence persisted by autoroute calibration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackendTimingEvidence {
    pub(crate) trials_ns: Vec<u128>,
}

impl BackendTimingEvidence {
    pub(crate) fn from_durations(durations: Vec<Duration>) -> Option<Self> {
        let trials_ns = durations.into_iter().map(|dur| dur.as_nanos()).collect();
        Self::from_trial_ns(trials_ns)
    }

    #[cfg(test)]
    pub(crate) fn constant_ms(ms: u128, trials: usize) -> Self {
        let trials_ns = vec![ms.saturating_mul(1_000_000); trials.max(1)];
        match Self::from_trial_ns(trials_ns) {
            Some(evidence) => evidence,
            None => unreachable!("a non-empty trial set always yields timing evidence"),
        }
    }

    pub(crate) fn from_trial_ns(trials_ns: Vec<u128>) -> Option<Self> {
        if trials_ns.is_empty() {
            return None;
        }
        Some(Self { trials_ns })
    }

    pub(crate) fn median_ns(&self) -> u128 {
        let mut trials = self.trials_ns.clone();
        trials.sort_unstable();
        let middle = trials.len() / 2;
        if trials.len() % 2 == 1 {
            trials[middle]
        } else {
            trials[middle - 1].saturating_add(trials[middle]) / 2
        }
    }

    pub(crate) fn median_ms(&self) -> u128 {
        self.median_ns() / 1_000_000
    }

    pub(crate) fn confidence_interval_95_ns(&self) -> TimingConfidenceInterval {
        TimingConfidenceInterval::from_trials(&self.trials_ns)
    }

    pub(crate) fn is_valid_for_trials(&self, expected_trials: usize) -> bool {
        self.trials_ns.len() == expected_trials && self.trials_ns.iter().all(|&trial| trial > 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TimingConfidenceInterval {
    pub(crate) low_ns: u128,
    pub(crate) high_ns: u128,
}

impl TimingConfidenceInterval {
    fn from_trials(trials_ns: &[u128]) -> Self {
        let count = trials_ns.len() as f64;
        let mean = trials_ns.iter().map(|&ns| ns as f64).sum::<f64>() / count;
        let variance = if trials_ns.len() > 1 {
            trials_ns
                .iter()
                .map(|&ns| {
                    let delta = ns as f64 - mean;
                    delta * delta
                })
                .sum::<f64>()
                / (count - 1.0)
        } else {
            0.0
        };
        let half_width =
            two_sided_95_student_t_critical(trials_ns.len()) * variance.sqrt() / count.sqrt();
        Self {
            low_ns: (mean - half_width).max(0.0).floor() as u128,
            high_ns: (mean + half_width).ceil() as u128,
        }
    }
}

fn two_sided_95_student_t_critical(sample_count: usize) -> f64 {
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
        // Keep larger future trial counts conservative rather than silently
        // reverting to the narrower normal-distribution multiplier.
        _ => 2.042_272_456,
    }
}
