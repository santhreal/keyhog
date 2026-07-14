//! Statistical timing evidence persisted by autoroute calibration.

use keyhog_core::timing::{midpoint_u128, two_sided_95_student_t_critical};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackendTimingEvidence {
    pub(crate) trials_ns: Vec<u128>,
}

impl BackendTimingEvidence {
    pub(crate) fn add_to_first_trial(mut self, overhead_ns: u128) -> Self {
        if let Some(first) = self.trials_ns.first_mut() {
            *first = first.saturating_add(overhead_ns);
        }
        self
    }

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
            midpoint_u128(trials[middle - 1], trials[middle])
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
