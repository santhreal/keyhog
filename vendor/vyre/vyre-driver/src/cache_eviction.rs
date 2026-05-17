//! Backend-neutral cache eviction policy.
//!
//! Concrete drivers use this for pipeline/module caches without depending
//! on domain or self-substrate crates. Inputs are caller-owned marginal
//! gains; output is a 0/1 retention vector where `1` means keep.

/// Compute the retention set: `k` entries to keep from `n` gains.
///
/// The algorithm is greedy argmax over caller-provided marginal gains.
/// The selected entry's gain is zeroed after each pick so it cannot be
/// selected twice. Callers that model correlated entries should update
/// `gains` between calls before invoking this helper.
#[must_use]
pub fn select_retention_set(gains: &mut [u32], n: u32, k: u32) -> Vec<u32> {
    let mut picked = Vec::with_capacity(effective_len(gains, n));
    select_retention_set_into(gains, n, k, &mut picked);
    picked
}

/// Compute the retention set into caller-owned storage.
pub fn select_retention_set_into(gains: &mut [u32], n: u32, k: u32, picked: &mut Vec<u32>) {
    let effective_n = effective_len(gains, n);
    let keep_limit = (k as usize).min(effective_n);
    picked.clear();
    picked.resize(effective_n, 0);
    let mut keep_count = 0usize;
    while keep_count < keep_limit {
        let Some(winner) = argmax_unpicked(&gains[..effective_n], picked) else {
            break;
        };
        picked[winner] = 1;
        gains[winner] = 0;
        keep_count += 1;
    }
}

/// Record one eviction decision in the driver metrics/log stream.
pub fn record_eviction(dropped_fraction: f64) {
    tracing::trace!(
        target: "vyre.driver.eviction",
        dropped_fraction = dropped_fraction.clamp(0.0, 1.0),
        "cache eviction decision",
    );
}

fn effective_len(gains: &[u32], n: u32) -> usize {
    gains.len().min(n as usize)
}

fn argmax_unpicked(gains: &[u32], picked: &[u32]) -> Option<usize> {
    let mut best: Option<(usize, u32)> = None;
    for (idx, gain) in gains.iter().copied().enumerate() {
        if picked.get(idx).copied().unwrap_or(0) != 0 || gain == 0 {
            continue;
        }
        match best {
            Some((_, current)) if gain <= current => {}
            _ => best = Some((idx, gain)),
        }
    }
    best.map(|(idx, _)| idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_top_k_gains() {
        let mut gains = vec![3, 10, 2, 8, 1];
        let picked = select_retention_set(&mut gains, 5, 2);
        assert_eq!(picked, vec![0, 1, 0, 1, 0]);
    }

    #[test]
    fn zero_k_evicts_all() {
        let mut gains = vec![3, 10, 2];
        let picked = select_retention_set(&mut gains, 3, 0);
        assert_eq!(picked, vec![0, 0, 0]);
    }

    #[test]
    fn k_equal_n_keeps_positive_gain_entries() {
        let mut gains = vec![3, 0, 2];
        let picked = select_retention_set(&mut gains, 3, 3);
        assert_eq!(picked, vec![1, 0, 1]);
    }

    #[test]
    fn into_reuses_storage() {
        let mut gains = vec![1, 9, 4];
        let mut picked = Vec::with_capacity(8);
        let ptr = picked.as_ptr();
        select_retention_set_into(&mut gains, 3, 2, &mut picked);
        assert_eq!(picked, vec![0, 1, 1]);
        assert_eq!(picked.as_ptr(), ptr);
    }

    #[test]
    fn invalid_sizing_is_clamped_not_panicked() {
        let mut gains = vec![5, 1];
        let picked = select_retention_set(&mut gains, 99, 99);
        assert_eq!(picked, vec![1, 1]);
    }
}
