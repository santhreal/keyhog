//! Sample collection helpers used by `run_case` to harvest metric data
//! from `BenchMetrics` after each measured iteration.

use std::collections::BTreeMap;

use crate::api::case::BenchRun;

use super::metric_keys::{
    custom_metric_key, custom_metric_value, derived_metric_key, gpu_counter_value, metric_key,
    rate_per_second_x1000,
};

pub(super) fn collect_samples(
    run_result: &BenchRun,
    samples: &mut BTreeMap<&'static str, Vec<u64>>,
    collect_baseline: bool,
) {
    collect_metric_fields("", &run_result.metrics, samples);
    collect_custom_metrics("", &run_result.metrics, samples);
    collect_gpu_counters("", &run_result.metrics, samples);
    collect_derived_metrics("", &run_result.metrics, samples);
    if collect_baseline {
        if let Some(baseline) = &run_result.baseline_metrics {
            collect_metric_fields("baseline_", baseline, samples);
            collect_custom_metrics("baseline_", baseline, samples);
            collect_gpu_counters("baseline_", baseline, samples);
            collect_derived_metrics("baseline_", baseline, samples);
        }
    }
}

pub(super) fn collect_metric_fields(
    prefix: &'static str,
    metrics: &crate::api::metric::BenchMetrics,
    samples: &mut BTreeMap<&'static str, Vec<u64>>,
) {
    #[allow(clippy::type_complexity)]
    const FIELDS: [(&str, fn(&crate::api::metric::BenchMetrics) -> Option<u64>); 32] = [
        ("wall_ns", |m| m.wall_ns),
        ("cpu_ns", |m| m.cpu_ns),
        ("compile_ns", |m| m.compile_ns),
        ("validate_ns", |m| m.validate_ns),
        ("optimize_ns", |m| m.optimize_ns),
        ("lower_ns", |m| m.lower_ns),
        ("cache_lookup_ns", |m| m.cache_lookup_ns),
        ("cache_hit", |m| m.cache_hit.map(|b| if b { 1 } else { 0 })),
        ("upload_ns", |m| m.upload_ns),
        ("dispatch_ns", |m| m.dispatch_ns),
        ("kernel_queue_submit_ns", |m| m.kernel_queue_submit_ns),
        ("kernel_execute_ns", |m| m.kernel_execute_ns),
        ("device_sync_ns", |m| m.device_sync_ns),
        ("readback_ns", |m| m.readback_ns),
        ("verify_ns", |m| m.verify_ns),
        ("alloc_count", |m| m.alloc_count),
        ("alloc_bytes", |m| m.alloc_bytes),
        ("peak_rss_bytes", |m| m.peak_rss_bytes),
        ("input_bytes", |m| m.input_bytes),
        ("output_bytes", |m| m.output_bytes),
        ("bytes_touched", |m| m.bytes_touched),
        ("bytes_read", |m| m.bytes_read),
        ("bytes_written", |m| m.bytes_written),
        ("atomic_op_count", |m| m.atomic_op_count),
        ("wire_bytes", |m| m.wire_bytes),
        ("cold_wall_ns", |m| m.cold_wall_ns),
        ("cold_compile_ns", |m| m.cold_compile_ns),
        ("cold_optimize_ns", |m| m.cold_optimize_ns),
        ("cold_lower_ns", |m| m.cold_lower_ns),
        ("cold_cache_lookup_ns", |m| m.cold_cache_lookup_ns),
        ("cold_dispatch_ns", |m| m.cold_dispatch_ns),
        ("cold_readback_ns", |m| m.cold_readback_ns),
    ];
    for (name, getter) in FIELDS {
        if let (Some(value), Some(key)) = (getter(metrics), metric_key(prefix, name)) {
            samples.entry(key).or_default().push(value);
        }
    }
}

pub(super) fn collect_custom_metrics(
    prefix: &'static str,
    metrics: &crate::api::metric::BenchMetrics,
    samples: &mut BTreeMap<&'static str, Vec<u64>>,
) {
    for point in &metrics.custom {
        if let Some(key) = custom_metric_key(prefix, point.name.as_str()) {
            samples.entry(key).or_default().push(point.value);
        }
    }
}

pub(super) fn collect_gpu_counters(
    prefix: &'static str,
    metrics: &crate::api::metric::BenchMetrics,
    samples: &mut BTreeMap<&'static str, Vec<u64>>,
) {
    for counter in &metrics.gpu_counter {
        // use custom_metric_key to leak the names into the standard space safely
        if let Some(key) = custom_metric_key(prefix, counter.name.as_str()) {
            samples.entry(key).or_default().push(counter.value);
        }
    }
}

pub(super) fn collect_derived_metrics(
    prefix: &'static str,
    metrics: &crate::api::metric::BenchMetrics,
    samples: &mut BTreeMap<&'static str, Vec<u64>>,
) {
    let host_bytes = metrics.bytes_touched.unwrap_or_else(|| {
        metrics
            .input_bytes
            .unwrap_or(0)
            .saturating_add(metrics.output_bytes.unwrap_or(0))
    });
    let device_bytes = metrics
        .bytes_read
        .unwrap_or(0)
        .saturating_add(metrics.bytes_written.unwrap_or(0));

    let device_bytes = if device_bytes > 0 {
        device_bytes
    } else {
        host_bytes
    };

    if let Some(wall_ns) = metrics.wall_ns.filter(|ns| *ns > 0) {
        if host_bytes > 0 {
            if let Some(key) = derived_metric_key(prefix, "wall_gb_s_x1000") {
                samples.entry(key).or_default().push(rate_per_second_x1000(
                    host_bytes,
                    wall_ns,
                    1_000_000_000,
                ));
            }
        }
    }

    if let Some(device_ns) = metrics.dispatch_ns.or(metrics.wall_ns).filter(|ns| *ns > 0) {
        if device_bytes > 0 {
            if let Some(key) = derived_metric_key(prefix, "device_gb_s_x1000") {
                samples.entry(key).or_default().push(rate_per_second_x1000(
                    device_bytes,
                    device_ns,
                    1_000_000_000,
                ));
            }
        }
    }

    if let Some(flop_count) = custom_metric_value(metrics, "flop_count") {
        if let Some(active_ns) = metrics.dispatch_ns.or(metrics.wall_ns).filter(|ns| *ns > 0) {
            if let Some(key) = derived_metric_key(prefix, "gflops_x1000") {
                samples.entry(key).or_default().push(rate_per_second_x1000(
                    flop_count,
                    active_ns,
                    1_000_000_000,
                ));
            }
        }
    }

    if let Some(peak_gb_s_x1000) =
        gpu_counter_value(metrics, "memory_peak_gb_s_x1000").filter(|v| *v > 0)
    {
        if let Some(wall_ns) = metrics.wall_ns.filter(|ns| *ns > 0) {
            let achieved_gb_s_x1000 = rate_per_second_x1000(device_bytes, wall_ns, 1_000_000_000);
            if let Some(key) = derived_metric_key(prefix, "roofline_mem_pct_x1000") {
                samples.entry(key).or_default().push(
                    ((u128::from(achieved_gb_s_x1000) * 100_000) / u128::from(peak_gb_s_x1000))
                        .min(u128::from(u64::MAX)) as u64,
                );
            }
        }
    }
}
