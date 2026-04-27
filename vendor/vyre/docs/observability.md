# vyre observability

Operators running vyre in production (inference servers, multi-
tenant GPU platforms, edge AI) need the same visibility every
well-engineered runtime provides. This document specifies the
tracing + metrics surface vyre emits so SRE teams can adopt
without building their own shim.

## Tracing spans

Every dispatch emits one `tracing::trace_span!("vyre.dispatch", ...)`
with the following attributes:

| Attribute | Type | Source |
| --- | --- | --- |
| `backend` | `&'static str` | `VyreBackend::id()` |
| `inputs` | `usize` | input buffer count |
| `label` | `Option<String>` | `DispatchConfig.label` (empty if unset) |

Subscribers — opentelemetry, datadog, honeycomb, tokio-console —
attach whatever attribute schema they want on top. The core span
stays minimal so every subscriber interprets it.

Every dispatch also emits a `tracing::trace!` event on completion:

```
target: "vyre.dispatch",
elapsed_us: <duration_in_microseconds>,
inputs: <count>,
message: "dispatch completed",
```

Over-budget dispatches (where `DispatchConfig.timeout` was exceeded)
emit a `tracing::warn!` event with `elapsed_ms` + `deadline_ms`
fields.

## Stats snapshot

Every `WgpuBackend` exposes a lock-free `stats() -> WgpuBackendStats`
method safe for polling from a metrics scrape loop:

```rust
pub struct WgpuBackendStats {
    pub adapter_name: String,             // "NVIDIA GeForce RTX 5090"
    pub pipeline_cache_entries: usize,    // live entries
    pub pipeline_cache_capacity: usize,   // soft cap before eviction
    pub persistent_pool: BufferPoolStats, // allocations/hits/releases/evictions/retained_bytes
}
```

Feed these into your pipeline's export format (prometheus, OTel,
datadog StatsD) — the fields are stable across minor versions.

## Recommended dashboards

SRE dashboards built on the above should surface:

| Metric | Source | Alert when |
| --- | --- | --- |
| p99 dispatch latency | `vyre.dispatch` span duration | > SLO (typically 50ms for inference) |
| Pipeline cache hit rate | `pipeline_cache_entries` / rate of dispatches | < 80% sustained |
| Buffer pool hit rate | `persistent_pool.hits / (hits + allocations)` | < 90% sustained |
| Timeout cancellations | `tracing::warn` on over-budget | > 0.1% of dispatches |
| Device-lost events | `WgpuBackend::device_lost()` probe | any non-zero count |
| Validation failures | `BackendError::InvalidProgram` counter | spike vs baseline |

## Extending

Backend-specific stats (CUDA kernel occupancy, Metal command-buffer
completion latency) live on the backend's own stats type. When a new
backend lands in 0.7 its stats struct follows the same shape:
`pub struct <Backend>BackendStats { adapter_name, ... }`.

## Future work (0.7)

- Prometheus exporter crate (`vyre-metrics`) that consumes
  `WgpuBackendStats` + span events and emits the `text/plain; version=0.0.4`
  format.
- OpenTelemetry resource descriptor auto-populated from
  `adapter_info`.
- Sampling budget on `vyre.dispatch` spans for high-QPS workloads
  (drop 99% at random seed; keep all over-budget + error events).
