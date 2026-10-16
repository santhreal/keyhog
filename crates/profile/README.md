# keyhog-profile

[![santh](https://img.shields.io/badge/santh-alpha-ffd60a?style=flat-square&labelColor=0a0a0a)](https://santh.dev/keyhog/)

Causal profiling, stage timing, worker-shard counters, and run-state records for the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

## Public entry points

- `Session` and `Runtime` record per-stage durations, worker concurrency, queue depth, cache effectiveness, and typed counters across threads.
- `span`, `serial_span`, `blocked`, `decision_timer`, and `counter_span` instrument synchronous and asynchronous execution paths.
- `CounterId`, `GaugeId`, `MetricId`, and `Stage` define the fixed metric schema.

## Failure behavior

When no profiling runtime is active on the calling thread, `span` and `counter_span` perform one relaxed atomic load and do not read the system clock or allocate memory.

## Documentation

- [Architecture](https://santhreal.github.io/keyhog/architecture.html)
- API documentation is on [docs.rs](https://docs.rs/keyhog-profile).
