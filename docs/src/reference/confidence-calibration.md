# Confidence calibration

> **Not the same as autoroute calibration.** This page is about *scoring*:
> teaching KeyHog how much to trust each detector from your own confirmed
> true/false positives. For *backend selection* (which engine is fastest and
> proven-correct), see [Autoroute calibration](./autoroute-calibration.md). The
> two subsystems share only the word "calibration": different command,
> different cache file, different purpose.

KeyHog keeps a per-detector Bayesian **Beta(α, β)** posterior over
`P(true positive | this detector fired)`. Each confirmed true positive
increments α; each confirmed false positive increments β. Both start from a
uniform `Beta(1, 1)` prior, so a detector with no recorded history has a
posterior mean of `0.5` and is treated neutrally.

At scan time, once a detector has accumulated real observations, its posterior
mean multiplies that detector's confidence score: detectors with a clean
history are amplified, chronic false-positive emitters are muted.

## Record outcomes

```sh
keyhog calibrate --tp stripe-secret-key   # record one true positive
keyhog calibrate --fp generic-api-key     # record one false positive
keyhog calibrate --show                   # print current counters
```

Counters persist to `$XDG_CACHE_HOME/keyhog/calibration.json` by default. Pass
`--cache <PATH>` to use a different file. A corrupted or
schema-incompatible cache fails closed and is never overwritten, so you never
silently lose recorded history.

## How it affects scans (opt-in and deterministic)

Calibration is **opt-in**. A default scan does *not* read the counter file, so
two machines produce byte-identical findings for the same input regardless of
what history happens to sit in a local cache. To apply calibration during a
scan, point at the file explicitly:

```sh
keyhog scan . --calibration-cache ~/.cache/keyhog/calibration.json
```

or in configuration:

```toml
[system]
calibration_cache = "/absolute/path/to/calibration.json"
```

An explicitly supplied cache must already exist and parse cleanly. A missing or
damaged explicit cache fails before scanning rather than silently continuing
without calibration, so a run that asked for calibration never quietly produces
uncalibrated scores.

When enabled, the multiplier is applied only to detectors that have
observations beyond the prior. A fresh, never-calibrated detector is left
untouched rather than uniformly halved, so a brand-new install behaves exactly
as it did before you enabled calibration until real history accumulates.

## Cache integrity

The cache carries a schema version. A version this binary does not understand,
a truncated/corrupt file, an out-of-range counter, or an empty detector id is
rejected on load (the scan fails closed rather than silently scoring against a
damaged cache). Counters are keyed by detector id; if you rename or retire a
detector, its old counters simply stop being consulted; re-record outcomes for
the new id.
