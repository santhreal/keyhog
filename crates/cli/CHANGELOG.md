# Changelog

## Unreleased

- Keep the daemon socket linked for the full accept-loop lifetime. Shutdown
  removes it only after the listener terminates.
- Bind every persisted GPU timing and parity receipt to the exact acquired
  execution peer. Route replay now rejects changed or missing adapter identity.
- Make the final backend summary identify invalid-autoroute scalar recovery and
  runtime-fault recovery directly. Recovered work is no longer
  described as a calibrated non-GPU winner.
- Let `calibrate-autoroute --policy` refresh one scan policy without rerunning
  every preset. The default remains the complete all-policy install sweep.
- Reject autoroute cache and runtime-health workload identities with impossible
  logarithmic ranges, phase-one subtotals, decoder bits, or decoder cost bands.
- Report automatic backend recovery as `complete_after_recovery` in JSON schema
  1.7 and JSONL schema 1.8, preserve the
  exact recovered ranges and byte totals across daemon responses, expose daemon
  recovery health, and persist the affected autoroute workload quarantine in a
  bounded artifact that survives restart, is visible in `backend --autoroute`
  and `doctor`, and clears through successful recalibration. Recovery replays
  stable bytes through the fastest remaining measured-correct peer resolved by
  the same workload evidence, rather than a hardcoded CPU backend.
- Measure every plain-pattern and keyword-anchor localization combination for
  every eligible backend, persist the fastest correct execution plan in cache
  schema 39, and carry both choices beside admission evidence through one-shot,
  fused, daemon, and automatic-recovery dispatch.

- Retain every exact calibration representative inside one canonical workload
  evidence envelope. A route class is reusable only when all points agree on
  the fastest-correct one-shot and daemon backends; inspection exposes each
  point's timings, confidence, and parity receipts, and calibration now probes
  both sides of the required 8 MiB crossover.
- Show the detector-owned keyword-free operator entropy margin in `explain`.
- Derive autoroute readiness and repair commands once from cache inspection,
  expose the repair command in `backend --autoroute --json`, and make `doctor`
  report scalar-only builds as direct-route ready instead of uncalibrated.
  Calibration now succeeds only when persisted readback is `ready` for the
  running build.
- Persist the resolved GPU batch-input byte cap in autoroute host identity and
  inspection, so a device-limit or configured-cap change cannot replay timing
  evidence measured with a different dispatch topology.
- Bind autoroute host identity to the live linked Hyperscan/Vectorscan runtime
  version, so a runtime replacement invalidates SIMD timing evidence and
  requires recalibration instead of replaying a stale winner.
- Split contiguous filesystem batches at safe source-family and size-provenance
  boundaries, extend the split to tracked and untracked git-diff inputs, and
  calibrate every default fused count for extracted tar members. Empty stdin is
  no longer reported as a calibrated workload. Current installers delegate this
  core sweep to the binary instead of maintaining a second matrix. Calibration
  output now calls the sweep count probes rather than unique workload buckets;
  it also reads back and reports both route classes measured by this sweep and
  the cache's total route-decision count. Installers still parse the earlier
  unified-command summary during migration.
- Rename the live GPU region-presence batch byte budget to
  `--gpu-batch-input-limit` / `gpu_batch_input_limit`; accept the retired
  MegaScan spelling as a hidden CLI/TOML migration alias.
- Include full-source-size provenance in autoroute workload keys so streamed or
  transformed payload sizes cannot silently reuse calibration measured from an
  equal numeric full-file-size bucket.
- Activate the CLI `simd` feature in default builds so the documented
  Hyperscan `--cache-dir` surface works whenever the default scanner includes
  Hyperscan instead of falsely reporting an accelerator-free binary.
- Stop prewarming an automatic backend from a zero-byte heuristic before the
  persisted workload-specific autoroute decision is known; explicit diagnostic
  backend overrides still prewarm directly.
- Report the configured backend policy at startup instead of claiming that a
  backend was selected before the persisted per-workload decision exists.
- Do not print end-of-run repeat summaries for dependency warnings hidden by
  the default log filter; summaries now describe only visible KeyHog warnings.
- Record the actual first GPU dispatch as autoroute cold-start evidence instead
  of discarding it and mislabelling an already-warm second dispatch as cold.
- Distinguish one-shot and persistent-daemon autorouting: one-shot scans include
  GPU cold cost, while the daemon initializes accelerator state before serving
  requests and selects from calibrated warm timing evidence.
- Replace autoroute cache writes through a synced same-directory temporary file
  so recalibration atomically replaces an existing cache path across supported
  operating systems.
- Route CLI report/cache writes through one atomic file replacement helper,
  including `scan-system --output`, to avoid truncated final-path artifacts.
- Refuse autoroute calibration on empty or zero-byte samples before timing so
  calibration cannot persist route decisions that the cache loader would later
  reject as missing sample evidence.
- Add `keyhog config --effective` and keep post-scan confidence filtering on the same resolved floor as the scanner.
- Update stale unit fixtures for the inline-byte credential-hash contract and removed duplicate startup-summary helper.
- Keep default `--git-diff HEAD` wired to worktree changes, honor CLI excludes for staged-only scans, and refresh git-mode e2e contracts for clean staged inputs and SARIF schema coherence.
- Move args, hook, and scan-system inline tests into registered aggregate unit modules, including scan-system redaction tests updated for the raw `[u8; 32]` hash contract.
- Refresh the dogfood detector-count oracle to 894 and keep the structured UUID named-detector default-recall e2e passing.
- Distinguish detector-TOML declarations from scan-time fallback policy in
  `keyhog explain`, using the same `scan-fallback` provenance label as effective
  configuration output.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep CLI orchestration, output modes, baseline filtering, and detector discovery behavior available for the 0.2 line.
