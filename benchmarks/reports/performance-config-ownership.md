# Performance configuration ownership

Scanner configuration identity and per-scan runtime snapshots now use `ResolvedScannerTuningConfig` and `ScannerTuningConfig::effective`.

| Ownership metric | Legacy | Candidate | Change |
|---|---:|---:|---:|
| Resolved tuning structs | 2 | 1 | duplicate eliminated |
| Runtime-only default field mappings | 14 | 0 | duplicate mapping eliminated |
| Canonical default resolver | 1 | 1 | unchanged |

The complete-struct regression compares default and fully overridden runtime snapshots with canonical effective configuration. Adding a tuning field fails compilation or equality until the runtime snapshot records an explicit decision.

The feature-neutral scanner library compiles with the consolidated type. This change removes configuration drift and duplicate resolution work; it does not claim an end-to-end scan speedup.

Receipt: [`performance-config-ownership.json`](performance-config-ownership.json)
