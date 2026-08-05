# Other integrations

Recipes for hook managers, CI systems, Rust embedding, and notifications. The
dedicated [pre-commit](./precommit.md) and [CI](./ci.md) guides own those
workflows. The pages below are platform recipes, not second specifications.

Pick your integration class:

| Class | Page |
|---|---|
| Git hook managers: pre-commit, pre-push, Husky, lefthook | [Git hook managers](./integrations/git-hooks.md) |
| CI systems: GitHub Actions, GitLab CI, CircleCI, Drone, Buildkite, Jenkins, Docker | [CI systems](./integrations/ci-systems.md) |
| Rust library, another CLI, SARIF for Code Scanning | [Embedding KeyHog](./integrations/embedding.md) |
| Slack, Discord, webhooks | [Alerts and notifications](./integrations/alerts.md) |

Install the release with the [verified installer](../install.md), which records
the host's autoroute evidence. A source-built multi-backend binary used outside
the GitHub Action must run `keyhog calibrate-autoroute` before its first
automatic scan. A portable single-backend build has no routing choice.

For the full contract behind a command, use the focused reference instead of
treating a copied snippet as a second specification:

| Task | Start here |
|---|---|
| Protect local commits | [`keyhog hook install`](./precommit.md) |
| Gate a pull request | [CI integration](./ci.md) |
| Scan a large tree or choose a policy | [Detection settings and hardware](../detection.md#settings-active-corpus-and-exact-identity) |
| Suppress an accepted finding | [Suppressions](../suppressions.md) |
| Interpret a failure | [Exit codes](../reference/exit-codes.md) |
| Tell a clean scan from a skipped input | [Coverage truth](../reference/coverage-truth.md) |

## Allowlists and baselines

When you have known-but-unfixable findings (rotated test keys, public
demo creds, fixtures), use a baseline:

```bash
# Once
keyhog scan . --create-baseline .keyhog-baseline.json

# Forever after
keyhog scan . --baseline .keyhog-baseline.json
```

Baseline JSON is strict: unknown root or entry fields fail closed instead of
silently changing suppression policy. The legacy v1 entry `status` field is
accepted only for compatibility and is never serialized or used as a policy
decision. Review baseline edits like code and regenerate them with
`--create-baseline` when the identity set is intentionally changed.

For per-file/per-line allowlists, the moving parts live in two separate files.
Scan execution policy has one canonical `[scan]` owner; unknown tables and
retired flat spellings fail closed:

`.keyhog.toml` at the repo root:

```toml
[scan]
severity       = "high"
min_confidence = 0.4
threads        = 8
exclude        = ["vendor/**", "node_modules/**", "**/*.lock"]
```

`.keyhogignore` (or `.keyhogignore.toml`) alongside it - gitignore-
style path globs plus `detector:<id>` and `hash:<sha256>` entries:

```gitignore
# silence all hits from this detector
detector:http-basic-auth

# gitignore-style path globs
vendor/**
node_modules/**
**/*.lock
```

See the [`.keyhogignore.toml` reference](../reference/keyhogignore-toml.md) for
the full schema.

## Exit codes

Use the canonical [exit-code reference](../reference/exit-codes.md) for the full
numeric contract. In CI, findings and verified-live credentials block the
change; configuration, system, backend, incomplete-coverage, panic, and
interruption outcomes also fail the job because the requested security control
did not complete. Never normalize every nonzero result to “findings found.”

---

## Choose a scan policy for scale

```bash
# Lightweight staged-content check; independent of host autoroute state
keyhog scan --fast --git-staged --backend cpu

# Deep release/security gate; uses calibrated automatic routing
keyhog scan . --deep --severity high

# High-precision policy for a large tree where false-positive review dominates
keyhog scan /large/tree --precision --severity high

# Force GPU for a diagnostic/benchmark run
keyhog scan . --backend gpu-wgpu

# Write the versioned JSONL stream to a file
keyhog scan . --format jsonl-envelope --output findings.jsonl
```

`--fast`, `--deep`, and `--precision` intentionally resolve different detection
policies and can produce different findings. Hardware and automatic backend
selection must not. Measure the chosen policy on the real corpus and let
persisted calibration choose among every measured-correct backend for that exact
host and workload. See [Configuration presets](../reference/configuration.md#presets)
and [Backends and routing](../backends.md) before changing policy or forcing an
engine.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Exit `12` with a selected-GPU diagnostic | Required, explicit, or calibration GPU execution could not start or complete | Run `keyhog backend --self-test`, repair the GPU stack, and recalibrate; normal automatic runtime faults instead produce a visible complete-after-recovery receipt when the stable bytes can be replayed |
| Findings count drops vs prior run | Baseline, detector corpus, scan policy, or `.keyhog.toml` changed | Compare the effective config, detector digest, baseline, and input scope from both runs |
| Pre-commit hook is slow | Scanning the whole repo on every commit | Use `--git-staged` not `scan .` |
| SARIF report is too large for the consumer | The selected scope produced more findings than the consumer accepts | Narrow the scanned source, use a reviewed baseline, or choose an explicit severity policy; do not hide an incomplete upload |
| Detection misses a known token | Detector absent from the loaded corpus / `--fast` disabled decode recursion or entropy discovery | Re-run with the embedded corpus and `--deep`; file an issue if it still misses |
