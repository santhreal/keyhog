# KeyHog GitHub Action: drop-in secret scanning

One step in your workflow. Findings fail the job, the report uploads to
GitHub code-scanning, and a copy of the report attaches as a workflow
artifact for download. The job summary shows the scan path, severity floor,
report name, raw exit code, finding count, and scan duration for fast PR triage.

```yaml
- uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.40
```

That's it. Defaults: scan the whole repo, fail on `high` or above, output
SARIF, upload to code-scanning. With `upload-sarif: 'true'`, Code Scanning
upload failures fail closed on trusted pushes and same-repo PRs. Fork PRs can
lack `security-events: write`; those upload failures stay advisory and the
SARIF report remains attached as a workflow artifact. Trusted upload failures
also keep the artifact so the failed job is still diagnosable.

## Full reference

```yaml
- uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.40
  with:
    path: .                     # file or directory to scan
    severity: high              # info | low | medium | high | critical
    format: sarif               # text | json | sarif | jsonl
    verify: 'false'             # 'true' to live-verify credentials
    upload-sarif: 'true'        # 'false' to keep the report local-only
    fail-on-findings: 'true'    # 'false' makes unverified findings advisory;
                                # verified-live credentials still fail
    baseline: ''                # path to a committed baseline file; only NEW
                                # findings (absent from the baseline) fail the job
    version: ''                 # pin a specific release (default: action ref)
```

### Adopting on a repo that already has findings

Generate a baseline once, commit it, then point the action at it. The job
then blocks only **new** secrets instead of failing on the existing backlog:

```bash
keyhog scan --create-baseline keyhog-baseline.json
git add keyhog-baseline.json && git commit -m "chore: keyhog baseline"
```

```yaml
- uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.40
  with:
    baseline: keyhog-baseline.json
```

## Outputs

```yaml
- id: keyhog
  uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.40
  with:
    fail-on-findings: 'false'

- name: Comment on PR if anything found
  if: steps.keyhog.outputs.findings != '0'
  run: gh pr comment ${{ github.event.number }} -b "KeyHog flagged ${{ steps.keyhog.outputs.findings }} potential secret(s)."
```

| Output | Description |
| --- | --- |
| `findings` | Number of findings at or above `severity`. |
| `exit-code` | Raw `keyhog` process exit: `0` clean, `1` findings, `10` live findings under `--verify`. |
| `duration-ms` | Wall-clock scan duration in milliseconds from the action wrapper. |
| `report`   | Path to the produced report file. |

## What it costs your CI

| Resource | Value |
| --- | --- |
| Prebuilt binary download | ~20 MB binary plus `.sha256`; checksum verified before execution |
| Cold-start (Hyperscan compile + ML weights load) | ~2 s the first run, ~500 ms warm (Hyperscan DB cached in `~/.cache/keyhog`) |
| Per-file scan throughput | ~500 MB/s on hosted runners (AVX-512 SIMD + Hyperscan) |
| Wall-clock for a 5k-file repo | typically under 10 s end-to-end |
| Runtime dependencies | `libhyperscan5` (auto-installed via apt on Ubuntu runners); none on macOS/Windows |
| Toolchains required | none for release-tag prebuilts; Rust only for branch/SHA source builds |
| GPU | optional; install-time calibration measures every backend available on the runner and persists the fastest correct route |

No Python, no JVM, no Docker daemon. Single static binary plus the
auto-installed Hyperscan shared library on Linux.

## Platforms

| OS | arch | Prebuilt binary | Branch/SHA source build |
| --- | --- | --- | --- |
| Linux | x86_64 | yes (full features) | yes |
| macOS | aarch64 | yes (no Hyperscan) | yes (`portable` feature) |
| macOS | x86_64 | yes (no Hyperscan) | yes (`portable` feature) |
| Windows | x86_64 | yes (portable feature set) | yes (`portable` feature) |

Release tags and explicit `version:` inputs require a matching prebuilt binary
and checksum; missing or unverifiable release assets fail closed instead of
silently source-building different code. Branch/SHA action refs may build from
source. macOS builds (both prebuilt and branch/SHA source builds) ship
without Hyperscan because there is no `libhyperscan-dev` package in homebrew;
everything else (entropy, multiline reassembly, ML scoring, decode-through, all
source backends) is included.

## Recipes

See [`docs/DROP_IN_USAGE.md`](../../../docs/DROP_IN_USAGE.md) for
pre-commit hooks, Husky, lefthook, GitLab CI, CircleCI, Drone, Jenkins,
BuildKite, Bazel, Docker, library integration, and SARIF/Slack/Discord
webhook recipes.
