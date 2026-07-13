# KeyHog integration PR template

Copy-paste-ready material for opening a PR that adds keyhog to a
third-party repo's CI. Two files (the workflow + an optional baseline)
and a PR description that lets the maintainer accept it in one read.

## The PR

### Title

```
ci: add keyhog secret scanning (SARIF -> code-scanning)
```

### Description

```markdown
Adds the [keyhog](https://github.com/santhreal/keyhog) secret
scanner to PR + push CI. Findings upload to GitHub code-scanning as
SARIF; the job fails the build only on high-severity findings.

**What it catches.** The embedded detector corpus over the full surface area
of this repo, including:
- named vendor detectors (AWS, GitHub, Stripe, Slack, OpenAI,
  Anthropic, GCP, Azure, and similar),
- generic shape detectors (entropy and pattern heuristics),
- base64- and hex-encoded secrets (decode-through),
- secrets split across lines in YAML / JS / Helm templates
  (multiline reassembly),
- secrets in nested archives (zip / tar / .tgz),
- credentials in git history (with `fetch-depth: 0`).

**Cost to CI.**
- One platform release binary download (cacheable).
- A visible one-time autoroute calibration when no explicit diagnostic backend
  is requested.
- Workload-dependent scan time reported in the Action job summary.
- Single `libhyperscan5` apt package on Ubuntu runners.
- No Python, no JVM, no Docker daemon, no daemon process.

**False-positive expectations.** If your repo has known-test-fixture credentials,
commit a baseline once (see "Adoption" below) and the action only
fails on NEW findings going forward.

**Adoption (zero-friction).** If this is the first run, the action
will likely surface a few existing findings (rotated leaks, test
fixtures, doc samples). To avoid blocking the first PR, generate
a baseline locally and include it:

    keyhog scan --create-baseline .keyhog-baseline.json
    git add .keyhog-baseline.json

Then the action gates only on findings ABSENT from the baseline.

**Trust.** keyhog is MIT/Apache-2.0 dual-licensed with an audited release
pipeline (minisign-signed binaries,
SBOM artifact). No telemetry or "phone home"; the only network
calls are when you explicitly run `keyhog scan --verify` to
live-check a finding against the vendor's API.

Reproduce locally:

    curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
    keyhog scan .

Project: https://github.com/santhreal/keyhog
Other CI recipes: https://github.com/santhreal/keyhog/blob/main/docs/src/workflows/integrations.md
```

### The workflow file (single new file)

Drop at `.github/workflows/keyhog.yml`:

```yaml
# Secret scan on every PR + push. Findings upload to GitHub code-
# scanning; the job fails only on high-severity findings (info / low /
# medium surface in code-scanning without blocking the merge).
#
# The Action reports measured duration and calibrates eligible backends on the
# runner before its default auto scan.
#
# Adoption: if this is the first run on a repo with existing findings,
# generate `.keyhog-baseline.json` once (keyhog scan --create-baseline)
# and commit it. The action then fails only on NEW secrets.
name: keyhog
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write   # SARIF upload to code-scanning
concurrency:
  group: keyhog-${{ github.ref }}
  cancel-in-progress: true
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history; drop if you only scan working tree
      - uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
        with:
          path: .
          severity: high
          format: sarif
          baseline: .keyhog-baseline.json   # remove if you didn't commit one
```

## After the PR lands

- Findings appear under **Security -> Code scanning** in the GitHub
  UI, deduped across runs by SARIF `partialFingerprints`.
- A keyhog finding includes the rule id, severity, CWE-798 + OWASP
  A07:2021 taxa, the redacted credential prefix, the file:line, and
  a rotation guide for the matching vendor.
- To raise the bar (block on medium+), change `severity: high` to
  `severity: medium`. To make findings advisory (no merge block),
  add `fail-on-findings: 'false'` to the action `with:` block. This
  does not make verified-live credentials advisory; `verify: 'true'`
  findings that exit `10` still fail after reports are uploaded.
- To suppress a known-public test fixture without touching code,
  drop its path or content hash in `.keyhogignore` at repo root
  (`path:tests/fixtures/`, `hash:<sha256>`, or `id:<detector-id>`).

## Reviewer checklist

What a thorough maintainer might verify before merging:

- [ ] No secrets in the workflow YAML itself (no API keys, no
      hardcoded paths to private buckets, no PAT references).
- [ ] `permissions:` block is minimal (`contents: read` +
      `security-events: write` for SARIF upload only).
- [ ] Action is pinned to a tagged release, not `@main` or `@v0`.
- [ ] No third-party action transitively pulled with broad scope.
- [ ] Runs only on `push: main` + `pull_request` (no `workflow_run`,
      no `pull_request_target`).
- [ ] `concurrency: cancel-in-progress: true` prevents stacking on
      rapid pushes.
- [ ] SARIF format produces a `keyhog.sarif` artifact uploaded to
      code-scanning; nothing else leaves the runner.

All seven hold for the snippet above.
