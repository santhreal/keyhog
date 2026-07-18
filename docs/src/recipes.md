# Recipes

Every recipe is a copy-paste command. Find your goal, paste the line, done. Put
provider tokens in the documented environment variables, never on the command
line. See [environment variables](./reference/env.md) and
[exit codes](./reference/exit-codes.md).

## Scan code you have locally

```bash
keyhog scan .                              # the working tree
keyhog scan path/to/file.env              # a single file
keyhog scan . --deep                      # highest-recall preset
keyhog scan . --fast                      # pre-commit speed, no entropy/ML/decode recursion
```

## Gate commits and pull requests

```bash
keyhog scan --git-staged                  # pre-commit: only staged blobs
keyhog scan --git-diff main               # only files changed since a base ref
keyhog scan --git-history .               # every added line in commits reachable from HEAD
keyhog scan --git-history . --max-commits 500
```

Pre-commit framework: keyhog ships a hook, so a `.pre-commit-config.yaml`
`repo: https://github.com/santhreal/keyhog` entry wires `keyhog scan
--git-staged` into every commit. See [pre-commit](./workflows/precommit.md).

## Add it to CI (one workflow file)

```yaml
# .github/workflows/keyhog.yml
name: keyhog
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: santhreal/keyhog/.github/actions/keyhog@v0
        with: { path: ., severity: high, format: sarif }
```

Findings upload to the GitHub Security tab as SARIF. Commit a baseline first so
CI fails only on NEW secrets (see [adopt on a noisy repo](#adopt-on-a-legacy-or-noisy-repo)).
See [CI integration](./workflows/ci.md).

## Scan an entire GitHub organization

```bash
export KEYHOG_GITHUB_TOKEN="$GH_PAT"
keyhog scan --github-org acme --format json-envelope --output acme.json
```

One command walks every repository in the org. The envelope report records
source identity and coverage. See [mass scanning](./guides/mass-scanning.md).

## Scan a single repo's collaboration surfaces

Issues, pull requests, discussions, wikis, and gists carry secrets that never
land in the tree:

```bash
export KEYHOG_GITHUB_TOKEN="$GH_PAT"
keyhog scan --github-collaboration acme/service \
  --github-issues --github-pull-requests --github-discussions --github-wiki
```

See [GitHub collaboration scans](./workflows/github-collaboration.md).

## Scan a GitLab group or Bitbucket workspace

```bash
KEYHOG_GITLAB_TOKEN="$GL_PAT" keyhog scan --gitlab-group acme      # incl. subgroups
KEYHOG_BITBUCKET_USERNAME="$BB_USER" KEYHOG_BITBUCKET_TOKEN="$BB_APP_PASSWORD" \
  keyhog scan --bitbucket-workspace acme
```

## Scan a Docker image before you ship it

```bash
keyhog scan --docker-image registry/app:v1                # unpacks image layers
```

## Audit a cloud bucket

```bash
keyhog scan --s3-bucket logs-prod --s3-prefix config/     # --s3-endpoint for non-AWS
keyhog scan --gcs-bucket logs-prod --gcs-prefix config/
keyhog scan --azure-container-url "$AZURE_CONTAINER_URL" --azure-prefix config/
```

## Scan a URL, endpoint response, or HAR capture

```bash
keyhog scan --url https://api.example.com/config          # one or more URLs
```

See [HTTP and wire scanning](./http-wire.md).

## Pipe arbitrary text through

```bash
echo "$SOME_BLOB" | keyhog scan --stdin
kubectl get secret app -o yaml | keyhog scan --stdin
```

## Sweep an entire machine

```bash
keyhog scan-system --space 50G            # every drive, every git history
```

See [system-wide triage](./guides/system-wide-triage.md).

## Confirm a finding is a live credential

```bash
keyhog scan . --verify                    # validate against provider APIs (exit 10 if live)
keyhog scan . --verify --verify-oob       # out-of-band verification server
```

See [verification](./verification.md).

## Adopt on a legacy or noisy repo

```bash
keyhog scan . --create-baseline .keyhog-baseline.json     # snapshot existing findings once
keyhog scan . --baseline .keyhog-baseline.json            # then report only NEW findings
```

## Make the CI loop fast

```bash
keyhog scan . --incremental               # BLAKE3 Merkle skip of unchanged inputs
keyhog scan . --incremental --incremental-cache .keyhog-cache
```

## Emit for any pipeline or SIEM

One engine, every dialect. Pick with `--format`:

```bash
keyhog scan . --format sarif -o keyhog.sarif          # GitHub / GitLab code scanning
keyhog scan . --format github-annotations             # inline PR annotations
keyhog scan . --format gitlab-sast -o gl-sast.json    # GitLab SAST report
keyhog scan . --format junit -o keyhog.xml            # JUnit for any CI dashboard
keyhog scan . --format jsonl-envelope                 # streaming machine contract
keyhog scan . --format csv -o findings.csv
```

Available formats: `text · json · json-envelope · jsonl · jsonl-envelope ·
sarif · csv · html · junit · github-annotations · gitlab-sast`.

## Filter and set the gate

```bash
keyhog scan . --severity high             # info | client-safe | low | medium | high | critical
keyhog scan . --min-confidence 0.5        # raise the reporting confidence floor
keyhog scan . --exclude-paths vendor,node_modules
```

Exit `0` clean, `1` findings above the floor, `10` live credentials found (with
`--verify`), `13` scan completed with coverage gaps. Full list in
[exit codes](./reference/exit-codes.md).
