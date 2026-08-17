# Recipes

Every recipe is a copy-paste command. Find your goal, paste the line, done. Put
provider tokens in the documented environment variables, never on the command
line. See [environment variables](./reference/env.md) and
[exit codes](./reference/exit-codes.md).

## Find the right recipe

Each command scans one explicit source boundary. Run several recipes when your
review spans several boundaries, and retain each `json-envelope` report with its
raw exit code.

| Goal | Recipe | Coverage reminder |
|---|---|---|
| Scan local files or choose a detection preset | [Scan code you have locally](#scan-code-you-have-locally) | A filesystem scan does not add Git history. |
| Gate staged content, a diff, or reachable commits | [Gate commits and pull requests](#gate-commits-and-pull-requests) | Staged, diff, history, and working-tree bytes are different inputs. |
| Add a maintained GitHub gate | [Add it to CI](#add-it-to-ci-one-workflow-file) | The Action owns one checked-out repository path. |
| Inventory GitHub, GitLab, or Bitbucket | [Scan an entire GitHub organization](#scan-an-entire-github-organization) or [Scan a GitLab group or Bitbucket workspace](#scan-a-gitlab-group-or-bitbucket-workspace) | Partition large estates and preserve one status per partition. |
| Inspect issues, pull requests, discussions, wikis, or gists | [Scan collaboration surfaces](#scan-a-single-repos-collaboration-surfaces) | Collaboration content is separate from repository files and Git objects. |
| Inspect an image, archive, or cloud bucket | [Scan a Docker image](#scan-a-docker-image-before-you-ship-it), [scan third-party archives](#scan-third-party-archives-without-a-false-clean), or [audit a cloud bucket](#audit-a-cloud-bucket) | Preserve coverage gaps for encrypted, corrupt, unsafe, truncated, or limited content. |
| Inspect a URL, response, HAR capture, or stdin | [Scan a URL](#scan-a-url-endpoint-response-or-har-capture) or [pipe arbitrary text](#pipe-arbitrary-text-through) | URL mode fetches selected responses. It is not a crawler. |
| Audit a local host | [Sweep an entire machine](#sweep-an-entire-machine) | The space ceiling and mount policy bound coverage. |
| Test whether eligible credentials are live | [Confirm a finding](#confirm-a-finding-is-a-live-credential) | Verification sends credential-derived requests to providers. |
| Adopt existing findings or approve one fixture | [Adopt on a noisy repo](#adopt-on-a-legacy-or-noisy-repo) or [approve one fixture](#approve-one-exact-fixture-finding) | A baseline and an exact suppression solve different policy problems. |
| Export to CI, a SIEM, or another tool | [Emit for any pipeline](#emit-for-any-pipeline-or-siem) | Envelope formats retain source status and coverage state. |

## Scan code you have locally

```bash
keyhog scan .                              # canonical default policy
keyhog scan path/to/file.env              # one file; may use a ready Unix daemon
keyhog scan . --fast                      # pattern-only: no decode, entropy, or ML
keyhog scan . --deep                      # bounded highest-recall preset
keyhog scan . --precision                 # 0.85 floor, no entropy/relaxed keyword bridge
keyhog scan . --lockdown                  # Linux; requires sufficient memlock
```

## Gate commits and pull requests

```bash
keyhog scan --git-staged                  # pre-commit: staged blobs (uses guard daemon if live)
keyhog scan --git-diff main               # only files changed since a base ref
keyhog scan --git-history .               # added lines from reachable commits, bounded by max_commits
keyhog scan --git-history . --max-commits 500
```

## Guard a repository for instant pre-commit scans

```bash
# 1. Start daemon in background
keyhog daemon start --backend auto &

# 2. Register repository (indexes baseline into memory once)
keyhog guard add /path/to/repo --mode repo

# 3. Inspect in-memory status and attestation metrics
keyhog guard status /path/to/repo

# 4. Staged commits now execute with sub-millisecond in-memory attestation caching
cd /path/to/repo && keyhog scan --git-staged

# 5. List all active guarded repositories
keyhog guard list

# 6. Free daemon memory whenever you finish working on a repository
keyhog guard remove /path/to/repo
```
Pre-commit framework: keyhog ships a hook, so a `.pre-commit-config.yaml`
`repo: https://github.com/santhreal/keyhog` entry wires `keyhog scan
--git-staged` into every commit. See [perpetual guard](./workflows/guard.md) and
[pre-commit](./workflows/precommit.md).

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: santhreal/keyhog@v0
        with: { path: ., severity: high, format: sarif, preset: default, lockdown: 'false' }
```

Findings upload to the GitHub Security tab as SARIF. Commit a baseline first so
CI fails only on new secrets. See [Adopt on a noisy
repo](#adopt-on-a-legacy-or-noisy-repo), the [GitHub Action
guide](./workflows/github-action.md), and the [direct CI
guide](./workflows/ci.md).

## Scan an entire GitHub organization

```bash
export KEYHOG_GITHUB_TOKEN="$GH_PAT"
keyhog scan --github-org acme --format json-envelope --output acme.json
```

The command traverses the organization until the configured page, repository,
and byte limits bind. The envelope records source identity and any remaining
inventory as coverage gaps. See [mass scanning](./guides/mass-scanning.md).

## Scan a single repo's collaboration surfaces

Issues, pull requests, discussions, wikis, and gists carry secrets that never
land in the tree:

```bash
export KEYHOG_GITHUB_TOKEN="$GH_PAT"
keyhog scan --github-collaboration acme/service --github-all
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

A producer that fails writes nothing to stdout. The scan then reads zero bytes
and exits `13` with a `scan covered nothing` gap row, which is honest but
blames the scanner rather than the producer. Make the pipeline carry the real
failure:

```bash
set -o pipefail
kubectl get secret app -o yaml | keyhog scan --stdin
```

With `pipefail`, a missing `kubectl` or a denied request surfaces the
producer's own exit code. See
[tell a real clean from a skipped input](./reference/coverage-truth.md).

## Sweep an entire machine

```bash
keyhog scan-system --space 50G            # eligible mounts and discovered Git history, bounded at 50 GiB
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

Commit the first file. An entry matches on the detector and the credential
value, not on the path, so moving a baselined secret does not fail the gate but
rotating it does. The complete CI path, including monorepo partitions, is
[Fail only on new secrets](./workflows/ci.md#fail-only-on-new-secrets).

## Approve one exact fixture finding

Append a detector, path, and credential hash to the same rule:

```bash
cat >> .keyhogignore.toml <<'EOF'
[[suppress]]
detector = "aws-access-key"
path_eq = "fixtures/aws.env"
credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
EOF
keyhog scan .
```

All three fields must match. A different value in the fixture, or the same
value in another path, still reports and keeps the findings exit. Invalid TOML
stops the scan with exit `2`; KeyHog does not ignore a broken policy. See
[suppressions](./suppressions.md).

## Ignore one generated tree

```bash
cat >> .keyhogignore <<'EOF'
path:generated/**
EOF
keyhog scan .
```

The rooted pattern matches `generated/app.js`, not
`packages/web/generated/app.js`. Use `path:**/generated/**` only if every
generated directory is reviewed and safe to exclude. `.keyhogignore` has no
negation or last-rule-wins override. An invalid entry stops the scan with exit
`2`.

## Scan third-party archives without a false clean

```bash
rc=0
keyhog scan incoming/ --format json-envelope -o keyhog-archives.json || rc=$?
jq '{scan_status, coverage_gap_summary, findings: (.findings | length)}' \
  keyhog-archives.json
printf 'keyhog exit=%s\n' "$rc"
```

Corrupt, encrypted, unsafe, oversized, or truncated members produce coverage
gaps. With no blocking finding, incomplete coverage exits `13`, not `0`.
Blocking findings in the covered portion take exit `1`, or `10` when
verification confirms a live credential, while `scan_status` remains `partial`.
See [source archives](./source-archives.md).

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

Exit `0` means no finding blocks the active evidence policy and no failing
source gap occurred. It can still accompany advisory skip gaps and
`scan_status: partial`, so it is not proof that skipped content was clean. Exit
`1` means a finding blocks the selected evidence policy; `10` means at least one
live credential under `--verify`; and `13` means failing source or coverage
gaps when no blocking finding took precedence. A blocking or live finding can
therefore exit `1` or `10` while `scan_status` remains `partial`. See the full
precedence table in [exit codes](./reference/exit-codes.md).
