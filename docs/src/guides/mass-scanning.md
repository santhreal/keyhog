# Mass scanning

## One command, whole account

For a single organization, group, workspace, or bucket, keyhog does the
inventory traversal itself. No loop, no clone script:

```bash
export KEYHOG_GITHUB_TOKEN="$GH_PAT"
keyhog scan --github-org acme --format json-envelope --output acme.json
```

```bash
KEYHOG_GITLAB_TOKEN="$GL_PAT"    keyhog scan --gitlab-group acme       --format json-envelope --output gitlab.json
KEYHOG_BITBUCKET_USERNAME="$U" KEYHOG_BITBUCKET_TOKEN="$P" \
  keyhog scan --bitbucket-workspace acme --format json-envelope --output bitbucket.json
keyhog scan --s3-bucket logs-prod --s3-prefix config/ --format json-envelope --output s3.json
```

Each run walks every repository or object under the target and writes one
envelope report carrying source identity and coverage. That is the whole setup
for a single provider target. The rest of this guide covers scanning *across
many* targets (multiple orgs, mixed local + cloud, thousands of repos) where
you partition and aggregate. If one org or bucket is all you need, the command
above is complete.

Use one bounded report and one exit status per partition when scanning many
repositories, buckets, or files. Keep the partition manifest outside the scan
tree so a scanner never treats its own answer key as input.

## Local partitions

This shell pattern preserves every report and status without turning a partial
partition into a clean result:

```bash
#!/usr/bin/env bash
set -u

out="${1:-keyhog-results}"
mkdir -p "$out"
overall=0

while IFS= read -r -d '' partition; do
  name="$(basename -- "$partition")"
  report="$out/$name.json"
  set +e
  keyhog scan "$partition" \
    --format json-envelope --output "$report" \
    --limit-stdin-bytes 10MiB
  rc=$?
  set -e
  printf '%s\t%s\t%s\n' "$partition" "$rc" "$report" \
    >> "$out/status.tsv"
  # Preserve the strongest actionable state: findings (1), live credentials
  # (10), coverage incomplete (13), and system failures remain visible.
  (( rc > overall )) && overall="$rc"
done < <(find ./partitions -mindepth 1 -maxdepth 1 -type d -print0)

exit "$overall"
```

The envelope records scan-wide coverage and the resolved policy. Keep
`status.tsv` with the reports; an aggregator must not discard a nonzero status
just because another partition was clean. If a partition is retried, replace
its report atomically and append a new attempt column or manifest row rather
than overwriting the only evidence.

For CI, upload the whole output directory as an artifact and make the job fail
on any status that the policy treats as actionable. Exit `13` means the scan
completed with coverage gaps, not that it found nothing; inspect the envelope
before deciding whether a retry is safe. Exit `2` or `3` is an input or system
failure and needs operator attention. See [exit codes](../reference/exit-codes.md).

## Hosted Git and cloud inventories

The source flags keep inventory traversal inside KeyHog so source identity and
coverage remain in the report:

```bash
keyhog scan --github-org "$ORG" \
  --limit-hosted-git-pages 100 \
  --format json-envelope --output github.json

keyhog scan --gitlab-group "$GROUP" \
  --limit-hosted-git-pages 100 \
  --format json-envelope --output gitlab.json

keyhog scan --s3-bucket "$BUCKET" --s3-prefix "$PREFIX" \
  --limit-cloud-max-objects 10000 --limit-s3-object-bytes 100MiB \
  --format json-envelope --output s3.json

keyhog scan --gcs-bucket "$BUCKET" --gcs-prefix "$PREFIX" \
  --limit-cloud-max-objects 10000 --limit-gcs-object-bytes 100MiB \
  --format json-envelope --output gcs.json
```

Use the credential environment variables documented by `keyhog scan --help`
and [environment variables](../reference/env.md); do not put provider tokens in
the command line. Azure Blob uses `--azure-container-url` and its matching
prefix/object limits. A page or object cap is deliberate bounded coverage:
the report names the limit and exits `13` when more inventory remains.

Hosted APIs and cloud listings can return transient transport or rate-limit
errors. Retry only the failed source with bounded exponential backoff, keep the
original partial envelope, and preserve the provider request diagnostics. Do
not increase object/page caps automatically, and do not classify a rate-limit
failure as a clean scan. Respect each provider's pagination and retry headers.

## Daemon semantics at scale

The daemon is useful for repeated eligible `stdin` or single-regular-file
requests. Directory trees, Git history, hosted inventories, cloud buckets,
archives, multiple roots, deep/fast/precision policy changes, and source-limit
changes stay in the in-process orchestrator. Starting a daemon does not make
those scopes faster and `--daemon=on` rejects them; `--daemon=auto` keeps them
local. See [daemon and warm scans](../workflows/daemon.md) for the exact
eligibility and retry matrix.

For a large inventory, partition at the provider or repository boundary, not
inside one daemon request. Calibrate autoroute on the actual worker class and
retain the per-partition resolved policy and coverage envelope. A missing or
stale autoroute decision triggers visible scalar correctness recovery, never a
silent CPU, Hyperscan, or GPU substitution. Treat `complete_after_recovery` as a
recalibration signal even though scan byte coverage is complete.

## Report aggregation

Aggregate only after every partition has a terminal envelope. Preserve the
partition identity, source inventory, resolved policy, coverage state, finding
count, and exit code. JSON and JSONL legacy formats contain findings only;
`json-envelope` and `jsonl-envelope` are the recommended machine contracts for
mass scans because they carry terminal coverage and identity. Never concatenate
JSON arrays or merge findings before deduplicating with the partition and
location identity.
