# Mass scanning

A mass scan covers an inventory that is too large or too independent for one
repository gate. Partition it by ownership and retry boundary, then preserve one
report and raw exit code per partition. Use the [GitHub Action
guide](../workflows/github-action.md) for one checked-out repository and the
[CI integration guide](../workflows/ci.md) for provider-specific job setup.

## One command, whole account

For a single organization, group, workspace, or bucket, keyhog does the
inventory traversal itself. No loop, no clone script:

```bash
export KEYHOG_GITHUB_TOKEN="$GH_PAT"
keyhog scan --daemon=off --github-org acme \
  --format json-envelope --output acme.json
```

```bash
KEYHOG_GITLAB_TOKEN="$GL_PAT" \
  keyhog scan --daemon=off --gitlab-group acme \
  --format json-envelope --output gitlab.json

KEYHOG_BITBUCKET_USERNAME="$U" KEYHOG_BITBUCKET_TOKEN="$P" \
  keyhog scan --daemon=off --bitbucket-workspace acme \
  --format json-envelope --output bitbucket.json

keyhog scan --daemon=off \
  --s3-bucket logs-prod --s3-prefix config/ \
  --format json-envelope --output s3.json
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
  keyhog scan --daemon=off "$partition" \
    --max-file-size 100MiB \
    --format json-envelope --output "$report"
  rc=$?
  set -e
  printf '%s\t%s\t%s\n' "$partition" "$rc" "$report" \
    >> "$out/status.tsv"
  # Keep each raw status in status.tsv. The wrapper only needs one nonzero
  # terminal status to make the aggregate CI job fail.
  (( rc != 0 )) && overall=1
done < <(find ./partitions -mindepth 1 -maxdepth 1 -type d -print0)

exit "$overall"
```

The envelope records scan-wide coverage and the resolved policy. Keep
`status.tsv` with the reports; an aggregator must not discard a nonzero status
just because another partition was clean. If a partition is retried, replace
its report atomically and append a new attempt column or manifest row rather
than overwriting the only evidence.

`--max-file-size` bounds each regular file. The default is 100 MiB. A larger
file is skipped and recorded as a coverage gap. `--limit-stdin-bytes` does not
bound a directory partition. It applies only to `--stdin`.

For CI, upload the whole output directory as an artifact and make the job fail
on any status that the policy treats as actionable. Exit `13` means the scan
completed with coverage gaps, not that it found nothing; inspect the envelope
before deciding whether a retry is safe. Exit `2` or `3` is an input or system
failure and needs operator attention. See [exit codes](../reference/exit-codes.md).

## Hosted Git and cloud inventories

The source flags keep inventory traversal inside KeyHog so source identity and
coverage remain in the report:

```bash
keyhog scan --daemon=off --github-org "$ORG" \
  --limit-hosted-git-pages 100 \
  --format json-envelope --output github.json

keyhog scan --daemon=off --gitlab-group "$GROUP" \
  --limit-hosted-git-pages 100 \
  --format json-envelope --output gitlab.json

keyhog scan --daemon=off \
  --s3-bucket "$BUCKET" --s3-prefix "$PREFIX" \
  --limit-cloud-max-objects 10000 --limit-s3-object-bytes 100MiB \
  --format json-envelope --output s3.json

keyhog scan --daemon=off \
  --gcs-bucket "$BUCKET" --gcs-prefix "$PREFIX" \
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

## Daemon and corpus semantics at scale

The examples use `--daemon=off` to make the execution contract explicit.
Directory trees, Git history, hosted inventories, cloud buckets, archives,
multiple roots, and source-limit changes require the in-process orchestrator.
A running daemon does not accelerate them.

Omitting the flag gives `--daemon=auto` on Unix. These unsupported request
classes are recognized before a socket connection and stay in process.
`--daemon=on` rejects them before scanning. It does not fall back:

```bash
# Supported in process.
keyhog scan --daemon=off ./partitions/team-a

# Unsupported. This exits before scanning the directory.
keyhog scan --daemon=on ./partitions/team-a
```

The daemon is useful only when a partitioner emits repeated eligible `stdin`
or single-regular-file requests. Start it with an explicit replacement corpus
only when each client selects the exact same corpus:

```bash
keyhog daemon start --detectors ./reviewed-detectors
keyhog scan --daemon=on \
  --detectors ./reviewed-detectors --detectors-mode=replace \
  one-object.txt
```

Overlay composition is unsupported by the daemon. Use `--daemon=off` with
`--detectors-mode=overlay`. A replacement identity mismatch is a handshake
error. Required daemon mode exits instead of using either the daemon's corpus
or an in-process scan. See [daemon and warm scans](../workflows/daemon.md) for
the lifecycle, socket, eligibility, and retry matrix.

For a large inventory, partition at the provider or repository boundary.
Calibrate autoroute on the actual worker class and retain the per-partition
resolved policy and coverage envelope. A missing or stale autoroute decision
uses visible scalar correctness recovery. It does not silently claim a
calibrated CPU, Hyperscan, or GPU route. Treat `complete_after_recovery` as a
recalibration signal even when scan byte coverage is complete.

## Concurrency and worker sizing

Each KeyHog process uses the available CPU cores by default. This is the right
default for one dedicated partition. It can oversubscribe a worker when your CI
or scheduler starts several partitions on the same host.

Allocate the host CPU budget across concurrent processes. For example, four
partition jobs on a 16-vCPU worker can each start with `--threads 4`. This is a
resource allocation example, not a universal optimum. Leave
`--reader-threads` unset until profiling shows that storage readers are the
bottleneck; its default derives from the scanner worker pool.

Keep these boundaries when increasing concurrency:

- Give every partition its own `json-envelope` report, raw exit code,
  incremental cache, and retry identity.
- Keep one incremental cache bound to one trusted repository or partition.
  Sharing it across unrelated jobs turns reuse into cross-workspace state.
- Bound provider jobs by API quotas and pagination limits as well as CPU. Live
  verification has separate `--verify-concurrency`, `--verify-rate`, and
  `--verify-batch` controls.
- Do not use a warm daemon to fan out directory or provider jobs. Each of these
  scans requires the in-process orchestrator.
- Aggregate only after every concurrent partition has reached a terminal
  state. One successful job cannot erase another job's coverage gap or error.

Use `--profile` on representative partitions before changing advanced
`--reader-threads`, `--fused-batch`, or `--fused-depth` values. Keep those
controls unset when a repeatable target-host measurement does not show a
benefit.

## Report aggregation

Aggregate only after every partition has a terminal envelope. Preserve the
partition identity, source inventory, resolved policy, coverage state, finding
count, and exit code. JSON and JSONL legacy formats contain findings only;
`json-envelope` and `jsonl-envelope` are the recommended machine contracts for
mass scans because they carry terminal coverage and identity. Never concatenate
JSON arrays or merge findings before deduplicating with the partition and
location identity.
