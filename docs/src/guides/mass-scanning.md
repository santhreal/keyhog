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

Each run traverses repositories or objects until a configured page, object,
byte, or source limit binds. The envelope records source identity and names any
remaining inventory as a coverage gap. That is the complete setup for one
bounded provider target. The rest of this guide covers scanning *across many*
targets (multiple orgs, mixed local and cloud sources, or thousands of
repositories) where you partition and aggregate.

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

Use `--daemon=off` when a scan needs baseline state, live verification,
lockdown, a preset, a detector overlay, a custom allowlist, or another per-scan
engine policy. The mass route accepts spec-bound incremental state for
daemon-local filesystem roots; the other contracts remain in process.

Use the explicit mass service for standard-policy directory trees, Git history,
hosted inventories, cloud buckets, archives, binaries, and remote endpoints:

```bash
keyhog calibrate-autoroute --policy default
keyhog daemon start --mass --socket /run/user/$UID/keyhog-mass.sock

keyhog scan --daemon=mass \
  --daemon-socket /run/user/$UID/keyhog-mass.sock \
  ./partitions/team-a \
  --format json-envelope --output team-a.json
```

For warm unchanged-tree scans, add `--incremental --incremental-cache
/absolute/path/merkle.idx`. The daemon loads and publishes that spec-bound
generation without rebuilding its scanner. Files with findings are forgotten
before publication and remain visible on every scan.

`--daemon=mass` is required routing. A missing, warm-only, stale, or
incompatible service is an error. KeyHog does not fall back to an in-process
scan. Policy incompatibility is checked before source acquisition.

### GPU-backed daemon worker

For a local filesystem root, the client sends only canonical path and
source-policy metadata. The daemon reads and batches the files without copying
payload bytes through IPC. Sources that require client-side credentials, such
as hosted Git and cloud inventories, use protected wire frames. Both paths keep
each batch at no more than 8 MiB of raw payload and 1,024 chunks. The daemon
processes each batch with its persisted autoroute decision while retaining one
exclusive fragment-state lease for the transaction. It clears fragment state
when the transaction ends or the client disconnects. This bounds batch memory
independently of total inventory size. Response JSON is written directly into
its bounded transport frame, so the daemon does not retain a second complete
serialized response body.
Daemon-local acquisition uses one drain request. The daemon streams one bounded
result response per batch followed by the terminal completion response. Socket
backpressure remains the memory bound; the client does not pause each batch to
send another request.

The completion receipt contains exact total and GPU batches, chunks, bytes, and
daemon execution time. Protected wire mode compares total chunks and bytes with
the sent stream. Daemon-local path mode uses the daemon receipt as source-byte
authority. Stderr reports the transport, GPU byte share, whether GPU processed
more than half of all bytes, and throughput. Invalid receipt invariants fail.
Source acquisition gaps remain visible in the envelope and exit `13`.

Check `keyhog daemon status --socket /run/user/$UID/keyhog-mass.sock` before
admitting jobs. The daemon serializes fragment-sensitive engine work, so
additional concurrent clients do not create extra GPU lanes. Scale across
separately budgeted worker hosts, not unbounded clients on one socket.

Routine workers use persisted autoroute evidence. Add
`--mass-gpu-primary` when the worker must prove that GPU processed more than
half of all non-empty payload bytes. The client rejects a CPU-majority receipt
before producing the final report. A forced `--backend
gpu-cuda-region-presence`, `gpu-metal-region-presence`, or
`gpu-wgpu-region-presence` service is a diagnostic GPU-only contract. It exits
`12` when required GPU startup fails and returns a
request error instead of substituting CPU after a runtime fault. It does not
prove that GPU is the fastest route for the workload.

The daemon and client must use the same replacement detector corpus. Overlay
composition is unsupported. Start the service with the reviewed replacement
corpus, then select that same corpus on the client:

```bash
keyhog daemon start --mass --detectors ./reviewed-detectors
keyhog scan --daemon=mass \
  --detectors ./reviewed-detectors --detectors-mode=replace \
  ./partitions/team-a
```

A replacement identity mismatch is a handshake error. See
[daemon and warm scans](../workflows/daemon.md) for lifecycle, socket,
eligibility, and retry behavior.

For a large inventory, partition at the provider or repository boundary.
Calibrate autoroute on the actual worker class and retain the per-partition
resolved policy, coverage envelope, and execution receipt. Missing or stale
autoroute evidence leaves the affected batch unscanned and records incomplete
coverage. It does not silently claim calibrated CPU, Hyperscan, or GPU
execution.

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
- Use `--daemon=mass` for standard-policy directory, history, archive, remote,
  or cloud streams. Use `--daemon=off` when the partition needs policy state
  that the mass service rejects.
- Aggregate only after every concurrent partition has reached a terminal
  state. One successful job cannot erase another job's coverage gap or error.

Use `--profile` on representative partitions before changing advanced
`--reader-threads`, `--fused-batch`, or `--fused-depth` values. Keep those
controls unset when a repeatable target-host measurement does not show a
benefit.

## Report aggregation

Aggregate only after every partition has a terminal envelope. One clean
partition never cancels another partition's coverage gap or error.

Read every report at once:

```bash
cat keyhog-results/*.json | jq -s '{
  partitions: length,
  findings: (map(.findings | length) | add),
  coverage_gaps: (map(.coverage_gap_summary | length) | add),
  incomplete: [ .[] | select(.scan_status != "success") | .metadata.targets[0] ]
}'
```

```json
{
  "partitions": 2,
  "findings": 1,
  "coverage_gaps": 0,
  "incomplete": []
}
```

Act on `incomplete` first. A partition listed there did not cover its input, so
its finding count proves nothing. Fix the cause, rerun that partition alone,
and replace only its report. The `findings` total is trustworthy once
`incomplete` is empty.

The envelope carries coverage state, not the process exit code, so keep
`status.tsv` beside the reports. The wrapper in
[Local partitions](#local-partitions) already exits nonzero when any partition
did; `status.tsv` is what tells a reviewer which partition produced which raw
code, because one aggregate exit code cannot express two different failures.

Preserve the partition identity, source inventory, resolved policy, coverage
state, finding count, and exit code. JSON and JSONL legacy formats contain
findings only; `json-envelope` and `jsonl-envelope` are the recommended machine
contracts for mass scans because they carry terminal coverage and identity.
Never concatenate JSON arrays or merge findings before deduplicating with the
partition and location identity.
