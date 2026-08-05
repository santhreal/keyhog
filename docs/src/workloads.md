# Pick your input shape

KeyHog scans more than one kind of thing. A repository working tree, a 4 GiB
log, a minified bundle, a container image, and a Git history are five different
workloads. Each has its own command, its own limits, and its own way of going
quiet when it fails.

Find your shape in the table, run the command, then run the coverage check for
that shape. The default command is right for exactly one shape.

| Input shape | Command | Page | Check first |
|---|---|---|---|
| A repository working tree | `keyhog scan .` | [Your first scan](./first-scan.md) | `source_bytes_scanned` is close to the tree size |
| Many small files, hundreds of thousands | `keyhog scan <root>` | [File shapes and sizes](./guides/file-shapes.md#many-small-files) | `source_chunks_scanned` matches the file count |
| One very large file | `keyhog scan --max-file-size <SIZE> <file>` | [File shapes and sizes](./guides/file-shapes.md#one-very-large-file) | No `exceeded --max-file-size` gap |
| A minified or single-line file | copy it to a non-vendored path first | [File shapes and sizes](./guides/file-shapes.md#minified-and-single-line-files) | `source_bytes_scanned` is not `0` |
| Git history | `keyhog scan --git-history <repo>` | [Deep recovery](./guides/deep-recovery.md) | `source_chunks_scanned` is more than the working tree alone |
| Container images and OCI layers | `keyhog scan --docker-image <ref>` | [Container images](./guides/container-images.md) | You passed a reference, not a saved tarball |
| Cloud object stores | `keyhog scan --s3-bucket`, `--gcs-bucket`, `--azure-container-url` | [Mass scanning](./guides/mass-scanning.md) | No object or page cap in `coverage_gap_summary` |
| Archives and nested archives | `keyhog scan <path>` | [Source archives](./source-archives.md) | No truncation gap |
| Changed files, continuously | `keyhog watch <dir>` | [Watch mode](./guides/watch-mode.md) | You ran a full scan first |
| A pipe or a here-string | `keyhog scan --stdin` | [Standard input and pipelines](./guides/stdin-and-pipelines.md) | `source_bytes_scanned` is not `0` |
| A CI job | `keyhog scan . --format sarif` | [CI secret scanning](./workflows/ci.md) | The job fails on exit `13`, not only on exit `1` |
| A whole estate, partitioned | one job per partition | [Mass scanning](./guides/mass-scanning.md) | Every partition produced its own report and exit code |
| A whole host | `keyhog scan-system` | [System-wide triage](./guides/system-wide-triage.md) | `--space` was not the binding limit |
| A URL, response, or HAR capture | `keyhog scan --url`, `keyhog scan capture.har` | [HTTP and wire](./http-wire.md) | The fetch succeeded |
| A native binary or firmware image | `keyhog scan --binary <file>`, on a build with the `binary` feature | [Choose a scanning workflow](./capabilities.md) | A plain directory scan does not cover binaries. It records a `binary (extension or content sniff)` gap and scans zero bytes. |

## Why the shape matters

The three defaults that decide whether a scan covers your input are set for a
repository working tree.

`--max-file-size` is 100 MiB. A single larger file is skipped.

The default exclusion policy removes `.git/`, lockfiles, vendored trees, and
minified bundles. On a repository that is what you want. On a directory of
build output it removes everything.

`--stdin` accepts 10 MiB. A larger stream fails closed.

None of the three is wrong. Each is wrong for at least one of the shapes above.

## Check coverage the same way every time

Every page in this section ends with the same check, because the question is
always the same. Did KeyHog read my input?

```sh
rm -f keyhog.json
rc=0
keyhog scan <target> --format json-envelope -o keyhog.json || rc=$?
jq '{bytes: .metadata.source_bytes_scanned, status: .scan_status,
     gaps: .coverage_gap_summary, findings: (.findings | length)}' keyhog.json
printf 'keyhog exit=%s\n' "$rc"
```

[Tell a real clean from a skipped input](./reference/coverage-truth.md) explains
each field, lists every coverage-gap reason, and names the cases where the
current build reports a clean scan over input it did not read.

## Combining shapes in one run

You can pass several roots to one `keyhog scan`. You cannot mix source kinds:

```sh
keyhog scan src/ config/ vendor-drop/
```

Nested or duplicate roots fold into their covering parent. One report and one
exit code cover all of them, so a gap in any root makes the whole run
`partial`.

A container image, a bucket, a Git history, and a working tree each need their
own run. Give each one its own output file so a failure in one does not hide
behind a success in another:

```sh
keyhog scan . --format json-envelope -o worktree.json
keyhog scan --git-history . --format json-envelope -o history.json
keyhog scan --docker-image registry/app:v1 --format json-envelope -o image.json
```

Check the exit code of each. Exit `13` on any of the three means that input was
not covered, whatever the other two reported.
