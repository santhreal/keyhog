# Pick your input shape

KeyHog scans more than one kind of thing. A repository working tree, a 4 GiB
log, a minified bundle, a container image, and a Git history are five different
workloads. Each has its own command, its own limits, and its own way of going
quiet when it fails.

Find your shape in the table, run the command, then run the coverage check for
that shape. The default command is right for exactly one shape.

| Input shape | Command | Required build | Page | Check first |
|---|---|---|---|---|
| A repository working tree | `keyhog scan .` | `portable` or `ci` | [Your first scan](./first-scan.md) | Bytes are nonzero; review exclusion and binary gap rows |
| Many small files | `keyhog scan <root>` | `portable` or `ci` | [File shapes and sizes](./guides/file-shapes.md#many-small-files) | Chunks are plausible for the eligible files; large files produce several chunks |
| One very large file | `keyhog scan <file> --max-file-size <SIZE>` | `portable` or `ci` | [File shapes and sizes](./guides/file-shapes.md#one-very-large-file) | No `exceeded --max-file-size` or source-error gap |
| A first-party minified or bundled file | `keyhog scan <file>` or `keyhog scan <root> --no-default-excludes` | `portable` or `ci` | [File shapes and sizes](./guides/file-shapes.md#minified-and-single-line-files) | Bytes are nonzero; directory scans need the explicit exclusion override |
| Git additions or repository objects | `--git-history <repo>` or `--git-blobs <repo>` | `portable` or `ci,git` | [Deep recovery](./guides/deep-recovery.md) | Use a full clone; reject shallow-history and object-read gaps |
| Container images and OCI layers | `keyhog scan --docker-image <ref>` | `portable` or the `docker` feature | [Container images](./guides/container-images.md) | Extraction completed within its byte and member budgets |
| Cloud object stores | `--s3-bucket <name>`, `--gcs-bucket <name>`, or `--azure-container-url <url>` | `portable` or the matching provider feature | [Mass scanning](./guides/mass-scanning.md) | No page, object, or byte cap left inventory uncovered |
| Archives and nested archives | `keyhog scan <path>` | `portable` or `ci` | [Source archives](./source-archives.md) | No encrypted, unsafe, corrupt, or truncation gap |
| Changed files, continuously | `keyhog watch <dir>` | `portable` or `ci` | [Watch mode](./guides/watch-mode.md) | Run one full scan before starting the watcher |
| A pipe or here-string | `keyhog scan --stdin` | `portable` or `ci` | [Standard input and pipelines](./guides/stdin-and-pipelines.md) | Bytes are nonzero and the producer's exit is preserved with `pipefail` |
| One checked-out repository in CI | Action `path: .` or `keyhog scan .` | Action `ci`, or a Cargo `portable`/`ci` build | [CI secret scanning](./workflows/ci.md) | Retain the report and raw exit code; do not accept zero scanned bytes |
| A whole estate, partitioned | One job per provider, repository, or bucket partition | `portable` or the matching provider features | [Mass scanning](./guides/mass-scanning.md) | Every partition produced its own report, exit code, and coverage state |
| A whole host | `keyhog scan-system --space <SIZE>` | `portable` for filesystem plus Git-history coverage | [System-wide triage](./guides/system-wide-triage.md) | Mount policy and the space ceiling did not exclude required input |
| A URL, response, or HAR capture | `keyhog scan --url <url>` or `keyhog scan capture.har` | `portable` or the `web` feature | [HTTP and wire](./http-wire.md) | Fetch/parse completed and the selected response bytes were scanned |
| A native binary or firmware image | `keyhog scan --binary <file>` | `portable` or the `binary` feature | [Choose a scanning workflow](./capabilities.md) | Printable strings or supported sections reached the scanner; no binary source error |

The small `ci` profile intentionally omits Git, cloud, web, container, binary,
and verification flags. Add only the named source feature you need, or use the
default `portable` profile. `keyhog scan --help` is authoritative for the
installed binary.

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

Check the exit code and envelope of each run. A failing source or coverage gap
returns `13` when no finding outcome takes precedence. Advisory skips can leave
`scan_status: partial` with exit `0`, so automation must also inspect the gap
reasons it treats as unacceptable.
