# Tell a real clean from a skipped input

An empty findings list has two very different causes. KeyHog read your input and
found nothing. Or KeyHog never read your input. This page shows you how to tell
those apart on any workload.

The most dangerous ambiguity is no longer a total source failure: a read-nothing
scan exits `13`. It is a partially read scan whose only missing content is
classified as an advisory skip. That scan can exit `0` while the envelope says
`partial`, so neither an empty findings list nor the process code proves that
the specific files you care about reached the detector pipeline. Check the byte
count and gap reasons together.

Read one number first:

```sh
keyhog scan . --format json-envelope -o keyhog.json
jq '.metadata.source_bytes_scanned' keyhog.json
```

`source_bytes_scanned` is the count of source bytes that actually entered the
detector pipeline. `0` means nothing was scanned. A read-nothing scan now also
exits `13`, which makes this check louder rather than redundant: a scan that
read SOME bytes but not the ones you cared about still exits `0`, and this
field is what catches that.

## The coverage check

Run this after any scan whose result you intend to act on:

```sh
rm -f keyhog.json
rc=0
keyhog scan . --format json-envelope -o keyhog.json || rc=$?
jq '{
  bytes: .metadata.source_bytes_scanned,
  chunks: .metadata.source_chunks_scanned,
  status: .scan_status,
  gaps: .coverage_gap_summary,
  findings: (.findings | length)
}' keyhog.json
printf 'keyhog exit=%s\n' "$rc"
```

Treat the result as a real clean only when `bytes` is greater than zero and the
gap reasons are acceptable for this source boundary. Compare against an
inventory or expected eligible-byte range when you have one; raw repository
size is not a valid oracle because exclusions and decode expansion move the
counter in opposite directions.

Read the structured fields, not the warnings. It is tempting to build a CI
check by searching stderr for the word `WARN`, but this page is about detecting
an ABSENCE, and a text search that silently matches nothing returns exactly the
answer you were hoping for. KeyHog also has more than one wording for most
failure classes, so a search for one of them passes over the others. The exit
code and `coverage_gap_summary` are complete and stable; the prose is neither.
Use the warnings to find out WHICH path or object failed, after a structured
field has already told you that something did.

## What each field means

`source_bytes_scanned` counts bytes handed to detectors. Decoding can raise it
above the on-disk size, because a decoded layer is scanned in addition to the
raw bytes it came from. A 32 MiB minified bundle scanned as `bundle.js` reports
about 38 MiB for that reason.

`source_chunks_scanned` counts the units of work. One small file is one chunk.
Files above the 1 MiB window size become several chunks. Empty `stdin` reports
one chunk and zero bytes, so chunk count alone does not prove coverage.

`scan_status` is one of five values.

| Value | Meaning |
|---|---|
| `success` | No coverage gap was recorded and no backend recovery happened. |
| `complete_after_recovery` | Coverage is complete after an authenticated backend fault completed through exact recovery. Missing or invalid autoroute evidence is not recovery; it records a `partial` scan. |
| `partial` | At least one coverage gap was recorded. |
| `cancelled` | The run was interrupted. |
| `failed` | The run failed before it could report. |

`coverage_gap_summary` is an array of `{reason, count}` rows. Each row names one
class of input that KeyHog did not fully scan.

## `partial` is not a reject rule

An ordinary working-tree scan of a Git repository reports `partial`:

```sh
keyhog scan . --format json-envelope -o keyhog.json
jq '{status: .scan_status, gaps: .coverage_gap_summary}' keyhog.json
```

```json
{
  "status": "partial",
  "gaps": [
    {
      "reason": "binary (extension or content sniff)",
      "count": 1
    },
    {
      "reason": "default exclusion policy (lock files, minified/bundled assets, vendored and build-output trees). User `.keyhogignore` / --exclude-paths removals are not counted here",
      "count": 6690
    }
  ]
}
```

The default skips for `.git/`, lockfiles, vendored trees, and minified bundles
are counted as coverage gaps, and on this repository that is 6,690 of them.
Almost every real repository therefore reports `partial`. A CI rule that fails
on `partial` fails on every scan and gets switched off within a week.

Gate on the gap reasons you care about instead:

```sh
jq -e '[.coverage_gap_summary[]
        | select(.reason | test("exclusion policy") | not)]
       | length == 0' keyhog.json
```

That expression exits non-zero when any gap other than the exclusion-policy gap
is present. On the sample above it exits `1`, because of the `binary` row, which
is the behavior you want: the exclusion gap is expected and the binary gap is
worth a look. Add `.metadata.source_bytes_scanned > 0` to the same expression
when the input is one you can size in advance.

## Gap reasons

Every reason string below comes from the scanner. The wording in the report is
longer; the fragment shown here is enough to match on.

| Reason fragment | What was not scanned | What to do |
|---|---|---|
| `exceeded --max-file-size` | A file larger than the cap, 100 MiB by default. | Raise `--max-file-size` with a unit, or scan the file on its own. |
| `binary (extension or content sniff)` | A file KeyHog classified as binary. A directory walk does not reinterpret it as text. A directory containing only skipped binaries also gets `scan covered nothing` and exits `13`; a mixed tree can exit `0` with this advisory row. | Expected for images. Never read it as coverage of an executable. `--no-default-excludes` does not change it. Use `keyhog scan --binary <file>` on a build with the `binary` feature. |
| `unreadable (permission denied or I/O error)` | A file KeyHog could not open. | Fix permissions or rerun with the right identity. |
| `default exclusion policy (lock files, minified/...)` | A path removed by the default skips. Your own `.keyhogignore` and `--exclude-paths` removals are NOT counted here. | Expected on repositories. See the next section for the limits. |
| `source emitted error rows` | A source returned an error for part of its input. | Read the stderr warnings, which name the exact path or object. |
| `source scan truncated by aggregate source cap` | Input past a total-bytes ceiling. | Raise the source cap or partition the input. |
| `archive or container extraction truncated by an unpack budget` | Archive or image members past the expansion budget. | Read the stderr warnings, which name the exact cap. Unpack with a trusted tool and scan the result. |
| `Git-LFS pointer` | The blob behind an LFS pointer file. | Run `git lfs pull`, then rescan. |
| `git object unreadable` | A Git object that could not be read. | Repair the repository, then rescan. |
| `scanner decode-through truncated by budget/cap` | Deeper encoded layers inside a chunk. | Raise `--decode-depth`. |
| `scanner decode-through declined by --decode-size-limit` | Everything encoded inside an oversize chunk. | Raise `--decode-size-limit`. |
| `scanner structured decode-through skipped by size cap` | Encoded values inside a large structured file, such as a Kubernetes `data` block. | Split the file. The structured parse cap has no CLI flag. |
| `scanner chunk abandoned at its per-chunk deadline` | The remaining bytes of one chunk. | Raise `--per-chunk-timeout-ms`. |
| `binary deep analysis degraded to strings-only` | Structured analysis of a native binary. | Expected without a working deep-analysis backend. Strings were still scanned. |
| `binary unreadable` | A native binary that could not be opened. | Fix permissions, then rescan. |

## Exit codes and coverage

Exit `13` means a requested source failed or coverage was incomplete. It is the
loud failure. Two examples, both real:

```sh
keyhog scan --docker-image registry/app:no-such-tag
```

```text
WARN source: failed to read source: failed to export docker image: ...
error: a requested scan source failed to read and produced no data (see the
warnings above). Not reporting "clean": that scan did not run.
```

Exit code `13`.

```sh
keyhog scan --s3-bucket no-such-bucket
```

```text
WARN source: failed to read source: S3 source listing failed: bucket request
returned 404 Not Found; objects were not scanned.
```

Exit code `13`.

### A total source failure still writes a report

Both examples above exit `13` and write a report. So does an oversize file
scanned on its own, and so does a directory whose only file is unreadable.
`--format json-envelope -o keyhog.json` always produces a parseable envelope,
carrying whatever findings there were and the gaps naming what was not covered:

```json
{
  "scan_status": "partial",
  "coverage_gap_summary": [
    {"reason": "scan covered nothing (zero source bytes read; ...)", "count": 1},
    {"reason": "source emitted error rows (requested input was not fully scanned)", "count": 1},
    {"reason": "exceeded a configured size cap (--max-file-size or the matching --limit-*-bytes)", "count": 1}
  ]
}
```

When a scan reaches report writing and the output path is writable, exit `13`
comes with an envelope naming the uncovered input. A missing report is not
evidence of a source gap: inspect the exit code and stderr. An invalid or
unwritable output path exits `2` and names that path.

Findings are never discarded because part of the input failed. A directory
holding one readable file with a credential and one unreadable file reports the
finding, both gap rows, and exits `1`.

A CI job can therefore parse the report unconditionally:

```sh
rm -f keyhog.json
rc=0
keyhog scan "$TARGET" --format json-envelope -o keyhog.json || rc=$?
jq '{bytes: .metadata.source_bytes_scanned, status: .scan_status,
     gaps: .coverage_gap_summary}' keyhog.json
printf 'keyhog exit=%s\n' "$rc"
```

Keep the `rm -f`. Its original reason is gone, but a report left by an earlier
run is still indistinguishable from a fresh one if anything ever stops this scan
writing. Give every scan its own output path, or delete the path before you
write to it.

Exit `13` does not track coverage gaps. It tracks source error rows. That
distinction decides whether your CI job notices.

A gap that is a *skip* leaves the exit code alone. The scan reports `partial`
and exits `0`:

| Gap | Exit |
|---|---:|
| `binary (extension or content sniff)` | `0` |
| `exclusion policy (...)` | `0` |
| `scanner decode-through declined by --decode-size-limit` | `0` |

That last row is the one to take seriously. It means a credential inside an
encoded payload was never decoded, on the default preset, over an ordinary
file, and your build did not fail. In any file over 1 MiB only the tail is
decode-reachable, so the same payload is found at the end of the file and
missed in the middle of it. See
[Encoded payloads: position decides](../guides/file-shapes.md#encoded-payloads-position-decides).

A gap that is an *error* also emits a `source emitted error rows` row, and that
is what produces exit `13`:

| Gap | Also emits | Exit |
|---|---|---:|
| `exceeded --max-file-size` | `source emitted error rows` | `13` |
| `unreadable (permission denied or I/O error)` | `source emitted error rows` | `13` |
| `scan covered nothing` | zero source bytes read, whatever the cause | `13` |

So a directory whose content is partly skipped exits `0` with `scan_status`
`partial`, a directory with one unreadable file exits `13`, and a scan that
read nothing at all exits `13`. All are `partial`. Only the first is quiet.

When the covered part of the input does have findings, the findings exit code
wins: `1` for findings, or `10` for a confirmed live credential under
`--verify`. The coverage gap stays in the report either way. Do not read exit
`1` as complete coverage, and do not read exit `0` as coverage at all. Read
`coverage_gap_summary` and `source_bytes_scanned`.

[Exit codes](./exit-codes.md) lists every code KeyHog returns.

## Shipped cases where a clean scan is wrong

Each case below returns an empty findings list over input that contains a
live-shaped credential. Two of them are now fixed and are kept because the
shape still catches people out; the surviving silent one is the Git-history
archive. Check for each on the workloads where it applies.

### Minified and vendored paths report nothing (fixed)

A directory containing only `app.min.js` reports no findings, and its
`source_bytes_scanned` count is zero. The file is skipped by the default
exclusion policy. That is now loud: the scan exits `13` with two gap rows, a
`scan covered nothing` row and a `default exclusion policy` row naming which
policy did it.

`--no-default-excludes` now makes the walker read the file AND turns off the
post-match drop, so the credential is reported. Without that flag, every
finding whose path ends in `.min.js`, `.bundle.js`, or `.min.css`, or sits
under `node_modules/`, `bower_components/`, `jspm_packages/`, `site-packages/`,
`wp-includes/`, `wp-content/plugins/`, `wp-content/themes/`, `public/plugins/`,
`public/static/`, `public/vendor/`, `static/vendor/`, `dist/vendor/`,
`dist/assets/`, or `vendor/assets/` is still dropped after matching. Each drop
is counted and reported as its own coverage-gap row naming how many findings
were dropped, so the suppression is visible rather than silent.

Measured: a directory holding only `app.min.js` with a planted credential
reports zero findings by default and exit `13`, and with
`--no-default-excludes` reports the credential and exits `1`.

`--dogfood` shows the individual suppressed matches and their reason, which is
more detail than the gap-row count:

```sh
keyhog scan dist/ --no-default-excludes --dogfood --format json-envelope
```

The stderr trace names the reason `vendored_minified_path`.

To scan a bundle you own, copy it to a path outside those names and scan the
copy:

```sh
cp dist/app.min.js /tmp/audit/app.js
keyhog scan /tmp/audit
```

The same bytes report the finding at that path.

### An archive reached through Git history is not opened

Container handling applies to files on disk. It does not apply to Git objects
or to cloud object bodies. The same archive gives different coverage depending
on how you reach it:

```sh
keyhog scan repo/ --no-default-excludes --format json-envelope
keyhog scan --git-history repo --format json-envelope
```

The working-tree scan descends into the archive and reports the credential
inside it. The Git-history scan reports a `binary (extension or content sniff)`
gap for that blob, `scan_status` `partial`, and exit `0`.

The gap row is there, so this is not fully silent. It is still easy to misread:
a `binary` gap normally means an image or a compiled object you did not want
scanned, and here it means an archive nobody opened. `--git-blobs` reports the
same gap and exits `13`, so the two Git commands disagree on loudness over the
same bytes.

Unpack committed archives and scan the result as a separate job when history is
in scope. See
[Container images and OCI layers](../guides/container-images.md).

### A total ignore rule scans nothing (fixed)

A `.keyhogignore` containing `path:**` matches every path, so the scan reads
zero source bytes. That now exits `13` and carries a `scan covered nothing` gap
row, and the text report says the scan covered nothing instead of reporting no
secrets. Path rules in `.keyhogignore` and `--exclude-paths` still record no
gap of their own, so a too-broad rule that leaves SOME bytes readable stays
invisible in the report. Only the read-nothing case is loud.

Measured: `--exclude-paths '**'` and a `.keyhogignore` containing `path:**`
each exit `13` with `scan_status` `partial`, zero `source_bytes_scanned`, and a
`scan covered nothing` gap row.

Find out whether an allowlist file is in effect before you trust a clean scan on
a repository whose ignore file you did not write:

```sh
keyhog config --effective
```

The `allowlist_file` line names the `.keyhogignore` that will be loaded. Read
that file, then confirm `source_bytes_scanned` is a plausible size for the tree.

## Prove your check works

Plant a credential-shaped value, scan, and confirm your check reports it. A
canary is a fake credential you place on purpose so you can prove the scan
reached it.

Generate the value instead of copying one. KeyHog suppresses the well-known
documentation samples on purpose, so `sk_live_4eC39HqLyjWDarjtT1zdp7dc` and
`AKIAIOSFODNN7EXAMPLE` both report zero findings and teach you nothing:

```sh
mkdir -p /tmp/keyhog-canary
printf 'STRIPE_SECRET_KEY=sk_live_%s\n' \
  "$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)" \
  > /tmp/keyhog-canary/canary.env
keyhog scan /tmp/keyhog-canary --format json-envelope | jq '.findings | length'
```

Expect `1`. If your pipeline reports `0` for that input, the pipeline is broken,
not the repository.

Put the canary inside the shape you actually scan. A canary in a plain file
proves nothing about a scan whose real input is a container layer, an archive
member, or a Git commit that no longer exists in the working tree.
