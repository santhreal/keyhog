# File shapes and sizes

Three file shapes need a different command from the repository default. Many
small files. One very large file. A minified or single-line file.

This page gets you a correct scan of each, names the limit that applies, and
shows the check that separates a real clean from a skipped input.

## Many small files

Scan the root. There is no special flag:

```sh
keyhog scan <root> --format json-envelope -o keyhog.json
```

Confirm the file count reached the scanner:

```sh
jq '.metadata.source_chunks_scanned' keyhog.json
```

A file under 1 MiB is one chunk. For a tree of small files, that count should be
close to the number of files you expect. If it is far lower, something removed
files before the scanner saw them.

The usual cause is the default exclusion policy. On a repository it removes
`.git/`, lockfiles, vendored trees, and minified bundles, which is correct. On a
directory of generated or vendored content it can remove almost everything.
Check what it removed:

```sh
jq '.coverage_gap_summary' keyhog.json
```

An `exclusion policy` gap with a count near your file count means the default
skips ate the input. Pass `--no-default-excludes` when you deliberately want
vendored and minified paths walked, and read
[Minified and single-line files](#minified-and-single-line-files) first, because
that flag turns off two separate rules and you should know both.

Limits that bind on this shape:

- `--threads <N>` caps parallel scanner workers. Unset uses the available cores.
- `--max-file-size` still applies per file, so one oversize file in the tree
  produces a gap while the rest of the tree scans normally.

Cost on a 5,000-file tree of about 240 KiB: median peak resident memory 154 MiB
over five runs. Peak memory on this shape is dominated by the compiled detector
corpus, not by the file count, so it barely moves as the tree grows. Plan
against memory, and measure wall time on your own runner: the same five runs
took a median of 0.84 s on an idle-ish host and 7.73 s on a heavily loaded one,
so a wall time quoted here would tell you nothing about yours.


## One very large file

The default `--max-file-size` is 100 MiB. A larger file is not scanned.

Passing a 256 MiB file with the default cap fails loudly:

```sh
keyhog scan bigfile.log
```

```text
WARN skipping file: size exceeds --max-file-size cap path=bigfile.log
     size_bytes=268436133 max_size=104857600
WARN source: failed to read source: ... file was not scanned.
error: a requested scan source failed to read and produced no data (see the
warnings above). Not reporting "clean": that scan did not run.
```

Exit code `13`.

Raise the cap to scan it. The value requires a unit:

```sh
keyhog scan bigfile.log --max-file-size 300M --format json-envelope -o keyhog.json
```

A bare number is rejected before the scan starts, with exit `2`:

```text
error: invalid value '300000000' for '--max-file-size <SIZE>': byte size
'300000000' is missing a unit. Use `B`, `K`/`KB`, `M`/`MB`, `G`/`GB`, or `T`/`TB`.
```

`keyhog watch` takes the same option as a bare byte count, not a size string.
That asymmetry is real. See [Watch mode](./watch-mode.md).

Files above the 1 MiB window size are read in overlapping windows, so a
credential that straddles a window boundary is still found. The 256 MiB file
above, with a credential on its last line, reports one finding and 293 chunks.

Cost on the same tree: median peak resident memory 315 MiB over five runs, for a
256 MiB file. Peak memory does not track file size one-for-one, because windows
stream to the scan pool as they are decoded rather than being collected first.
It is still the number to check before raising the cap on a shared runner.

### The dangerous case is a large file inside a normal tree

When the oversize file is one member of a directory, the rest of the directory
scans and the run does not stop:

```sh
keyhog scan mixed-tree/ --format json-envelope -o keyhog.json
```

```json
{
  "scan_status": "partial",
  "coverage_gap_summary": [
    {"reason": "source emitted error rows (requested input was not fully scanned)", "count": 1},
    {"reason": "exceeded --max-file-size", "count": 1}
  ]
}
```

Exit code is `13` when nothing was found in the covered part, and `1` when
something was. In the `1` case the report still carries the gap. Read
`coverage_gap_summary`, not the exit code alone.

Do not raise `--max-file-size` just to clear exit `13`. Raise it when you trust
the input and the runner has the memory. Otherwise scan the large file as its
own job so its cost and its result are separate.

## Minified and single-line files

A minified file is one whose whole content sits on one or two very long lines. A
single-line file is any file with no newline until the end.

Line length is not a problem. A 32 MiB single-line JavaScript bundle named
`bundle.js` scans normally: 37 chunks, one finding for a credential near the
end, and median peak resident memory 144 MiB over five runs, the same as an
ordinary tree. Windowing is by bytes, not by lines.

The problem is the filename and the directory.

### What the default policy does

A directory containing only `app.min.js` reports no findings and zero
`source_bytes_scanned`. The file never reaches the scanner. The report carries
two gap rows and exits `13`:

```json
{
  "scan_status": "partial",
  "coverage_gap_summary": [
    {"reason": "scan covered nothing (zero source bytes read; every candidate was skipped by exclusion or skip policy, so nothing was examined)", "count": 1},
    {"reason": "exclusion policy (default excludes such as lock files, minified/bundled assets, vendored and build-output trees; --git-staged also counts repository `.keyhogignore` matches here)", "count": 1}
  ]
}
```

A scan that reads zero bytes is a loud failure, not a clean result. The second
row tells you which policy did it.

### What `--no-default-excludes` now does

`--no-default-excludes` turns off both layers: the walker reads the file, and
the post-match drop is disabled, so the credential is reported. The same
directory with the flag reads 1441 bytes and reports the finding.

Without the flag, a match is still dropped after the fact when its path ends in
`.min.js`, `.bundle.js`, or `.min.css`, or sits under `node_modules/`,
`bower_components/`, `jspm_packages/`, `site-packages/`, `wp-includes/`,
`wp-content/plugins/`, `wp-content/themes/`, `public/plugins/`,
`public/static/`, `public/vendor/`, `static/vendor/`, `dist/vendor/`,
`dist/assets/`, or `vendor/assets/`. Each drop is counted, and the total
appears in `coverage_gap_summary` as its own row, so the suppression is visible
in the report rather than silent.

Measured: a directory holding only `app.min.js` with a planted credential
reports zero findings by default, and reports the credential with
`--no-default-excludes`.
`--dogfood` shows the individual suppressed matches and their reason, which is
more detail than the gap-row count:

```sh
keyhog scan dist/ --no-default-excludes --dogfood --format json-envelope
```

The stderr trace names the reason `vendored_minified_path`.

### Scan a bundle you own

Pass one first-party bundle as an explicit file, or disable default exclusions
for the directory that owns it:

```sh
keyhog scan dist/app.min.js --format json-envelope -o keyhog.json
keyhog scan dist/ --no-default-excludes --format json-envelope -o keyhog-dist.json
```

An explicit file request is not removed by the directory walker's default path
policy. Use `--no-default-excludes` when the scan must cover several minified or
vendored-shaped paths. Review that broader scope first: it also enables
third-party bundles that the repository default intentionally omits.

This matters most for a first-party bundle you ship. A vendored third-party
bundle you did not write is what the suppression is for, and leaving it
suppressed is usually right.

## Encoded payloads: position decides

In any file over 1 MiB, a credential inside an encoded payload is only found
when it sits in the last part of the file. Everywhere else it is missed, on the
default preset, with no warning that fails your build. This is the sharpest
edge on this page.

`--decode-size-limit` defaults to 512K and bounds decoding per WINDOW, not per
file. Files over 1 MiB are read as 1 MiB windows, so every window except the
tail is over the limit and is never decode-expanded.

Measured on one file whose only credential is a Base64 payload on the LAST
line, at the default preset:

| File size | Findings | Exit |
|---|---:|---:|
| 400K | 2 | `1` |
| 510K | 2 | `1` |
| 520K | 0 | `0` |
| 600K | 0 | `0` |
| 1000K | 0 | `0` |
| 1100K | 2 | `1` |
| 1500K | 0 | `0` |
| 2000K | 2 | `1` |

The table looks random in file size and is exactly predictable in something
else. A credential at the END of a file lands in the LAST window. Windows are
1 MiB with 128K of overlap, so they advance 896K at a time and the last window
holds whatever is left over. Decoding happens per window, so:

> A payload is decoded when the window holding it is at or under
> `--decode-size-limit`.

At 1100K the last window holds only 204K and the payload is found. At 1500K it
holds 604K and is not. At 2000K it holds 208K and is found again.

### Position matters more than size

Every row above puts the credential at the end of the file, which is the only
position that can succeed. Hold the size fixed and move the payload instead:

| 2000K file, payload at | Findings | Exit |
|---|---:|---:|
| end of file | 2 | `1` |
| middle | 0 | `0` |
| one quarter in | 0 | `0` |

Same size, same bytes, opposite result. A payload anywhere but the tail sits in
a full 1 MiB window, and a full window is always over the 512K limit.

So the honest rule is not about file size at all. In any file larger than
1 MiB, only the tail is decode-reachable, and the whole interior is not. The
bigger the file, the smaller that reachable fraction: a 12 MB file is roughly
1.6% decode-reachable.

Measured on a 2.2 GB Rust registry checkout, 377 of 110,846 files are over
512K and hold 595 MB between them. Of that, 574 MB is decode-unreachable and
20 MB is reachable through tail windows.

The underlying cause is that two defaults are ordered wrongly. The window size,
1 MiB, is larger than the decode limit, 512K, so a full-size window can never
be decode-expanded no matter what it contains. That ordering alone accounts for
173 MB of the 574 MB, in files between 512K and 1 MiB whose single window
merely exceeds the cap. The remaining 422 MB is genuine interior of files over
1 MiB, which only a subdividing decode path can reach.

The report does say so, in the one place worth reading:

```json
{
  "reason": "scanner decode-through declined by --decode-size-limit (chunk larger than the limit; raw bytes scanned, nothing encoded inside it was recovered)",
  "count": 1
}
```

`scan_status` is `partial` and the exit code is `0`. This is a skip, not an
error, so nothing fails your build. Gate on the gap reason, not the exit code.

The gap also appears on the rows that DID report findings, at 1100K and 2000K
above. That is correct, not a false positive: those files still hold oversize
chunks whose encoded content was never expanded, and a differently-split chunk
happened to recover this particular payload. Findings plus this gap means
partial decode coverage, not complete coverage.

Raise the limit when your inputs carry encoded payloads:

```sh
keyhog scan . --decode-size-limit 4M --format json-envelope -o keyhog.json
```

That recovers the credential at every size and every position tested above.

`--deep` also recovers them, but do not rely on it for this. Deep raises the
decode ceiling to exactly 1 MiB, which is exactly the window size, so it clears
the limit with no margin at all. Any increase to the window, or a ceiling
compared as strictly-less-than rather than at-most, silently reopens the hole
for deep too. Use `--decode-size-limit` when the decode budget is what you
need, and `--deep` when you want the rest of its policy as well.

## Check coverage on every shape

```sh
jq '{bytes: .metadata.source_bytes_scanned, chunks: .metadata.source_chunks_scanned,
     status: .scan_status, gaps: .coverage_gap_summary}' keyhog.json
```

Zero bytes means nothing was scanned, whatever the findings list says.
[Tell a real clean from a skipped input](../reference/coverage-truth.md)
explains each field and each gap reason.
