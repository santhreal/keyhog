# Watch mode

`keyhog watch` monitors directories and scans files as they change.

```sh
keyhog watch src/ config/
```

It runs in the foreground, compiles one scanner at startup, scans what is
already in the tree, and then prints each finding as it happens:

```text
🔍 stripe-secret-key /home/you/project/src/b.env:1 CRITICAL (1.00)  sk_l...EaNn
👁  keyhog watch (☰ 927 detectors compiled)
    workers: 16
    watching: /home/you/project/src
    Ctrl-C to exit
```

## Readiness means the tree is covered

The startup block is printed last, on purpose. By the time you see
`watching:`, the filesystem watches are registered and every file already in
the tree has been scanned. Findings from that first pass appear above the
block, which is why the example shows one there.

That ordering is the whole guarantee. A file written while the scanner was
compiling, or between compilation and watch registration, is still reported,
because the startup pass sees it on disk. It is reported once: the same
deduplication that collapses an editor's event burst also collapses a file
caught by both the startup pass and an event.

A large tree makes startup slower for the same reason. The watcher is scanning
it. If a root holds more than 10000 files, the startup pass stops at that
limit and says so, naming the `keyhog scan` command that covers the rest.

Watch still reports changes, not state. Run a full scan again after the watcher
exits for any reason, because every change while it was down is unobserved:

```sh
keyhog scan src/ config/ --format json-envelope -o baseline.json
```

A scan also gives you the machine-readable coverage the watcher cannot.

## What triggers a scan

A new file in a watched root is scanned. A new file in a subdirectory created
after the watcher started is scanned, because roots are watched recursively.

A whole directory that appears in a watched tree is scanned, including the
files it already contained. This covers `mv ~/Downloads/config-dump src/`,
`cp -r`, `tar -xf`, and a dependency vendoring step. The kernel reports one
event for the directory and none for its contents, so the watcher walks the
new subtree itself rather than waiting for events that never come. The walk
stops at 10000 files or 64 levels and says so; it does not follow a symlinked
directory out of the watched root.

A modified file is rescanned in full. Every finding in that file is printed
again, including ones you already saw. One editor save can produce more than one
event, so the same finding can appear several times in a row. The output is a
stream of events, not a deduplicated report.

An editor that saves by writing a temporary file and renaming it over the
original is handled. The rename is a change to the destination path and the
destination is rescanned. Some editors leave the temporary file visible long
enough to be scanned too, so you may see the same finding reported once
against a `.swp`-style name and once against the real one.

Nested or duplicate roots fold into their covering parent, the same as
`keyhog scan`. Each root must be a directory.

## Paths watch skips, and the one that stops it

A symlink is not followed, and neither is a FIFO, socket, or device node.
`keyhog scan` declines the same paths, so this is shared policy rather than a
watch limitation. Each one prints a line saying it was not scanned and that
`keyhog scan` skips it too. These do not count toward
`--max-consecutive-failures`, so a tree full of symlinks does not stop the
watcher. A file that exists, is in policy, and still cannot be read, such as
one you lack permission for, does count.

Deleting a watched root removes its watch. The kernel discards the watch along
with the directory, so there is nothing left to observe and no way to tell that
apart from a quiet tree. The watcher says so and then waits up to 30 seconds
for the directory to come back, because a root is more often replaced than
deleted:

```text
WARN keyhog watch: watched root /home/you/project/build was removed; its
     filesystem watch is gone and changes under that path are NOT being
     observed. Waiting up to 30s for it to return.
OK   keyhog watch: /home/you/project/build is being watched again; rescanned
     12 file(s) to cover the gap while it was missing.
```

The rescan is the point. Nothing was observed between the two messages, so the
whole subtree is scanned again on return rather than assumed unchanged. A file
written while the root was missing is reported.

If the directory does not come back within that window, `keyhog watch` exits
non-zero naming the root, rather than continuing to report a clean tree that
nobody is watching.

## What watch cannot do

`keyhog watch` prints text only. It has no `--format` and no `--output`. There is
no JSON envelope, so there is no `source_bytes_scanned`, no
`coverage_gap_summary`, and no machine-readable coverage signal. When you need a
report you can check, run `keyhog scan`.

Suppression that runs after a match applies, so a change to `app.min.js`
produces no output, for the same reason a scan of it produces no findings. See
[Minified and single-line files](./file-shapes.md#minified-and-single-line-files).

Exclusion by filename does not. `keyhog scan` skips lock files before reading
them; `keyhog watch` only skips excluded DIRECTORY names, so it reports
findings in files a scan of the same tree leaves out. Measured on one tree with
a credential planted in each file, scan reports 4 and watch reports 9; the five
extra are `Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and
`go.sum`. Watch is noisier here, never blinder: nothing that scan reports is
missing from watch.

Watch is not the daemon. It compiles its own scanner, does not use the daemon
socket, and does not appear in `keyhog daemon status`. Watch also does not scan
Git history.

## Limits

| Flag | Meaning |
|---|---|
| `--max-file-size <BYTES>` | Maximum bytes per changed file. Same 100 MiB default as `keyhog scan`. Pass `0` for the built-in default. |
| `--max-consecutive-failures <N>` | Exit after this many consecutive per-file scan engine failures. Default `8`. |
| `--detectors <DIR>` | Replacement detector corpus. An explicitly named missing path is an error. |
| `--backend <BACKEND>` | Force one backend instead of persisted autoroute. |
| `--quiet` | Print findings only, without the startup status block. |

`watch --max-file-size` takes a bare byte count. `scan --max-file-size` requires
a unit. These two are not interchangeable:

```sh
keyhog watch ~/projects --max-file-size 104857600
keyhog scan ~/projects --max-file-size 100M
```

Passing `104857600` to `keyhog scan` exits `2` with a message about the missing
unit. Passing `100M` to `keyhog watch` is not a byte count.

`--max-consecutive-failures` exists so a wedged scanner cannot keep silently
dropping changed files. It counts scanner faults only. A path skipped by shared
policy, such as a symlink or a file over `--max-file-size`, does not count, so
ordinary repository layout cannot exhaust the budget. When the watcher does
exit for that reason, treat every change since the first failure as unscanned
and run a full scan.

## Warm routing

The watcher warms its routes at startup and reuses that evidence for later file
events, so it does not pay a cold backend start per change. Without valid
autoroute calibration the watcher fails startup without scanning changes. Run
`keyhog calibrate-autoroute` once on the host before starting the watcher.

## A working loop

```sh
keyhog scan ~/projects --format json-envelope -o ~/keyhog-baseline.json
jq '{bytes: .metadata.source_bytes_scanned, status: .scan_status,
     gaps: .coverage_gap_summary}' ~/keyhog-baseline.json

keyhog watch ~/projects \
  --max-file-size 104857600 \
  --max-consecutive-failures 8
```

Read the baseline coverage before you trust the watcher. If the baseline scan
did not reach your files,
[Tell a real clean from a skipped input](../reference/coverage-truth.md) explains
why, and the watcher will have the same blind spots.
