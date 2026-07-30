# System-wide credential triage

`keyhog scan-system` performs a one-shot audit across the mounted filesystems
that KeyHog can enumerate and read. It scans working-tree files first. It also
discovers Git repositories and scans their history unless you disable that
step.

Start with a bounded local sweep:

```sh
sudo keyhog scan-system --space 10G 2>scan-system.log
```

Keep the exit status and stderr log. Stderr contains the selected mounts,
coverage warnings, byte count, and terminal summary. Add `--output findings.json`
when you also need a redacted JSON findings array.

Run with enough privilege to read the trees in scope. An unreadable path is a
coverage gap. KeyHog reports the gap and does not describe the run as complete.
Use elevated privilege only on a host and scope you are authorized to audit.

Choose the host boundary explicitly:

| Goal | Command | Coverage and cost |
|---|---|---|
| Quick working-file health check | `sudo keyhog scan-system --space 50G --no-git-history` | Skips discovered Git history. Choose a space ceiling large enough for the local files you intend to cover. |
| Full local-host recovery | `sudo keyhog scan-system --space 50G` | Scans eligible filesystem data, then reachable additions from every discovered Git repository. |
| Authorized network-estate sweep | `sudo keyhog scan-system --space 1T --include-network` | Adds NFS, SMB, and other network mounts. It can be slow and may cross ownership boundaries, so opt in only with authorization. |
| Shared-host CPU budget | `sudo keyhog scan-system --space 50G --threads <N>` | Caps parallel scanner workers. Leaving it unset uses the available CPU cores. |

The quick command is not a substitute for the full recovery command. Keep its
report labeled as a working-file-only system check.

## Execution mode

`scan-system` always builds and runs its scanner in process. It does not accept
`--daemon`, and a running daemon does not change its behavior. This is distinct
from `keyhog scan --daemon=auto`, which can route an eligible single file or
`stdin` request through a warm daemon.

Use `watch` after the one-shot sweep when you need to inspect future file
changes:

```sh
keyhog watch ~/projects \
  --max-file-size 104857600 \
  --max-consecutive-failures 8
```

`watch` is also an in-process foreground command. It compiles one scanner and
scans changed regular files. It does not perform the initial directory sweep or
Git-history scan for you. Run `keyhog scan --daemon=off ~/projects` for a full
rescan after a watch failure. The watcher exits after eight consecutive scan
engine failures by default so a broken scanner does not keep dropping changes.

## What the system sweep walks

The command discovers targets instead of accepting a path. It enumerates
mounted filesystems and skips pseudo-filesystems such as `/proc`, `/sys`,
`tmpfs`, and `nsfs`. Network mounts such as NFS, SMB, and sshfs are skipped by
default. Add `--include-network` only when that remote scope is authorized:

```sh
sudo keyhog scan-system --space 1T --include-network
```

During discovery, KeyHog finds ordinary worktrees, bare repositories, and
submodules. After the filesystem walk, it scans their Git histories. A
credential committed and later deleted can therefore surface. Use
`--no-git-history` when only current files are in scope:

```sh
sudo keyhog scan-system --space 10G --no-git-history
```

A binary built without the `git` feature cannot scan discovered history.
KeyHog reports each skipped history as a coverage gap. Reinstall a build with
Git support, or use `--no-git-history` to state the reduced scope.

## Space and findings limits

`--space <SIZE>` is a hard aggregate byte ceiling. The default is `50G`, which
means 50 GiB. Sizes require a unit and accept `B`, `K`, `M`, `G`, or `T` and
their `KB` or `KiB` forms. Fractional values such as `1.5G` are accepted.

KeyHog stops before a chunk that would cross the ceiling. Filesystem data is
scanned before Git history, so a small ceiling can leave later mounts and
histories untouched. Reaching the ceiling records a coverage gap. Raise the
limit and rerun when complete host coverage is required.

The command retains at most 1,000,000 redacted findings in memory and continues
counting additional findings. A warning says when detail was dropped. Preserve
the stderr summary with the JSON output.

The terminal states are:

| Result | Exit |
|---|---:|
| No findings and complete coverage | `0` |
| One or more findings, including a partial scan | `1` |
| No findings and one or more coverage gaps | `13` |
| Invalid arguments or operator input | `2` |
| System or I/O failure | `3` |

Exit `13` is not a clean result. Correct permissions, raise `--space`, restore
Git support, or isolate the affected path with a normal in-process scan.

## Detector corpus

Both system scans and watchers accept an explicit detector directory:

```sh
sudo keyhog scan-system --space 10G \
  --detectors /opt/keyhog/reviewed-detectors

keyhog watch ~/projects \
  --detectors /opt/keyhog/reviewed-detectors
```

An explicitly selected directory is a replacement corpus by default. It does
not silently fall back to embedded detectors when the path is missing or
invalid. These subcommands do not expose a `--detectors-mode` flag. They use the
shared scan configuration, so a valid `detectors_mode = "overlay"` in the
resolved `.keyhog.toml` explicitly requests composition instead.

This corpus is compiled by the command itself. It need not match a running
daemon because neither `scan-system` nor `watch` uses the daemon socket.

## Ignore and lockdown policy

Unlike a normal filesystem scan, `scan-system` ignores `.gitignore` and
`.keyhogignore` by default. This prevents a local ignore rule from hiding the
files being triaged. Use `--respect-gitignore` only when that narrower scope is
intentional.

Every system sweep disables core dumps and ptrace when the host permits it.
`--lockdown` also requires the stronger protections to succeed and refuses
network mounts. It cannot be combined with `--include-network`.

For recovery, address every warning before treating the host as covered. Fix
permissions for unreadable paths, raise the byte ceiling, repair corrupt Git
objects, or rerun a deliberately reduced scope. See the
[CLI reference](../reference/cli.md#keyhog-scan-system) for the full flag list
and [exit codes](../reference/exit-codes.md) for shared failures.
