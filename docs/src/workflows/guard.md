# Perpetual repository and filesystem guard

The guard is a daemon-resident runtime that registers Git repositories and
filesystem trees as guarded roots. Each root has a 7-state machine, a clean
attestation cache, and a policy identity that binds attestations to the exact
detector corpus, suppression rules, and configuration the daemon was started
with.

The guard supplements staged and working-tree scans. It does not replace them.
A commit is allowed only after the exact staged-object transaction proves the
content is clean.

## Start the daemon

```sh
keyhog daemon start --backend cpu
```

The guard uses the same daemon as scan requests. One daemon serves all guard
roots and scan traffic.

## Register a root

```sh
keyhog guard add /path/to/repo --mode repo
```

`--mode repo` uses Git object IDs for exact staged-content identity.
`--mode filesystem` uses content hashes without immutable Git OIDs.

A newly added root starts in the `stopped` state. Run `keyhog guard reconcile`
to transition it to `current` after the initial baseline scan.

## Check status

```sh
keyhog guard status /path/to/repo
```

Output includes the root state, terminal sequence, pending events, files and
bytes scanned, attestation cache hits and misses, findings count, coverage
gaps, and scanner residency label.

JSON output:

```sh
keyhog guard status /path/to/repo --format json
```

## List roots

```sh
keyhog guard list
```

## Reconcile a root

```sh
keyhog guard reconcile /path/to/repo
```

Reconciliation forces a full baseline scan. Use it after an intentional policy
or filesystem change.

## Remove a root

```sh
keyhog guard remove /path/to/repo
```

## States

| Label | Meaning |
|---|---|
| `stopped` | The root is registered but not actively guarded. |
| `indexing` | A baseline reconciliation is in progress. |
| `current` | The root is clean and up to date. |
| `dirty` | Filesystem events were observed but not yet reconciled. |
| `blocked` | Unsuppressed findings were detected. The root is not clean. |
| `degraded` | Coverage is incomplete. The guard cannot prove the root is clean. |
| `stale-policy` | The daemon's detector corpus, suppression, or configuration changed. Existing attestations are invalid. |

## Exit codes

| Code | Condition |
|---|---|
| 0 | The root is `current` or `dirty`. |
| 1 | The root is `blocked` or has unsuppressed findings. |
| 13 | The root is `stopped`, `indexing`, `degraded`, or `stale-policy`. |

## Scanner residency

The scanner is always in memory in the daemon process. The residency label
reports whether the guard is actively using it:

- `active` — in-flight commit transactions right now.
- `resident` — recent guard activity within the idle threshold (5 minutes).
- `idle-unload` — no guard activity for longer than the threshold.

## Configuration

The `[guard]` section in `.keyhog.toml` configures the guard runtime. Settings
include the hot index memory budget, event queue caps, coalesce window,
scanner residency, idle-unload timeout, scrub interval, and subtree
reconciliation bounds.

## How attestations work

When a commit transaction scans a blob and finds no unsuppressed secrets, the
daemon records a clean attestation keyed by the blob's Git OID, hash algorithm,
and policy identity digest. Future transactions that reference the same blob
under the same policy skip the payload scan entirely.

A policy identity change (new detectors, new suppression rules, new
configuration) invalidates all existing attestations and transitions active
roots to `stale-policy`.
