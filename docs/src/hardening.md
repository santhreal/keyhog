# Hardening and data handling

A secret scanner reads credentials into memory for a living. KeyHog treats
that as a threat model, not an afterthought. This chapter describes what the
process does to protect the secrets it handles and what it never does with
them. (For how to report a vulnerability in KeyHog itself, see the
[Security policy](./security.md).)

## Detection is local

KeyHog does not phone home. Detection runs entirely on your machine: the
detector corpus is compiled in, service validators prove a credential's shape
with offline checks (GitHub and npm CRC32, PyPI payload decoding) rather than
by calling the service, and no finding, filename, or telemetry event leaves the
host. There is no analytics endpoint to disable because there is none.

Two operations are allowed to reach the network, and only when you ask for
them: `--verify`, which live-checks whether a found credential is still active,
and `keyhog update`, which fetches a signed release. A default scan makes no
outbound connection.

## Always-on process hardening

Every KeyHog invocation, not just lockdown runs, applies zero-cost process
protections before it reads a byte:

- **Linux:** `prctl(PR_SET_DUMPABLE, 0)` disables core dumps, `ptrace` attach
  from non-root, and `/proc/<pid>/mem` reads against the KeyHog process.
- **macOS:** `ptrace(PT_DENY_ATTACH, …)` denies debugger attachment with the
  same intent.
- **Windows:** a best-effort process mitigation policy.

These have no throughput cost, so they are never gated behind a flag. The
practical effect: another process on the same host cannot snapshot KeyHog's
memory to read the credentials it is scanning, and a crash cannot spill them
into a core file.

## Lockdown mode

When KeyHog runs on the same machine that holds the secrets, for example paired
with [EnvSeal](https://github.com/santhsecurity/envseal), there is no trusted
boundary between the scanner and the credentials. `keyhog scan . --lockdown`
adds the protections that carry a real cost:

- `mlockall(MCL_CURRENT | MCL_FUTURE)` pins every current and future page into
  RAM so no credential can be swapped to disk.
- On Linux it refuses to run if `/proc/self/coredump_filter` would let
  anonymous pages reach a dump.
- It refuses to run if any persistence cache exists, and refuses
  `--incremental` writes, `--verify`, and `--show-secrets`, so nothing about
  the run is written to disk.
- It refuses the completeness-trading fast flags (`--fast`, `--no-decode`,
  `--no-entropy`, `--no-ml`, and the like): a lockdown run is the
  highest-stakes run, so every detection gate stays engaged.

Lockdown and `--include-network` on [`scan-system`](./guides/system-wide-triage.md)
are mutually exclusive; pick one posture per run.

## Credentials in memory

Found credentials are held in an opaque `Credential` type whose bytes are
zeroed on drop through the `zeroize` crate, so a freed heap page never keeps a
readable copy. Reports redact every secret to a fixed shape (`sk_l...p7dc`);
the full value is written out only when you explicitly pass `--show-secrets`,
which lockdown refuses.

## Signed, fail-closed releases

The install and update path verifies a SHA-256 checksum and a minisign
signature against the release-side files before it replaces a binary, and rolls
back if verification fails. An unsigned or tampered artifact never runs. The
[install guide](./install.md) documents the pinned, authenticated flow, and
`keyhog update` performs the same verification atomically.
