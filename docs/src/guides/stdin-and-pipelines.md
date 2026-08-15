# Standard input and pipelines

Scan bytes that never touch disk:

```sh
kubectl get secret app -o yaml | keyhog scan --stdin
```

`keyhog scan -` is the same as `keyhog scan --stdin`, following the `grep` and
`wc` convention:

```sh
terraform output -json | keyhog scan -
```

Findings from stdin carry the source `stdin` and no file path. The `file_path`
field in the report is `null`, because there is no file.

## The result depends on your working directory

A stdin scan has no filesystem path, so KeyHog resolves its allowlist from the
current directory. A `.keyhogignore` in the directory you happen to be standing
in is applied to bytes that have nothing to do with that repository.

Reproduce it. The same credential on stdin, the same binary, two directories:

```sh
mkdir -p /tmp/allowlist-demo
VALUE="sk_live_$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
HASH="$(printf '%s' "$VALUE" | sha256sum | cut -d' ' -f1)"
printf 'hash:%s; reason="demo"; approved_by="you"\n' "$HASH" \
  > /tmp/allowlist-demo/.keyhogignore

cd /tmp          && printf 'STRIPE_SECRET_KEY=%s\n' "$VALUE" | keyhog scan --stdin
cd /tmp/allowlist-demo && printf 'STRIPE_SECRET_KEY=%s\n' "$VALUE" | keyhog scan --stdin
```

The first exits `1` with one finding. The second exits `0` with none, over
identical bytes. There is no coverage gap, `source_bytes_scanned` is the same
`51` in both runs, and `scan_status` is `complete_after_recovery` either way.
Every field that normally distinguishes a skipped input from a scanned one says
this was a real scan that found nothing.

This matters because the recommended pipeline above is usually run from a
checkout.

Only `hash:` rules can affect a pipe. A `path:` rule has no path to match
against, so it does nothing here: piping the same credential from a directory
whose `.keyhogignore` contains `path:**` still reports the finding. Judge your
exposure by the number of live `hash:` entries, not by the length of the file.

Two ways to avoid it:

```sh
cd / && kubectl get secret app -o yaml | keyhog scan --stdin
```

Run the pipe from a directory with no `.keyhogignore`, or write the input to a
file outside the checkout and scan the path, which resolves the allowlist from
the input's own location:

```sh
kubectl get secret app -o yaml > /tmp/secret.yaml
keyhog scan /tmp/secret.yaml
```

Check which allowlist file is in play before you trust a clean stdin scan:

```sh
keyhog config --effective
```

The `allowlist_file` line names it.


## Empty input fails the scan

The command in front of the pipe is the part that usually fails. A `kubectl`
call against the wrong context, a `vault read` without a token, or a `curl` that
404s all produce empty output. KeyHog treats that as a failed scan rather than a
clean one:

```sh
printf '' | keyhog scan --stdin
```

Exit code `13`. The envelope reports `scan_status` `partial`, one chunk, zero
bytes, and one coverage gap:

```json
{
  "reason": "scan covered nothing (zero source bytes reached the scanner and no skip was counted; nothing was examined, so this result is not a clean bill of health)",
  "count": 1
}
```

This is a change in behavior. An empty stream used to exit `0` with
`scan_status` `success` and no gaps, which read as a clean scan. If you have a
pipeline that legitimately feeds an empty stream, for example a matrix job whose
partition is sometimes empty, it will now fail. Guard the producer instead of
suppressing the exit code:

```sh
if [ -s changed.diff ]; then
  keyhog scan --stdin < changed.diff
fi
```

There is deliberately no flag that turns the failure off.

Check the byte count, always:

```sh
kubectl get secret app -o yaml \
  | keyhog scan --stdin --format json-envelope -o keyhog.json
jq -e '.metadata.source_bytes_scanned > 0' keyhog.json
```

`jq -e` exits non-zero when the expression is false, so that line fails the
pipeline when nothing was scanned.

Set `pipefail` as well, so the producer's own failure is not swallowed:

```bash
set -o pipefail
kubectl get secret app -o yaml \
  | keyhog scan --stdin --format json-envelope -o keyhog.json
```

Without `pipefail` the shell reports only KeyHog's exit code, and KeyHog
succeeded at scanning nothing.

`pipefail` is a Bash and Zsh feature, not a POSIX one. Under `dash`, which is
`/bin/sh` on Debian and Ubuntu, `set -o pipefail` fails with
`set: Illegal option -o pipefail` and the guard you thought you had is not
there. Give the script a `#!/usr/bin/env bash` shebang, or run it with `bash`,
or capture the report and branch on the exit code as shown below, which needs
no shell option at all.

### Piping KeyHog into `jq` throws its exit code away

The reverse direction has the same hazard and is easier to get wrong, because
it looks like a summary rather than a gate:

```sh
keyhog scan . --format json | jq '.findings | length'
```

A shell reports the exit status of the LAST command in a pipeline. That line
reports `jq`'s status, not KeyHog's. A bad flag, an unreadable config, or a
detector corpus that will not compile all exit `2` and print nothing on stdout,
and the pipeline still succeeds. Add `|| echo 0` and you have converted every
one of those into the answer you were hoping for.

Two ways to keep the exit code. Turn on `pipefail`:

```sh
set -o pipefail
keyhog scan . --format json | jq '.findings | length'
```

That reports `2` when the scan failed. Or capture first and parse second, which
also lets you inspect what was written:

```sh
rm -f keyhog.json
rc=0
keyhog scan . --format json-envelope -o keyhog.json || rc=$?
[ "$rc" -le 1 ] || { echo "keyhog failed: exit $rc" >&2; exit 1; }
jq '.findings | length' keyhog.json
```

Capturing is the more robust of the two, because a scan that fails before it
can report writes no file at all, so the missing file is a second independent
signal that something went wrong.

## The size limit

`--stdin` accepts 10 MiB by default. A larger stream fails closed:

```sh
keyhog scan --stdin < big.json
```

```text
WARN source: failed to read source: stdin exceeds 10485760 byte limit.
error: a requested scan source failed to read and produced no data (see the
warnings above). Not reporting "clean": that scan did not run.
```

Exit code `13`. Nothing is scanned, including the first 10 MiB. The limit is
not a truncation point.

Raise it when a larger stream is intentional:

```sh
keyhog scan --stdin --limit-stdin-bytes 20M < big.json
```

An 11 MB input is first spooled to an anonymous temporary file so the limit is
validated before any partial result can escape. KeyHog then scans overlapping
1 MiB windows with 128 KiB of boundary coverage. Memory stays bounded, findings
retain absolute offsets and line numbers, and independent windows can use the
configured scan workers. The anonymous file is removed automatically when the
source closes.

`--limit-stdin-bytes` applies only to `--stdin`. It does not bound a directory
scan.

## Warm routing

An eligible stdin request can be served by a running daemon, which avoids
recompiling the detector corpus per invocation. That is the case worth a daemon:
a pipeline that runs `keyhog scan --stdin` many times.

```sh
keyhog daemon start
kubectl get secret app -o yaml | keyhog scan --stdin
```

`--daemon=auto` is the default and is safe to leave on unattended. A daemon
failure degrades to an in-process scan rather than losing the run, and for the
default configuration the findings are the same.

Do not read that as byte-identical. Coverage can differ across the fallback
boundary: scanner-side gaps such as the decode-cap skip below do not cross the
daemon wire, so the two routes can report a different `coverage_gap_summary`
for the same input even when the findings match.

What the pipeline cannot tell you is whether the daemon was actually used.
Omitting the flag prints nothing on either path, so a daemon you started but
are not reaching looks exactly like one that is working. Pass `--daemon=auto`
explicitly when that matters, and it says so on stderr when it fell back:

```text
keyhog: daemon route not used (no daemon is listening on <socket>);
running in-process scanner
```

That notice is on stderr, so a pipeline that redirects stderr and pipes stdout
into `jq` can be silently in-process and silently failing at the same time.

Force in-process execution when you want the scan isolated from daemon state:

```sh
kubectl get secret app -o yaml | keyhog scan --stdin --daemon=off
```

See [GPU-backed daemon file queues](../workflows/daemon.md) for eligibility and
lifecycle.

## A pipeline that cannot report a false clean

```sh
set -o pipefail
rm -f keyhog.json
rc=0
vault kv get -format=json secret/app \
  | keyhog scan --stdin --format json-envelope -o keyhog.json || rc=$?

[ -f keyhog.json ] \
  || { echo "keyhog wrote no report; the scan did not run" >&2; exit 1; }
jq -e '.metadata.source_bytes_scanned > 0' keyhog.json \
  || { echo "keyhog scanned nothing; the producer failed" >&2; exit 1; }

case "$rc" in
  0)  echo "no policy-blocking finding over $(jq '.metadata.source_bytes_scanned' keyhog.json) bytes" ;;
  1)  echo "blocking findings"; exit 1 ;;
  10) echo "live credential"; exit 1 ;;
  13) echo "coverage incomplete"; exit 1 ;;
  *)  echo "keyhog failed: exit $rc"; exit 1 ;;
esac
```

The byte check runs before the exit-code branch on purpose. Exit `0` only means
something when bytes were scanned.

[Tell a real clean from a skipped input](../reference/coverage-truth.md) covers
the report fields. [Exit codes](../reference/exit-codes.md) lists every code.
