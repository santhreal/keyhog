# Container images and OCI layers

Scan an image by reference:

```sh
keyhog scan --docker-image registry/app:v1 --format json-envelope -o image.json
```

KeyHog runs `docker image save` for that reference, then streams each layer
tarball through the shared in-memory archive scanner. Layer members are not
materialized onto disk before scanning. A credential baked into a layer is found
even when a later layer deletes the file, because every layer is scanned
independently: whiteout and opaque-dir markers are ordinary members, not a
reason to hide earlier-layer content.

Nested members keep the same coverage as an unpack-then-walk scan: gzip/zip/tar/compressed payloads descend in memory, `.7z`/`.rar` use the shared path extractors (staged from the already-buffered member), and layer `.har` files expand at the Docker boundary with `wire:har` labels. Nested `.har` inside ordinary zip/tar/7z/RAR keep the historical `filesystem/archive` leaf identity. Large already-UTF-8 plain layer members stream in ~1 MiB windows from the tar entry; UTF-16 and other encodings keep the whole-member decode path. Windowed members keep the `filesystem/archive` source identity.

## What you need

`--docker-image` shells out to the `docker` CLI and needs a reachable Docker
daemon. It does not talk to a registry itself, so the image must already be
present locally or pullable by that daemon.

Pull first when the image is remote:

```sh
docker pull registry/app:v1
keyhog scan --docker-image registry/app:v1
```

A reference the daemon cannot resolve fails loudly:

```sh
keyhog scan --docker-image registry/app:no-such-tag
```

```text
WARN source: failed to read source: failed to export docker image:
registry/app:no-such-tag: Error response from daemon: No such image: ...
error: a requested scan source failed to read and produced no data (see the
warnings above). Not reporting "clean": that scan did not run.
```

Exit code `13`. That is the behavior you want. A typo in a tag never reads as a
clean image.

## Scanning a saved tarball

`docker image save` writes an OCI layout whose layer payloads are
`blobs/sha256/<digest>` files with no extension. Scanning that tarball as a path
works:

```sh
docker image save registry/app:v1 -o app.tar
keyhog scan app.tar --format json-envelope
```

For a one-layer image holding a live-shaped credential, that reports the
finding. A container member is admitted by its own leading bytes when its name
carries no recognized extension, so an extensionless gzip or tar layer is
descended into rather than treated as opaque.

Extracting the tarball first works too:

```sh
mkdir -p /tmp/image-audit
tar xf app.tar -C /tmp/image-audit
keyhog scan /tmp/image-audit --format json-envelope -o image.json
```

Prefer `--docker-image` when you have a daemon. It takes a reference rather than
asking you to produce and manage a tarball, and a bad reference fails loudly
instead of scanning a file that is not the image you meant.

If you want the layer contents as ordinary files, for example to map a finding
back to a path inside the image, unpack the layers yourself:

```sh
mkdir -p /tmp/image-audit/layers
for blob in /tmp/image-audit/blobs/sha256/*; do
  if file -b "$blob" | grep -q gzip; then
    mkdir -p "/tmp/image-audit/layers/$(basename "$blob")"
    tar xzf "$blob" -C "/tmp/image-audit/layers/$(basename "$blob")"
  fi
done
keyhog scan /tmp/image-audit/layers --format json-envelope -o layers.json
```

## An image in a repository or a bucket is not covered

Container handling applies to files on disk and to the sources that expand
them. It does not apply to Git objects or to cloud object bodies. An image
tarball committed to a repository, or sitting in an S3 bucket, is not descended
into.

The same bytes behave differently depending on how you reach them:

```sh
keyhog scan repo/ --no-default-excludes      # descends into the tarball
keyhog scan --git-history repo               # does not
```

The working-tree scan reports the credential inside the archive. The
Git-history scan reports a `binary (extension or content sniff)` gap for that
blob and exits `0` with a partial status. Running `--git-blobs` instead reports
the same gap and exits `13`.

That gap row is easy to misread. A `binary` gap usually means an image or a
compiled object you did not want scanned. Here it means an archive whose
contents were never examined. If your repository holds committed archives and
you scan history, unpack them and scan the result as a separate job.

## Limits

Three caps bound image expansion. Each one fails loudly when it binds.

| Flag | Bounds |
|---|---|
| `--limit-docker-tar-total-bytes` | Cumulative bytes admitted for one image, summed across the outer image tar and every streamed layer tar. Partial coverage is reported as a gap; it is never a silent clean. |
| `--limit-docker-tar-entry-bytes` | Bytes accepted for one entry inside a layer. |
| `--limit-docker-image-config-bytes` | Bytes accepted for the image config and manifest JSON. |

A cumulative cap that binds stops the whole export:

```sh
keyhog scan --docker-image registry/app:v1 --limit-docker-tar-total-bytes 100B
```

```text
WARN source: failed to read source: docker archive cumulative size exceeds 100
bytes at entry 'blobs/sha256/0d8eec63...' (likely zip-bomb).
error: a requested scan source failed to read and produced no data ...
```

Exit code `13`.

A per-entry cap that binds skips that entry and keeps going, with the skip
recorded:

```sh
keyhog scan --docker-image registry/app:v1 --limit-docker-tar-entry-bytes 10B \
  --format json-envelope
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

Exit code `13`, because nothing was found in the part that was covered.

The caps exist because an image layer is attacker-controllable compressed data.
Raise them for an image you trust, on a runner with the memory to hold the
expansion. Do not raise them to make exit `13` disappear on an image you pulled
from somewhere you do not control.

## Check coverage

```sh
jq '{bytes: .metadata.source_bytes_scanned, chunks: .metadata.source_chunks_scanned,
     status: .scan_status, gaps: .coverage_gap_summary,
     findings: (.findings | length)}' image.json
```

For an image scan, sanity-check `bytes` against the image size you expect.
A multi-hundred-megabyte application image that reports a few kilobytes was not
unpacked.

Prove your pipeline can see into a layer before you trust it. Build a canary
image, scan it, and confirm the finding:

```sh
mkdir -p /tmp/canary-image
printf 'STRIPE_SECRET_KEY=sk_live_%s\n' \
  "$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)" \
  > /tmp/canary-image/creds.env
printf 'FROM scratch\nCOPY creds.env /etc/creds.env\n' > /tmp/canary-image/Dockerfile
docker build -t keyhog-canary:v1 /tmp/canary-image
keyhog scan --docker-image keyhog-canary:v1 --format json-envelope \
  | jq '.findings | length'
```

Expect `1`. A pipeline that reports `0` there is not scanning layers, and no
real image will tell you so.

[Tell a real clean from a skipped input](../reference/coverage-truth.md) covers
the report fields and every gap reason.
