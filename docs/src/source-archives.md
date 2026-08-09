# Source archives

KeyHog recognizes archive and compressed formats while scanning a file or
directory. You do not need a separate archive flag.

```sh
keyhog scan incoming/ --format json-envelope -o keyhog-archives.json
```

ZIP-family containers include ZIP, JAR, WAR, APK, IPA, CRX, Python and NuGet
packages, and common office formats. KeyHog also reads tar, 7z, RAR, and tar or
single streams compressed with gzip, zstd, LZ4, Snappy, bzip2, or xz. Supported
archives nested inside those formats are scanned within bounded depth and byte
budgets.

Each eligible readable regular member enters the normal detector pipeline.
Binary members use printable-string extraction. Finding paths retain every
container and member, such as `submission.tar//paper/main.tex`.

## How a member is admitted

A member's extension is consulted first, so a named member always resolves to
the format it has always resolved to. A member whose name carries no recognized
extension is admitted on its own leading bytes: gzip, zstd, xz, LZ4, Snappy,
bzip2, ZIP, and tar all have a signature at a fixed offset. An extensionless
gzip layer inside a tarball, a `.zip` renamed `.dat`, and a `.dat` that is
really a tar are therefore all descended into.

The probe reads a bounded prefix at offset zero. KeyHog never speculatively
runs an extractor to find out what a member is.

Some families have no signature and are not covered: cab, iso, xar, lzip, `.Z`,
and raw deflate or raw LZMA streams, which have no magic in principle. Those
fall through to printable-string extraction with no container coverage gap.
A 7z, RAR, or ar/deb member is different: it produces an explicit error row
naming the family, because those formats need a seekable file and have no
in-memory extractor.

## Streaming nested archives

KeyHog streams compressed tarballs (`.tar.gz`, `.tgz`, and nested compressed tar
members) into the member scanner. It does not keep a full decompressed tarball
resident while walking entries. Peak resident memory for archive extraction is
bounded by the compressed input, decoder window state, and the largest single
member under the active size caps, not by the sum of every decompressed layer.

TeX role annotations need member source bytes up front. Uncompressed `.tar` and
ZIP-family packages still run the buffered provenance pass when header/central
directory names include TeX sources. Compressed tarballs stay on the single-pass
streaming path so nested layers do not pay a second full inflate; members remain
fully scannable, without TeX role annotations on that compressed-tar path.

## Archives reached through Git or a bucket

Container expansion applies to files on disk and to the sources that expand
them. It does not apply to Git objects or to cloud object bodies. An archive
committed to a repository is descended into by `keyhog scan <path>` and is not
descended into by `--git-history` or `--git-blobs`, which report it as a
`binary (extension or content sniff)` gap. An object in an S3, GCS, or Azure
container is not descended into either.

Download or check out the archive and scan it as a file when its contents are
in scope.

## Scan untrusted archives

Keep the envelope report when the input may be corrupt or hostile:

```sh
rc=0
keyhog scan incoming/ --format json-envelope -o keyhog-archives.json || rc=$?
jq '{scan_status, coverage_gap_summary, findings: (.findings | length)}' \
  keyhog-archives.json
printf 'keyhog exit=%s\n' "$rc"
```

KeyHog does not extract members into the filesystem or execute their contents. Compressed tarballs are streamed member-by-member so nested layers do not each retain a full decompressed image in resident memory.
It rejects archive paths that are absolute, contain traversal, use ambiguous
encoding, or name a special file. It also refuses a top-level archive reached
through a symbolic link. Decoded bytes per member, nested depth, and aggregate
output are bounded. Formats with compression-ratio metadata also apply a ratio
guard.

Rejected, encrypted, corrupt, unreadable, oversized, or budget-truncated input
is not treated as clean. KeyHog reports the uncovered member or archive on
stderr and records a coverage gap in the envelope. With no findings, incomplete
coverage exits `13`. If the covered portion has findings, exit `1`, or exit `10`
for a confirmed live credential, takes precedence. The coverage warning and
`scan_status = "partial"` remain in the report.

Do not raise `--max-file-size` merely to make exit `13` disappear. Raise it only
when you trust the input and the runner has enough memory. Otherwise isolate the
failed archive, repair or unpack it with a trusted tool, and scan the recovered
files as a new input.

## Suppress one reviewed archive fixture

Use the full member path in `.keyhogignore.toml`. Include the detector and hash
so another credential in the same member still reports:

```toml
[[suppress]]
detector = "aws-access-key"
path_eq = "vendor-bundle.zip//examples/demo.env"
credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

The rule does not match the same member in a differently named container. It
also does not match a different value in `demo.env`. Inline directives are not
loaded from archive member text. See [Suppressions](./suppressions.md) for rule
precedence and failure behavior.

## TeX source packages

Scan a TeX source package like any other archive:

```sh
keyhog scan submission.tar
```

TeX packages receive an additional bounded dependency pass. It recognizes
`input`, `include`, `subfile`, `includegraphics`, `bibliography`, and
`addbibresource` commands. Paths are resolved relative to the referring member.
Absolute paths and references that escape the archive root do not enter the
dependency graph. After an exact member-name lookup, unresolved references try
the command's standard `.tex`, `.bib`, or graphics extensions.

Archive chunks use these source labels:

- `filesystem/archive/tex-root` for document roots
- `filesystem/archive/tex-referenced` for members reachable from a root
- `filesystem/archive/tex-orphaned` for inventory members not reachable from a root
- `filesystem/archive/tex-comment/<role>` for exact unescaped TeX comment spans

Binary members with printable strings use the corresponding
`filesystem/archive-binary/tex-<role>` label.

Comments are scanned with their original member path and byte offset. The full
member is also scanned unchanged. Expansion cycles terminate through a visited
member set. Malformed commands do not stop ordinary member scanning.

The dependency pass caps member count, per-source bytes, total source bytes,
references per member, and group nesting. If the analysis exceeds a cap,
role annotations are unavailable and every readable member still takes the
ordinary archive path. The scan reports the incomplete semantic expansion as a
coverage gap rather than claiming complete TeX analysis.

## Android packages

```sh
keyhog scan app-release.apk --format json-envelope -o app-release.keyhog.json
```

APK scans decode `resources.arsc` value tables and compiled Android XML before
running the normal detector pipeline. Resource findings preserve package, type,
entry name, resource ID, and configuration qualifier. XML findings preserve the
element path, attribute name, framework resource ID, and inline or referenced
value.

Decoded chunks use `filesystem/archive/android-resource` or
`filesystem/archive/android-xml`. KeyHog also scans each original member through
the ordinary archive path. It does not execute Dalvik code or resolve runtime
resource selection.

Input bytes, chunk count, string pools, resource entries, XML depth, emitted
items, and emitted bytes are bounded. A malformed compiled resource records an
`inaccessible` coverage gap. A cap records a `truncated` coverage gap. Semantic
decoding is incomplete in either case, while the original member scan
continues.
