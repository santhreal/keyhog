# Source archives

KeyHog scans every readable regular member of ZIP and tar archives through the
normal detector pipeline. Nested supported archives use the same path. Finding
paths retain the container and member name, such as
`submission.tar//paper/main.tex`.

## TeX source packages

TeX packages receive an additional bounded dependency pass. It recognizes
`input`, `include`, `subfile`, `includegraphics`, `bibliography`, and
`addbibresource` commands. Paths are resolved relative to the referring member.
Absolute paths and references that escape the archive root do not enter the
dependency graph. After an exact member-name lookup, unresolved references try
the command's standard `.tex`, `.bib`, or graphics extensions.

Archive chunks expose these source labels:

- `filesystem/archive/tex-root` for document roots
- `filesystem/archive/tex-referenced` for members reachable from a root
- `filesystem/archive/tex-orphaned` for inventory members not reachable from a root
- `filesystem/archive/tex-comment/<role>` for exact unescaped TeX comment spans

Binary members with printable strings use the corresponding
`filesystem/archive-binary/tex-<role>` label.

Comments are scanned with their original member path and byte offset. The full
member is also scanned unchanged. Expansion cycles terminate through a visited
member set. Malformed commands do not stop member scanning.

The dependency pass caps member count, per-source bytes, total source bytes,
references per member, and group nesting. If a package exceeds a cap, KeyHog
reports that role annotations are unavailable and still scans every readable
member through the ordinary archive path.

## Android packages

APK scans decode `resources.arsc` value tables and compiled Android XML before
running the normal detector pipeline. The resource-table path preserves package,
type, entry name, resource ID, and configuration qualifier. The XML path
preserves the element path, attribute name, framework resource ID, and inline or
referenced value.

Decoded chunks use `filesystem/archive/android-resource` or
`filesystem/archive/android-xml`. Paths retain the APK, member, semantic name,
and byte-backed resource identity. KeyHog also scans each original member through
the ordinary archive path. The adapter does not execute Dalvik code or resolve
runtime resource selection.

Input bytes, chunk count, string pools, resource entries, XML depth, emitted
items, and emitted bytes are bounded. A malformed compiled resource emits an
`inaccessible` coverage gap. A cap emits a `truncated` coverage gap. Both state
that semantic decoding was incomplete while the original member scan continues.
