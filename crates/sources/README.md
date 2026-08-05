# keyhog-sources

Input sources for the KeyHog secret scanner. Each source turns one kind of
input into a stream of `Chunk` values: the filesystem, the exact Git staged
index, Git history, diffs and blobs, standard input, container images, archives
and nested archives, native binaries, web URLs, hosted Git organizations, and
the S3, GCS, and Azure Blob object stores.

Part of the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

```rust
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

let directory = std::env::temp_dir().join("keyhog-sources-readme");
std::fs::create_dir_all(&directory)?;
std::fs::write(directory.join("app.env"), "API_TOKEN=example\n")?;

let source = FilesystemSource::new(directory.clone());

// Every source yields `Result<Chunk, SourceError>`. An input the source cannot
// read is an Err row in the stream, not a missing chunk.
let mut read = 0usize;
for chunk in source.chunks() {
    let chunk = chunk?;
    read += chunk.data.len();
}
assert!(read > 0);
# std::fs::remove_dir_all(&directory).ok();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Public entry points

- `Source` from `keyhog-core` is the one trait every source implements.
  Consume `chunks()` and handle both arms; an `Err` row means that input was not
  scanned.
- `create_source` and its `create_source_with_*` variants build the right source
  for a target string plus HTTP config, limits, and policy. Use the factory
  rather than naming a concrete source when the target comes from a user.
- `SourceLimits` and `DEFAULT_SOURCE_LIMITS` carry every cap. A cap that trips
  is recorded, not swallowed.
- `skip_counts` and `SkipCounts` report what was skipped and why. Read them
  before you treat an empty finding set as a clean result.

## Failure behavior

A source that cannot honor a target fails loudly. Caps, unreadable inputs, and
unsupported members are recorded as typed skip or error rows so a caller can
tell "nothing was found" apart from "nothing was looked at". Never read an empty
chunk stream as proof of a clean input without also reading `skip_counts`.

## Features

`default = ["git", "web"]`. The remote and container sources are opt in:
`github`, `gitlab`, `bitbucket`, `docker`, `s3`, `gcs`, `azure`, `slack`, and
`binary`. Enabling only what you consume keeps both the dependency graph and the
binary smaller.

## Documentation

- [Source archives and containers](https://santhreal.github.io/keyhog/source-archives.html)
  describes the admission rules these sources apply.
- [Architecture](https://santhreal.github.io/keyhog/architecture.html) describes
  the bytes-to-finding pipeline this crate feeds.
- API documentation is on [docs.rs](https://docs.rs/keyhog-sources).
