# Third-party notices & attribution, benchmark suite

keyhog's benchmark suite compares keyhog against other open-source secret
scanners and scores against public datasets. We are grateful to these projects.
This file credits each one and records its license.

keyhog itself is licensed under its own terms, see the repository-root
`LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT`, and `NOTICE`. Nothing here relicenses
keyhog; it documents the third-party tools and data the benchmark *uses*.

## Benchmarked scanners

| Tool | Upstream | License |
|---|---|---|
| Kingfisher | https://github.com/mongodb/kingfisher | Apache-2.0 |
| TruffleHog | https://github.com/trufflesecurity/trufflehog | AGPL-3.0 |
| Nosey Parker | https://github.com/praetorian-inc/noseyparker | Apache-2.0 |
| `betterleaks` (bench alias) | upstream project, see note below | per upstream |
| `titus` (bench alias) | upstream project, see note below | per upstream |

> **Note on `betterleaks` / `titus`:** these are the bench's internal adapter
> names (`benchmarks/bench/scanners/competitors.py`). They wrap real upstream
> tools invoked from `$BETTERLEAKS_BIN` / `$TITUS_BIN`. Replace these rows with
> the exact upstream project + SPDX license once the alias→tool mapping is
> confirmed, so attribution is precise rather than assumed.

Each scanner is invoked as an external binary the operator installs; keyhog does
not vendor, redistribute, or relink any of their code. AGPL-3.0 (TruffleHog) is
copyleft: running it as a benchmark subprocess is use, not distribution, but
keep this in mind before bundling its binary.

## Datasets

| Dataset | Upstream | License |
|---|---|---|
| Samsung CredData | https://github.com/Samsung/CredData | Per-file original (upstream-project) licenses + repo `LICENSE`; see CredData's `license/` dir keyed by RepoID |

CredData is **not committed** to this repo: `make creddata` downloads it at a
pinned commit (`benchmarks/corpora/` is gitignored). We ship only loader code
and the pinned reference, never the dataset bytes.

## Home-turf harvested fixtures

`benchmarks/corpora/homefield/{betterleaks,kingfisher}/` are harvested by
`harvest_betterleaks.py` / `harvest_kingfisher.py` from each tool's **own
published rule examples** (betterleaks `cmd/generate/config/rules/*.go`
`tps`/`fps`; kingfisher `data/rules/*.yml` `examples`/`negative_examples`) 
the exact strings the upstream project ships as its own regression ground truth,
used here only to benchmark detection on each tool's home turf.

These fixtures are **gitignored and never committed** (`homefield/.gitignore`
ignores `*/corpus/`); they are regenerated locally from a checkout/cache of the
upstream source. Their content remains under the respective upstream project's
license (Apache-2.0 for kingfisher; see the `betterleaks` upstream for its
terms). We redistribute none of it.
