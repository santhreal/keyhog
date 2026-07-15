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
| Betterleaks | https://github.com/betterleaks/betterleaks (benchmark pin: v1.6.1, `28f08b4c8c4420a601f67ee9887c201697ff4568`) | MIT |
| Titus | https://github.com/praetorian-inc/titus (benchmark pin: v1.1.20, `750ced31697c3eb209adc145f3d13a754e849ffa`) | Apache-2.0 |

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

## Recovery benchmark methodology

The `ioc-recovery` corpus adapts the P0-P12 experimental progression described
in Jaime Morales, Sergio Pastrana, and Juan Tapiador, [*Benchmarking Large
Language Models for IoC Recovery under Adversarial Code Obfuscation and
Encryption*](https://arxiv.org/abs/2605.06910), licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The authors publish an MIT-licensed repository with 13 demonstration files at
[`jaimemorales52/llm-ioc-detection`](https://github.com/jaimemorales52/llm-ioc-detection/tree/91d45377cf482c1de6c36a0d33744665976a19b6),
commit `91d45377cf482c1de6c36a0d33744665976a19b6`. It does not contain the
paper's 336-program evaluation corpus. KeyHog ships its own generator and no
upstream dataset bytes. The generated corpus is a methodology adaptation using
deterministic synthetic credentials, not a byte-identical copy of the paper's
evaluation data.

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
license (MIT for Betterleaks and Apache-2.0 for Kingfisher). We redistribute
none of it.
