# vyre-libs op naming

Every public Cat-A free function follows the pattern:

```
<verb>[_<qualifier>]*
```

where:

- `<verb>` is a lowercase snake_case noun/verb describing the operation
  (`dot`, `matmul`, `softmax`, `layer_norm`, `attention`, `scan`,
  `broadcast`, `substring`, `aho_corasick`, `blake3`, `fnv1a`).
- `<qualifier>` is an optional suffix describing the variant
  (`_tiled`, `_prefix_sum`, `_compress`, `_search`, `32`).

Examples that match the scheme:

- `dot` — verb only, canonical.
- `matmul` — verb + implicit `_dense` qualifier baked in.
- `matmul_tiled` — verb + qualifier (tile-unrolled variant).
- `scan_prefix_sum` — verb + qualifier (prefix-sum flavour of scan).
- `substring_search` — verb (`substring`) + qualifier (`_search`).
- `aho_corasick` — legacy two-word verb; pre-0.6 canonical name.
- `blake3_compress` — verb (`blake3`) + qualifier (`_compress`).
- `fnv1a32` — verb (`fnv1a`) + qualifier (`32`-bit variant).

## Counter-examples (would reject)

- `dotProduct` — camelCase not allowed.
- `DotProd` — PascalCase not allowed at free-function level.
- `compute_dot_product` — leading noun `compute_` is noise; drop it.
- `do_softmax` — imperative prefix is noise.
- `softmax_op` — `_op` suffix is redundant; every vyre-libs fn is an op.

## Builders

Typed builders use `PascalCase` matching the verb, no qualifier:

| Free function | Builder type |
| --- | --- |
| `softmax` | `Softmax` |
| `layer_norm` | `LayerNorm` |
| `attention` | `Attention` |
| `matmul` | `Matmul` |
| `matmul_tiled` | `MatmulTiled` |

Builders for community ops follow the same convention.

## CI gate

`scripts/check_op_names.sh` greps every `pub fn` under
`vyre-libs/src/*/*.rs` (op modules) against the regex
`^pub fn [a-z][a-z0-9_]*\s*\(` and rejects any name that:

- starts with `compute_`, `do_`, `run_`, `make_`, `create_`, `new_`;
- contains uppercase letters;
- ends with `_op`, `_impl`, `_internal`.

Builder types are checked against `^pub struct [A-Z][A-Za-z0-9]*\s*{`.

Runs on every PR.
