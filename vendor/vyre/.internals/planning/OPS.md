# vyre op gallery

Generated from `vyre-core/src/ops/` at commit 179769c8ee38a52beb054d772152bce8ea209f54. Do not edit by hand;
run `scripts/generate-ops-md.sh` to regenerate.

## Family — primitive.bitwise (14 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| primitive.bitwise.and | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.clz | unary-bitwise | (U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.ctz | unary-bitwise | (U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.extract_bits | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.insert_bits | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.not | unary-bitwise | (U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.or | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.popcount | unary-bitwise | (U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.reverse_bits | unary-bitwise | (U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.rotl | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.rotr | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.shl | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.shr | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.bitwise.xor | binary-bitwise | (U32, U32) -> U32 | - | ✅ | - | - |

## Family — primitive.math (11 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| primitive.math.abs | unary-arithmetic | (U32) -> U32 | - | ✅ | - | - |
| primitive.math.add | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.math.add_sat | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.math.div | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.math.mod | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.math.mul | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.math.neg | unary-arithmetic | (I32) -> I32 | - | ✅ | - | - |
| primitive.math.negate | unary-arithmetic | (U32) -> U32 | - | ✅ | - | - |
| primitive.math.sign | unary-arithmetic | (I32) -> I32 | - | ✅ | - | - |
| primitive.math.sub | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |
| primitive.math.sub_sat | binary-arithmetic | (U32, U32) -> U32 | - | ✅ | - | - |

## Family — primitive.compare (7 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| primitive.compare.eq | binary-comparison | (U32, U32) -> Bool | - | ✅ | - | - |
| primitive.compare.ge | binary-comparison | (U32, U32) -> Bool | - | ✅ | - | - |
| primitive.compare.gt | binary-comparison | (U32, U32) -> Bool | - | ✅ | - | - |
| primitive.compare.le | binary-comparison | (U32, U32) -> Bool | - | ✅ | - | - |
| primitive.compare.logical_not | unary-logical | (U32) -> U32 | - | ✅ | - | - |
| primitive.compare.lt | binary-comparison | (U32, U32) -> Bool | - | ✅ | - | - |
| primitive.compare.ne | binary-comparison | (U32, U32) -> Bool | - | ✅ | - | - |

## Family — hash (10 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| hash.crc32 | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.entropy | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.fnv1a32 | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.hmac_sha256 | hash-bytes-to-u32 | (Bytes, Bytes) -> U32 | - | ✅ | - | - |
| hash.md5 | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.rolling | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.sha1 | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.sha256 | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| hash.xxhash3_64 | hash-bytes-to-u64 | (Bytes) -> U64 | - | ✅ | - | - |
| hash.xxhash64 | hash-bytes-to-u64 | (Bytes) -> U64 | - | ✅ | - | - |

## Family — decode (5 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| decode.base32 | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| decode.base64url | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| decode.hex_decode_strict | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| decode.url_percent | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| decode.utf8_validate | rule-bytes-to-bool | (Bytes) -> Bool | - | ✅ | - | - |

## Family — encode (3 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| encode.base64_encode | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| encode.hex_encode_lower | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| encode.url_percent_encode | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |

## Family — compression (3 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| compression.deflate_decompress | compression-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| compression.gzip_decompress | compression-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| compression.zlib_decompress | compression-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |

## Family — match (2 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| match.dfa_scan | match-bytes-pattern | (U32) -> U32 | - | ✅ | - | - |
| match.scatter | match-bytes-pattern | (U32) -> U32 | - | ✅ | - | - |

## Family — graph (2 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| graph.bfs | graph-reachability | (Bytes, U32) -> Bool | - | ✅ | - | - |
| graph.reachability | graph-reachability | (Bytes, U32) -> Bool | - | ✅ | - | - |

## Family — string (2 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| string.prefix_brace | tokenize-bytes | (Bytes) -> U32 | - | ✅ | - | - |
| string.tokenize_gpu | tokenize-bytes | (Bytes) -> U32 | - | ✅ | - | - |

## Family — stats (6 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| stats.arithmetic_mean | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| stats.byte_histogram | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| stats.chi_square | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| stats.sliding_entropy | decode-bytes-to-bytes | (Bytes, U32) -> Bytes | - | ✅ | - | - |
| stats.std_dev | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |
| stats.variance | hash-bytes-to-u32 | (Bytes) -> U32 | - | ✅ | - | - |

## Family — buffer (7 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| buffer.byte_count | graph-reachability | (Bytes, U32) -> U32 | - | ✅ | - | - |
| buffer.byte_swap_u32 | unary-bitwise | (U32) -> U32 | - | ✅ | - | - |
| buffer.byte_swap_u64 | hash-bytes-to-u64 | (U64) -> U64 | - | ✅ | - | - |
| buffer.memchr | graph-reachability | (Bytes, U32) -> U32 | - | ✅ | - | - |
| buffer.memcmp | rule-bytes-to-bool | (Bytes, Bytes) -> Bool | - | ✅ | - | - |
| buffer.memcpy | decode-bytes-to-bytes | (Bytes) -> Bytes | - | ✅ | - | - |
| buffer.memset | decode-bytes-to-bytes | (U32, U32) -> Bytes | - | ✅ | - | - |

## Family — other (8 ops)

| op | archetype | signature | laws | status | consumer | benchmark |
|---|---|---|---|---|---|---|
| reductions.argmax_u32 | hash-bytes-to-u32 | (U32) -> U32 | - | ✅ | - | - |
| reductions.argmin_u32 | hash-bytes-to-u32 | (U32) -> U32 | - | ✅ | - | - |
| reductions.reduce_all | hash-bytes-to-u32 | (Bool) -> Bool | - | ✅ | - | - |
| reductions.reduce_any | hash-bytes-to-u32 | (Bool) -> Bool | - | ✅ | - | - |
| reductions.reduce_count | hash-bytes-to-u32 | (U32) -> U32 | - | ✅ | - | - |
| reductions.reduce_max_u32 | hash-bytes-to-u32 | (U32) -> U32 | - | ✅ | - | - |
| reductions.reduce_min_u32 | hash-bytes-to-u32 | (U32) -> U32 | - | ✅ | - | - |
| reductions.reduce_sum_u32 | hash-bytes-to-u32 | (U32) -> U32 | - | ✅ | - | - |
