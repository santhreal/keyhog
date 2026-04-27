# op-id stability catalog

This file is **generated** from the live `DialectRegistry`.
Editing it by hand is meaningless — the test
`vyre-core/tests/op_id_catalog.rs` regenerates on demand
(`VYRE_REGEN_OP_CATALOG=1 cargo test --test op_id_catalog`) and
gates CI against drift.

Every op id below is a **stable public contract**: programs
encoded against an id expect the id to mean the same thing
in perpetuity. Renaming an op is a breaking API change.

## `buffer`

| op id | category |
|-------|----------|
| `buffer.byte_count` | C |
| `buffer.byte_swap_u32` | C |
| `buffer.byte_swap_u64` | C |
| `buffer.memchr` | C |
| `buffer.memcmp` | C |
| `buffer.memcpy` | C |
| `buffer.memset` | C |

## `core`

| op id | category |
|-------|----------|
| `core.indirect_dispatch` | C |

## `decode`

| op id | category |
|-------|----------|
| `decode.base32` | C |
| `decode.base64url` | C |
| `decode.url_percent` | C |
| `decode.utf8_validate` | C |

## `encode`

| op id | category |
|-------|----------|
| `encode.url_percent_encode` | C |

## `hash`

| op id | category |
|-------|----------|
| `hash.argon2id` | C |
| `hash.blake2b` | C |
| `hash.blake2s` | C |
| `hash.blake3` | C |
| `hash.hkdf_expand` | C |
| `hash.hkdf_extract` | C |
| `hash.hmac_md5` | C |
| `hash.hmac_sha1` | C |
| `hash.hmac_sha256` | C |
| `hash.md5` | C |
| `hash.pbkdf2_sha256` | C |
| `hash.ripemd160` | C |
| `hash.sha1` | C |
| `hash.sha256` | C |
| `hash.sha3` | C |
| `hash.sha384` | C |
| `hash.sha3_256` | C |
| `hash.sha3_512` | C |
| `hash.sha512` | C |
| `hash.siphash13` | C |
| `hash.xxhash` | C |
| `hash.xxhash3_64` | C |
| `hash.xxhash64` | C |

## `io`

| op id | category |
|-------|----------|
| `io.dma_from_nvme` | C |
| `io.write_back_to_nvme` | C |
| `mem.unmap` | C |
| `mem.zerocopy_map` | C |

## `logical`

| op id | category |
|-------|----------|
| `primitive.logical.and` | A |
| `primitive.logical.nand` | A |
| `primitive.logical.nor` | A |
| `primitive.logical.or` | A |
| `primitive.logical.xor` | A |

## `math`

| op id | category |
|-------|----------|
| `primitive.math.avg_floor` | A |
| `primitive.math.wrapping_neg` | A |

## `security_detection`

| op id | category |
|-------|----------|
| `security_detection.detect_base64_run` | C |
| `security_detection.detect_command_injection` | C |
| `security_detection.detect_email` | C |
| `security_detection.detect_hex_run` | C |
| `security_detection.detect_high_entropy_window` | C |
| `security_detection.detect_ipv4` | C |
| `security_detection.detect_ipv6` | C |
| `security_detection.detect_jwt` | C |
| `security_detection.detect_lfi` | C |
| `security_detection.detect_obfuscated_js` | C |
| `security_detection.detect_packed_binary` | C |
| `security_detection.detect_path_traversal` | C |
| `security_detection.detect_pem_block` | C |
| `security_detection.detect_rfi` | C |
| `security_detection.detect_sql_injection` | C |
| `security_detection.detect_ssrf` | C |
| `security_detection.detect_url` | C |
| `security_detection.detect_uuid` | C |
| `security_detection.detect_xor_single_byte` | C |
| `security_detection.detect_xss` | C |
| `security_detection.detect_xxe` | C |
| `security_detection.file_magic_detect` | C |

## `stats`

| op id | category |
|-------|----------|
| `stats.arithmetic_mean` | C |
| `stats.kernel` | C |
| `stats.sliding_entropy` | C |
| `stats.std_dev` | C |
| `stats.variance` | C |

## `string_matching`

| op id | category |
|-------|----------|
| `string_matching.aho_corasick_scan` | C |
| `string_matching.boyer_moore_find` | C |
| `string_matching.glob_match` | C |
| `string_matching.kmp_find` | C |
| `string_matching.substring_contains` | C |
| `string_matching.substring_find_all` | C |
| `string_matching.substring_find_first` | C |
| `string_matching.wildcard_match` | C |

## `string_similarity`

| op id | category |
|-------|----------|
| `string_similarity.hamming` | C |
| `string_similarity.ngram_extract` | C |
| `string_similarity.ngram_histogram` | C |
| `string_similarity.simhash64` | C |

## `wgsl_byte_primitives`

| op id | category |
|-------|----------|
| `wgsl_byte_primitives.bytes` | C |

## `workgroup`

| op id | category |
|-------|----------|
| `workgroup.hashmap` | C |
| `workgroup.queue_fifo` | C |
| `workgroup.queue_priority` | C |
| `workgroup.stack` | C |
| `workgroup.state_machine` | C |
| `workgroup.string_interner` | C |
| `workgroup.typed_arena` | C |
| `workgroup.union_find` | C |
| `workgroup.visitor` | C |

