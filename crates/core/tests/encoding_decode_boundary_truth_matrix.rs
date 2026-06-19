//! LANE-4 detection-truth: a DATA-DRIVEN standard-base64 decode boundary
//! matrix that pins `keyhog_core::decode_standard_base64` with EXACT
//! decoded bytes over thousands of generated cases.
//!
//! The hand-written cases in `regression_encoding_base64_padding_edge_cases.rs`
//! pin the named truncation-fix corner cases (interior `=`, leading `=`,
//! unalignable padding). This suite is the COMPLEMENTARY breadth lane: it
//! exhaustively round-trips the decoder against an independently-implemented,
//! trivially-auditable RFC-4648 reference ENCODER (below) over every payload
//! length 0..=N and a deterministic pseudo-random byte stream, then asserts the
//! decoded bytes are byte-for-byte the original payload — the *strongest*
//! oracle for "the wave-1 base64-truncation fix stays fixed": if the decoder
//! ever drops a tail byte again, a specific payload length flips red with the
//! exact lost bytes named.
//!
//! Every assertion is exact (Law 6): `assert_eq!(decoded, payload)` on real
//! bytes, never `is_ok`/`!is_empty`. Deterministic and host-independent (pure
//! arithmetic, no GPU, no scan timing). The reference encoder is local so this
//! test adds NO dependency to keyhog-core's `Cargo.toml` (it would be a
//! self-referential oracle to encode with the crate-under-test).

use keyhog_core::decode_standard_base64;

/// Trivially-auditable RFC-4648 standard-alphabet base64 ENCODER. ~20 lines,
/// no `=`-truncation subtlety — it is the independent oracle the decoder is
/// differential-tested against. Always emits canonical trailing padding.
fn encode_standard_base64_reference(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        match chunk.len() {
            1 => {
                out.push('=');
                out.push('=');
            }
            2 => {
                out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
                out.push('=');
            }
            _ => {
                out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
                out.push(ALPHABET[(n & 0x3F) as usize] as char);
            }
        }
    }
    out
}

/// Deterministic xorshift64* pseudo-random byte stream (seeded) — gives a
/// reproducible, non-trivial byte distribution (so we exercise every 6-bit
/// alphabet symbol and every padding remainder class) without an RNG crate or
/// non-determinism. Same seed ⇒ same corpus on every run / host / CI.
struct Xorshift64(u64);
impl Xorshift64 {
    fn next_byte(&mut self) -> u8 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

/// Self-check: the local reference encoder is correct on the canonical RFC-4648
/// §10 vectors, so a differential failure below is the DECODER's fault, never a
/// buggy oracle. (Without this the whole matrix could pass vacuously against a
/// wrong encoder.)
#[test]
fn reference_encoder_matches_rfc4648_test_vectors() {
    let vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (raw, expected) in vectors {
        assert_eq!(
            encode_standard_base64_reference(raw),
            *expected,
            "reference encoder disagrees with RFC-4648 §10 on {raw:?} — the \
             differential oracle is broken, fix the test encoder first"
        );
    }
}

/// THE breadth oracle: for every payload length 0..=768, encode a deterministic
/// pseudo-random payload of that length with the reference encoder, decode it
/// with `decode_standard_base64`, and assert the decoded bytes EQUAL the
/// original payload byte-for-byte. 769 distinct round-trip cases, each covering
/// a different `len % 3` padding-remainder class and a different final-quad
/// shape. A tail-truncation regression (the wave-1 bug) drops the last 1-2
/// bytes — caught here as a length/byte mismatch naming the exact payload.
#[test]
fn every_payload_length_round_trips_to_exact_bytes() {
    let mut rng = Xorshift64(0x9E3779B97F4A7C15);
    let mut cases = 0usize;
    for len in 0..=768usize {
        let payload = rng.bytes(len);
        let encoded = encode_standard_base64_reference(&payload);
        let decoded = decode_standard_base64(&encoded).unwrap_or_else(|e| {
            panic!("len {len}: well-formed base64 {encoded:?} must decode, got error {e:?}")
        });
        assert_eq!(
            decoded.len(),
            len,
            "len {len}: decoded {} bytes, expected {len} — TAIL TRUNCATION \
             regression (the wave-1 base64 fix). encoded={encoded:?}",
            decoded.len()
        );
        assert_eq!(
            decoded, payload,
            "len {len}: round-trip corrupted the payload. encoded={encoded:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 769, "expected 769 length cases, ran {cases}");
}

/// Round-trip the UNPADDED form too: `decode_standard_base64` accepts base64
/// without trailing `=` (the scanner's wire path strips it). For every payload
/// length, strip the reference encoder's trailing `=` and assert the decode
/// still yields the exact original bytes. Pins that dropping canonical padding
/// never drops a data byte. 769 more cases.
#[test]
fn unpadded_form_round_trips_to_exact_bytes() {
    let mut rng = Xorshift64(0xD1B54A32D192ED03);
    let mut cases = 0usize;
    for len in 0..=768usize {
        let payload = rng.bytes(len);
        let encoded = encode_standard_base64_reference(&payload);
        let unpadded = encoded.trim_end_matches('=');
        let decoded = decode_standard_base64(unpadded).unwrap_or_else(|e| {
            panic!("len {len}: unpadded {unpadded:?} must decode, got error {e:?}")
        });
        assert_eq!(
            decoded, payload,
            "len {len}: unpadded round-trip corrupted the payload. unpadded={unpadded:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 769, "expected 769 unpadded cases, ran {cases}");
}

/// Interior-`=` rejection over a generated matrix: for every well-formed
/// encoding of length >= 8, split it before each interior position and inject a
/// single `=`, then a data char. EVERY such mutation must be REJECTED with the
/// exact "data after padding" message — the wave-1 silent-truncation bug
/// decoded the prefix and dropped the suffix. Thousands of mutation cases.
#[test]
fn interior_padding_followed_by_data_is_always_rejected() {
    let mut rng = Xorshift64(0x2545F4914F6CDD1D);
    const MSG: &str = "invalid base64: data after padding '=' (padding may only appear at the end)";
    let mut cases = 0usize;
    for len in 3..=120usize {
        let payload = rng.bytes(len);
        let encoded = encode_standard_base64_reference(&payload);
        let base = encoded.trim_end_matches('=').to_string();
        let chars: Vec<char> = base.chars().collect();
        // Inject `=` after each interior data char (positions 1..chars.len()),
        // keeping at least one data char AFTER the injected `=` so it is an
        // interior-padding-then-data violation, not a legal trailing pad.
        for cut in 1..chars.len() {
            let mut mutated: String = chars[..cut].iter().collect();
            mutated.push('=');
            mutated.extend(&chars[cut..]); // data after the `=`
            let res = decode_standard_base64(&mutated);
            assert!(
                res.is_err(),
                "len {len} cut {cut}: interior '=' then data {mutated:?} must be \
                 REJECTED (silent-truncation regression), but it decoded to {:?}",
                res.clone().unwrap_or_default()
            );
            assert_eq!(
                res.unwrap_err(),
                MSG,
                "len {len} cut {cut}: interior-padding rejection message regressed for {mutated:?}"
            );
            cases += 1;
        }
    }
    assert!(
        cases >= 2000,
        "interior-padding matrix should generate >=2000 mutation cases, ran {cases}"
    );
}

/// Invalid-alphabet rejection: for a representative spread of out-of-alphabet
/// bytes injected into an otherwise-valid quad, decode must FAIL (never silently
/// skip the bad char). Asserts the error names the offending char so a future
/// "lenient skip" regression is caught.
#[test]
fn out_of_alphabet_bytes_are_rejected_not_skipped() {
    // Every byte 0..=127 that is NOT in the standard alphabet and not `=`.
    let in_alphabet = |c: u8| {
        c.is_ascii_uppercase()
            || c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == b'+'
            || c == b'/'
            || c == b'='
    };
    let mut cases = 0usize;
    for bad in 0u8..=127 {
        if in_alphabet(bad) {
            continue;
        }
        // Place the bad byte in a 4-char quad: `AB?D`.
        let probe = format!("AB{}D", bad as char);
        let res = decode_standard_base64(&probe);
        assert!(
            res.is_err(),
            "byte {bad:#x} is outside the base64 alphabet; {probe:?} must be \
             rejected, not silently skipped (it decoded to {:?})",
            res.clone().unwrap_or_default()
        );
        let msg = res.unwrap_err();
        assert!(
            msg.contains("invalid base64 char") && msg.contains(&format!("{bad:#x}")),
            "byte {bad:#x}: rejection must name the offending char, got {msg:?}"
        );
        cases += 1;
    }
    // 128 ASCII minus the 65 alphabet/pad chars = 63 invalid ASCII bytes.
    assert_eq!(
        cases, 63,
        "expected 63 invalid-ASCII-byte cases, ran {cases}"
    );
}

/// Truncated final quad (a lone leftover char, `idx % 4 == 1`) is impossible to
/// encode and must be rejected — over a generated spread of base lengths. A
/// lone trailing char carries < 6 bits of a byte; accepting it would fabricate
/// a byte. Pins the "truncated base64" / unalignable arms.
#[test]
fn lone_trailing_char_is_rejected() {
    let mut rng = Xorshift64(0x106689D45497FDB5);
    let mut cases = 0usize;
    for len in 1..=200usize {
        let payload = rng.bytes(len);
        let base = encode_standard_base64_reference(&payload)
            .trim_end_matches('=')
            .to_string();
        // Append exactly one extra alphabet char to force `len % 4 == 1`
        // somewhere, OR truncate to a `% 4 == 1` length. Use truncation: chop
        // to the largest length L < base.len() with L % 4 == 1.
        let mut l = base.len();
        while l > 0 && l % 4 != 1 {
            l -= 1;
        }
        if l == 0 || l == base.len() {
            continue; // no usable rem-1 truncation for this length
        }
        let truncated = &base[..l];
        let res = decode_standard_base64(truncated);
        assert!(
            res.is_err(),
            "len {len}: a final quad with one leftover char {truncated:?} \
             (len%4==1) must be rejected, but decoded to {:?}",
            res.unwrap_or_default()
        );
        cases += 1;
    }
    assert!(
        cases >= 50,
        "lone-trailing-char matrix should generate >=50 cases, ran {cases}"
    );
}

/// Oversize guard: an input one byte over the cap is rejected with the exact
/// byte-limit message; an input AT the cap is accepted by the length check
/// (it then proceeds to normal decode). Pins the DoS bound exactly.
#[test]
fn oversize_input_is_rejected_at_the_exact_boundary() {
    let max_standard_base64_input_bytes =
        keyhog_core::testing::CoreTestApi::max_standard_base64_input_bytes(
            &keyhog_core::testing::TestApi,
        );
    // One byte over the cap → rejected with the size message.
    let over = "A".repeat(max_standard_base64_input_bytes + 1);
    let err = decode_standard_base64(&over).expect_err("input over the cap must be rejected");
    assert_eq!(
        err,
        format!("base64 input exceeds {max_standard_base64_input_bytes} bytes"),
        "oversize rejection message regressed"
    );
    // A small, well-formed input at/under the cap is NOT rejected by the size
    // guard (it decodes normally). Use a tiny valid one to prove the guard
    // doesn't false-trip below the boundary.
    assert_eq!(
        decode_standard_base64("QUJD").expect("under-cap input decodes"),
        b"ABC",
        "the size guard must not reject inputs under the cap"
    );
    // Exact value pin of the cap so a silent widening/narrowing is caught.
    assert_eq!(
        max_standard_base64_input_bytes,
        16 * 1024 * 1024,
        "the standard-base64 input cap changed — update the DoS-bound contract \
         and the scanner's matching limit together"
    );
}
